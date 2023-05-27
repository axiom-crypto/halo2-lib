/*
 * Runs through a smoke test for KZGChip.
 */
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::{poly::kzg::multiopen::{ProverGWC, VerifierGWC}, halo2curves::bn256::G2Affine},
    utils::fs::gen_srs,
    Context,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
use crate::{fields::{FieldChip, PrimeField, fp::BaseFieldChip, FpStrategy}, ecc::EccChip, commitments::kzg::KZGChip};
use crate::{
    bn254::{pairing::PairingChip, FpChip, Fp2Chip},
    fields::fp::{FpConfig},
};
use crate::{
    fields::{
        fp12::Fp12Chip,
    },
};
use crate::commitments::tests::polynomial::Polynomial;
use crate::halo2_proofs::dev::MockProver;
use crate::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G1, G2};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct KZGCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

/*
 * Convenience function for running a mock setup() for the commitment
 * scheme. This is not secure.
 */
fn mock_trusted_setup(tau: Fr, blob_len: usize, n_openings: usize) -> (Vec<G1>, Vec<G2>) {
    // Powers of tau in G1 to commit to polynomials p(X) and q(X)
    let mut ptau_g1: Vec<G1> = vec![G1::generator()];
    for _ in 1..blob_len {
        ptau_g1.push(ptau_g1.last().unwrap() * tau);
    }

    // Powers of tau in G2 to commit to polynomials z(X) and r(X)
    let mut ptau_g2: Vec<G2> = vec![G2::generator()];
    for _ in 1..=n_openings {
        ptau_g2.push(ptau_g2.last().unwrap() * tau);
    }

    (ptau_g1, ptau_g2)
}

fn kzg_test(
    builder: &mut GateThreadBuilder<Fr>,
    params: KZGCircuitParams,
    q_bar: G1Affine,
    p_bar: G1Affine,
    ptau_g1: Vec<G1>,
    ptau_g2: Vec<G2>,
    z_coeffs: Vec<Fr>,
    r_coeffs: Vec<Fr>
) {
    let ctx = builder.main(0);
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let g1_chip = EccChip::new(&fp_chip);
    let fp2_chip = Fp2Chip::<Fr>::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);

    let assigned_q_bar = g1_chip.assign_point(ctx, q_bar);
    let assigned_p_bar = g1_chip.assign_point(ctx, p_bar);
    let g2_generator = g2_chip.assign_point(ctx, G2Affine::generator());

    let mut ptau_g1_loaded = vec![];
    let mut ptau_g2_loaded = vec![];
    let mut z_coeffs_loaded = vec![];
    let mut r_coeffs_loaded = vec![];

    for el in ptau_g1.iter() {
        ptau_g1_loaded.push(g1_chip.assign_point(ctx, G1Affine::from(el)));
    }
    for el in ptau_g2.iter() {
        ptau_g2_loaded.push(g2_chip.assign_point(ctx, G2Affine::from(el)));
    }

    for (i, z_coeff) in z_coeffs.iter().enumerate() {
        z_coeffs_loaded.push(
            ctx.load_witness(z_coeff.clone())
        );
    }

    for (i, r_coeff) in r_coeffs.iter().enumerate() {
        r_coeffs_loaded.push(
            ctx.load_witness(r_coeff.clone())
        );
    }

    let kzg_chip = KZGChip::new(&pairing_chip, &g1_chip, &g2_chip);

    kzg_chip.opening_assert(
        builder,
        &ptau_g1_loaded[..],
        &ptau_g2_loaded[..],
        r_coeffs_loaded.iter().map(|x| vec![x.clone()]).collect::<Vec<_>>(),
        z_coeffs_loaded.iter().map(|x| vec![x.clone()]).collect::<Vec<_>>(),
        assigned_p_bar,
        assigned_q_bar
    );
}

fn random_kzg_circuit(
    params: KZGCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    // Smoke test values
    let tau: Fr = Fr::from(111);
    let blob_len = 4;
    let dummy_data: Vec<Fr> = (0..blob_len).map(|_| Fr::from(OsRng.next_u64())).collect();
    let openings: Vec<u64> = vec![2, 3];
    let n_openings = openings.len();

    // Run mock trusted setup
    let (ptau_g1, ptau_g2) = mock_trusted_setup(tau, dummy_data.len(), openings.len());

    // Commit to a polynomial
    let idxs: Vec<Fr> = (0..dummy_data.len()).map(|x| Fr::from(x as u64)).collect();
    let p = Polynomial::from_points(&idxs, &dummy_data);
    let p_bar = G1Affine::from(p.eval_ptau(&ptau_g1));

    // Compute opening proof
    let idxs_fr: Vec<Fr> = openings.iter().map(|idx| Fr::from(*idx)).collect();
    let vals: Vec<Fr> = openings.iter().map(|idx| dummy_data[*idx as usize]).collect();
    let r: Polynomial<Fr> = Polynomial::from_points(&idxs_fr, &vals);
    let z: Polynomial<Fr> = Polynomial::vanishing(openings);
    let (q, rem) = Polynomial::div_euclid(&(p.clone() - r.clone()), &z);
    if !rem.is_zero() {
        panic!("p(X) - r(X) is not divisible by z(X). Cannot compute q(X)");
    }

    let q_bar: G1Affine = G1Affine::from(q.eval_ptau(&ptau_g1));

    // use halo2_base::halo2_proofs::halo2curves::bn256::{pairing, G2Affine, Gt};
    println!("p: {:?}", p);
    println!("r: {:?}", r);

    kzg_test(&mut builder, params, q_bar, p_bar, ptau_g1[..n_openings].to_vec(), ptau_g2[..=n_openings].to_vec(), z.get_coeffs(), r.get_coeffs());

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    circuit
}

#[test]
fn test_kzg() {
    let path = "configs/commitments/kzg_circuit.config";
    let params: KZGCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_kzg_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
