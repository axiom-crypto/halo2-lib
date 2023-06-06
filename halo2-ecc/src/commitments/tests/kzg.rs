use std::fs::File;

/*
 * Test suite for KZGChip.
 */
use ff::PrimeField;
use rand_core::OsRng;
use crate::{
    bn254::{pairing::PairingChip, Fp2Chip, FpChip, FrChip},
    commitments::{kzg::KZGChip, tests::polynomial::Polynomial, poly::PolyChip},
    ecc::EccChip,
    fields::{FpStrategy, FieldChip},
    halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G1, G2},
};
use halo2_base::{
    gates::{
        builder::{CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{halo2curves::{bn256::G2Affine, FieldExt}, dev::MockProver},
};
use rand_core::{RngCore};
use serde::{Deserialize, Serialize};

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
pub fn mock_trusted_setup(tau: Fr, blob_len: usize, n_openings: usize) -> (Vec<G1>, Vec<G2>) {
    let tau_fr: Fr = Fr::from(tau);

    // Powers of tau in G1 to commit to polynomials p(X) and q(X)
    let mut ptau_g1: Vec<G1> = vec![G1::generator()];
    for _ in 1..blob_len {
        ptau_g1.push(ptau_g1.last().unwrap() * tau_fr);
    }

    // Powers of tau in G2 to commit to polynomials z(X) and r(X)
    let mut ptau_g2: Vec<G2> = vec![G2::generator()];
    for _ in 1..=n_openings {
        ptau_g2.push(ptau_g2.last().unwrap() * tau_fr);
    }

    (ptau_g1, ptau_g2)
}

/*
 * Creates vector commitment by interpolating a polynomial p(X) and evaluating
 * at p(τ).
 */
pub fn commit_vector(k: usize, d: &Vec<Fr>, ptau_g1: &Vec<G1>) -> (Polynomial<Fr>, G1Affine) {
    let selected_root = Fr::root_of_unity().pow(&[2u64.pow(Fr::S - K as u32) as u64, 0, 0, 0]);
    let mut idxs = vec![Fr::one()];
    for _ in 1..d.len() {
        idxs.push(idxs.last().unwrap() * selected_root);
    }
    let p = Polynomial::from_points(&idxs, &d);
    let p_bar = G1Affine::from(p.eval_ptau(&ptau_g1));
    (p, p_bar)
}

/*
 * Computes multi-open proof. Done by computing a quotient polynomial
 * q(X) = [p(X) - r(X)]/z(X). Opening proof is q(τ). Also saves the coefficients
 * of z(X) and r(X) to avoid having to recompute within the circuit.
 */
pub fn open_prf(
    k: usize, 
    data: &Vec<Fr>,
    p: &Polynomial<Fr>,
    ptau_g1: &Vec<G1>,
    idxs: &Vec<u64>,
) -> (G1Affine, Vec<Fr>, Vec<Fr>) {

    let selected_root = Fr::root_of_unity().pow(&[2u64.pow(Fr::S - K as u32) as u64, 0, 0, 0]);
    let idxs_fr: Vec<Fr> = idxs.iter().map(|idx| selected_root.pow(&[*idx as u64, 0, 0, 0])).collect();
    let vals: Vec<Fr> = idxs.iter().map(|idx| data[*idx as usize]).collect();

    let r: Polynomial<Fr> = Polynomial::from_points(&idxs_fr, &vals);
    let z: Polynomial<Fr> = Polynomial::vanishing(&idxs_fr);

    let (q, rem) = Polynomial::div_euclid(&(p.clone() - r.clone()), &z);
    if !rem.is_zero() {
        panic!("p(X) - r(X) is not divisible by z(X). Cannot compute q(X)");
    }

    let q_bar: G1Affine = G1Affine::from(q.eval_ptau(&ptau_g1));
    (q_bar, z.get_coeffs(), r.get_coeffs())
}

/*
 * Assigns all input values for the KZGChip and proves multi-opens.
 */
fn kzg_multi_test(
    builder: &mut GateThreadBuilder<Fr>,
    params: KZGCircuitParams,
    q_bar: G1Affine,
    p_bar: G1Affine,
    ptau_g1: Vec<G1>,
    ptau_g2: Vec<G2>,
    z_coeffs: Vec<Fr>,
    r_coeffs: Vec<Fr>,
    open_idxs: Vec<Fr>,
    open_vals: Vec<Fr>
) {
    let ctx = builder.main(0);
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());

    // Initialize chips
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fr_chip = FrChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);

    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let g1_chip = EccChip::new(&fp_chip);
    let fp2_chip = Fp2Chip::<Fr>::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);
    let poly_chip = PolyChip::new(&fr_chip);

    // Load individual group elements
    let assigned_q_bar = g1_chip.assign_point(ctx, q_bar);
    let assigned_p_bar = g1_chip.assign_point(ctx, p_bar);

    // Load vectors
    let mut ptau_g1_loaded = vec![];
    let mut ptau_g2_loaded = vec![];
    let mut z_coeffs_loaded = vec![];
    let mut z_coeffs_fr_loaded = vec![];
    let mut r_coeffs_loaded = vec![];
    let mut r_coeffs_fr_loaded = vec![];
    let mut open_idxs_loaded = vec![];
    let mut open_vals_loaded = vec![];
    for el in ptau_g1.iter() {
        ptau_g1_loaded.push(g1_chip.assign_point(ctx, G1Affine::from(el)));
    }
    for el in ptau_g2.iter() {
        ptau_g2_loaded.push(g2_chip.assign_point(ctx, G2Affine::from(el)));
    }
    for c in z_coeffs {
        z_coeffs_loaded.push(ctx.load_witness(c.clone()));
        z_coeffs_fr_loaded.push(fr_chip.load_private(ctx, c));
    }
    for c in r_coeffs {
        r_coeffs_loaded.push(ctx.load_witness(c.clone()));
        r_coeffs_fr_loaded.push(fr_chip.load_private(ctx, c));
    }
    for c in open_idxs {
        open_idxs_loaded.push(fr_chip.load_private(ctx, c));
    }
    for c in open_vals {
        open_vals_loaded.push(fr_chip.load_private(ctx, c));
    }

    // Test chip
    let kzg_chip = KZGChip::new(&poly_chip, &pairing_chip, &g1_chip, &g2_chip);

    kzg_chip.opening_assert(
        builder,
        &ptau_g1_loaded[..],
        &ptau_g2_loaded[..],
        &open_idxs_loaded,
        &open_vals_loaded,
        &r_coeffs_fr_loaded,
        &z_coeffs_fr_loaded,
        assigned_p_bar,
        assigned_q_bar,
    );
}

/*
 * Commits to a random vector and proves a multi-open.
 */
fn random_kzg_multi_circuit(
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

    let tau: Fr = Fr::from(111);
    let k = 2;
    let blob_len = 4;
    let openings: Vec<u64> = vec![2, 3];
    let n_openings = openings.len();
    let dummy_data: Vec<Fr> = (0..blob_len).map(|_| Fr::from(OsRng.next_u64())).collect();

    let (ptau_g1, ptau_g2) = mock_trusted_setup(tau, blob_len, n_openings);
    let (p, p_bar) = commit_vector(K, &dummy_data, &ptau_g1);
    let (q_bar, z_coeffs, r_coeffs) = open_prf(K, &dummy_data, &p, &ptau_g1, &openings);
    let selected_root = Fr::root_of_unity().pow(&[2u64.pow(Fr::S - K as u32) as u64, 0, 0, 0]);

    kzg_multi_test(
        &mut builder,
        params,
        q_bar,
        p_bar,
        ptau_g1[..n_openings].to_vec(),
        ptau_g2[..=n_openings].to_vec(),
        z_coeffs,
        r_coeffs,
        openings.iter().map(|op| selected_root.pow(&[op.clone() as u64, 0, 0, 0])).collect(),
        openings.iter().map(|op| dummy_data[op.clone() as usize]).collect()
    );

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

    let circuit = random_kzg_multi_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
