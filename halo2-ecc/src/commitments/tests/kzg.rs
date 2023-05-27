/*
 * Runs through a smoke test for KZGChip.
 */
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
use super::*;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC},
    utils::fs::gen_srs,
    Context,
};
use halo2_proofs::

// use crate::commitments::tests::polynomial::Polynomial;
// use crate::fields::FpStrategy;
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

fn kzg_smoke_circuit(
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

    let P = G1Affine::random(OsRng);
    let Q = G2Affine::random(OsRng);

    pairing_test::<Fr>(builder.main(0), params, P, Q);

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

    let circuit = kzg_smoke_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();

    // Smoke test values
    let tau: Fr = Fr::from(111);
    let dummy_data: Vec<Fr> = vec![Fr::from(12), Fr::from(34), Fr::from(56), Fr::from(78)];
    let openings: Vec<u64> = vec![2, 3];

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
    // (q_bar, z.get_coeffs(), r.get_coeffs())
}
