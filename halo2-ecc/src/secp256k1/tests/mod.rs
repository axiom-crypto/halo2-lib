#![allow(non_snake_case)]
use std::fs::File;

use ff::Field;
use group::Curve;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::{
            bn256::Fr,
            secp256k1::{Fq, Secp256k1Affine},
        },
    },
    utils::{biguint_to_fe, fe_to_biguint, BigPrimeField},
    Context,
};
use num_bigint::BigUint;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    ecc::EccChip,
    fields::{FieldChip, FpStrategy},
    secp256k1::{FpChip, FqChip},
};

pub mod ecdsa;
pub mod ecdsa_tests;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn sm_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    base: Secp256k1Affine,
    scalar: Fq,
    window_bits: usize,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    let s = fq_chip.load_private(ctx, scalar);
    let P = ecc_chip.assign_point(ctx, base);

    let sm = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        P,
        s.limbs().to_vec(),
        fq_chip.limb_bits,
        window_bits,
    );

    let sm_answer = (base * scalar).to_affine();

    let sm_x = sm.x.value();
    let sm_y = sm.y.value();
    assert_eq!(sm_x, fe_to_biguint(&sm_answer.x));
    assert_eq!(sm_y, fe_to_biguint(&sm_answer.y));
}

fn sm_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    base: Secp256k1Affine,
    scalar: Fq,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = GateThreadBuilder::new(stage == CircuitBuilderStage::Prover);

    sm_test(builder.main(0), params, base, scalar, 4);

    match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    }
}

#[test]
fn test_secp_sm_random() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = sm_circuit(
        params,
        CircuitBuilderStage::Mock,
        None,
        Secp256k1Affine::random(OsRng),
        Fq::random(OsRng),
    );
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_secp_sm_minus_1() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let base = Secp256k1Affine::random(OsRng);
    let mut s = -Fq::one();
    let mut n = fe_to_biguint(&s);
    loop {
        let circuit = sm_circuit(params, CircuitBuilderStage::Mock, None, base, s);
        MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
        if &n % BigUint::from(2usize) == BigUint::from(0usize) {
            break;
        }
        n /= 2usize;
        s = biguint_to_fe(&n);
    }
}

#[test]
fn test_secp_sm_0_1() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let base = Secp256k1Affine::random(OsRng);
    let s = Fq::zero();
    let circuit = sm_circuit(params, CircuitBuilderStage::Mock, None, base, s);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();

    let s = Fq::one();
    let circuit = sm_circuit(params, CircuitBuilderStage::Mock, None, base, s);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
