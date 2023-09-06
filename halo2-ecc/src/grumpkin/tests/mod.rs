#![allow(non_snake_case)]
use std::fs::File;

use crate::ff::Field;
use crate::group::Curve;
use halo2_base::{
    gates::RangeChip,
    halo2_proofs::halo2curves::grumpkin::{Fq, Fr, G1Affine},
    utils::{biguint_to_fe, fe_to_biguint, testing::base_test, BigPrimeField},
    Context,
};
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::{
    ecc::EccChip,
    fields::{FieldChip, FpStrategy},
    grumpkin::{FpChip, FqChip},
};

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
    range: &RangeChip<F>,
    params: CircuitParams,
    base: G1Affine,
    scalar: Fr,
    window_bits: usize,
) {
    let fp_chip = FpChip::<F>::new(range);
    let fq_chip = FqChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    let s = fq_chip.load_private(ctx, scalar);
    let P = ecc_chip.assign_point(ctx, base);

    let sm = ecc_chip.scalar_mult::<G1Affine>(
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

fn run_test(base: G1Affine, scalar: Fr) {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        sm_test(ctx, range, params, base, scalar, 4);
    });
}

#[test]
fn test_secp_sm_random() {
    let mut rng = StdRng::seed_from_u64(0);
    run_test(G1Affine::random(&mut rng), Fr::random(&mut rng));
}

#[test]
fn test_secp_sm_minus_1() {
    let rng = StdRng::seed_from_u64(0);
    let base = G1Affine::random(rng);
    let mut s = -Fq::one();
    let mut n = fe_to_biguint(&s);
    loop {
        run_test(base, s);
        if &n % BigUint::from(2usize) == BigUint::from(0usize) {
            break;
        }
        n /= 2usize;
        s = biguint_to_fe(&n);
    }
}

#[test]
fn test_secp_sm_0_1() {
    let rng = StdRng::seed_from_u64(0);
    let base = G1Affine::random(rng);
    run_test(base, Fr::ZERO);
    run_test(base, Fr::ONE);
}
