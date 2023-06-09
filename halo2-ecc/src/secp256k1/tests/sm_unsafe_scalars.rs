use crate::{
    ecc::fixed_base::scalar_multiply,
    fields::{fp::FpChip, FpStrategy},
};
use ff::PrimeField;
use halo2_base::{
    gates::{builder::GateThreadBuilder, RangeChip},
    halo2_proofs::halo2curves::secp256k1::{Fp, Secp256k1, Secp256k1Affine},
};
use std::fs::File;

use super::*;

const GROUP_ORDER: Fp =
    Fp::from_raw([0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff]);

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct SMCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    window_bits: usize,
}

fn scalar_multiply_test(params: SMCircuitParams, point: Secp256k1Affine, scalar: Fp) {
    let mut builder = GateThreadBuilder::mock();

    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<Fp>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fp, Fp>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let ctx = builder.main(0);
    let scalar_assigned = vec![ctx.load_witness(scalar)];

    let _sm = scalar_multiply(
        ecc_chip.field_chip(),
        ctx,
        &point,
        scalar_assigned,
        Fp::NUM_BITS as usize,
        params.window_bits,
    );

    //println!("{:?}", sm.x().value());
}

#[test]
fn test_sm1() {
    let path = "configs/secp256k1/scalar_multiplication.config";
    let params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let generator_point = Secp256k1::generator().to_affine();

    let scalar = GROUP_ORDER;

    println!("the scalar is {scalar:?}");
    scalar_multiply_test(params, generator_point, scalar);
}

#[test]
fn test_sm2() {
    let path = "configs/secp256k1/scalar_multiplication.config";
    let params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let generator_point = Secp256k1::generator().to_affine();

    let scalar = GROUP_ORDER - Fp::one();

    println!("the scalar is {scalar:?}");
    scalar_multiply_test(params, generator_point, scalar);
}

#[test]
fn test_sm3() {
    let path = "configs/secp256k1/scalar_multiplication.config";
    let params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let generator_point = Secp256k1::generator().to_affine();

    let scalar = GROUP_ORDER - Fp::one();

    println!("the scalar is {scalar:?}");
    scalar_multiply_test(params, generator_point, scalar);
}

#[test]
fn test_sm4() {
    let path = "configs/secp256k1/scalar_multiplication.config";
    let params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let generator_point = Secp256k1::generator().to_affine();

    let scalar = GROUP_ORDER - Fp::from(2);

    println!("the scalar is {scalar:?}");
    scalar_multiply_test(params, generator_point, scalar);
}

#[test]
fn test_sm5() {
    let path = "configs/secp256k1/scalar_multiplication.config";
    let params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let generator_point = Secp256k1::generator().to_affine();

    let scalar = GROUP_ORDER + Fp::one();

    println!("the scalar is {scalar:?}");
    scalar_multiply_test(params, generator_point, scalar);
}

#[test]
fn test_sm6() {
    let path = "configs/secp256k1/scalar_multiplication.config";
    let params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let generator_point = Secp256k1::generator().to_affine();

    let scalar = GROUP_ORDER + Fp::from(2);

    println!("the scalar is {scalar:?}");
    scalar_multiply_test(params, generator_point, scalar);
}
