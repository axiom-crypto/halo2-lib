use crate::{fields::{FpStrategy, fp::FpChip}, ecc::fixed_base::scalar_multiply, ecc::EcPoint};
use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use halo2_base::{gates::{
    builder::{
        CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
    },
    RangeChip,
}, 
    halo2_proofs::halo2curves::{
        CurveAffine, 
        secp256k1::{Fp, Fq, Secp256k1Affine, Secp256k1},},
    utils::{modulus, bigint_to_fe, biguint_to_fe, }};
use num_bigint::BigUint;
use rand_core::OsRng;
use std::fs::File;

use super::*;

const GROUP_ORDER: Fp  = Fp::from_raw([    
    0xbfd25e8cd0364141,
    0xbaaedce6af48a03b ,    
    0xfffffffffffffffe ,
    0xffffffffffffffff
]);

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

fn scalar_multiply_test(
    params: SMCircuitParams,
    point:  Secp256k1Affine,
    scalar: Fp,
    scalar_is_safe: bool,
){
    let mut builder = GateThreadBuilder::mock();

    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<Fp>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fp, Fp>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);


    let ctx = builder.main(0);
    let scalar_assigned = vec![ctx.load_witness(scalar)];
    
    

    let sm = scalar_multiply(ecc_chip.field_chip(), ctx, &point, scalar_assigned, Fp::NUM_BITS as usize, params.window_bits, scalar_is_safe);

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

    println!("the scalar is {:?}", scalar);
    scalar_multiply_test(params, generator_point, scalar, false);

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

    println!("the scalar is {:?}", scalar);
    scalar_multiply_test(params, generator_point, scalar, false);

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

    println!("the scalar is {:?}", scalar);
    scalar_multiply_test(params, generator_point, scalar, true);

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

    println!("the scalar is {:?}", scalar);
    scalar_multiply_test(params, generator_point, scalar, false);

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

    println!("the scalar is {:?}", scalar);
    scalar_multiply_test(params, generator_point, scalar, false);

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

    println!("the scalar is {:?}", scalar);
    scalar_multiply_test(params, generator_point, scalar, false);

}
