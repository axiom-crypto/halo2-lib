use crate::{fields::{FpStrategy, fp::FpChip}, ecc::fixed_base::scalar_multiply, ecc::EcPoint};
use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use halo2_base::gates::{
    builder::{
        CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
    },
    RangeChip,
};
use rand_core::OsRng;
use std::fs::File;

use super::*;

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
    batch_size: usize,
    window_bits: usize,
}

fn scalar_multiply_test(
    params: SMCircuitParams,
    point: G1Affine,
    scalar: Fr,
){//->  G1Affine{
    let mut builder = GateThreadBuilder::mock();

    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr, Fq>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let ctx = builder.main(0);
    let scalar_assigned = vec![ctx.load_witness(scalar)];
    

    let sm = scalar_multiply(ecc_chip.field_chip(), ctx,  &point, scalar_assigned, Fr::NUM_BITS as usize, params.window_bits, true);

    //let sm_point: G1Affine = sm.into();
    println!("{:?}, {:?}", sm.x().value(), point);
    //let generator_point = G1Affine::generator();
    //if point == generator_point{
    //    let sm_ans = 
    //}
    //else {
    //    let sm_ans = 
    //}
    //let msm_x = msm.x.value();
    //let msm_y = msm.y.value();
    //assert_eq!(msm_x, fe_to_biguint(&msm_answer.x));
    //assert_eq!(msm_y, fe_to_biguint(&msm_answer.y));
    //sm.to_affine()
}

#[test]
fn test_sm1() {
    let path = "configs/bn254/msm_circuit.config";
    let mut params: SMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    params.batch_size = 3;

    let random_point = G1Affine::random(OsRng);
    let scalar = Fr::one();
    scalar_multiply_test(params, random_point, scalar);

}