#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::*;
use crate::ecc::EccChip;
use crate::group::Curve;
use crate::{
    fields::FpStrategy,
    halo2_proofs::halo2curves::bn256::{pairing, Fr, G1Affine},
};
use halo2_base::utils::fe_to_biguint;
use halo2_base::{
    gates::{flex_gate::threads::SinglePhaseCoreManager, RangeChip},
    halo2_proofs::halo2curves::bn256::G1,
    utils::testing::base_test,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::io::Write;

pub mod ec_add;
pub mod fixed_base_msm;
pub mod msm;
pub mod msm_sum_infinity;
pub mod msm_sum_infinity_fixed_base;
pub mod pairing;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MSMCircuitParams {
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FixedMSMCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    batch_size: usize,
    radix: usize,
    clump_factor: usize,
}
