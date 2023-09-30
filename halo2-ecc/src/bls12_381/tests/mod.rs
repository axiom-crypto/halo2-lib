#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::*;
use crate::ecc::EccChip;
use crate::group::Curve;
use crate::{
    fields::FpStrategy,
    halo2_proofs::halo2curves::bls12_381::{pairing, Fr, G1Affine},
};
use halo2_base::utils::fe_to_biguint;
use halo2_base::{
    gates::{flex_gate::threads::SinglePhaseCoreManager, RangeChip},
    halo2_proofs::halo2curves::bls12_381::G1,
    utils::testing::base_test,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::io::Write;

pub mod pairing;
