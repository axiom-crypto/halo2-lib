#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::*;
use crate::ecc::EccChip;
use crate::group::Curve;
use crate::{
    fields::FpStrategy,
    halo2_proofs::halo2curves::bls12_381::{pairing, Fr as Scalar, G1Affine},
};
use halo2_base::utils::testing::base_test;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::io::Write;

pub mod ec_add;
pub mod pairing;
