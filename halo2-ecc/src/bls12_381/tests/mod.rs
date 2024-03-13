#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::*;
use crate::ecc::EccChip;
use crate::fields::FpStrategy;
use crate::group::Curve;
use halo2_base::utils::testing::base_test;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[cfg(feature = "halo2-axiom")]
pub(crate) use crate::halo2_proofs::halo2curves::bls12_381::{pairing, Fr as Scalar};
#[cfg(feature = "halo2-pse")]
pub(crate) use halo2curves::bls12_381::{pairing, Fr as Scalar};

pub mod ec_add;
pub mod pairing;
