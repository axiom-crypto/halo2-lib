#![allow(clippy::too_many_arguments)]
#![allow(clippy::op_ref)]
#![allow(clippy::type_complexity)]
#![feature(trait_alias)]

pub mod bigint;
pub mod ecc;
pub mod fields;

pub mod bn254;
pub mod grumpkin;
pub mod secp256k1;

pub use halo2_base;
pub(crate) use halo2_base::halo2_proofs;
use halo2_proofs::halo2curves;
use halo2curves::ff;
use halo2curves::group;
