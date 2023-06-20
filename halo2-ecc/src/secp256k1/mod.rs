use crate::halo2_proofs::halo2curves::secp256k1::{Fp, Fq};

use crate::ecc;
use crate::fields::fp;

pub type FpChip<'range, F> = fp::FpChip<'range, F, Fp>;
pub type FqChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type Secp256k1Chip<'chip, F> = ecc::EccChip<'chip, F, FpChip<'chip, F>>;
pub const SECP_B: u64 = 7;

#[cfg(test)]
mod tests;
