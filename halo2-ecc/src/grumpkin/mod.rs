use crate::ecc;
use crate::fields::fp;
use crate::fields::native_fp;
use crate::halo2_proofs::halo2curves::grumpkin::{Fq, Fr};

pub type FpChip<'range, F> = native_fp::NativeFieldChip<'range, F>;
pub type FqChip<'range, F> = fp::FpChip<'range, F, Fr>;
pub type GrumpkinChip<'chip, F> = ecc::EccChip<'chip, F, FpChip<'chip, Fq>>;

#[cfg(test)]
mod tests;
