use crate::ecc;
use crate::fields::fp;
use crate::fields::native_fp;
// use halo2curves::grumpkin::Fq;
// use halo2curves::grumpkin::Fr;
use crate::halo2_proofs::halo2curves::bn256::{Fq, Fr};

pub type FpChip<'range, F> = native_fp::NativeFieldChip<'range, F>;
pub type FqChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type GrumpkinChip<'chip, F> = ecc::EccChip<'chip, F, FpChip<'chip, Fr>>;

#[cfg(test)]
mod tests;
