use crate::ecc;
use crate::fields::fp;
use crate::fields::native_fp;
use halo2curves::grumpkin::Fq;
use halo2curves::grumpkin::Fr;

pub type FpChip<'range, F> = native_fp::NativeFieldChip<'range, F>;
pub type FqChip<'range, F> = fp::FpChip<'range, F, Fr>;
pub type GrumpkinChip<'chip, F> = ecc::EccChip<'chip, F, FpChip<'chip, Fq>>;

#[cfg(test)]
mod tests;
