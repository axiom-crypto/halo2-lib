use crate::ecc;
use crate::fields::fp;
use crate::halo2_proofs::halo2curves::grumpkin::{Fq, Fr};

pub type GrumpkinFrChip<'chip, F> = ecc::EccChip<'chip, F, fp::FpChip<'chip, Fq, Fr>>;

#[cfg(test)]
mod tests;
