use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use crate::fields::fp;

#[cfg(test)]
pub(crate) mod tests;
pub mod kzg;
pub mod utils;

pub type FrChip<'range, F> = fp::FpChip<'range, F, Fr>;
