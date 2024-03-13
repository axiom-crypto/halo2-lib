use crate::bigint::ProperCrtUint;
use crate::fields::vector::FieldVector;
use crate::fields::{fp, fp12, fp2};

pub mod final_exp;
pub mod pairing;

#[cfg(feature = "halo2-axiom")]
pub(crate) use crate::halo2_proofs::halo2curves::bls12_381::{
    Fq, Fq12, Fq2, G1Affine, G2Affine, BLS_X, BLS_X_IS_NEGATIVE, FROBENIUS_COEFF_FQ12_C1,
};
#[cfg(feature = "halo2-pse")]
pub(crate) use halo2curves::bls12_381::{
    Fq, Fq12, Fq2, G1Affine, G2Affine, BLS_X, BLS_X_IS_NEGATIVE, FROBENIUS_COEFF_FQ12_C1,
};

pub(crate) const XI_0: i64 = 1;

pub type FpChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type FpPoint<F> = ProperCrtUint<F>;
pub type FqPoint<F> = FieldVector<FpPoint<F>>;
pub type Fp2Chip<'chip, F> = fp2::Fp2Chip<'chip, F, FpChip<'chip, F>, Fq2>;
pub type Fp12Chip<'chip, F> = fp12::Fp12Chip<'chip, F, FpChip<'chip, F>, Fq12, XI_0>;

#[cfg(test)]
pub(crate) mod tests;
