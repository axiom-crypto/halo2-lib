use crate::halo2_proofs::halo2curves::bn256::{Fq, Fq12, Fq2};
use crate::{
    bigint::CRTInteger,
    fields::{fp, fp12, fp2, FieldExtPoint},
};

pub mod final_exp;
pub mod pairing;

type FpChip<F> = fp::FpConfig<F, Fq>;
type FpPoint<F> = CRTInteger<F>;
type FqPoint<F> = FieldExtPoint<FpPoint<F>>;
type Fp2Chip<F> = fp2::Fp2Chip<F, FpChip<F>, Fq2>;
type Fp12Chip<F> = fp12::Fp12Chip<F, FpChip<F>, Fq12, 9>;

#[cfg(test)]
pub(crate) mod tests;
