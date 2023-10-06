use crate::bigint::ProperCrtUint;
use crate::ecc::EcPoint;
use crate::fields::vector::FieldVector;
use crate::fields::{fp, fp12, fp2};
use crate::halo2_proofs::halo2curves::bls12_381::{Fq, Fq12, Fq2};

pub mod bls_signature;
pub mod final_exp;
pub mod hash_to_curve;
pub mod pairing;
pub(crate) mod utils;

pub(crate) const XI_0: i64 = 1;

pub type FpChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type Fp2Chip<'chip, F> = fp2::Fp2Chip<'chip, F, FpChip<'chip, F>, Fq2>;
pub type Fp12Chip<'chip, F> = fp12::Fp12Chip<'chip, F, FpChip<'chip, F>, Fq12, XI_0>;

pub type FpPoint<F> = ProperCrtUint<F>;
pub type FqPoint<F> = FieldVector<FpPoint<F>>;
pub type Fp2Point<F> = FieldVector<FpPoint<F>>;
pub type G1Point<F> = EcPoint<F, ProperCrtUint<F>>;
pub type G2Point<F> = EcPoint<F, FieldVector<FpPoint<F>>>;

#[cfg(test)]
pub(crate) mod tests;
