use std::fmt::Debug;

use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::{AssignedValue, Context};
use num_bigint::BigUint;
use num_traits::Zero;
use crate::bigint::{CRTInteger, ProperCrtUint};
use crate::bn254::{FpChip, Fp2Chip};
use crate::ecc::EcPoint;
use crate::{bn254::pairing::PairingChip, ecc::EccChip};

use crate::fields::{
    FieldChip, PrimeField
};
use crate::fields::Selectable;

/// Represent Fp2 point as `FieldVector` with degree = 2
/// `Fp2 = Fp[u] / (u^2 + 1)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp2 point as `a_0 + a_1 * u` where `a_0, a_1 in Fp`
#[derive(Clone, Debug)]
pub struct PolyChip<'a, F: PrimeField> {
    field_chip: &'a FpChip<'a, F>
}

impl<'a, F: PrimeField> PolyChip<'a, F> {
    pub fn new(field_chip: &'a FpChip<F>) -> Self {
        Self { field_chip }
    }

    pub fn evaluate(
        &self,
        ctx: &mut Context<F>,
        coeffs: &Vec<<FpChip<F> as FieldChip<F>>::FieldPoint>,
        point: &<FpChip<F> as FieldChip<F>>::FieldPoint
    ) -> <FpChip<F> as FieldChip<F>>::FieldPoint {
        let mut acc  = self.field_chip.load_constant_uint(ctx, BigUint::zero());
        for c in coeffs.iter().rev() {
            let mul_int = self.field_chip.mul_no_carry(ctx, acc, point);
            acc = self.field_chip.carry_mod(ctx, mul_int);
            let add_int = self.field_chip.add_no_carry(ctx, acc, point);
            acc = self.field_chip.carry_mod(ctx, add_int);
        }
        acc
    }
}
