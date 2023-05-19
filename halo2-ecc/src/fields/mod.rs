use crate::halo2_proofs::arithmetic::Field;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub mod fp;
pub mod fp12;
pub mod fp2;

#[cfg(test)]
mod tests;

pub trait PrimeField = BigPrimeField;

#[derive(Clone, Debug)]
pub struct FieldExtPoint<FieldPoint: Clone + Debug> {
    // `F_q` field extension of `F_p` where `q = p^degree`
    // An `F_q` point consists of `degree` number of `F_p` points
    // The `F_p` points are stored as `FieldPoint`s

    // We do not specify the irreducible `F_p` polynomial used to construct `F_q` here - that is implementation specific
    pub coeffs: Vec<FieldPoint>,
    // `degree = coeffs.len()`
}

impl<FieldPoint: Clone + Debug> FieldExtPoint<FieldPoint> {
    pub fn construct(coeffs: Vec<FieldPoint>) -> Self {
        Self { coeffs }
    }
}

/// Common functionality for finite field chips
pub trait FieldChip<F: PrimeField>: Clone + Debug + Send + Sync {
    const PRIME_FIELD_NUM_BITS: u32;

    type ConstantType: Debug;
    type WitnessType: Debug;
    type FieldPoint: Clone + Debug + Send + Sync;
    // a type implementing `Field` trait to help with witness generation (for example with inverse)
    type FieldType: Field;
    type RangeChip: RangeInstructions<F>;

    fn native_modulus(&self) -> &BigUint;
    fn gate(&self) -> &<Self::RangeChip as RangeInstructions<F>>::Gate {
        self.range().gate()
    }
    fn range(&self) -> &Self::RangeChip;
    fn limb_bits(&self) -> usize;

    fn get_assigned_value(&self, x: &Self::FieldPoint) -> Self::FieldType;

    fn fe_to_constant(x: Self::FieldType) -> Self::ConstantType;
    fn fe_to_witness(x: &Self::FieldType) -> Self::WitnessType;

    fn load_private(&self, ctx: &mut Context<F>, coeffs: Self::WitnessType) -> Self::FieldPoint;

    fn load_constant(&self, ctx: &mut Context<F>, coeffs: Self::ConstantType) -> Self::FieldPoint;

    fn add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint;

    /// output: `a + c`
    fn add_constant_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        c: Self::ConstantType,
    ) -> Self::FieldPoint;

    fn sub_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint;

    fn negate(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> Self::FieldPoint;

    /// a * c
    fn scalar_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        c: i64,
    ) -> Self::FieldPoint;

    /// a * c + b
    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
        c: i64,
    ) -> Self::FieldPoint;

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint;

    fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint);

    fn carry_mod(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> Self::FieldPoint;

    fn range_check(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, max_bits: usize);

    fn enforce_less_than(&self, ctx: &mut Context<F>, a: &Self::FieldPoint);

    // Returns 1 iff the underlying big integer for `a` is 0. Otherwise returns 0.
    // For field extensions, checks coordinate-wise.
    fn is_soft_zero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F>;

    // Constrains that the underlying big integer is in [0, p - 1].
    // Then returns 1 iff the underlying big integer for `a` is 0. Otherwise returns 0.
    // For field extensions, checks coordinate-wise.
    fn is_soft_nonzero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F>;

    fn is_zero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F>;

    // assuming `a, b` have been range checked to be a proper BigInt
    // constrain the witnesses `a, b` to be `< p`
    // then check `a == b` as BigInts
    fn is_equal(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> AssignedValue<F> {
        self.enforce_less_than(ctx, a);
        self.enforce_less_than(ctx, b);
        // a.native and b.native are derived from `a.truncation, b.truncation`, so no need to check if they're equal
        self.is_equal_unenforced(ctx, a, b)
    }

    fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> AssignedValue<F>;

    fn assert_equal(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, b: &Self::FieldPoint);

    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let no_carry = self.mul_no_carry(ctx, a, b);
        self.carry_mod(ctx, &no_carry)
    }

    /// Constrains that `b` is nonzero as a field element and then returns `a / b`.
    fn divide(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let b_is_zero = self.is_zero(ctx, b);
        self.gate().assert_is_const(ctx, &b_is_zero, &F::zero());

        self.divide_unsafe(ctx, a, b)
    }

    /// Returns `a / b` without constraining `b` to be nonzero.
    ///
    /// Warning: undefined behavior when `b` is zero.
    fn divide_unsafe(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let a_val = self.get_assigned_value(a);
        let b_val = self.get_assigned_value(b);
        let b_inv: Self::FieldType = Option::from(b_val.invert()).unwrap_or_default();
        let quot_val = a_val * b_inv;

        let quot = self.load_private(ctx, Self::fe_to_witness(&quot_val));

        // constrain quot * b - a = 0 mod p
        let quot_b = self.mul_no_carry(ctx, &quot, b);
        let quot_constraint = self.sub_no_carry(ctx, &quot_b, a);
        self.check_carry_mod_to_zero(ctx, &quot_constraint);

        quot
    }

    /// Constrains that `b` is nonzero as a field element and then returns `-a / b`.
    fn neg_divide(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let b_is_zero = self.is_zero(ctx, b);
        self.gate().assert_is_const(ctx, &b_is_zero, &F::zero());

        self.neg_divide_unsafe(ctx, a, b)
    }

    // Returns `-a / b` without constraining `b` to be nonzero.
    // this is usually cheaper constraint-wise than computing -a and then (-a) / b separately
    fn neg_divide_unsafe(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let a_val = self.get_assigned_value(a);
        let b_val = self.get_assigned_value(b);
        let b_inv: Self::FieldType = Option::from(b_val.invert()).unwrap_or_default();
        let quot_val = -a_val * b_inv;

        let quot = self.load_private(ctx, Self::fe_to_witness(&quot_val));
        self.range_check(ctx, &quot, Self::PRIME_FIELD_NUM_BITS as usize);

        // constrain quot * b + a = 0 mod p
        let quot_b = self.mul_no_carry(ctx, &quot, b);
        let quot_constraint = self.add_no_carry(ctx, &quot_b, a);
        self.check_carry_mod_to_zero(ctx, &quot_constraint);

        quot
    }
}

pub trait Selectable<F: ScalarField> {
    type Point;

    fn select(
        &self,
        ctx: &mut Context<F>,
        a: &Self::Point,
        b: &Self::Point,
        sel: AssignedValue<F>,
    ) -> Self::Point;

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &[Self::Point],
        coeffs: &[AssignedValue<F>],
    ) -> Self::Point;
}

// Common functionality for prime field chips
pub trait PrimeFieldChip<F: PrimeField>: FieldChip<F>
where
    Self::FieldType: PrimeField,
{
    fn num_limbs(&self) -> usize;
    fn limb_mask(&self) -> &BigUint;
    fn limb_bases(&self) -> &[F];
}

// helper trait so we can actually construct and read the Fp2 struct
// needs to be implemented for Fp2 struct for use cases below
pub trait FieldExtConstructor<Fp: ff::PrimeField, const DEGREE: usize> {
    fn new(c: [Fp; DEGREE]) -> Self;

    fn coeffs(&self) -> Vec<Fp>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum FpStrategy {
    Simple,
}
