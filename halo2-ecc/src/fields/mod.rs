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
pub mod native_fp;
pub mod vector;

#[cfg(test)]
mod tests;

pub trait PrimeField = BigPrimeField;

/// Trait for common functionality for finite field chips.
/// Primarily intended to emulate a "non-native" finite field using "native" values in a prime field `F`.
/// Most functions are designed for the case when the non-native field is larger than the native field, but
/// the trait can still be implemented and used in other cases.
pub trait FieldChip<F: PrimeField>: Clone + Send + Sync {
    const PRIME_FIELD_NUM_BITS: u32;

    /// A representation of a field element that is used for intermediate computations.
    /// The representation can have "overflows" (e.g., overflow limbs or negative limbs).
    type UnsafeFieldPoint: Clone
        + Debug
        + Send
        + Sync
        + From<Self::FieldPoint>
        + for<'a> From<&'a Self::UnsafeFieldPoint>
        + for<'a> From<&'a Self::FieldPoint>; // Cloning all the time impacts readability, so we allow references to be cloned into owned values

    /// The "proper" representation of a field element. Allowed to be a non-unique representation of a field element (e.g., can be greater than modulus)
    type FieldPoint: Clone
        + Debug
        + Send
        + Sync
        + From<Self::ReducedFieldPoint>
        + for<'a> From<&'a Self::FieldPoint>;

    /// A proper representation of field elements that guarantees a unique representation of each field element. Typically this means Uints that are less than the modulus.
    type ReducedFieldPoint: Clone + Debug + Send + Sync;

    /// A type implementing `Field` trait to help with witness generation (for example with inverse)
    type FieldType: Field;
    type RangeChip: RangeInstructions<F>;

    fn native_modulus(&self) -> &BigUint;
    fn gate(&self) -> &<Self::RangeChip as RangeInstructions<F>>::Gate {
        self.range().gate()
    }
    fn range(&self) -> &Self::RangeChip;
    fn limb_bits(&self) -> usize;

    fn get_assigned_value(&self, x: &Self::UnsafeFieldPoint) -> Self::FieldType;

    /// Assigns `fe` as private witness. Note that the witness may **not** be constrained to be a unique representation of the field element `fe`.
    fn load_private(&self, ctx: &mut Context<F>, fe: Self::FieldType) -> Self::FieldPoint;

    /// Assigns `fe` as private witness and contrains the witness to be in reduced form.
    fn load_private_reduced(
        &self,
        ctx: &mut Context<F>,
        fe: Self::FieldType,
    ) -> Self::ReducedFieldPoint {
        let fe = self.load_private(ctx, fe);
        self.enforce_less_than(ctx, fe)
    }

    /// Assigns `fe` as constant.
    fn load_constant(&self, ctx: &mut Context<F>, fe: Self::FieldType) -> Self::FieldPoint;

    fn add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::UnsafeFieldPoint;

    /// output: `a + c`
    fn add_constant_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        c: Self::FieldType,
    ) -> Self::UnsafeFieldPoint;

    fn sub_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::UnsafeFieldPoint;

    fn negate(&self, ctx: &mut Context<F>, a: Self::FieldPoint) -> Self::FieldPoint;

    /// a * c
    fn scalar_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        c: i64,
    ) -> Self::UnsafeFieldPoint;

    /// a * c + b
    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
        c: i64,
    ) -> Self::UnsafeFieldPoint;

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::UnsafeFieldPoint;

    fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: Self::UnsafeFieldPoint);

    fn carry_mod(&self, ctx: &mut Context<F>, a: Self::UnsafeFieldPoint) -> Self::FieldPoint;

    fn range_check(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        max_bits: usize,
    );

    /// Constrains that `a` is a reduced representation and returns the wrapped `a`.
    fn enforce_less_than(
        &self,
        ctx: &mut Context<F>,
        a: Self::FieldPoint,
    ) -> Self::ReducedFieldPoint;

    // Returns 1 iff the underlying big integer for `a` is 0. Otherwise returns 0.
    // For field extensions, checks coordinate-wise.
    fn is_soft_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::FieldPoint>,
    ) -> AssignedValue<F>;

    // Constrains that the underlying big integer is in [0, p - 1].
    // Then returns 1 iff the underlying big integer for `a` is 0. Otherwise returns 0.
    // For field extensions, checks coordinate-wise.
    fn is_soft_nonzero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::FieldPoint>,
    ) -> AssignedValue<F>;

    fn is_zero(&self, ctx: &mut Context<F>, a: impl Into<Self::FieldPoint>) -> AssignedValue<F>;

    fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: Self::ReducedFieldPoint,
        b: Self::ReducedFieldPoint,
    ) -> AssignedValue<F>;

    fn assert_equal(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::FieldPoint>,
        b: impl Into<Self::FieldPoint>,
    );

    // =========== default implementations =============

    // assuming `a, b` have been range checked to be a proper BigInt
    // constrain the witnesses `a, b` to be `< p`
    // then check `a == b` as BigInts
    fn is_equal(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::FieldPoint>,
        b: impl Into<Self::FieldPoint>,
    ) -> AssignedValue<F> {
        let a = self.enforce_less_than(ctx, a.into());
        let b = self.enforce_less_than(ctx, b.into());
        // a.native and b.native are derived from `a.truncation, b.truncation`, so no need to check if they're equal
        self.is_equal_unenforced(ctx, a, b)
    }

    /// If using `UnsafeFieldPoint`, make sure multiplication does not cause overflow.
    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::FieldPoint {
        let no_carry = self.mul_no_carry(ctx, a, b);
        self.carry_mod(ctx, no_carry)
    }

    /// Constrains that `b` is nonzero as a field element and then returns `a / b`.
    fn divide(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::FieldPoint>,
        b: impl Into<Self::FieldPoint>,
    ) -> Self::FieldPoint {
        let b = b.into();
        let b_is_zero = self.is_zero(ctx, b.clone());
        self.gate().assert_is_const(ctx, &b_is_zero, &F::zero());

        self.divide_unsafe(ctx, a.into(), b)
    }

    /// Returns `a / b` without constraining `b` to be nonzero.
    ///
    /// Warning: undefined behavior when `b` is zero.
    ///
    /// `a, b` must be such that `quot * b - a` without carry does not overflow, where `quot` is the output.
    fn divide_unsafe(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::FieldPoint {
        let a = a.into();
        let b = b.into();
        let a_val = self.get_assigned_value(&a);
        let b_val = self.get_assigned_value(&b);
        let b_inv: Self::FieldType = Option::from(b_val.invert()).unwrap_or_default();
        let quot_val = a_val * b_inv;

        let quot = self.load_private(ctx, quot_val);

        // constrain quot * b - a = 0 mod p
        let quot_b = self.mul_no_carry(ctx, quot.clone(), b);
        let quot_constraint = self.sub_no_carry(ctx, quot_b, a);
        self.check_carry_mod_to_zero(ctx, quot_constraint);

        quot
    }

    /// Constrains that `b` is nonzero as a field element and then returns `-a / b`.
    fn neg_divide(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::FieldPoint>,
        b: impl Into<Self::FieldPoint>,
    ) -> Self::FieldPoint {
        let b = b.into();
        let b_is_zero = self.is_zero(ctx, b.clone());
        self.gate().assert_is_const(ctx, &b_is_zero, &F::zero());

        self.neg_divide_unsafe(ctx, a.into(), b)
    }

    // Returns `-a / b` without constraining `b` to be nonzero.
    // this is usually cheaper constraint-wise than computing -a and then (-a) / b separately
    fn neg_divide_unsafe(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::FieldPoint {
        let a = a.into();
        let b = b.into();
        let a_val = self.get_assigned_value(&a);
        let b_val = self.get_assigned_value(&b);
        let b_inv: Self::FieldType = Option::from(b_val.invert()).unwrap_or_default();
        let quot_val = -a_val * b_inv;

        let quot = self.load_private(ctx, quot_val);

        // constrain quot * b + a = 0 mod p
        let quot_b = self.mul_no_carry(ctx, quot.clone(), b);
        let quot_constraint = self.add_no_carry(ctx, quot_b, a);
        self.check_carry_mod_to_zero(ctx, quot_constraint);

        quot
    }
}

pub trait Selectable<F: ScalarField, Pt> {
    fn select(&self, ctx: &mut Context<F>, a: Pt, b: Pt, sel: AssignedValue<F>) -> Pt;

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[Pt]>,
        coeffs: &[AssignedValue<F>],
    ) -> Pt;
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
