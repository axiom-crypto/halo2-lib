use crate::halo2_proofs::{arithmetic::Field, circuit::Value};
use halo2_base::{gates::RangeInstructions, utils::PrimeField, AssignedValue, Context};
use num_bigint::BigUint;
use std::fmt::Debug;

pub mod fp;
pub mod fp12;
pub mod fp2;

#[cfg(test)]
mod tests;

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
pub trait FieldChip<F: PrimeField> {
    const PRIME_FIELD_NUM_BITS: u32;

    type ConstantType: Debug;
    type WitnessType: Debug;
    type FieldPoint: Clone + Debug;
    // a type implementing `Field` trait to help with witness generation (for example with inverse)
    type FieldType: Field;
    type RangeChip: RangeInstructions<F>;

    fn native_modulus(&self) -> &BigUint;
    fn gate(&self) -> &<Self::RangeChip as RangeInstructions<F>>::Gate {
        self.range().gate()
    }
    fn range(&self) -> &Self::RangeChip;
    fn limb_bits(&self) -> usize;

    fn get_assigned_value(&self, x: &Self::FieldPoint) -> Value<Self::FieldType>;

    fn fe_to_constant(x: Self::FieldType) -> Self::ConstantType;
    fn fe_to_witness(x: &Value<Self::FieldType>) -> Self::WitnessType;

    fn load_private(&self, ctx: &mut Context<F>, coeffs: Self::WitnessType) -> Self::FieldPoint;

    fn load_constant(&self, ctx: &mut Context<F>, coeffs: Self::ConstantType) -> Self::FieldPoint;

    fn add_no_carry<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint;

    /// output: `a + c`
    fn add_constant_no_carry<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        c: Self::ConstantType,
    ) -> Self::FieldPoint;

    fn sub_no_carry<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint;

    fn negate<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> Self::FieldPoint;

    /// a * c
    fn scalar_mul_no_carry<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        c: i64,
    ) -> Self::FieldPoint;

    /// a * c + b
    fn scalar_mul_and_add_no_carry<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
        c: i64,
    ) -> Self::FieldPoint;

    fn mul_no_carry<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint;

    fn check_carry_mod_to_zero<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint);

    fn carry_mod<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> Self::FieldPoint;

    fn range_check<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, max_bits: usize);

    fn enforce_less_than<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint);

    // Assumes the witness for a is 0
    // Constrains that the underlying big integer is 0 and < p.
    // For field extensions, checks coordinate-wise.
    fn is_soft_zero<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F>;

    // Constrains that the underlying big integer is in [1, p - 1].
    // For field extensions, checks coordinate-wise.
    fn is_soft_nonzero<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F>;

    fn is_zero<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F>;

    // assuming `a, b` have been range checked to be a proper BigInt
    // constrain the witnesses `a, b` to be `< p`
    // then check `a == b` as BigInts
    fn is_equal<'v>(
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

    fn is_equal_unenforced<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> AssignedValue<F>;

    fn assert_equal<'v>(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, b: &Self::FieldPoint);

    fn mul<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let no_carry = self.mul_no_carry(ctx, a, b);
        self.carry_mod(ctx, &no_carry)
    }

    fn divide<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let a_val = self.get_assigned_value(a);
        let b_val = self.get_assigned_value(b);
        let b_inv = b_val.map(|bv| bv.invert().unwrap());
        let quot_val = a_val.zip(b_inv).map(|(a, bi)| a * bi);

        let quot = self.load_private(ctx, Self::fe_to_witness(&quot_val));

        // constrain quot * b - a = 0 mod p
        let quot_b = self.mul_no_carry(ctx, &quot, b);
        let quot_constraint = self.sub_no_carry(ctx, &quot_b, a);
        self.check_carry_mod_to_zero(ctx, &quot_constraint);

        quot
    }

    // constrain and output -a / b
    // this is usually cheaper constraint-wise than computing -a and then (-a) / b separately
    fn neg_divide<'v>(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        let a_val = self.get_assigned_value(a);
        let b_val = self.get_assigned_value(b);
        let b_inv = b_val.map(|bv| bv.invert().unwrap());
        let quot_val = a_val.zip(b_inv).map(|(a, b)| -a * b);

        let quot = self.load_private(ctx, Self::fe_to_witness(&quot_val));
        self.range_check(ctx, &quot, Self::PRIME_FIELD_NUM_BITS as usize);

        // constrain quot * b + a = 0 mod p
        let quot_b = self.mul_no_carry(ctx, &quot, b);
        let quot_constraint = self.add_no_carry(ctx, &quot_b, a);
        self.check_carry_mod_to_zero(ctx, &quot_constraint);

        quot
    }
}

pub trait Selectable<F: PrimeField> {
    type Point;

    fn select(
        &self,
        ctx: &mut Context<F>,
        a: &Self::Point,
        b: &Self::Point,
        sel: &AssignedValue<F>,
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
pub trait FieldExtConstructor<Fp: PrimeField, const DEGREE: usize> {
    fn new(c: [Fp; DEGREE]) -> Self;

    fn coeffs(&self) -> Vec<Fp>;
}
