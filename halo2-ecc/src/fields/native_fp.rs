use super::{BigPrimeField, FieldChip, Selectable};
use halo2_base::gates::RangeChip;
use halo2_base::QuantumCell::Constant;
use halo2_base::{
    gates::GateInstructions, gates::RangeInstructions, utils::modulus, AssignedValue, Context,
};
use num_bigint::BigUint;
use std::marker::PhantomData;

// native field chip which implements FieldChip, use GateInstructions for basic arithmetic operations
#[derive(Clone, Debug)]
pub struct NativeFieldChip<'range, F: BigPrimeField> {
    pub range: &'range RangeChip<F>,
    pub native_modulus: BigUint,
    _marker: PhantomData<F>,
}

impl<'range, F: BigPrimeField> NativeFieldChip<'range, F> {
    pub fn new(range: &'range RangeChip<F>) -> Self {
        let native_modulus = modulus::<F>();
        Self { range, native_modulus, _marker: PhantomData }
    }
}

impl<'range, F: BigPrimeField> FieldChip<F> for NativeFieldChip<'range, F> {
    const PRIME_FIELD_NUM_BITS: u32 = F::NUM_BITS;
    type UnsafeFieldPoint = AssignedValue<F>;
    type FieldPoint = AssignedValue<F>;
    type ReducedFieldPoint = AssignedValue<F>;
    type FieldType = F;
    type RangeChip = RangeChip<F>;

    fn native_modulus(&self) -> &BigUint {
        &self.native_modulus
    }
    fn range(&self) -> &'range Self::RangeChip {
        self.range
    }
    fn limb_bits(&self) -> usize {
        F::NUM_BITS as usize
    }

    fn get_assigned_value(&self, x: &AssignedValue<F>) -> F {
        *x.value()
    }

    fn load_private(&self, ctx: &mut Context<F>, a: F) -> AssignedValue<F> {
        ctx.load_witness(a)
    }

    fn load_constant(&self, ctx: &mut Context<F>, a: F) -> AssignedValue<F> {
        ctx.load_constant(a)
    }

    // signed overflow BigInt functions
    fn add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        self.gate().add(ctx, a.into(), b.into())
    }

    fn add_constant_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        c: F,
    ) -> AssignedValue<F> {
        self.gate().add(ctx, a.into(), Constant(c))
    }

    fn sub_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        self.gate().sub(ctx, a.into(), b.into())
    }

    // Input: a
    // Output: p - a if a != 0, else a
    fn negate(&self, ctx: &mut Context<F>, a: AssignedValue<F>) -> AssignedValue<F> {
        self.gate().neg(ctx, a)
    }

    fn scalar_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        c: i64,
    ) -> AssignedValue<F> {
        let c_f = if c >= 0 {
            let c_abs = u64::try_from(c).unwrap();
            F::from(c_abs)
        } else {
            let c_abs = u64::try_from(-c).unwrap();
            -F::from(c_abs)
        };

        self.gate().mul(ctx, a.into(), Constant(c_f))
    }

    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
        c: i64,
    ) -> AssignedValue<F> {
        let c_f = if c >= 0 {
            let c_abs = u64::try_from(c).unwrap();
            F::from(c_abs)
        } else {
            let c_abs = u64::try_from(-c).unwrap();
            -F::from(c_abs)
        };

        self.gate().mul_add(ctx, a.into(), Constant(c_f), b.into())
    }

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        self.gate().mul(ctx, a.into(), b.into())
    }

    fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: AssignedValue<F>) {
        let is_zero = self.gate().is_zero(ctx, a);
        self.gate().assert_is_const(ctx, &is_zero, &F::ONE);
    }

    // noop
    fn carry_mod(&self, _ctx: &mut Context<F>, a: AssignedValue<F>) -> AssignedValue<F> {
        a
    }

    fn range_check(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        max_bits: usize, // the maximum bits that a.value could take
    ) {
        // skip range chek if max_bits >= F::NUM_BITS
        if max_bits < F::NUM_BITS as usize {
            let a: AssignedValue<F> = a.into();
            self.range().range_check(ctx, a, max_bits);
        }
    }

    fn enforce_less_than(&self, _ctx: &mut Context<F>, a: AssignedValue<F>) -> AssignedValue<F> {
        a
    }

    /// Returns 1 iff `a` is 0 as a BigUint.
    fn is_soft_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        let a = a.into();
        self.gate().is_zero(ctx, a)
    }

    fn is_soft_nonzero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        let a = a.into();
        let is_soft_zero = self.is_soft_zero(ctx, a);
        self.gate().neg(ctx, is_soft_zero)
    }

    fn is_zero(&self, ctx: &mut Context<F>, a: impl Into<AssignedValue<F>>) -> AssignedValue<F> {
        self.is_soft_zero(ctx, a)
    }

    fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: AssignedValue<F>,
        b: AssignedValue<F>,
    ) -> AssignedValue<F> {
        self.gate().is_equal(ctx, a, b)
    }

    fn assert_equal(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
    ) {
        ctx.constrain_equal(&a.into(), &b.into());
    }
}

impl<'range, F: BigPrimeField> Selectable<F, AssignedValue<F>> for NativeFieldChip<'range, F> {
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: AssignedValue<F>,
        b: AssignedValue<F>,
        sel: AssignedValue<F>,
    ) -> AssignedValue<F> {
        let gate = self.gate();
        GateInstructions::select(gate, ctx, a, b, sel)
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[AssignedValue<F>]>,
        coeffs: &[AssignedValue<F>],
    ) -> AssignedValue<F> {
        let a = a.as_ref().to_vec();
        let gate = self.gate();
        GateInstructions::select_by_indicator(gate, ctx, a, coeffs.to_vec())
    }
}
