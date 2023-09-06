use super::{BigPrimeField, FieldChip};
use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::{gates::GateInstructions, utils::modulus, AssignedValue, Context};
use num_bigint::BigUint;
use std::marker::PhantomData;

// `Fp` always needs to be `BigPrimeField`, we may later want support for `F` being just `ScalarField` but for optimization reasons we'll assume it's also `BigPrimeField` for now
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
        F::CAPACITY as usize
    }

    fn get_assigned_value(&self, x: &AssignedValue<F>) -> F {
        *x.value()
    }

    fn load_private(&self, ctx: &mut Context<F>, a: F) -> AssignedValue<F> {
        let a_loaded = ctx.load_witness(a);

        a_loaded
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
        let c = self.load_constant(ctx, c);
        self.add_no_carry(ctx, a, c)
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
    // Assume the actual value of `a` equals `a.truncation`
    // Constrains a.truncation <= p using subtraction with carries
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

        let c_loaded = ctx.load_constant(c_f);
        self.gate().mul(ctx, a.into(), c_loaded)
    }

    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
        c: i64,
    ) -> AssignedValue<F> {
        let a_mul_c = self.scalar_mul_no_carry(ctx, a, c);
        self.add_no_carry(ctx, a_mul_c, b)
    }

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        b: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        self.gate().mul(ctx, a.into(), b.into())
    }

    // noop
    fn check_carry_mod_to_zero(&self, _ctx: &mut Context<F>, _a: AssignedValue<F>) {}

    // noop
    fn carry_mod(&self, _ctx: &mut Context<F>, a: AssignedValue<F>) -> AssignedValue<F> {
        a
    }

    fn range_check(
        &self,
        _ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
        max_bits: usize, // the maximum bits that a.value could take
    ) {
        let a: AssignedValue<F> = a.into();
        debug_assert!(a.value().to_bytes_le().len() <= max_bits);
    }

    fn enforce_less_than(&self, _ctx: &mut Context<F>, a: AssignedValue<F>) -> AssignedValue<F> {
        a
    }

    /// Returns 1 iff `a` is 0 as a BigUint. This means that even if `a` is 0 modulo `p`, this may return 0.
    fn is_soft_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        let a = a.into();
        self.gate().is_zero(ctx, a)
    }

    /// Given proper CRT integer `a`, returns 1 iff `a < modulus::<F>()` and `a != 0` as integers
    ///
    /// # Assumptions
    /// * `a` is proper representation of BigUint
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
        self.is_soft_nonzero(ctx, a)
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
        let is_equal = self.is_equal_unenforced(ctx, a.into(), b.into());
        self.gate().assert_is_const(ctx, &is_equal, &F::ONE);
    }
}
