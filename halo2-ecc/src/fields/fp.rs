use super::{FieldChip, PrimeField, PrimeFieldChip, Selectable};
use crate::bigint::{
    add_no_carry, big_is_equal, big_is_even, big_is_zero, carry_mod, check_carry_mod_to_zero,
    mul_no_carry, scalar_mul_and_add_no_carry, scalar_mul_no_carry, select, select_by_indicator,
    sub, sub_no_carry, CRTInteger, FixedCRTInteger, OverflowInteger, ProperCrtUint, ProperUint,
};
use crate::halo2_proofs::halo2curves::CurveAffine;
use halo2_base::gates::RangeChip;
use halo2_base::utils::ScalarField;
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, bit_length, decompose_biguint, fe_to_biguint, modulus},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use num_bigint::{BigInt, BigUint};
use num_traits::One;
use std::cmp;
use std::{cmp::max, marker::PhantomData};

pub type BaseFieldChip<'range, C> =
    FpChip<'range, <C as CurveAffine>::ScalarExt, <C as CurveAffine>::Base>;

pub type FpConfig<F> = RangeConfig<F>;

/// Wrapper around `FieldPoint` to guarantee this is a "reduced" representation of an `Fp` field element.
/// A reduced representation guarantees that there is a *unique* representation of each field element.
/// Typically this means Uints that are less than the modulus.
#[derive(Clone, Debug)]
pub struct Reduced<FieldPoint, Fp>(pub(crate) FieldPoint, PhantomData<Fp>);

impl<FieldPoint, Fp> Reduced<FieldPoint, Fp> {
    pub fn as_ref(&self) -> Reduced<&FieldPoint, Fp> {
        Reduced(&self.0, PhantomData)
    }

    pub fn inner(&self) -> &FieldPoint {
        &self.0
    }
}

impl<F: ScalarField, Fp> From<Reduced<ProperCrtUint<F>, Fp>> for ProperCrtUint<F> {
    fn from(x: Reduced<ProperCrtUint<F>, Fp>) -> Self {
        x.0
    }
}

// `Fp` always needs to be `BigPrimeField`, we may later want support for `F` being just `ScalarField` but for optimization reasons we'll assume it's also `BigPrimeField` for now

#[derive(Clone, Debug)]
pub struct FpChip<'range, F: PrimeField, Fp: PrimeField> {
    pub range: &'range RangeChip<F>,

    pub limb_bits: usize,
    pub num_limbs: usize,

    pub num_limbs_bits: usize,
    pub num_limbs_log2_ceil: usize,
    pub limb_bases: Vec<F>,
    pub limb_base_big: BigInt,
    pub limb_mask: BigUint,

    pub p: BigInt,
    pub p_limbs: Vec<F>,
    pub p_native: F,

    pub native_modulus: BigUint,
    _marker: PhantomData<Fp>,
}

impl<'range, F: PrimeField, Fp: PrimeField> FpChip<'range, F, Fp> {
    pub fn new(range: &'range RangeChip<F>, limb_bits: usize, num_limbs: usize) -> Self {
        assert!(limb_bits > 0);
        assert!(num_limbs > 0);
        assert!(limb_bits <= F::CAPACITY as usize);
        let limb_mask = (BigUint::from(1u64) << limb_bits) - 1usize;
        let p = modulus::<Fp>();
        let p_limbs = decompose_biguint(&p, num_limbs, limb_bits);
        let native_modulus = modulus::<F>();
        let p_native = biguint_to_fe(&(&p % &native_modulus));

        let limb_base = biguint_to_fe::<F>(&(BigUint::one() << limb_bits));
        let mut limb_bases = Vec::with_capacity(num_limbs);
        limb_bases.push(F::one());
        while limb_bases.len() != num_limbs {
            limb_bases.push(limb_base * limb_bases.last().unwrap());
        }

        Self {
            range,
            limb_bits,
            num_limbs,
            num_limbs_bits: bit_length(num_limbs as u64),
            num_limbs_log2_ceil: bit_length(num_limbs as u64),
            limb_bases,
            limb_base_big: BigInt::one() << limb_bits,
            limb_mask,
            p: p.into(),
            p_limbs,
            p_native,
            native_modulus,
            _marker: PhantomData,
        }
    }

    pub fn enforce_less_than_p(&self, ctx: &mut Context<F>, a: ProperCrtUint<F>) {
        // a < p iff a - p has underflow
        let mut borrow: Option<AssignedValue<F>> = None;
        for (&p_limb, a_limb) in self.p_limbs.iter().zip(a.0.truncation.limbs) {
            let lt = match borrow {
                None => self.range.is_less_than(ctx, a_limb, Constant(p_limb), self.limb_bits),
                Some(borrow) => {
                    let plus_borrow = self.gate().add(ctx, Constant(p_limb), borrow);
                    self.range.is_less_than(
                        ctx,
                        Existing(a_limb),
                        Existing(plus_borrow),
                        self.limb_bits,
                    )
                }
            };
            borrow = Some(lt);
        }
        self.gate().assert_is_const(ctx, &borrow.unwrap(), &F::one());
    }

    pub fn load_constant_uint(&self, ctx: &mut Context<F>, a: BigUint) -> ProperCrtUint<F> {
        FixedCRTInteger::from_native(a, self.num_limbs, self.limb_bits).assign(
            ctx,
            self.limb_bits,
            self.native_modulus(),
        )
    }

    // assuming `a` has been range checked to be a proper BigInt
    // constrain the witness `a` to be `< p`
    // then check if `a[0]` is even
    pub fn is_even(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<ProperCrtUint<F>>,
    ) -> AssignedValue<F> {
        let a = a.into();
        self.enforce_less_than_p(ctx, a.clone());
        big_is_even::positive(self.gate(), ctx, a.0.truncation)
    }
}

impl<'range, F: PrimeField, Fp: PrimeField> PrimeFieldChip<F> for FpChip<'range, F, Fp> {
    fn num_limbs(&self) -> usize {
        self.num_limbs
    }
    fn limb_mask(&self) -> &BigUint {
        &self.limb_mask
    }
    fn limb_bases(&self) -> &[F] {
        &self.limb_bases
    }
}

impl<'range, F: PrimeField, Fp: PrimeField> FieldChip<F> for FpChip<'range, F, Fp> {
    const PRIME_FIELD_NUM_BITS: u32 = Fp::NUM_BITS;
    type UnsafeFieldPoint = CRTInteger<F>;
    type FieldPoint = ProperCrtUint<F>;
    type ReducedFieldPoint = Reduced<ProperCrtUint<F>, Fp>;
    type FieldType = Fp;
    type RangeChip = RangeChip<F>;

    fn native_modulus(&self) -> &BigUint {
        &self.native_modulus
    }
    fn range(&self) -> &'range Self::RangeChip {
        self.range
    }
    fn limb_bits(&self) -> usize {
        self.limb_bits
    }

    fn get_assigned_value(&self, x: &CRTInteger<F>) -> Fp {
        bigint_to_fe(&(&x.value % &self.p))
    }

    fn load_private(&self, ctx: &mut Context<F>, a: Fp) -> ProperCrtUint<F> {
        let a = fe_to_biguint(&a);
        let a_vec = decompose_biguint::<F>(&a, self.num_limbs, self.limb_bits);
        let limbs = ctx.assign_witnesses(a_vec);

        let a_loaded =
            ProperUint(limbs).into_crt(ctx, self.gate(), a, &self.limb_bases, self.limb_bits);

        self.range_check(ctx, a_loaded.clone(), Self::PRIME_FIELD_NUM_BITS as usize);
        a_loaded
    }

    fn load_constant(&self, ctx: &mut Context<F>, a: Fp) -> ProperCrtUint<F> {
        self.load_constant_uint(ctx, fe_to_biguint(&a))
    }

    // signed overflow BigInt functions
    fn add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        b: impl Into<CRTInteger<F>>,
    ) -> CRTInteger<F> {
        add_no_carry::crt(self.gate(), ctx, a.into(), b.into())
    }

    fn add_constant_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        c: Fp,
    ) -> CRTInteger<F> {
        let c = FixedCRTInteger::from_native(fe_to_biguint(&c), self.num_limbs, self.limb_bits);
        let c_native = biguint_to_fe::<F>(&(&c.value % modulus::<F>()));
        let a = a.into();
        let mut limbs = Vec::with_capacity(a.truncation.limbs.len());
        for (a_limb, c_limb) in a.truncation.limbs.into_iter().zip(c.truncation.limbs) {
            let limb = self.gate().add(ctx, a_limb, Constant(c_limb));
            limbs.push(limb);
        }
        let native = self.gate().add(ctx, a.native, Constant(c_native));
        let trunc =
            OverflowInteger::new(limbs, max(a.truncation.max_limb_bits, self.limb_bits) + 1);
        let value = a.value + BigInt::from(c.value);

        CRTInteger::new(trunc, native, value)
    }

    fn sub_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        b: impl Into<CRTInteger<F>>,
    ) -> CRTInteger<F> {
        sub_no_carry::crt::<F>(self.gate(), ctx, a.into(), b.into())
    }

    // Input: a
    // Output: p - a if a != 0, else a
    // Assume the actual value of `a` equals `a.truncation`
    // Constrains a.truncation <= p using subtraction with carries
    fn negate(&self, ctx: &mut Context<F>, a: ProperCrtUint<F>) -> ProperCrtUint<F> {
        // Compute p - a.truncation using carries
        let p = self.load_constant_uint(ctx, self.p.to_biguint().unwrap());
        let (out_or_p, underflow) =
            sub::crt(self.range(), ctx, p, a.clone(), self.limb_bits, self.limb_bases[1]);
        // constrain underflow to equal 0
        self.gate().assert_is_const(ctx, &underflow, &F::zero());

        let a_is_zero = big_is_zero::positive(self.gate(), ctx, a.0.truncation.clone());
        ProperCrtUint(select::crt(self.gate(), ctx, a.0, out_or_p, a_is_zero))
    }

    fn scalar_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        c: i64,
    ) -> CRTInteger<F> {
        scalar_mul_no_carry::crt(self.gate(), ctx, a.into(), c)
    }

    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        b: impl Into<CRTInteger<F>>,
        c: i64,
    ) -> CRTInteger<F> {
        scalar_mul_and_add_no_carry::crt(self.gate(), ctx, a.into(), b.into(), c)
    }

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        b: impl Into<CRTInteger<F>>,
    ) -> CRTInteger<F> {
        mul_no_carry::crt(self.gate(), ctx, a.into(), b.into(), self.num_limbs_log2_ceil)
    }

    fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: CRTInteger<F>) {
        check_carry_mod_to_zero::crt::<F>(
            self.range(),
            ctx,
            a,
            self.num_limbs_bits,
            &self.p,
            &self.p_limbs,
            self.p_native,
            self.limb_bits,
            &self.limb_bases,
            &self.limb_base_big,
        )
    }

    fn carry_mod(&self, ctx: &mut Context<F>, a: CRTInteger<F>) -> ProperCrtUint<F> {
        carry_mod::crt::<F>(
            self.range(),
            ctx,
            a,
            self.num_limbs_bits,
            &self.p,
            &self.p_limbs,
            self.p_native,
            self.limb_bits,
            &self.limb_bases,
            &self.limb_base_big,
        )
    }

    /// # Assumptions
    /// * `max_bits <= n * k` where `n = self.limb_bits` and `k = self.num_limbs`
    /// * `a.truncation.limbs.len() = self.num_limbs`
    fn range_check(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<CRTInteger<F>>,
        max_bits: usize, // the maximum bits that a.value could take
    ) {
        let n = self.limb_bits;
        let a = a.into();
        let mut remaining_bits = max_bits;

        debug_assert!(a.value.bits() as usize <= max_bits);

        // range check limbs of `a` are in [0, 2^n) except last limb should be in [0, 2^last_limb_bits)
        for cell in a.truncation.limbs {
            let limb_bits = cmp::min(n, remaining_bits);
            remaining_bits -= limb_bits;
            self.range.range_check(ctx, cell, limb_bits);
        }
    }

    fn enforce_less_than(
        &self,
        ctx: &mut Context<F>,
        a: ProperCrtUint<F>,
    ) -> Reduced<ProperCrtUint<F>, Fp> {
        self.enforce_less_than_p(ctx, a.clone());
        Reduced(a, PhantomData)
    }

    /// Returns 1 iff `a` is 0 as a BigUint. This means that even if `a` is 0 modulo `p`, this may return 0.
    fn is_soft_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<ProperCrtUint<F>>,
    ) -> AssignedValue<F> {
        let a = a.into();
        big_is_zero::positive(self.gate(), ctx, a.0.truncation)
    }

    /// Given proper CRT integer `a`, returns 1 iff `a < modulus::<F>()` and `a != 0` as integers
    ///
    /// # Assumptions
    /// * `a` is proper representation of BigUint
    fn is_soft_nonzero(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<ProperCrtUint<F>>,
    ) -> AssignedValue<F> {
        let a = a.into();
        let is_zero = big_is_zero::positive(self.gate(), ctx, a.0.truncation.clone());
        let is_nonzero = self.gate().not(ctx, is_zero);

        // underflow != 0 iff carry < p
        let p = self.load_constant_uint(ctx, self.p.to_biguint().unwrap());
        let (_, underflow) =
            sub::crt::<F>(self.range(), ctx, a, p, self.limb_bits, self.limb_bases[1]);
        let is_underflow_zero = self.gate().is_zero(ctx, underflow);
        let no_underflow = self.gate().not(ctx, is_underflow_zero);

        self.gate().and(ctx, is_nonzero, no_underflow)
    }

    // assuming `a` has been range checked to be a proper BigInt
    // constrain the witness `a` to be `< p`
    // then check if `a` is 0
    fn is_zero(&self, ctx: &mut Context<F>, a: impl Into<ProperCrtUint<F>>) -> AssignedValue<F> {
        let a = a.into();
        self.enforce_less_than_p(ctx, a.clone());
        // just check truncated limbs are all 0 since they determine the native value
        big_is_zero::positive(self.gate(), ctx, a.0.truncation)
    }

    fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: Reduced<ProperCrtUint<F>, Fp>,
        b: Reduced<ProperCrtUint<F>, Fp>,
    ) -> AssignedValue<F> {
        big_is_equal::assign::<F>(self.gate(), ctx, a.0, b.0)
    }

    // assuming `a, b` have been range checked to be a proper BigInt
    // constrain the witnesses `a, b` to be `< p`
    // then assert `a == b` as BigInts
    fn assert_equal(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<ProperCrtUint<F>>,
        b: impl Into<ProperCrtUint<F>>,
    ) {
        let a = a.into();
        let b = b.into();
        // a.native and b.native are derived from `a.truncation, b.truncation`, so no need to check if they're equal
        for (limb_a, limb_b) in a.limbs().iter().zip(b.limbs().iter()) {
            ctx.constrain_equal(limb_a, limb_b);
        }
        self.enforce_less_than_p(ctx, a);
        self.enforce_less_than_p(ctx, b);
    }
}

impl<'range, F: PrimeField, Fp: PrimeField> Selectable<F, CRTInteger<F>> for FpChip<'range, F, Fp> {
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: CRTInteger<F>,
        b: CRTInteger<F>,
        sel: AssignedValue<F>,
    ) -> CRTInteger<F> {
        select::crt(self.gate(), ctx, a, b, sel)
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[CRTInteger<F>]>,
        coeffs: &[AssignedValue<F>],
    ) -> CRTInteger<F> {
        select_by_indicator::crt(self.gate(), ctx, a.as_ref(), coeffs, &self.limb_bases)
    }
}

impl<'range, F: PrimeField, Fp: PrimeField> Selectable<F, ProperCrtUint<F>>
    for FpChip<'range, F, Fp>
{
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: ProperCrtUint<F>,
        b: ProperCrtUint<F>,
        sel: AssignedValue<F>,
    ) -> ProperCrtUint<F> {
        ProperCrtUint(select::crt(self.gate(), ctx, a.0, b.0, sel))
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[ProperCrtUint<F>]>,
        coeffs: &[AssignedValue<F>],
    ) -> ProperCrtUint<F> {
        let out = select_by_indicator::crt(self.gate(), ctx, a.as_ref(), coeffs, &self.limb_bases);
        ProperCrtUint(out)
    }
}

impl<F: PrimeField, Fp, Pt: Clone, FC> Selectable<F, Reduced<Pt, Fp>> for FC
where
    FC: Selectable<F, Pt>,
{
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: Reduced<Pt, Fp>,
        b: Reduced<Pt, Fp>,
        sel: AssignedValue<F>,
    ) -> Reduced<Pt, Fp> {
        Reduced(self.select(ctx, a.0, b.0, sel), PhantomData)
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[Reduced<Pt, Fp>]>,
        coeffs: &[AssignedValue<F>],
    ) -> Reduced<Pt, Fp> {
        // this is inefficient, could do std::mem::transmute but that is unsafe. hopefully compiler optimizes it out
        let a = a.as_ref().iter().map(|a| a.0.clone()).collect::<Vec<_>>();
        Reduced(self.select_by_indicator(ctx, &a, coeffs), PhantomData)
    }
}
