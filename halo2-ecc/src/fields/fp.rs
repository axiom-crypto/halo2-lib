use super::{FieldChip, PrimeField, PrimeFieldChip, Selectable};
use crate::bigint::{
    add_no_carry, big_is_equal, big_is_zero, carry_mod, check_carry_mod_to_zero, mul_no_carry,
    scalar_mul_and_add_no_carry, scalar_mul_no_carry, select, select_by_indicator, sub,
    sub_no_carry, CRTInteger, FixedCRTInteger, OverflowInteger,
};
use crate::halo2_proofs::halo2curves::CurveAffine;
use halo2_base::gates::RangeChip;
use halo2_base::utils::decompose_bigint;
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, biguint_to_fe, bit_length, decompose_biguint, fe_to_biguint, modulus},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use num_bigint::{BigInt, BigUint};
use num_traits::One;
use std::{cmp::max, marker::PhantomData};

pub type BaseFieldChip<'range, C> =
    FpChip<'range, <C as CurveAffine>::ScalarExt, <C as CurveAffine>::Base>;

pub type FpConfig<F> = RangeConfig<F>;

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

    pub fn enforce_less_than_p(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) {
        // a < p iff a - p has underflow
        let mut borrow: Option<AssignedValue<F>> = None;
        for (&p_limb, &a_limb) in self.p_limbs.iter().zip(a.truncation.limbs.iter()) {
            let lt = match borrow {
                None => self.range.is_less_than(ctx, a_limb, Constant(p_limb), self.limb_bits),
                Some(borrow) => {
                    let plus_borrow = self.range.gate.add(ctx, Constant(p_limb), borrow);
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
        self.range.gate.assert_is_const(ctx, &borrow.unwrap(), &F::one());
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
    type ConstantType = BigUint;
    type WitnessType = BigInt;
    type FieldPoint = CRTInteger<F>;
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

    fn fe_to_constant(x: Fp) -> BigUint {
        fe_to_biguint(&x)
    }

    fn fe_to_witness(x: &Fp) -> BigInt {
        BigInt::from(fe_to_biguint(x))
    }

    fn load_private(&self, ctx: &mut Context<F>, a: BigInt) -> CRTInteger<F> {
        let a_vec = decompose_bigint::<F>(&a, self.num_limbs, self.limb_bits);
        let limbs = ctx.assign_witnesses(a_vec);

        let a_native = OverflowInteger::<F>::evaluate(
            self.range.gate(),
            ctx,
            limbs.iter().copied(),
            self.limb_bases.iter().copied(),
        );

        let a_loaded =
            CRTInteger::construct(OverflowInteger::construct(limbs, self.limb_bits), a_native, a);

        // TODO: this range check prevents loading witnesses that are not in "proper" representation form, is that ok?
        self.range_check(ctx, &a_loaded, Self::PRIME_FIELD_NUM_BITS as usize);
        a_loaded
    }

    fn load_constant(&self, ctx: &mut Context<F>, a: BigUint) -> CRTInteger<F> {
        let a_native = ctx.load_constant(biguint_to_fe(&(&a % self.native_modulus())));
        let a_limbs = decompose_biguint::<F>(&a, self.num_limbs, self.limb_bits)
            .into_iter()
            .map(|c| ctx.load_constant(c))
            .collect();

        CRTInteger::construct(
            OverflowInteger::construct(a_limbs, self.limb_bits),
            a_native,
            BigInt::from(a),
        )
    }

    // signed overflow BigInt functions
    fn add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        b: &CRTInteger<F>,
    ) -> CRTInteger<F> {
        add_no_carry::crt::<F>(self.range.gate(), ctx, a, b)
    }

    fn add_constant_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        c: BigUint,
    ) -> CRTInteger<F> {
        let c = FixedCRTInteger::from_native(c, self.num_limbs, self.limb_bits);
        let c_native = biguint_to_fe::<F>(&(&c.value % modulus::<F>()));
        let mut limbs = Vec::with_capacity(a.truncation.limbs.len());
        for (a_limb, c_limb) in a.truncation.limbs.iter().zip(c.truncation.limbs.into_iter()) {
            let limb = self.range.gate.add(ctx, *a_limb, Constant(c_limb));
            limbs.push(limb);
        }
        let native = self.range.gate.add(ctx, a.native, Constant(c_native));
        let trunc =
            OverflowInteger::construct(limbs, max(a.truncation.max_limb_bits, self.limb_bits) + 1);
        let value = &a.value + BigInt::from(c.value);

        CRTInteger::construct(trunc, native, value)
    }

    fn sub_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        b: &CRTInteger<F>,
    ) -> CRTInteger<F> {
        sub_no_carry::crt::<F>(self.range.gate(), ctx, a, b)
    }

    // Input: a
    // Output: p - a if a != 0, else a
    // Assume the actual value of `a` equals `a.truncation`
    // Constrains a.truncation <= p using subtraction with carries
    fn negate(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) -> CRTInteger<F> {
        // Compute p - a.truncation using carries
        let p = self.load_constant(ctx, self.p.to_biguint().unwrap());
        let (out_or_p, underflow) =
            sub::crt::<F>(self.range(), ctx, &p, a, self.limb_bits, self.limb_bases[1]);
        // constrain underflow to equal 0
        self.range.gate.assert_is_const(ctx, &underflow, &F::zero());

        let a_is_zero = big_is_zero::assign::<F>(self.gate(), ctx, &a.truncation);
        select::crt::<F>(self.range.gate(), ctx, a, &out_or_p, a_is_zero)
    }

    fn scalar_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        c: i64,
    ) -> CRTInteger<F> {
        scalar_mul_no_carry::crt::<F>(self.range.gate(), ctx, a, c)
    }

    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        b: &CRTInteger<F>,
        c: i64,
    ) -> CRTInteger<F> {
        scalar_mul_and_add_no_carry::crt::<F>(self.range.gate(), ctx, a, b, c)
    }

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        b: &CRTInteger<F>,
    ) -> CRTInteger<F> {
        mul_no_carry::crt::<F>(self.range.gate(), ctx, a, b, self.num_limbs_log2_ceil)
    }

    fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) {
        check_carry_mod_to_zero::crt::<F>(
            self.range(),
            // &self.bigint_chip,
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

    fn carry_mod(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) -> CRTInteger<F> {
        carry_mod::crt::<F>(
            self.range(),
            // &self.bigint_chip,
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
    /// * `max_bits` in `(n * (k - 1), n * k]`
    fn range_check(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        max_bits: usize, // the maximum bits that a.value could take
    ) {
        let n = self.limb_bits;
        let k = a.truncation.limbs.len();
        debug_assert!(max_bits > n * (k - 1) && max_bits <= n * k);
        let last_limb_bits = max_bits - n * (k - 1);

        debug_assert!(a.value.bits() as usize <= max_bits);

        // range check limbs of `a` are in [0, 2^n) except last limb should be in [0, 2^last_limb_bits)
        for (i, cell) in a.truncation.limbs.iter().enumerate() {
            let limb_bits = if i == k - 1 { last_limb_bits } else { n };
            self.range.range_check(ctx, *cell, limb_bits);
        }
    }

    fn enforce_less_than(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) {
        self.enforce_less_than_p(ctx, a)
    }

    fn is_soft_zero(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) -> AssignedValue<F> {
        big_is_zero::crt::<F>(self.gate(), ctx, a)

        // CHECK: I don't think this is necessary:
        // underflow != 0 iff carry < p
        // let p = self.load_constant(ctx, self.p.to_biguint().unwrap());
        // let (_, underflow) =
        //     sub::crt::<F>(self.range(), ctx, a, &p, self.limb_bits, self.limb_bases[1]);
        // let is_underflow_zero = self.gate().is_zero(ctx, &underflow);
        // let range_check = self.gate().not(ctx, Existing(&is_underflow_zero));

        // self.gate().and(ctx, is_zero, range_check)
    }

    fn is_soft_nonzero(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) -> AssignedValue<F> {
        let is_zero = big_is_zero::crt::<F>(self.gate(), ctx, a);
        let is_nonzero = self.gate().not(ctx, is_zero);

        // underflow != 0 iff carry < p
        let p = self.load_constant(ctx, self.p.to_biguint().unwrap());
        let (_, underflow) =
            sub::crt::<F>(self.range(), ctx, a, &p, self.limb_bits, self.limb_bases[1]);
        let is_underflow_zero = self.gate().is_zero(ctx, underflow);
        let no_underflow = self.gate().not(ctx, is_underflow_zero);

        self.gate().and(ctx, is_nonzero, no_underflow)
    }

    // assuming `a` has been range checked to be a proper BigInt
    // constrain the witness `a` to be `< p`
    // then check if `a` is 0
    fn is_zero(&self, ctx: &mut Context<F>, a: &CRTInteger<F>) -> AssignedValue<F> {
        self.enforce_less_than_p(ctx, a);
        // just check truncated limbs are all 0 since they determine the native value
        big_is_zero::positive::<F>(self.gate(), ctx, &a.truncation)
    }

    fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> AssignedValue<F> {
        big_is_equal::assign::<F>(self.gate(), ctx, &a.truncation, &b.truncation)
    }

    // assuming `a, b` have been range checked to be a proper BigInt
    // constrain the witnesses `a, b` to be `< p`
    // then assert `a == b` as BigInts
    fn assert_equal(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, b: &Self::FieldPoint) {
        self.enforce_less_than_p(ctx, a);
        self.enforce_less_than_p(ctx, b);
        // a.native and b.native are derived from `a.truncation, b.truncation`, so no need to check if they're equal
        for (limb_a, limb_b) in a.truncation.limbs.iter().zip(b.truncation.limbs.iter()) {
            ctx.constrain_equal(limb_a, limb_b);
        }
    }
}

impl<'range, F: PrimeField, Fp: PrimeField> Selectable<F> for FpChip<'range, F, Fp> {
    type Point = CRTInteger<F>;

    fn select(
        &self,
        ctx: &mut Context<F>,
        a: &CRTInteger<F>,
        b: &CRTInteger<F>,
        sel: AssignedValue<F>,
    ) -> CRTInteger<F> {
        select::crt::<F>(self.range.gate(), ctx, a, b, sel)
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &[CRTInteger<F>],
        coeffs: &[AssignedValue<F>],
    ) -> CRTInteger<F> {
        select_by_indicator::crt::<F>(self.range.gate(), ctx, a, coeffs, &self.limb_bases)
    }
}
