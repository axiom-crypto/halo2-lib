use super::{FieldChip, FieldExtConstructor, FieldExtPoint, PrimeFieldChip};
use crate::halo2_proofs::{arithmetic::Field, circuit::Value};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{fe_to_biguint, value_to_option, PrimeField},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use num_bigint::{BigInt, BigUint};
use std::marker::PhantomData;

/// Represent Fp12 point as FqPoint with degree = 12
/// `Fp12 = Fp2[w] / (w^6 - u - xi)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to
/// be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp12 point as `\sum_{i = 0}^6 (a_{i0} + a_{i1} * u) * w^i`
/// This is encoded in an FqPoint of degree 12 as `(a_{00}, ..., a_{50}, a_{01}, ..., a_{51})`
pub struct Fp12Chip<'a, F: PrimeField, FpChip: PrimeFieldChip<F>, Fp12: Field, const XI_0: i64>
where
    FpChip::FieldType: PrimeField,
{
    // for historical reasons, leaving this as a reference
    // for the current implementation we could also just use the de-referenced version: `fp_chip: FpChip`
    pub fp_chip: &'a FpChip,
    _f: PhantomData<F>,
    _fp12: PhantomData<Fp12>,
}

impl<'a, F, FpChip, Fp12, const XI_0: i64> Fp12Chip<'a, F, FpChip, Fp12, XI_0>
where
    F: PrimeField,
    FpChip: PrimeFieldChip<F>,
    FpChip::FieldType: PrimeField,
    Fp12: Field + FieldExtConstructor<FpChip::FieldType, 12>,
{
    /// User must construct an `FpChip` first using a config. This is intended so everything shares a single `FlexGateChip`, which is needed for the column allocation to work.
    pub fn construct(fp_chip: &'a FpChip) -> Self {
        Self { fp_chip, _f: PhantomData, _fp12: PhantomData }
    }

    pub fn fp2_mul_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &FieldExtPoint<FpChip::FieldPoint<'v>>,
        fp2_pt: &FieldExtPoint<FpChip::FieldPoint<'v>>,
    ) -> FieldExtPoint<FpChip::FieldPoint<'v>> {
        assert_eq!(a.coeffs.len(), 12);
        assert_eq!(fp2_pt.coeffs.len(), 2);

        let mut out_coeffs = Vec::with_capacity(12);
        for i in 0..6 {
            let coeff1 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i], &fp2_pt.coeffs[0]);
            let coeff2 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i + 6], &fp2_pt.coeffs[1]);
            let coeff = self.fp_chip.sub_no_carry(ctx, &coeff1, &coeff2);
            out_coeffs.push(coeff);
        }
        for i in 0..6 {
            let coeff1 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i + 6], &fp2_pt.coeffs[0]);
            let coeff2 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i], &fp2_pt.coeffs[1]);
            let coeff = self.fp_chip.add_no_carry(ctx, &coeff1, &coeff2);
            out_coeffs.push(coeff);
        }
        FieldExtPoint::construct(out_coeffs)
    }

    // for \sum_i (a_i + b_i u) w^i, returns \sum_i (-1)^i (a_i + b_i u) w^i
    pub fn conjugate<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &FieldExtPoint<FpChip::FieldPoint<'v>>,
    ) -> FieldExtPoint<FpChip::FieldPoint<'v>> {
        assert_eq!(a.coeffs.len(), 12);

        let coeffs = a
            .coeffs
            .iter()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.clone() } else { self.fp_chip.negate(ctx, c) })
            .collect();
        FieldExtPoint::construct(coeffs)
    }
}

/// multiply (a0 + a1 * u) * (XI0 + u) without carry
pub fn mul_no_carry_w6<'v, F: PrimeField, FC: FieldChip<F>, const XI_0: i64>(
    fp_chip: &FC,
    ctx: &mut Context<'v, F>,
    a: &FieldExtPoint<FC::FieldPoint<'v>>,
) -> FieldExtPoint<FC::FieldPoint<'v>> {
    assert_eq!(a.coeffs.len(), 2);
    let (a0, a1) = (&a.coeffs[0], &a.coeffs[1]);
    // (a0 + a1 u) * (XI_0 + u) = (a0 * XI_0 - a1) + (a1 * XI_0 + a0) u     with u^2 = -1
    // This should fit in the overflow representation if limb_bits is large enough
    let a0_xi0 = fp_chip.scalar_mul_no_carry(ctx, a0, XI_0);
    let out0_0_nocarry = fp_chip.sub_no_carry(ctx, &a0_xi0, a1);
    let out0_1_nocarry = fp_chip.scalar_mul_and_add_no_carry(ctx, a1, a0, XI_0);
    FieldExtPoint::construct(vec![out0_0_nocarry, out0_1_nocarry])
}

impl<'a, F, FpChip, Fp12, const XI_0: i64> FieldChip<F> for Fp12Chip<'a, F, FpChip, Fp12, XI_0>
where
    F: PrimeField,
    FpChip: PrimeFieldChip<F, WitnessType = Value<BigInt>, ConstantType = BigUint>,
    FpChip::FieldType: PrimeField,
    Fp12: Field + FieldExtConstructor<FpChip::FieldType, 12>,
{
    const PRIME_FIELD_NUM_BITS: u32 = FpChip::FieldType::NUM_BITS;
    type ConstantType = Fp12;
    type WitnessType = Vec<Value<BigInt>>;
    type FieldPoint<'v> = FieldExtPoint<FpChip::FieldPoint<'v>>;
    type FieldType = Fp12;
    type RangeChip = FpChip::RangeChip;

    fn native_modulus(&self) -> &BigUint {
        self.fp_chip.native_modulus()
    }
    fn range(&self) -> &Self::RangeChip {
        self.fp_chip.range()
    }

    fn limb_bits(&self) -> usize {
        self.fp_chip.limb_bits()
    }

    fn get_assigned_value(&self, x: &Self::FieldPoint<'_>) -> Value<Fp12> {
        assert_eq!(x.coeffs.len(), 12);
        let values = x.coeffs.iter().map(|v| self.fp_chip.get_assigned_value(v));
        let values_collected: Value<Vec<FpChip::FieldType>> = values.into_iter().collect();
        values_collected.map(|c| Fp12::new(c.try_into().unwrap()))
    }

    fn fe_to_constant(x: Self::FieldType) -> Self::ConstantType {
        x
    }
    fn fe_to_witness(x: &Value<Fp12>) -> Vec<Value<BigInt>> {
        match value_to_option(*x) {
            Some(x) => {
                x.coeffs().iter().map(|c| Value::known(BigInt::from(fe_to_biguint(c)))).collect()
            }
            None => vec![Value::unknown(); 12],
        }
    }

    fn load_private<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        coeffs: Vec<Value<BigInt>>,
    ) -> Self::FieldPoint<'v> {
        assert_eq!(coeffs.len(), 12);
        let mut assigned_coeffs = Vec::with_capacity(12);
        for a in coeffs {
            let assigned_coeff = self.fp_chip.load_private(ctx, a.clone());
            assigned_coeffs.push(assigned_coeff);
        }
        Self::FieldPoint::construct(assigned_coeffs)
    }

    fn load_constant<'v>(&self, ctx: &mut Context<'_, F>, c: Fp12) -> Self::FieldPoint<'v> {
        let mut assigned_coeffs = Vec::with_capacity(12);
        for a in &c.coeffs() {
            let assigned_coeff = self.fp_chip.load_constant(ctx, fe_to_biguint(a));
            assigned_coeffs.push(assigned_coeff);
        }
        Self::FieldPoint::construct(assigned_coeffs)
    }

    // signed overflow BigInt functions
    fn add_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
    ) -> Self::FieldPoint<'v> {
        assert_eq!(a.coeffs.len(), b.coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff = self.fp_chip.add_no_carry(ctx, &a.coeffs[i], &b.coeffs[i]);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn add_constant_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        c: Self::ConstantType,
    ) -> Self::FieldPoint<'v> {
        let c_coeffs = c.coeffs();
        assert_eq!(a.coeffs.len(), c_coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for (a, c) in a.coeffs.iter().zip(c_coeffs.into_iter()) {
            let coeff = self.fp_chip.add_constant_no_carry(ctx, a, FpChip::fe_to_constant(c));
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn sub_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
    ) -> Self::FieldPoint<'v> {
        assert_eq!(a.coeffs.len(), b.coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff = self.fp_chip.sub_no_carry(ctx, &a.coeffs[i], &b.coeffs[i]);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn negate<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
    ) -> Self::FieldPoint<'v> {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for a_coeff in &a.coeffs {
            let out_coeff = self.fp_chip.negate(ctx, a_coeff);
            out_coeffs.push(out_coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn scalar_mul_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        c: i64,
    ) -> Self::FieldPoint<'v> {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff = self.fp_chip.scalar_mul_no_carry(ctx, &a.coeffs[i], c);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn scalar_mul_and_add_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
        c: i64,
    ) -> Self::FieldPoint<'v> {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff =
                self.fp_chip.scalar_mul_and_add_no_carry(ctx, &a.coeffs[i], &b.coeffs[i], c);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    // w^6 = u + xi for xi = 9
    fn mul_no_carry<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
    ) -> Self::FieldPoint<'v> {
        assert_eq!(a.coeffs.len(), 12);
        assert_eq!(b.coeffs.len(), 12);

        // a = \sum_{i = 0}^5 (a_i * w^i + a_{i + 6} * w^i * u)
        // b = \sum_{i = 0}^5 (b_i * w^i + b_{i + 6} * w^i * u)
        let mut a0b0_coeffs = Vec::with_capacity(11);
        let mut a0b1_coeffs = Vec::with_capacity(11);
        let mut a1b0_coeffs = Vec::with_capacity(11);
        let mut a1b1_coeffs = Vec::with_capacity(11);
        for i in 0..6 {
            for j in 0..6 {
                let coeff00 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i], &b.coeffs[j]);
                let coeff01 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i], &b.coeffs[j + 6]);
                let coeff10 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i + 6], &b.coeffs[j]);
                let coeff11 = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i + 6], &b.coeffs[j + 6]);
                if i + j < a0b0_coeffs.len() {
                    a0b0_coeffs[i + j] =
                        self.fp_chip.add_no_carry(ctx, &a0b0_coeffs[i + j], &coeff00);
                    a0b1_coeffs[i + j] =
                        self.fp_chip.add_no_carry(ctx, &a0b1_coeffs[i + j], &coeff01);
                    a1b0_coeffs[i + j] =
                        self.fp_chip.add_no_carry(ctx, &a1b0_coeffs[i + j], &coeff10);
                    a1b1_coeffs[i + j] =
                        self.fp_chip.add_no_carry(ctx, &a1b1_coeffs[i + j], &coeff11);
                } else {
                    a0b0_coeffs.push(coeff00);
                    a0b1_coeffs.push(coeff01);
                    a1b0_coeffs.push(coeff10);
                    a1b1_coeffs.push(coeff11);
                }
            }
        }

        let mut a0b0_minus_a1b1 = Vec::with_capacity(11);
        let mut a0b1_plus_a1b0 = Vec::with_capacity(11);
        for i in 0..11 {
            let a0b0_minus_a1b1_entry =
                self.fp_chip.sub_no_carry(ctx, &a0b0_coeffs[i], &a1b1_coeffs[i]);
            let a0b1_plus_a1b0_entry =
                self.fp_chip.add_no_carry(ctx, &a0b1_coeffs[i], &a1b0_coeffs[i]);

            a0b0_minus_a1b1.push(a0b0_minus_a1b1_entry);
            a0b1_plus_a1b0.push(a0b1_plus_a1b0_entry);
        }

        // out_i       = a0b0_minus_a1b1_i + XI_0 * a0b0_minus_a1b1_{i + 6} - a0b1_plus_a1b0_{i + 6}
        // out_{i + 6} = a0b1_plus_a1b0_{i} + a0b0_minus_a1b1_{i + 6} + XI_0 * a0b1_plus_a1b0_{i + 6}
        let mut out_coeffs = Vec::with_capacity(12);
        for i in 0..6 {
            if i < 5 {
                let mut coeff = self.fp_chip.scalar_mul_and_add_no_carry(
                    ctx,
                    &a0b0_minus_a1b1[i + 6],
                    &a0b0_minus_a1b1[i],
                    XI_0,
                );
                coeff = self.fp_chip.sub_no_carry(ctx, &coeff, &a0b1_plus_a1b0[i + 6]);
                out_coeffs.push(coeff);
            } else {
                out_coeffs.push(a0b0_minus_a1b1[i].clone());
            }
        }
        for i in 0..6 {
            if i < 5 {
                let mut coeff =
                    self.fp_chip.add_no_carry(ctx, &a0b1_plus_a1b0[i], &a0b0_minus_a1b1[i + 6]);
                coeff = self.fp_chip.scalar_mul_and_add_no_carry(
                    ctx,
                    &a0b1_plus_a1b0[i + 6],
                    &coeff,
                    XI_0,
                );
                out_coeffs.push(coeff);
            } else {
                out_coeffs.push(a0b1_plus_a1b0[i].clone());
            }
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn check_carry_mod_to_zero<'v>(&self, ctx: &mut Context<'v, F>, a: &Self::FieldPoint<'v>) {
        for coeff in &a.coeffs {
            self.fp_chip.check_carry_mod_to_zero(ctx, coeff);
        }
    }

    fn carry_mod<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
    ) -> Self::FieldPoint<'v> {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.carry_mod(ctx, a_coeff);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn range_check<'v>(&self, ctx: &mut Context<'v, F>, a: &Self::FieldPoint<'v>, max_bits: usize) {
        for a_coeff in &a.coeffs {
            self.fp_chip.range_check(ctx, a_coeff, max_bits);
        }
    }

    fn enforce_less_than<'v>(&self, ctx: &mut Context<'v, F>, a: &Self::FieldPoint<'v>) {
        for a_coeff in &a.coeffs {
            self.fp_chip.enforce_less_than(ctx, a_coeff)
        }
    }

    fn is_soft_zero<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
    ) -> AssignedValue<'v, F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.is_soft_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.fp_chip.range().gate().and(ctx, Existing(&coeff), Existing(&p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn is_soft_nonzero<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
    ) -> AssignedValue<'v, F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.is_soft_nonzero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.fp_chip.range().gate().or(ctx, Existing(&coeff), Existing(&p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn is_zero<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
    ) -> AssignedValue<'v, F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.is_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.fp_chip.range().gate().and(ctx, Existing(&coeff), Existing(&p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn is_equal<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
    ) -> AssignedValue<'v, F> {
        let mut acc = None;
        for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
            let coeff = self.fp_chip.is_equal(ctx, a_coeff, b_coeff);
            if let Some(c) = acc {
                acc = Some(self.fp_chip.range().gate().and(ctx, Existing(&coeff), Existing(&c)));
            } else {
                acc = Some(coeff);
            }
        }
        acc.unwrap()
    }

    fn is_equal_unenforced<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
    ) -> AssignedValue<'v, F> {
        let mut acc = None;
        for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
            let coeff = self.fp_chip.is_equal_unenforced(ctx, a_coeff, b_coeff);
            if let Some(c) = acc {
                acc = Some(self.fp_chip.range().gate().and(ctx, Existing(&coeff), Existing(&c)));
            } else {
                acc = Some(coeff);
            }
        }
        acc.unwrap()
    }

    fn assert_equal<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &Self::FieldPoint<'v>,
        b: &Self::FieldPoint<'v>,
    ) {
        for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
            self.fp_chip.assert_equal(ctx, a_coeff, b_coeff);
        }
    }
}

mod bn254 {
    use crate::fields::FieldExtConstructor;
    use crate::halo2_proofs::halo2curves::bn256::{Fq, Fq12, Fq2, Fq6};
    // This means we store an Fp12 point as `\sum_{i = 0}^6 (a_{i0} + a_{i1} * u) * w^i`
    // This is encoded in an FqPoint of degree 12 as `(a_{00}, ..., a_{50}, a_{01}, ..., a_{51})`
    impl FieldExtConstructor<Fq, 12> for Fq12 {
        fn new(c: [Fq; 12]) -> Self {
            Fq12 {
                c0: Fq6 {
                    c0: Fq2 { c0: c[0], c1: c[6] },
                    c1: Fq2 { c0: c[2], c1: c[8] },
                    c2: Fq2 { c0: c[4], c1: c[10] },
                },
                c1: Fq6 {
                    c0: Fq2 { c0: c[1], c1: c[7] },
                    c1: Fq2 { c0: c[3], c1: c[9] },
                    c2: Fq2 { c0: c[5], c1: c[11] },
                },
            }
        }

        fn coeffs(&self) -> Vec<Fq> {
            let x = self;
            vec![
                x.c0.c0.c0, x.c1.c0.c0, x.c0.c1.c0, x.c1.c1.c0, x.c0.c2.c0, x.c1.c2.c0, x.c0.c0.c1,
                x.c1.c0.c1, x.c0.c1.c1, x.c1.c1.c1, x.c0.c2.c1, x.c1.c2.c1,
            ]
        }
    }
}
