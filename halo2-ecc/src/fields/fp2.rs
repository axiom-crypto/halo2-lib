use super::{FieldChip, FieldExtConstructor, FieldExtPoint, PrimeFieldChip, Selectable};
use crate::halo2_proofs::{arithmetic::Field, circuit::Value};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{fe_to_biguint, value_to_option, PrimeField},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use num_bigint::{BigInt, BigUint};
use std::marker::PhantomData;

/// Represent Fp2 point as `FieldExtPoint` with degree = 2
/// `Fp2 = Fp[u] / (u^2 + 1)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp2 point as `a_0 + a_1 * u` where `a_0, a_1 in Fp`
#[derive(Clone, Debug)]
pub struct Fp2Chip<F: PrimeField, FpChip: PrimeFieldChip<F>, Fp2: Field>
where
    FpChip::FieldType: PrimeField,
{
    // for historical reasons, leaving this as a reference
    // for the current implementation we could also just use the de-referenced version: `fp_chip: FpChip`
    pub fp_chip: FpChip,
    _f: PhantomData<F>,
    _fp2: PhantomData<Fp2>,
}

impl<F, FpChip, Fp2> Fp2Chip<F, FpChip, Fp2>
where
    F: PrimeField,
    FpChip: PrimeFieldChip<F>,
    FpChip::FieldType: PrimeField,
    Fp2: Field + FieldExtConstructor<FpChip::FieldType, 2>,
{
    /// User must construct an `FpChip` first using a config. This is intended so everything shares a single `FlexGateChip`, which is needed for the column allocation to work.
    pub fn construct(fp_chip: FpChip) -> Self {
        Self { fp_chip, _f: PhantomData, _fp2: PhantomData }
    }

    pub fn fp_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &FieldExtPoint<FpChip::FieldPoint>,
        fp_point: &FpChip::FieldPoint,
    ) -> FieldExtPoint<FpChip::FieldPoint> {
        assert_eq!(a.coeffs.len(), 2);

        let mut out_coeffs = Vec::with_capacity(2);
        for c in &a.coeffs {
            let coeff = self.fp_chip.mul_no_carry(ctx, c, fp_point);
            out_coeffs.push(coeff);
        }
        FieldExtPoint::construct(out_coeffs)
    }

    pub fn conjugate(
        &self,
        ctx: &mut Context<F>,
        a: &FieldExtPoint<FpChip::FieldPoint>,
    ) -> FieldExtPoint<FpChip::FieldPoint> {
        assert_eq!(a.coeffs.len(), 2);

        let neg_a1 = self.fp_chip.negate(ctx, &a.coeffs[1]);
        FieldExtPoint::construct(vec![a.coeffs[0].clone(), neg_a1])
    }

    pub fn neg_conjugate(
        &self,
        ctx: &mut Context<F>,
        a: &FieldExtPoint<FpChip::FieldPoint>,
    ) -> FieldExtPoint<FpChip::FieldPoint> {
        assert_eq!(a.coeffs.len(), 2);

        let neg_a0 = self.fp_chip.negate(ctx, &a.coeffs[0]);
        FieldExtPoint::construct(vec![neg_a0, a.coeffs[1].clone()])
    }

    pub fn select(
        &self,
        ctx: &mut Context<F>,
        a: &FieldExtPoint<FpChip::FieldPoint>,
        b: &FieldExtPoint<FpChip::FieldPoint>,
        sel: &AssignedValue<F>,
    ) -> FieldExtPoint<FpChip::FieldPoint>
    where
        FpChip: Selectable<F, Point = FpChip::FieldPoint>,
    {
        let coeffs: Vec<_> = a
            .coeffs
            .iter()
            .zip(b.coeffs.iter())
            .map(|(a, b)| self.fp_chip.select(ctx, a, b, sel))
            .collect();
        FieldExtPoint::construct(coeffs)
    }
}

impl<F, FpChip, Fp2> FieldChip<F> for Fp2Chip<F, FpChip, Fp2>
where
    F: PrimeField,
    FpChip::FieldType: PrimeField,
    FpChip: PrimeFieldChip<F, WitnessType = Value<BigInt>, ConstantType = BigUint>,
    Fp2: Field + FieldExtConstructor<FpChip::FieldType, 2>,
{
    const PRIME_FIELD_NUM_BITS: u32 = FpChip::FieldType::NUM_BITS;
    type ConstantType = Fp2;
    type WitnessType = Vec<Value<BigInt>>;
    type FieldPoint = FieldExtPoint<FpChip::FieldPoint>;
    type FieldType = Fp2;
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

    fn get_assigned_value(&self, x: &Self::FieldPoint) -> Value<Fp2> {
        assert_eq!(x.coeffs.len(), 2);
        let c0 = self.fp_chip.get_assigned_value(&x.coeffs[0]);
        let c1 = self.fp_chip.get_assigned_value(&x.coeffs[1]);
        c0.zip(c1).map(|(c0, c1)| Fp2::new([c0, c1]))
    }

    fn fe_to_constant(x: Fp2) -> Fp2 {
        x
    }

    fn fe_to_witness(x: &Value<Fp2>) -> Vec<Value<BigInt>> {
        match value_to_option(*x) {
            None => vec![Value::unknown(), Value::unknown()],
            Some(x) => {
                let coeffs = x.coeffs();
                assert_eq!(coeffs.len(), 2);
                coeffs.iter().map(|c| Value::known(BigInt::from(fe_to_biguint(c)))).collect()
            }
        }
    }

    fn load_private(&self, ctx: &mut Context<F>, coeffs: Vec<Value<BigInt>>) -> Self::FieldPoint {
        assert_eq!(coeffs.len(), 2);
        let mut assigned_coeffs = Vec::with_capacity(2);
        for a in coeffs {
            let assigned_coeff = self.fp_chip.load_private(ctx, a);
            assigned_coeffs.push(assigned_coeff);
        }
        Self::FieldPoint::construct(assigned_coeffs)
    }

    fn load_constant(&self, ctx: &mut Context<F>, c: Fp2) -> Self::FieldPoint {
        let mut assigned_coeffs = Vec::with_capacity(2);
        for a in &c.coeffs() {
            let assigned_coeff = self.fp_chip.load_constant(ctx, fe_to_biguint(a));
            assigned_coeffs.push(assigned_coeff);
        }
        Self::FieldPoint::construct(assigned_coeffs)
    }

    // signed overflow BigInt functions
    fn add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        assert_eq!(a.coeffs.len(), b.coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff = self.fp_chip.add_no_carry(ctx, &a.coeffs[i], &b.coeffs[i]);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn add_constant_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        c: Self::ConstantType,
    ) -> Self::FieldPoint {
        let c_coeffs = c.coeffs();
        assert_eq!(a.coeffs.len(), c_coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for (a, c) in a.coeffs.iter().zip(c_coeffs.into_iter()) {
            let coeff = self.fp_chip.add_constant_no_carry(ctx, a, FpChip::fe_to_constant(c));
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn sub_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        assert_eq!(a.coeffs.len(), b.coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff = self.fp_chip.sub_no_carry(ctx, &a.coeffs[i], &b.coeffs[i]);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn negate(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> Self::FieldPoint {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for a_coeff in &a.coeffs {
            let out_coeff = self.fp_chip.negate(ctx, a_coeff);
            out_coeffs.push(out_coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn scalar_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        c: i64,
    ) -> Self::FieldPoint {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff = self.fp_chip.scalar_mul_no_carry(ctx, &a.coeffs[i], c);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn scalar_mul_and_add_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
        c: i64,
    ) -> Self::FieldPoint {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for i in 0..a.coeffs.len() {
            let coeff =
                self.fp_chip.scalar_mul_and_add_no_carry(ctx, &a.coeffs[i], &b.coeffs[i], c);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> Self::FieldPoint {
        assert_eq!(a.coeffs.len(), b.coeffs.len());
        // (a_0 + a_1 * u) * (b_0 + b_1 * u) = (a_0 b_0 - a_1 b_1) + (a_0 b_1 + a_1 b_0) * u
        let mut ab_coeffs = Vec::with_capacity(a.coeffs.len() * b.coeffs.len());
        for i in 0..a.coeffs.len() {
            for j in 0..b.coeffs.len() {
                let coeff = self.fp_chip.mul_no_carry(ctx, &a.coeffs[i], &b.coeffs[j]);
                ab_coeffs.push(coeff);
            }
        }
        let a0b0_minus_a1b1 =
            self.fp_chip.sub_no_carry(ctx, &ab_coeffs[0], &ab_coeffs[b.coeffs.len() + 1]);
        let a0b1_plus_a1b0 =
            self.fp_chip.add_no_carry(ctx, &ab_coeffs[1], &ab_coeffs[b.coeffs.len()]);

        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        out_coeffs.push(a0b0_minus_a1b1);
        out_coeffs.push(a0b1_plus_a1b0);

        Self::FieldPoint::construct(out_coeffs)
    }

    fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) {
        for coeff in &a.coeffs {
            self.fp_chip.check_carry_mod_to_zero(ctx, coeff);
        }
    }

    fn carry_mod(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> Self::FieldPoint {
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.carry_mod(ctx, a_coeff);
            out_coeffs.push(coeff);
        }
        Self::FieldPoint::construct(out_coeffs)
    }

    fn range_check(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, max_bits: usize) {
        for a_coeff in &a.coeffs {
            self.fp_chip.range_check(ctx, a_coeff, max_bits);
        }
    }

    fn enforce_less_than(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) {
        for a_coeff in &a.coeffs {
            self.fp_chip.enforce_less_than(ctx, a_coeff)
        }
    }

    fn is_soft_zero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.is_soft_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.fp_chip.range().gate().and(ctx, Existing(coeff), Existing(p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn is_soft_nonzero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.is_soft_nonzero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.fp_chip.range().gate().or(ctx, Existing(coeff), Existing(p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn is_zero(&self, ctx: &mut Context<F>, a: &Self::FieldPoint) -> AssignedValue<F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.fp_chip.is_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.fp_chip.range().gate().and(ctx, Existing(coeff), Existing(p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: &Self::FieldPoint,
        b: &Self::FieldPoint,
    ) -> AssignedValue<F> {
        let mut acc = None;
        for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
            let coeff = self.fp_chip.is_equal_unenforced(ctx, a_coeff, b_coeff);
            if let Some(c) = acc {
                acc = Some(self.fp_chip.range().gate().and(ctx, Existing(coeff), Existing(c)));
            } else {
                acc = Some(coeff);
            }
        }
        acc.unwrap()
    }

    fn assert_equal(&self, ctx: &mut Context<F>, a: &Self::FieldPoint, b: &Self::FieldPoint) {
        for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
            self.fp_chip.assert_equal(ctx, a_coeff, b_coeff)
        }
    }
}

mod bn254 {
    use crate::fields::FieldExtConstructor;
    use crate::halo2_proofs::halo2curves::bn256::{Fq, Fq2};
    impl FieldExtConstructor<Fq, 2> for Fq2 {
        fn new(c: [Fq; 2]) -> Self {
            Fq2 { c0: c[0], c1: c[1] }
        }

        fn coeffs(&self) -> Vec<Fq> {
            vec![self.c0, self.c1]
        }
    }
}
