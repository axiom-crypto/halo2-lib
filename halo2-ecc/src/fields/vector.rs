use halo2_base::{
    gates::GateInstructions,
    utils::{BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use itertools::Itertools;
use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use crate::bigint::{CRTInteger, ProperCrtUint};

use super::{fp::Reduced, FieldChip, FieldExtConstructor, PrimeFieldChip, Selectable};

/// A fixed length vector of `FieldPoint`s
#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct FieldVector<T>(pub Vec<T>);

impl<T> Index<usize> for FieldVector<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for FieldVector<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T> AsRef<[T]> for FieldVector<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<'a, T: Clone, U: From<T>> From<&'a FieldVector<T>> for FieldVector<U> {
    fn from(other: &'a FieldVector<T>) -> Self {
        FieldVector(other.clone().into_iter().map(Into::into).collect())
    }
}

impl<F: ScalarField> From<FieldVector<ProperCrtUint<F>>> for FieldVector<CRTInteger<F>> {
    fn from(other: FieldVector<ProperCrtUint<F>>) -> Self {
        FieldVector(other.into_iter().map(|x| x.0).collect())
    }
}

impl<T, Fp> From<FieldVector<Reduced<T, Fp>>> for FieldVector<T> {
    fn from(value: FieldVector<Reduced<T, Fp>>) -> Self {
        FieldVector(value.0.into_iter().map(|x| x.0).collect())
    }
}

impl<T> IntoIterator for FieldVector<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Contains common functionality for vector operations that can be derived from those of the underlying `FpChip`
#[derive(Clone, Copy, Debug)]
pub struct FieldVectorChip<'fp, F: BigPrimeField, FpChip: FieldChip<F>> {
    pub fp_chip: &'fp FpChip,
    _f: PhantomData<F>,
}

impl<'fp, F, FpChip> FieldVectorChip<'fp, F, FpChip>
where
    F: BigPrimeField,
    FpChip: PrimeFieldChip<F>,
    FpChip::FieldType: BigPrimeField,
{
    pub fn new(fp_chip: &'fp FpChip) -> Self {
        Self { fp_chip, _f: PhantomData }
    }

    pub fn gate(&self) -> &impl GateInstructions<F> {
        self.fp_chip.gate()
    }

    pub fn fp_mul_no_carry<FP>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FP>,
        fp_point: impl Into<FpChip::UnsafeFieldPoint>,
    ) -> FieldVector<FpChip::UnsafeFieldPoint>
    where
        FP: Into<FpChip::UnsafeFieldPoint>,
    {
        let fp_point = fp_point.into();
        FieldVector(
            a.into_iter().map(|a| self.fp_chip.mul_no_carry(ctx, a, fp_point.clone())).collect(),
        )
    }

    pub fn select<FP>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FP>,
        b: impl IntoIterator<Item = FP>,
        sel: AssignedValue<F>,
    ) -> FieldVector<FP>
    where
        FpChip: Selectable<F, FP>,
    {
        FieldVector(
            a.into_iter().zip_eq(b).map(|(a, b)| self.fp_chip.select(ctx, a, b, sel)).collect(),
        )
    }

    pub fn load_private<FieldExt, const DEGREE: usize>(
        &self,
        ctx: &mut Context<F>,
        fe: FieldExt,
    ) -> FieldVector<FpChip::FieldPoint>
    where
        FieldExt: FieldExtConstructor<FpChip::FieldType, DEGREE>,
    {
        FieldVector(fe.coeffs().into_iter().map(|a| self.fp_chip.load_private(ctx, a)).collect())
    }

    pub fn load_constant<FieldExt, const DEGREE: usize>(
        &self,
        ctx: &mut Context<F>,
        c: FieldExt,
    ) -> FieldVector<FpChip::FieldPoint>
    where
        FieldExt: FieldExtConstructor<FpChip::FieldType, DEGREE>,
    {
        FieldVector(c.coeffs().into_iter().map(|a| self.fp_chip.load_constant(ctx, a)).collect())
    }

    // signed overflow BigInt functions
    pub fn add_no_carry<A, B>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = A>,
        b: impl IntoIterator<Item = B>,
    ) -> FieldVector<FpChip::UnsafeFieldPoint>
    where
        A: Into<FpChip::UnsafeFieldPoint>,
        B: Into<FpChip::UnsafeFieldPoint>,
    {
        FieldVector(
            a.into_iter().zip_eq(b).map(|(a, b)| self.fp_chip.add_no_carry(ctx, a, b)).collect(),
        )
    }

    pub fn add_constant_no_carry<A, FieldExt, const DEGREE: usize>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = A>,
        c: FieldExt,
    ) -> FieldVector<FpChip::UnsafeFieldPoint>
    where
        A: Into<FpChip::UnsafeFieldPoint>,
        FieldExt: FieldExtConstructor<FpChip::FieldType, DEGREE>,
    {
        let c_coeffs = c.coeffs();
        FieldVector(
            a.into_iter()
                .zip_eq(c_coeffs)
                .map(|(a, c)| self.fp_chip.add_constant_no_carry(ctx, a, c))
                .collect(),
        )
    }

    pub fn sub_no_carry<A, B>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = A>,
        b: impl IntoIterator<Item = B>,
    ) -> FieldVector<FpChip::UnsafeFieldPoint>
    where
        A: Into<FpChip::UnsafeFieldPoint>,
        B: Into<FpChip::UnsafeFieldPoint>,
    {
        FieldVector(
            a.into_iter().zip_eq(b).map(|(a, b)| self.fp_chip.sub_no_carry(ctx, a, b)).collect(),
        )
    }

    pub fn negate(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::FieldPoint>,
    ) -> FieldVector<FpChip::FieldPoint> {
        FieldVector(a.into_iter().map(|a| self.fp_chip.negate(ctx, a)).collect())
    }

    pub fn scalar_mul_no_carry<A>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = A>,
        c: i64,
    ) -> FieldVector<FpChip::UnsafeFieldPoint>
    where
        A: Into<FpChip::UnsafeFieldPoint>,
    {
        FieldVector(a.into_iter().map(|a| self.fp_chip.scalar_mul_no_carry(ctx, a, c)).collect())
    }

    pub fn scalar_mul_and_add_no_carry<A, B>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = A>,
        b: impl IntoIterator<Item = B>,
        c: i64,
    ) -> FieldVector<FpChip::UnsafeFieldPoint>
    where
        A: Into<FpChip::UnsafeFieldPoint>,
        B: Into<FpChip::UnsafeFieldPoint>,
    {
        FieldVector(
            a.into_iter()
                .zip_eq(b)
                .map(|(a, b)| self.fp_chip.scalar_mul_and_add_no_carry(ctx, a, b, c))
                .collect(),
        )
    }

    pub fn check_carry_mod_to_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::UnsafeFieldPoint>,
    ) {
        for coeff in a {
            self.fp_chip.check_carry_mod_to_zero(ctx, coeff);
        }
    }

    pub fn carry_mod(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::UnsafeFieldPoint>,
    ) -> FieldVector<FpChip::FieldPoint> {
        FieldVector(a.into_iter().map(|coeff| self.fp_chip.carry_mod(ctx, coeff)).collect())
    }

    pub fn range_check<A>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = A>,
        max_bits: usize,
    ) where
        A: Into<FpChip::UnsafeFieldPoint>,
    {
        for coeff in a {
            self.fp_chip.range_check(ctx, coeff, max_bits);
        }
    }

    pub fn enforce_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::FieldPoint>,
    ) -> FieldVector<FpChip::ReducedFieldPoint> {
        FieldVector(a.into_iter().map(|coeff| self.fp_chip.enforce_less_than(ctx, coeff)).collect())
    }

    pub fn is_soft_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::FieldPoint>,
    ) -> AssignedValue<F> {
        let mut prev = None;
        for a_coeff in a {
            let coeff = self.fp_chip.is_soft_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.gate().and(ctx, coeff, p);
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    pub fn is_soft_nonzero(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::FieldPoint>,
    ) -> AssignedValue<F> {
        let mut prev = None;
        for a_coeff in a {
            let coeff = self.fp_chip.is_soft_nonzero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.gate().or(ctx, coeff, p);
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    pub fn is_zero(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::FieldPoint>,
    ) -> AssignedValue<F> {
        let mut prev = None;
        for a_coeff in a {
            let coeff = self.fp_chip.is_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self.gate().and(ctx, coeff, p);
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    pub fn is_equal_unenforced(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::ReducedFieldPoint>,
        b: impl IntoIterator<Item = FpChip::ReducedFieldPoint>,
    ) -> AssignedValue<F> {
        let mut acc = None;
        for (a_coeff, b_coeff) in a.into_iter().zip_eq(b) {
            let coeff = self.fp_chip.is_equal_unenforced(ctx, a_coeff, b_coeff);
            if let Some(c) = acc {
                acc = Some(self.gate().and(ctx, coeff, c));
            } else {
                acc = Some(coeff);
            }
        }
        acc.unwrap()
    }

    pub fn assert_equal(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = FpChip::FieldPoint>,
        b: impl IntoIterator<Item = FpChip::FieldPoint>,
    ) {
        for (a_coeff, b_coeff) in a.into_iter().zip(b) {
            self.fp_chip.assert_equal(ctx, a_coeff, b_coeff)
        }
    }

    pub fn select_by_indicator<FP: Clone>(
        &self,
        ctx: &mut Context<F>,
        v: &impl AsRef<[FieldVector<FP>]>,
        coeffs: &[AssignedValue<F>],
    ) -> FieldVector<FP>
    where
        FpChip: Selectable<F, FP>,
    {
        let v = v.as_ref().to_vec();
        let len = v[0].0.len();
        let mut iters = v.into_iter().map(|n| n.into_iter()).collect_vec();
        let v_transpoed = (0..len)
            .map(|_| {
                iters
                    .iter_mut()
                    .map(|n| n.next().unwrap())
                    .collect_vec()
            });


        FieldVector(
            v_transpoed.map(|x| self.fp_chip.select_by_indicator(ctx, &x, coeffs)).collect(),
        )
    }
}

#[macro_export]
macro_rules! impl_field_ext_chip_common {
    // Implementation of the functions in `FieldChip` trait for field extensions that can be derived from `FieldVectorChip`
    () => {
        fn native_modulus(&self) -> &BigUint {
            self.0.fp_chip.native_modulus()
        }

        fn range(&self) -> &Self::RangeChip {
            self.0.fp_chip.range()
        }

        fn limb_bits(&self) -> usize {
            self.0.fp_chip.limb_bits()
        }

        fn load_private(&self, ctx: &mut Context<F>, fe: Self::FieldType) -> Self::FieldPoint {
            self.0.load_private(ctx, fe)
        }

        fn load_constant(&self, ctx: &mut Context<F>, fe: Self::FieldType) -> Self::FieldPoint {
            self.0.load_constant(ctx, fe)
        }

        fn add_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
        ) -> Self::UnsafeFieldPoint {
            self.0.add_no_carry(ctx, a.into(), b.into())
        }

        fn add_constant_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            c: Self::FieldType,
        ) -> Self::UnsafeFieldPoint {
            self.0.add_constant_no_carry(ctx, a.into(), c)
        }

        fn sub_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
        ) -> Self::UnsafeFieldPoint {
            self.0.sub_no_carry(ctx, a.into(), b.into())
        }

        fn negate(&self, ctx: &mut Context<F>, a: Self::FieldPoint) -> Self::FieldPoint {
            self.0.negate(ctx, a)
        }

        fn scalar_mul_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            c: i64,
        ) -> Self::UnsafeFieldPoint {
            self.0.scalar_mul_no_carry(ctx, a.into(), c)
        }

        fn scalar_mul_and_add_no_carry(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            b: impl Into<Self::UnsafeFieldPoint>,
            c: i64,
        ) -> Self::UnsafeFieldPoint {
            self.0.scalar_mul_and_add_no_carry(ctx, a.into(), b.into(), c)
        }

        fn check_carry_mod_to_zero(&self, ctx: &mut Context<F>, a: Self::UnsafeFieldPoint) {
            self.0.check_carry_mod_to_zero(ctx, a);
        }

        fn carry_mod(&self, ctx: &mut Context<F>, a: Self::UnsafeFieldPoint) -> Self::FieldPoint {
            self.0.carry_mod(ctx, a)
        }

        fn range_check(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::UnsafeFieldPoint>,
            max_bits: usize,
        ) {
            self.0.range_check(ctx, a.into(), max_bits)
        }

        fn enforce_less_than(
            &self,
            ctx: &mut Context<F>,
            a: Self::FieldPoint,
        ) -> Self::ReducedFieldPoint {
            self.0.enforce_less_than(ctx, a)
        }

        fn is_soft_zero(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
        ) -> AssignedValue<F> {
            let a = a.into();
            self.0.is_soft_zero(ctx, a)
        }

        fn is_soft_nonzero(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
        ) -> AssignedValue<F> {
            let a = a.into();
            self.0.is_soft_nonzero(ctx, a)
        }

        fn is_zero(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
        ) -> AssignedValue<F> {
            let a = a.into();
            self.0.is_zero(ctx, a)
        }

        fn is_equal_unenforced(
            &self,
            ctx: &mut Context<F>,
            a: Self::ReducedFieldPoint,
            b: Self::ReducedFieldPoint,
        ) -> AssignedValue<F> {
            self.0.is_equal_unenforced(ctx, a, b)
        }

        fn assert_equal(
            &self,
            ctx: &mut Context<F>,
            a: impl Into<Self::FieldPoint>,
            b: impl Into<Self::FieldPoint>,
        ) {
            let a = a.into();
            let b = b.into();
            self.0.assert_equal(ctx, a, b)
        }
    };
}
