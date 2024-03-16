use std::fmt::Debug;
use std::marker::PhantomData;

use crate::bigint::ProperCrtUint;
#[cfg(feature = "halo2-axiom")]
use crate::ff::PrimeField as _;
use crate::impl_field_ext_chip_common;

use super::FieldChipExt;
use super::{
    vector::{FieldVector, FieldVectorChip},
    BigPrimeField, FieldChip, FieldExtConstructor, PrimeFieldChip,
};
use halo2_base::gates::GateInstructions;
use halo2_base::{utils::modulus, AssignedValue, Context};
use num_bigint::BigUint;

/// Represent Fp2 point as `FieldVector` with degree = 2
/// `Fp2 = Fp[u] / (u^2 + 1)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp2 point as `a_0 + a_1 * u` where `a_0, a_1 in Fp`
#[derive(Clone, Copy, Debug)]
pub struct Fp2Chip<'a, F: BigPrimeField, FpChip: FieldChip<F>, Fp2>(
    pub FieldVectorChip<'a, F, FpChip>,
    PhantomData<Fp2>,
);

impl<'a, F: BigPrimeField, FpChip: PrimeFieldChip<F>, Fp2: crate::ff::Field>
    Fp2Chip<'a, F, FpChip, Fp2>
where
    FpChip::FieldType: BigPrimeField,
{
    /// User must construct an `FpChip` first using a config. This is intended so everything shares a single `FlexGateChip`, which is needed for the column allocation to work.
    pub fn new(fp_chip: &'a FpChip) -> Self {
        assert_eq!(
            modulus::<FpChip::FieldType>() % 4usize,
            BigUint::from(3u64),
            "p must be 3 (mod 4) for the polynomial u^2 + 1 to be irreducible"
        );
        Self(FieldVectorChip::new(fp_chip), PhantomData)
    }

    pub fn fp_chip(&self) -> &FpChip {
        self.0.fp_chip
    }

    pub fn neg_conjugate(
        &self,
        ctx: &mut Context<F>,
        a: FieldVector<FpChip::FieldPoint>,
    ) -> FieldVector<FpChip::FieldPoint> {
        assert_eq!(a.0.len(), 2);
        let mut a = a.0.into_iter();

        let neg_a0 = self.fp_chip().negate(ctx, a.next().unwrap());
        FieldVector(vec![neg_a0, a.next().unwrap()])
    }
}

impl<'a, F, FpChip, Fp2> FieldChip<F> for Fp2Chip<'a, F, FpChip, Fp2>
where
    F: BigPrimeField,
    FpChip::FieldType: BigPrimeField,
    FpChip: PrimeFieldChip<F>,
    Fp2: crate::ff::Field + FieldExtConstructor<FpChip::FieldType, 2>,
    FieldVector<FpChip::UnsafeFieldPoint>: From<FieldVector<FpChip::FieldPoint>>,
    FieldVector<FpChip::FieldPoint>: From<FieldVector<FpChip::ReducedFieldPoint>>,
{
    const PRIME_FIELD_NUM_BITS: u32 = FpChip::FieldType::NUM_BITS;
    type UnsafeFieldPoint = FieldVector<FpChip::UnsafeFieldPoint>;
    type FieldPoint = FieldVector<FpChip::FieldPoint>;
    type ReducedFieldPoint = FieldVector<FpChip::ReducedFieldPoint>;
    type FieldType = Fp2;
    type RangeChip = FpChip::RangeChip;

    fn get_assigned_value(&self, x: &Self::UnsafeFieldPoint) -> Fp2 {
        assert_eq!(x.0.len(), 2);
        let c0 = self.fp_chip().get_assigned_value(&x[0]);
        let c1 = self.fp_chip().get_assigned_value(&x[1]);
        Fp2::new([c0, c1])
    }

    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::UnsafeFieldPoint {
        let a = a.into().0;
        let b = b.into().0;
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
        let fp_chip = self.fp_chip();
        // (a_0 + a_1 * u) * (b_0 + b_1 * u) = (a_0 b_0 - a_1 b_1) + (a_0 b_1 + a_1 b_0) * u
        let mut ab_coeffs = Vec::with_capacity(4);
        for a_i in a {
            for b_j in b.iter() {
                let coeff = fp_chip.mul_no_carry(ctx, &a_i, b_j);
                ab_coeffs.push(coeff);
            }
        }
        let a0b0_minus_a1b1 = fp_chip.sub_no_carry(ctx, &ab_coeffs[0], &ab_coeffs[3]);
        let a0b1_plus_a1b0 = fp_chip.add_no_carry(ctx, &ab_coeffs[1], &ab_coeffs[2]);

        FieldVector(vec![a0b0_minus_a1b1, a0b1_plus_a1b0])
    }

    // ========= inherited from FieldVectorChip =========
    impl_field_ext_chip_common!();
}

impl<'a, F, FpChip, Fp2> FieldChipExt<F> for Fp2Chip<'a, F, FpChip, Fp2>
where
    F: BigPrimeField,
    FpChip: FieldChipExt<F>,
    FpChip::FieldType: BigPrimeField,
    FpChip: PrimeFieldChip<F>,
    Fp2: crate::ff::Field + FieldExtConstructor<FpChip::FieldType, 2>,
    FieldVector<FpChip::UnsafeFieldPoint>: From<FieldVector<FpChip::FieldPoint>>,
    FieldVector<FpChip::FieldPoint>: From<FieldVector<FpChip::ReducedFieldPoint>>,
{
    fn conjugate(&self, ctx: &mut Context<F>, a: impl Into<Self::FieldPoint>) -> Self::FieldPoint {
        let a: Self::FieldPoint = a.into();
        let mut a = a.0;
        assert_eq!(a.len(), 2);

        let neg_a1 = self.fp_chip().negate(ctx, a.pop().unwrap());
        FieldVector(vec![a.pop().unwrap(), neg_a1])
    }

    fn sgn0(&self, ctx: &mut Context<F>, a: impl Into<Self::FieldPoint>) -> AssignedValue<F> {
        let x: Self::FieldPoint = a.into();
        let gate = self.gate();

        let c0 = x.0[0].clone();
        let c1 = x.0[1].clone();

        let c0_zero = self.fp_chip().is_zero(ctx, &c0);
        let c0_sgn = self.fp_chip().sgn0(ctx, c0);
        let c1_sgn = self.fp_chip().sgn0(ctx, c1);
        let sgn = gate.select(ctx, c1_sgn, c0_sgn, c0_zero);
        gate.assert_bit(ctx, sgn);
        sgn
    }
}

impl<'range, F: BigPrimeField, FC: PrimeFieldChip<F>, Fp>
    super::Selectable<F, FieldVector<ProperCrtUint<F>>> for Fp2Chip<'range, F, FC, Fp>
where
    FC: super::Selectable<F, ProperCrtUint<F>>,
    <FC as FieldChip<F>>::FieldType: BigPrimeField,
{
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: FieldVector<ProperCrtUint<F>>,
        b: FieldVector<ProperCrtUint<F>>,
        sel: AssignedValue<F>,
    ) -> FieldVector<ProperCrtUint<F>> {
        self.0.select(ctx, a, b, sel)
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[FieldVector<ProperCrtUint<F>>]>,
        coeffs: &[AssignedValue<F>],
    ) -> FieldVector<ProperCrtUint<F>> {
        self.0.select_by_indicator(ctx, a, coeffs)
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

mod bls12_381 {
    use crate::fields::FieldExtConstructor;
    #[cfg(feature = "halo2-axiom")]
    use crate::halo2_proofs::halo2curves::bls12_381::{Fq, Fq2};
    #[cfg(feature = "halo2-pse")]
    use halo2curves::bls12_381::{Fq, Fq2};

    impl FieldExtConstructor<Fq, 2> for Fq2 {
        fn new(c: [Fq; 2]) -> Self {
            Fq2 { c0: c[0], c1: c[1] }
        }

        fn coeffs(&self) -> Vec<Fq> {
            vec![self.c0, self.c1]
        }
    }
}
