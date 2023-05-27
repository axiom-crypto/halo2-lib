use std::fmt::Debug;
use std::marker::PhantomData;

use halo2_base::{utils::modulus, AssignedValue, Context};
use num_bigint::BigUint;

use crate::impl_field_ext_chip_common;

use super::{
    vector::{FieldVector, FieldVectorChip},
    FieldChip, FieldExtConstructor, PrimeField, PrimeFieldChip,
};

use crate::fields::Selectable;
use crate::bigint::ProperCrtUint;
use crate::fields::fp::Reduced;
use crate::halo2_proofs::halo2curves::bn256::{Fq, Fq2};

/// Represent Fp2 point as `FieldVector` with degree = 2
/// `Fp2 = Fp[u] / (u^2 + 1)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp2 point as `a_0 + a_1 * u` where `a_0, a_1 in Fp`
#[derive(Clone, Copy, Debug)]
pub struct KZGChip<'a, F: PrimeField, FpChip: FieldChip<F>, Fp2> {
    range_chip: RangeChip<F>,
    pairing_chip: PairingChip<F, 'a>,
    g1_chip: EccChip<'chip, F: PrimeField, FC: FieldChip<F>,
    g2_chip: EccChip<'chip, F: PrimeField, FC: FieldChip<F>,
    fp_chip: Fp2Chip<'a, F>,
    fp2_chip: FpChip<'a, F>
};

pub type Fp2Chip<'chip, F> = fp2::Fp2Chip<'chip, F, FpChip<'chip, F>, Fq2>;
FpChip


impl<'a, F: PrimeField, FpChip: PrimeFieldChip<F>, Fp2: ff::Field> KZGChip<'a, F, FpChip, Fp2>
where
    FpChip::FieldType: PrimeField,
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

    pub fn conjugate(
        &self,
        ctx: &mut Context<F>,
        a: FieldVector<FpChip::FieldPoint>,
    ) -> FieldVector<FpChip::FieldPoint> {
        let mut a = a.0;
        assert_eq!(a.len(), 2);

        let neg_a1 = self.fp_chip().negate(ctx, a.pop().unwrap());
        FieldVector(vec![a.pop().unwrap(), neg_a1])
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
    F: PrimeField,
    FpChip::FieldType: PrimeField,
    FpChip: PrimeFieldChip<F>,
    Fp2: ff::Field + FieldExtConstructor<FpChip::FieldType, 2>,
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

impl<'fp, F: PrimeField, FpChip: FieldChip<F>, Fp2> Selectable<F, FieldVector<ProperCrtUint<F>>> for Fp2Chip<'fp, F, FpChip, Fp2>
    where FpChip: Selectable<F, ProperCrtUint<F>>
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

impl<'fp, F: PrimeField, FpChip: FieldChip<F>, Fp2: Clone> Selectable<F, FieldVector<Reduced<ProperCrtUint<F>, Fq>>> for Fp2Chip<'fp, F, FpChip, Fp2>
    where FpChip: Selectable<F, Reduced<ProperCrtUint<F>, Fq>>
{
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: FieldVector<Reduced<ProperCrtUint<F>, Fq>>,
        b: FieldVector<Reduced<ProperCrtUint<F>, Fq>>,
        sel: AssignedValue<F>,
    ) -> FieldVector<Reduced<ProperCrtUint<F>, Fq>> {
        (&self.0).select(ctx, a, b, sel)
    }

    fn select_by_indicator(
        &self,
        ctx: &mut Context<F>,
        a: &impl AsRef<[FieldVector<Reduced<ProperCrtUint<F>, Fq>>]>,
        coeffs: &[AssignedValue<F>],
    ) -> FieldVector<Reduced<ProperCrtUint<F>, Fq>> {
        (&self.0).select_by_indicator(ctx, a, coeffs)
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
