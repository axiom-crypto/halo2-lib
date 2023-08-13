use std::marker::PhantomData;

use ff::PrimeField as _;
use halo2_base::{utils::modulus, AssignedValue, Context};
use num_bigint::BigUint;

use crate::impl_field_ext_chip_common;

use super::{
    vector::{FieldVector, FieldVectorChip},
    FieldChip, FieldExtConstructor, PrimeField, PrimeFieldChip,
};

/// Represent Fp12 point as FqPoint with degree = 12
/// `Fp12 = Fp2[w] / (w^6 - u - xi)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to
/// be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp12 point as `\sum_{i = 0}^6 (a_{i0} + a_{i1} * u) * w^i`
/// This is encoded in an FqPoint of degree 12 as `(a_{00}, ..., a_{50}, a_{01}, ..., a_{51})`
#[derive(Clone, Copy, Debug)]
pub struct Fp12Chip<'a, F: PrimeField, FpChip: FieldChip<F>, Fp12, const XI_0: i64>(
    pub FieldVectorChip<'a, F, FpChip>,
    PhantomData<Fp12>,
);

impl<'a, F, FpChip, Fp12, const XI_0: i64> Fp12Chip<'a, F, FpChip, Fp12, XI_0>
where
    F: PrimeField,
    FpChip: PrimeFieldChip<F>,
    FpChip::FieldType: PrimeField,
    Fp12: ff::Field,
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

    pub fn fp2_mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        fp12_pt: FieldVector<FpChip::UnsafeFieldPoint>,
        fp2_pt: FieldVector<FpChip::UnsafeFieldPoint>,
    ) -> FieldVector<FpChip::UnsafeFieldPoint> {
        let fp12_pt = fp12_pt.0;
        let fp2_pt = fp2_pt.0;
        assert_eq!(fp12_pt.len(), 12);
        assert_eq!(fp2_pt.len(), 2);

        let fp_chip = self.fp_chip();
        let mut out_coeffs = Vec::with_capacity(12);
        for i in 0..6 {
            let coeff1 = fp_chip.mul_no_carry(ctx, fp12_pt[i].clone(), fp2_pt[0].clone());
            let coeff2 = fp_chip.mul_no_carry(ctx, fp12_pt[i + 6].clone(), fp2_pt[1].clone());
            let coeff = fp_chip.sub_no_carry(ctx, coeff1, coeff2);
            out_coeffs.push(coeff);
        }
        for i in 0..6 {
            let coeff1 = fp_chip.mul_no_carry(ctx, fp12_pt[i + 6].clone(), fp2_pt[0].clone());
            let coeff2 = fp_chip.mul_no_carry(ctx, fp12_pt[i].clone(), fp2_pt[1].clone());
            let coeff = fp_chip.add_no_carry(ctx, coeff1, coeff2);
            out_coeffs.push(coeff);
        }
        FieldVector(out_coeffs)
    }

    // for \sum_i (a_i + b_i u) w^i, returns \sum_i (-1)^i (a_i + b_i u) w^i
    pub fn conjugate(
        &self,
        ctx: &mut Context<F>,
        a: FieldVector<FpChip::FieldPoint>,
    ) -> FieldVector<FpChip::FieldPoint> {
        let a = a.0;
        assert_eq!(a.len(), 12);

        let coeffs = a
            .into_iter()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c } else { self.fp_chip().negate(ctx, c) })
            .collect();
        FieldVector(coeffs)
    }
}

/// multiply Fp2 elts: (a0 + a1 * u) * (XI0 + u) without carry
///
/// # Assumptions
/// * `a` is `Fp2` point represented as `FieldVector` with degree = 2
pub fn mul_no_carry_w6<F: PrimeField, FC: FieldChip<F>, const XI_0: i64>(
    fp_chip: &FC,
    ctx: &mut Context<F>,
    a: FieldVector<FC::UnsafeFieldPoint>,
) -> FieldVector<FC::UnsafeFieldPoint> {
    let [a0, a1]: [_; 2] = a.0.try_into().unwrap();
    // (a0 + a1 u) * (XI_0 + u) = (a0 * XI_0 - a1) + (a1 * XI_0 + a0) u     with u^2 = -1
    // This should fit in the overflow representation if limb_bits is large enough
    let a0_xi0 = fp_chip.scalar_mul_no_carry(ctx, a0.clone(), XI_0);
    let out0_0_nocarry = fp_chip.sub_no_carry(ctx, a0_xi0, a1.clone());
    let out0_1_nocarry = fp_chip.scalar_mul_and_add_no_carry(ctx, a1, a0, XI_0);
    FieldVector(vec![out0_0_nocarry, out0_1_nocarry])
}

// a lot of this is common to any field extension (lots of for loops), but due to the way rust traits work, it is hard to create a common generic trait that does this. The main problem is that if you had a `FieldExtCommon` trait and wanted to implement `FieldChip` for anything with `FieldExtCommon`, rust will stop you because someone could implement `FieldExtCommon` and `FieldChip` for the same type, causing a conflict.
// partially solved using macro

impl<'a, F, FpChip, Fp12, const XI_0: i64> FieldChip<F> for Fp12Chip<'a, F, FpChip, Fp12, XI_0>
where
    F: PrimeField,
    FpChip: PrimeFieldChip<F>,
    FpChip::FieldType: PrimeField,
    Fp12: ff::Field + FieldExtConstructor<FpChip::FieldType, 12>,
    FieldVector<FpChip::UnsafeFieldPoint>: From<FieldVector<FpChip::FieldPoint>>,
    FieldVector<FpChip::FieldPoint>: From<FieldVector<FpChip::ReducedFieldPoint>>,
{
    const PRIME_FIELD_NUM_BITS: u32 = FpChip::FieldType::NUM_BITS;
    type UnsafeFieldPoint = FieldVector<FpChip::UnsafeFieldPoint>;
    type FieldPoint = FieldVector<FpChip::FieldPoint>;
    type ReducedFieldPoint = FieldVector<FpChip::ReducedFieldPoint>;
    type FieldType = Fp12;
    type RangeChip = FpChip::RangeChip;

    fn get_assigned_value(&self, x: &Self::UnsafeFieldPoint) -> Fp12 {
        assert_eq!(x.0.len(), 12);
        let values = x.0.iter().map(|v| self.fp_chip().get_assigned_value(v)).collect::<Vec<_>>();
        Fp12::new(values.try_into().unwrap())
    }

    // w^6 = u + xi for xi = 9
    fn mul_no_carry(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<Self::UnsafeFieldPoint>,
        b: impl Into<Self::UnsafeFieldPoint>,
    ) -> Self::UnsafeFieldPoint {
        let a = a.into().0;
        let b = b.into().0;
        assert_eq!(a.len(), 12);
        assert_eq!(b.len(), 12);

        let fp_chip = self.fp_chip();
        // a = \sum_{i = 0}^5 (a_i * w^i + a_{i + 6} * w^i * u)
        // b = \sum_{i = 0}^5 (b_i * w^i + b_{i + 6} * w^i * u)
        let mut a0b0_coeffs: Vec<FpChip::UnsafeFieldPoint> = Vec::with_capacity(11);
        let mut a0b1_coeffs: Vec<FpChip::UnsafeFieldPoint> = Vec::with_capacity(11);
        let mut a1b0_coeffs: Vec<FpChip::UnsafeFieldPoint> = Vec::with_capacity(11);
        let mut a1b1_coeffs: Vec<FpChip::UnsafeFieldPoint> = Vec::with_capacity(11);
        for i in 0..6 {
            for j in 0..6 {
                let coeff00 = fp_chip.mul_no_carry(ctx, &a[i], &b[j]);
                let coeff01 = fp_chip.mul_no_carry(ctx, &a[i], &b[j + 6]);
                let coeff10 = fp_chip.mul_no_carry(ctx, &a[i + 6], &b[j]);
                let coeff11 = fp_chip.mul_no_carry(ctx, &a[i + 6], &b[j + 6]);
                if i + j < a0b0_coeffs.len() {
                    a0b0_coeffs[i + j] = fp_chip.add_no_carry(ctx, &a0b0_coeffs[i + j], coeff00);
                    a0b1_coeffs[i + j] = fp_chip.add_no_carry(ctx, &a0b1_coeffs[i + j], coeff01);
                    a1b0_coeffs[i + j] = fp_chip.add_no_carry(ctx, &a1b0_coeffs[i + j], coeff10);
                    a1b1_coeffs[i + j] = fp_chip.add_no_carry(ctx, &a1b1_coeffs[i + j], coeff11);
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
            let a0b0_minus_a1b1_entry = fp_chip.sub_no_carry(ctx, &a0b0_coeffs[i], &a1b1_coeffs[i]);
            let a0b1_plus_a1b0_entry = fp_chip.add_no_carry(ctx, &a0b1_coeffs[i], &a1b0_coeffs[i]);

            a0b0_minus_a1b1.push(a0b0_minus_a1b1_entry);
            a0b1_plus_a1b0.push(a0b1_plus_a1b0_entry);
        }

        // out_i       = a0b0_minus_a1b1_i + XI_0 * a0b0_minus_a1b1_{i + 6} - a0b1_plus_a1b0_{i + 6}
        // out_{i + 6} = a0b1_plus_a1b0_{i} + a0b0_minus_a1b1_{i + 6} + XI_0 * a0b1_plus_a1b0_{i + 6}
        let mut out_coeffs = Vec::with_capacity(12);
        for i in 0..6 {
            if i < 5 {
                let mut coeff = fp_chip.scalar_mul_and_add_no_carry(
                    ctx,
                    &a0b0_minus_a1b1[i + 6],
                    &a0b0_minus_a1b1[i],
                    XI_0,
                );
                coeff = fp_chip.sub_no_carry(ctx, coeff, &a0b1_plus_a1b0[i + 6]);
                out_coeffs.push(coeff);
            } else {
                out_coeffs.push(a0b0_minus_a1b1[i].clone());
            }
        }
        for i in 0..6 {
            if i < 5 {
                let mut coeff =
                    fp_chip.add_no_carry(ctx, &a0b1_plus_a1b0[i], &a0b0_minus_a1b1[i + 6]);
                coeff =
                    fp_chip.scalar_mul_and_add_no_carry(ctx, &a0b1_plus_a1b0[i + 6], coeff, XI_0);
                out_coeffs.push(coeff);
            } else {
                out_coeffs.push(a0b1_plus_a1b0[i].clone());
            }
        }
        FieldVector(out_coeffs)
    }

    impl_field_ext_chip_common!();
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
