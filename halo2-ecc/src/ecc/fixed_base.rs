#![allow(non_snake_case)]
use super::{ec_add_unequal, ec_select, ec_select_from_bits, EcPoint, EccChip};
use crate::halo2_proofs::arithmetic::CurveAffine;
use crate::{
    bigint::{CRTInteger, FixedCRTInteger},
    fields::{PrimeFieldChip, Selectable},
};
use group::Curve;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{fe_to_biguint, CurveAffineExt, PrimeField},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use itertools::Itertools;
use num_bigint::BigUint;
use std::{cmp::min, marker::PhantomData};

// this only works for curves GA with base field of prime order
#[derive(Clone, Debug)]
pub struct FixedEcPoint<F: PrimeField, C: CurveAffine> {
    pub x: FixedCRTInteger<F>, // limbs in `F` and value in `BigUint`
    pub y: FixedCRTInteger<F>,
    _marker: PhantomData<C>,
}

impl<F: PrimeField, C: CurveAffineExt> FixedEcPoint<F, C>
where
    C::Base: PrimeField,
{
    pub fn construct(x: FixedCRTInteger<F>, y: FixedCRTInteger<F>) -> Self {
        Self { x, y, _marker: PhantomData }
    }

    pub fn from_curve(point: C, num_limbs: usize, limb_bits: usize) -> Self {
        let (x, y) = point.into_coordinates();
        let x = FixedCRTInteger::from_native(fe_to_biguint(&x), num_limbs, limb_bits);
        let y = FixedCRTInteger::from_native(fe_to_biguint(&y), num_limbs, limb_bits);
        Self::construct(x, y)
    }

    pub fn assign<'v, FC>(
        self,
        chip: &FC,
        ctx: &mut Context<'_, F>,
        native_modulus: &BigUint,
    ) -> EcPoint<F, FC::FieldPoint<'v>>
    where
        FC: PrimeFieldChip<F, FieldType = C::Base, FieldPoint<'v> = CRTInteger<'v, F>>,
    {
        let assigned_x = self.x.assign(chip.range().gate(), ctx, chip.limb_bits(), native_modulus);
        let assigned_y = self.y.assign(chip.range().gate(), ctx, chip.limb_bits(), native_modulus);
        EcPoint::construct(assigned_x, assigned_y)
    }

    pub fn assign_without_caching<'v, FC>(
        self,
        chip: &FC,
        ctx: &mut Context<'_, F>,
        native_modulus: &BigUint,
    ) -> EcPoint<F, FC::FieldPoint<'v>>
    where
        FC: PrimeFieldChip<F, FieldType = C::Base, FieldPoint<'v> = CRTInteger<'v, F>>,
    {
        let assigned_x = self.x.assign_without_caching(
            chip.range().gate(),
            ctx,
            chip.limb_bits(),
            native_modulus,
        );
        let assigned_y = self.y.assign_without_caching(
            chip.range().gate(),
            ctx,
            chip.limb_bits(),
            native_modulus,
        );
        EcPoint::construct(assigned_x, assigned_y)
    }
}

// computes `[scalar] * P` on y^2 = x^3 + b where `P` is fixed (constant)
// - `scalar` is represented as a reference array of `AssignedCell`s
// - `scalar = sum_i scalar_i * 2^{max_bits * i}`
// - an array of length > 1 is needed when `scalar` exceeds the modulus of scalar field `F`
// assumes:
// - `scalar_i < 2^{max_bits} for all i` (constrained by num_to_bits)
// - `max_bits <= modulus::<F>.bits()`

pub fn scalar_multiply<'v, F, FC, C>(
    chip: &FC,
    ctx: &mut Context<'v, F>,
    point: &C,
    scalar: &[AssignedValue<'v, F>],
    max_bits: usize,
    window_bits: usize,
) -> EcPoint<F, FC::FieldPoint<'v>>
where
    F: PrimeField,
    C: CurveAffineExt,
    C::Base: PrimeField,
    FC: PrimeFieldChip<F, FieldType = C::Base, FieldPoint<'v> = CRTInteger<'v, F>>
        + Selectable<F, Point<'v> = FC::FieldPoint<'v>>,
{
    if point.is_identity().into() {
        let point = FixedEcPoint::from_curve(*point, chip.num_limbs(), chip.limb_bits());
        return FixedEcPoint::assign(point, chip, ctx, chip.native_modulus());
    }
    assert!(!scalar.is_empty());
    assert!((max_bits as u32) <= F::NUM_BITS);

    let total_bits = max_bits * scalar.len();
    let num_windows = (total_bits + window_bits - 1) / window_bits;

    // Jacobian coordinate
    let base_pt = point.to_curve();
    // cached_points[i * 2^w + j] holds `[j * 2^(i * w)] * point` for j in {0, ..., 2^w - 1}

    // first we compute all cached points in Jacobian coordinates since it's fastest
    let mut increment = base_pt;
    let cached_points_jacobian = (0..num_windows)
        .flat_map(|i| {
            let mut curr = increment;
            // start with increment at index 0 instead of identity just as a dummy value to avoid divide by 0 issues
            let cache_vec = std::iter::once(increment)
                .chain((1..(1usize << min(window_bits, total_bits - i * window_bits))).map(|_| {
                    let prev = curr;
                    curr += increment;
                    prev
                }))
                .collect::<Vec<_>>();
            increment = curr;
            cache_vec
        })
        .collect::<Vec<_>>();
    // for use in circuits we need affine coordinates, so we do a batch normalize: this is much more efficient than calling `to_affine` one by one since field inversion is very expensive
    // initialize to all 0s
    let mut cached_points_affine = vec![C::default(); cached_points_jacobian.len()];
    C::Curve::batch_normalize(&cached_points_jacobian, &mut cached_points_affine);

    // TODO: do not assign and use select_from_bits on Constant(_) QuantumCells
    let cached_points = cached_points_affine
        .into_iter()
        .map(|point| {
            let point = FixedEcPoint::from_curve(point, chip.num_limbs(), chip.limb_bits());
            FixedEcPoint::assign(point, chip, ctx, chip.native_modulus())
        })
        .collect_vec();

    let bits = scalar
        .iter()
        .flat_map(|scalar_chunk| chip.gate().num_to_bits(ctx, scalar_chunk, max_bits))
        .collect::<Vec<_>>();

    let cached_point_window_rev = cached_points.chunks(1usize << window_bits).rev();
    let bit_window_rev = bits.chunks(window_bits).rev();
    let mut curr_point = None;
    // `is_started` is just a way to deal with if `curr_point` is actually identity
    let mut is_started = chip.gate().load_zero(ctx);
    for (cached_point_window, bit_window) in cached_point_window_rev.zip(bit_window_rev) {
        let bit_sum = chip.gate().sum(ctx, bit_window.iter().map(Existing));
        // are we just adding a window of all 0s? if so, skip
        let is_zero_window = chip.gate().is_zero(ctx, &bit_sum);
        let add_point = ec_select_from_bits::<F, _>(chip, ctx, cached_point_window, bit_window);
        curr_point = if let Some(curr_point) = curr_point {
            let sum = ec_add_unequal(chip, ctx, &curr_point, &add_point, false);
            let zero_sum = ec_select(chip, ctx, &curr_point, &sum, &is_zero_window);
            Some(ec_select(chip, ctx, &zero_sum, &add_point, &is_started))
        } else {
            Some(add_point)
        };
        is_started = {
            // is_started || !is_zero_window
            // (a || !b) = (1-b) + a*b
            let not_zero_window = chip.gate().not(ctx, Existing(&is_zero_window));
            chip.gate().mul_add(
                ctx,
                Existing(&is_started),
                Existing(&is_zero_window),
                Existing(&not_zero_window),
            )
        };
    }
    curr_point.unwrap()
}

// basically just adding up individual fixed_base::scalar_multiply except that we do all batched normalization of cached points at once to further save inversion time during witness generation
// we also use the random accumulator for some extra efficiency (which also works in scalar multiply case but that is TODO)
pub fn msm<'v, F, FC, C>(
    chip: &EccChip<F, FC>,
    ctx: &mut Context<'v, F>,
    points: &[C],
    scalars: &[Vec<AssignedValue<'v, F>>],
    max_scalar_bits_per_cell: usize,
    window_bits: usize,
) -> EcPoint<F, FC::FieldPoint<'v>>
where
    F: PrimeField,
    C: CurveAffineExt,
    C::Base: PrimeField,
    FC: PrimeFieldChip<F, FieldType = C::Base, FieldPoint<'v> = CRTInteger<'v, F>>
        + Selectable<F, Point<'v> = FC::FieldPoint<'v>>,
{
    assert!((max_scalar_bits_per_cell as u32) <= F::NUM_BITS);
    let scalar_len = scalars[0].len();
    let total_bits = max_scalar_bits_per_cell * scalar_len;
    let num_windows = (total_bits + window_bits - 1) / window_bits;

    // `cached_points` is a flattened 2d vector
    // first we compute all cached points in Jacobian coordinates since it's fastest
    let cached_points_jacobian = points
        .iter()
        .flat_map(|point| {
            let base_pt = point.to_curve();
            // cached_points[idx][i * 2^w + j] holds `[j * 2^(i * w)] * points[idx]` for j in {0, ..., 2^w - 1}
            let mut increment = base_pt;
            (0..num_windows)
                .flat_map(|i| {
                    let mut curr = increment;
                    let cache_vec = std::iter::once(increment)
                        .chain((1..(1usize << min(window_bits, total_bits - i * window_bits))).map(
                            |_| {
                                let prev = curr;
                                curr += increment;
                                prev
                            },
                        ))
                        .collect_vec();
                    increment = curr;
                    cache_vec
                })
                .collect_vec()
        })
        .collect_vec();
    // for use in circuits we need affine coordinates, so we do a batch normalize: this is much more efficient than calling `to_affine` one by one since field inversion is very expensive
    // initialize to all 0s
    let mut cached_points_affine = vec![C::default(); cached_points_jacobian.len()];
    C::Curve::batch_normalize(&cached_points_jacobian, &mut cached_points_affine);

    let field_chip = chip.field_chip();
    let cached_points = cached_points_affine
        .into_iter()
        .map(|point| {
            let point =
                FixedEcPoint::from_curve(point, field_chip.num_limbs(), field_chip.limb_bits());
            point.assign_without_caching(field_chip, ctx, field_chip.native_modulus())
        })
        .collect_vec();

    let bits = scalars
        .iter()
        .flat_map(|scalar| {
            assert_eq!(scalar.len(), scalar_len);
            scalar
                .iter()
                .flat_map(|scalar_chunk| {
                    field_chip.gate().num_to_bits(ctx, scalar_chunk, max_scalar_bits_per_cell)
                })
                .collect_vec()
        })
        .collect_vec();

    let sm = cached_points
        .chunks(cached_points.len() / points.len())
        .zip(bits.chunks(total_bits))
        .map(|(cached_points, bits)| {
            let cached_point_window_rev =
                cached_points.chunks(1usize << window_bits).rev();
            let bit_window_rev = bits.chunks(window_bits).rev();
            let mut curr_point = None;
            // `is_started` is just a way to deal with if `curr_point` is actually identity
            let mut is_started = field_chip.gate().load_zero(ctx);
            for (cached_point_window, bit_window) in cached_point_window_rev.zip(bit_window_rev) {
                let is_zero_window = {
                    let sum = field_chip.gate().sum(ctx, bit_window.iter().map(Existing));
                    field_chip.gate().is_zero(ctx, &sum)
                };
                let add_point =
                    ec_select_from_bits::<F, _>(field_chip, ctx, cached_point_window, bit_window);
                curr_point = if let Some(curr_point) = curr_point {
                    let sum = ec_add_unequal(field_chip, ctx, &curr_point, &add_point, false);
                    let zero_sum = ec_select(field_chip, ctx, &curr_point, &sum, &is_zero_window);
                    Some(ec_select(field_chip, ctx, &zero_sum, &add_point, &is_started))
                } else {
                    Some(add_point)
                };
                is_started = {
                    // is_started || !is_zero_window
                    // (a || !b) = (1-b) + a*b
                    let not_zero_window =
                        field_chip.range().gate().not(ctx, Existing(&is_zero_window));
                    field_chip.range().gate().mul_add(
                        ctx,
                        Existing(&is_started),
                        Existing(&is_zero_window),
                        Existing(&not_zero_window),
                    )
                };
            }
            curr_point.unwrap()
        })
        .collect_vec();
    chip.sum::<C>(ctx, sm.iter())
}
