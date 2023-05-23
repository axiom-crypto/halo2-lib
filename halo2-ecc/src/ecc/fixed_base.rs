#![allow(non_snake_case)]
use super::{ec_add_unequal, ec_select, ec_select_from_bits, EcPoint, EccChip};
use crate::ecc::ec_sub_strict;
use crate::fields::{FieldChip, PrimeField, Selectable};
use group::Curve;
use halo2_base::gates::builder::{parallelize_in, GateThreadBuilder};
use halo2_base::{gates::GateInstructions, utils::CurveAffineExt, AssignedValue, Context};
use itertools::Itertools;
use rayon::prelude::*;
use std::cmp::min;

/// Computes `[scalar] * P` on y^2 = x^3 + b where `P` is fixed (constant)
/// - `scalar` is represented as a non-empty reference array of `AssignedValue`s
/// - `scalar = sum_i scalar_i * 2^{max_bits * i}`
/// - an array of length > 1 is needed when `scalar` exceeds the modulus of scalar field `F`
///
/// # Assumptions
/// - `scalar_i < 2^{max_bits} for all i` (constrained by num_to_bits)
/// - `scalar > 0`
/// - If `scalar_is_safe == true`, then we assume the integer `scalar` is in range [1, order of `P`)
/// - Even if `scalar_is_safe == false`, some constraints may still fail if `scalar` is not in range [1, order of `P`)
/// - `max_bits <= modulus::<F>.bits()`
pub fn scalar_multiply<F, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    point: &C,
    scalar: Vec<AssignedValue<F>>,
    max_bits: usize,
    window_bits: usize,
    scalar_is_safe: bool,
) -> EcPoint<F, FC::FieldPoint>
where
    F: PrimeField,
    C: CurveAffineExt,
    FC: FieldChip<F, FieldType = C::Base> + Selectable<F, FC::FieldPoint>,
{
    if point.is_identity().into() {
        let zero = chip.load_constant(ctx, C::Base::zero());
        return EcPoint::new(zero.clone(), zero);
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
            let (x, y) = point.into_coordinates();
            let [x, y] = [x, y].map(|x| chip.load_constant(ctx, x));
            EcPoint::new(x, y)
        })
        .collect_vec();

    let bits = scalar
        .into_iter()
        .flat_map(|scalar_chunk| chip.gate().num_to_bits(ctx, scalar_chunk, max_bits))
        .collect::<Vec<_>>();

    let cached_point_window_rev = cached_points.chunks(1usize << window_bits).rev();
    let bit_window_rev = bits.chunks(window_bits).rev();
    let mut curr_point = None;
    // `is_started` is just a way to deal with if `curr_point` is actually identity
    let mut is_started = ctx.load_zero();
    for (cached_point_window, bit_window) in cached_point_window_rev.zip(bit_window_rev) {
        let bit_sum = chip.gate().sum(ctx, bit_window.iter().copied());
        // are we just adding a window of all 0s? if so, skip
        let is_zero_window = chip.gate().is_zero(ctx, bit_sum);
        let add_point = ec_select_from_bits(chip, ctx, cached_point_window, bit_window);
        curr_point = if let Some(curr_point) = curr_point {
            let sum = ec_add_unequal(chip, ctx, &curr_point, &add_point, !scalar_is_safe);
            let zero_sum = ec_select(chip, ctx, curr_point, sum, is_zero_window);
            Some(ec_select(chip, ctx, zero_sum, add_point, is_started))
        } else {
            Some(add_point)
        };
        is_started = {
            // is_started || !is_zero_window
            // (a || !b) = (1-b) + a*b
            let not_zero_window = chip.gate().not(ctx, is_zero_window);
            chip.gate().mul_add(ctx, is_started, is_zero_window, not_zero_window)
        };
    }
    curr_point.unwrap()
}

// basically just adding up individual fixed_base::scalar_multiply except that we do all batched normalization of cached points at once to further save inversion time during witness generation
// we also use the random accumulator for some extra efficiency (which also works in scalar multiply case but that is TODO)

/// # Assumptions
/// * `points.len() = scalars.len()`
/// * `scalars[i].len() = scalars[j].len()` for all `i,j`
/// * `points` are all on the curve
/// * `points[i]` is not point at infinity (0, 0); these should be filtered out beforehand
/// * The integer value of `scalars[i]` is less than the order of `points[i]` (some constraints may fail otherwise)
/// * Output may be point at infinity, in which case (0, 0) is returned
pub fn msm_par<F, FC, C>(
    chip: &EccChip<F, FC>,
    builder: &mut GateThreadBuilder<F>,
    points: &[C],
    scalars: Vec<Vec<AssignedValue<F>>>,
    max_scalar_bits_per_cell: usize,
    window_bits: usize,
    phase: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    F: PrimeField,
    C: CurveAffineExt,
    FC: FieldChip<F, FieldType = C::Base> + Selectable<F, FC::FieldPoint>,
{
    if points.is_empty() {
        return chip.assign_constant_point(builder.main(phase), C::identity());
    }
    assert!((max_scalar_bits_per_cell as u32) <= F::NUM_BITS);
    assert_eq!(points.len(), scalars.len());
    assert!(!points.is_empty(), "fixed_base::msm_par requires at least one point");
    let scalar_len = scalars[0].len();
    let total_bits = max_scalar_bits_per_cell * scalar_len;
    let num_windows = (total_bits + window_bits - 1) / window_bits;

    // `cached_points` is a flattened 2d vector
    // first we compute all cached points in Jacobian coordinates since it's fastest
    let cached_points_jacobian = points
        .par_iter()
        .flat_map(|point| -> Vec<_> {
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
                        .collect::<Vec<_>>();
                    increment = curr;
                    cache_vec
                })
                .collect()
        })
        .collect::<Vec<_>>();
    // for use in circuits we need affine coordinates, so we do a batch normalize: this is much more efficient than calling `to_affine` one by one since field inversion is very expensive
    // initialize to all 0s
    let mut cached_points_affine = vec![C::default(); cached_points_jacobian.len()];
    C::Curve::batch_normalize(&cached_points_jacobian, &mut cached_points_affine);

    let field_chip = chip.field_chip();

    let zero = builder.main(phase).load_zero();
    let scalar_mults = parallelize_in(
        phase,
        builder,
        cached_points_affine
            .chunks(cached_points_affine.len() / points.len())
            .zip_eq(scalars)
            .collect(),
        |ctx, (cached_points, scalar)| {
            let cached_points = cached_points
                .iter()
                .map(|point| chip.assign_constant_point(ctx, *point))
                .collect_vec();
            let cached_point_window_rev = cached_points.chunks(1usize << window_bits).rev();

            assert_eq!(scalar.len(), scalar_len);
            let bits = scalar
                .into_iter()
                .flat_map(|scalar_chunk| {
                    field_chip.gate().num_to_bits(ctx, scalar_chunk, max_scalar_bits_per_cell)
                })
                .collect::<Vec<_>>();
            let bit_window_rev = bits.chunks(window_bits).rev();
            let mut curr_point = None;
            // `is_started` is just a way to deal with if `curr_point` is actually identity
            let mut is_started = zero;
            for (cached_point_window, bit_window) in cached_point_window_rev.zip(bit_window_rev) {
                let is_zero_window = {
                    let sum = field_chip.gate().sum(ctx, bit_window.iter().copied());
                    field_chip.gate().is_zero(ctx, sum)
                };
                let add_point =
                    ec_select_from_bits(field_chip, ctx, cached_point_window, bit_window);
                curr_point = if let Some(curr_point) = curr_point {
                    // We don't need strict mode because we assume scalars[i] is less than the order of points[i]
                    let sum = ec_add_unequal(field_chip, ctx, &curr_point, &add_point, false);
                    let zero_sum = ec_select(field_chip, ctx, curr_point, sum, is_zero_window);
                    Some(ec_select(field_chip, ctx, zero_sum, add_point, is_started))
                } else {
                    Some(add_point)
                };
                is_started = {
                    // is_started || !is_zero_window
                    // (a || !b) = (1-b) + a*b
                    let not_zero_window = field_chip.gate().not(ctx, is_zero_window);
                    field_chip.gate().mul_add(ctx, is_started, is_zero_window, not_zero_window)
                };
            }
            (curr_point.unwrap(), is_started)
        },
    );
    let ctx = builder.main(phase);
    // sum `scalar_mults` but take into account possiblity of identity points
    let any_point = chip.load_random_point::<C>(ctx);
    let mut acc = any_point.clone();
    for (point, is_not_identity) in scalar_mults {
        let new_acc = chip.add_unequal(ctx, &acc, point, true);
        acc = chip.select(ctx, new_acc, acc, is_not_identity);
    }
    ec_sub_strict(field_chip, ctx, acc, any_point)
}
