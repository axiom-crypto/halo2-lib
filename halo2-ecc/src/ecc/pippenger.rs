use super::{
    ec_add_unequal, ec_double, ec_select, ec_sub_unequal, into_strict_point, load_random_point,
    strict_ec_select_from_bits, EcPoint,
};
use crate::{
    ecc::ec_sub_strict,
    fields::{FieldChip, PrimeField, Selectable},
};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions},
    utils::CurveAffineExt,
    AssignedValue, Context,
};
use rayon::prelude::*;

// Reference: https://jbootle.github.io/Misc/pippenger.pdf

// Reduction to multi-products
// Output:
// * new_points: length `points.len() * radix`
// * new_bool_scalars: 2d array `ceil(scalar_bits / radix)` by `points.len() * radix`
//
// Empirically `radix = 1` is best, so we don't use this function for now
/*
pub fn decompose<F, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    scalars: &[Vec<AssignedValue<F>>],
    max_scalar_bits_per_cell: usize,
    radix: usize,
) -> (Vec<EcPoint<F, FC::FieldPoint>>, Vec<Vec<AssignedValue<F>>>)
where
    F: PrimeField,
    FC: FieldChip<F>,
{
    assert_eq!(points.len(), scalars.len());
    let scalar_bits = max_scalar_bits_per_cell * scalars[0].len();
    let t = (scalar_bits + radix - 1) / radix;

    let mut new_points = Vec::with_capacity(radix * points.len());
    let mut new_bool_scalars = vec![Vec::with_capacity(radix * points.len()); t];

    let zero_cell = ctx.load_zero();
    for (point, scalar) in points.iter().zip(scalars.iter()) {
        assert_eq!(scalars[0].len(), scalar.len());
        let mut g = point.clone();
        new_points.push(g);
        for _ in 1..radix {
            // if radix > 1, this does not work if `points` contains identity point
            g = ec_double(chip, ctx, new_points.last().unwrap());
            new_points.push(g);
        }
        let mut bits = Vec::with_capacity(scalar_bits);
        for x in scalar {
            let mut new_bits = chip.gate().num_to_bits(ctx, *x, max_scalar_bits_per_cell);
            bits.append(&mut new_bits);
        }
        for k in 0..t {
            new_bool_scalars[k]
                .extend_from_slice(&bits[(radix * k)..std::cmp::min(radix * (k + 1), scalar_bits)]);
        }
        new_bool_scalars[t - 1].extend(vec![zero_cell.clone(); radix * t - scalar_bits]);
    }

    (new_points, new_bool_scalars)
}
*/

/* Left as reference; should always use msm_par
// Given points[i] and bool_scalars[j][i],
// compute G'[j] = sum_{i=0..points.len()} points[i] * bool_scalars[j][i]
// output is [ G'[j] + rand_point ]_{j=0..bool_scalars.len()}, rand_point
pub fn multi_product<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    bool_scalars: &[Vec<AssignedValue<F>>],
    clumping_factor: usize,
) -> (Vec<StrictEcPoint<F, FC>>, EcPoint<F, FC::FieldPoint>)
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint> + Selectable<F, FC::ReducedFieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    let c = clumping_factor; // this is `b` in Section 3 of Bootle

    // to avoid adding two points that are equal or negative of each other,
    // we use a trick from halo2wrong where we load a random C point as witness
    // note that while we load a random point, an adversary could load a specifically chosen point, so we must carefully handle edge cases with constraints
    // TODO: an alternate approach is to use Fiat-Shamir transform (with Poseidon) to hash all the inputs (points, bool_scalars, ...) to get the random point. This could be worth it for large MSMs as we get savings from `add_unequal` in "non-strict" mode. Perhaps not worth the trouble / security concern, though.
    let any_base = load_random_point::<F, FC, C>(chip, ctx);

    let mut acc = Vec::with_capacity(bool_scalars.len());

    let mut bucket = Vec::with_capacity(1 << c);
    let mut any_point = any_base.clone();
    for (round, points_clump) in points.chunks(c).enumerate() {
        // compute all possible multi-products of elements in points[round * c .. round * (c+1)]

        // for later addition collision-prevension, we need a different random point per round
        // we take 2^round * rand_base
        if round > 0 {
            any_point = ec_double(chip, ctx, any_point);
        }
        // stores { rand_point, rand_point + points[0], rand_point + points[1], rand_point + points[0] + points[1] , ... }
        // since rand_point is random, we can always use add_unequal (with strict constraint checking that the points are indeed unequal and not negative of each other)
        bucket.clear();
        let strict_any_point = into_strict_point(chip, ctx, any_point.clone());
        bucket.push(strict_any_point);
        for (i, point) in points_clump.iter().enumerate() {
            // we allow for points[i] to be the point at infinity, represented by (0, 0) in affine coordinates
            // this can be checked by points[i].y == 0 iff points[i] == O
            let is_infinity = chip.is_zero(ctx, &point.y);
            let point = into_strict_point(chip, ctx, point.clone());

            for j in 0..(1 << i) {
                let mut new_point = ec_add_unequal(chip, ctx, &bucket[j], &point, true);
                // if points[i] is point at infinity, do nothing
                new_point = ec_select(chip, ctx, (&bucket[j]).into(), new_point, is_infinity);
                let new_point = into_strict_point(chip, ctx, new_point);
                bucket.push(new_point);
            }
        }

        // for each j, select using clump in e[j][i=...]
        for (j, bits) in bool_scalars.iter().enumerate() {
            let multi_prod = strict_ec_select_from_bits(
                chip,
                ctx,
                &bucket,
                &bits[round * c..round * c + points_clump.len()],
            );
            // since `bucket` is all `StrictEcPoint` and we are selecting from it, we know `multi_prod` is StrictEcPoint
            // everything in bucket has already been enforced
            if round == 0 {
                acc.push(multi_prod);
            } else {
                let _acc = ec_add_unequal(chip, ctx, &acc[j], multi_prod, true);
                acc[j] = into_strict_point(chip, ctx, _acc);
            }
        }
    }

    // we have acc[j] = G'[j] + (2^num_rounds - 1) * rand_base
    any_point = ec_double(chip, ctx, any_point);
    any_point = ec_sub_unequal(chip, ctx, any_point, any_base, false);

    (acc, any_point)
}

/// Currently does not support if the final answer is actually the point at infinity (meaning constraints will fail in that case)
///
/// # Assumptions
/// * `points.len() == scalars.len()`
/// * `scalars[i].len() == scalars[j].len()` for all `i, j`
pub fn multi_exp<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    scalars: Vec<Vec<AssignedValue<F>>>,
    max_scalar_bits_per_cell: usize,
    // radix: usize, // specialize to radix = 1
    clump_factor: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint> + Selectable<F, FC::ReducedFieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    // let (points, bool_scalars) = decompose::<F, _>(chip, ctx, points, scalars, max_scalar_bits_per_cell, radix);

    debug_assert_eq!(points.len(), scalars.len());
    let scalar_bits = max_scalar_bits_per_cell * scalars[0].len();
    // bool_scalars: 2d array `scalar_bits` by `points.len()`
    let mut bool_scalars = vec![Vec::with_capacity(points.len()); scalar_bits];
    for scalar in scalars {
        for (scalar_chunk, bool_chunk) in
            scalar.into_iter().zip(bool_scalars.chunks_mut(max_scalar_bits_per_cell))
        {
            let bits = chip.gate().num_to_bits(ctx, scalar_chunk, max_scalar_bits_per_cell);
            for (bit, bool_bit) in bits.into_iter().zip(bool_chunk.iter_mut()) {
                bool_bit.push(bit);
            }
        }
    }

    let (mut agg, any_point) =
        multi_product::<F, FC, C>(chip, ctx, points, &bool_scalars, clump_factor);
    // everything in agg has been enforced

    // compute sum_{k=0..t} agg[k] * 2^{radix * k} - (sum_k 2^{radix * k}) * rand_point
    // (sum_{k=0..t} 2^{radix * k}) = (2^{radix * t} - 1)/(2^radix - 1)
    let mut sum = agg.pop().unwrap().into();
    let mut any_sum = any_point.clone();
    for g in agg.iter().rev() {
        any_sum = ec_double(chip, ctx, any_sum);
        // cannot use ec_double_and_add_unequal because you cannot guarantee that `sum != g`
        sum = ec_double(chip, ctx, sum);
        sum = ec_add_unequal(chip, ctx, sum, g, true);
    }

    any_sum = ec_double(chip, ctx, any_sum);
    // assume 2^scalar_bits != +-1 mod modulus::<F>()
    any_sum = ec_sub_unequal(chip, ctx, any_sum, any_point, false);

    ec_sub_unequal(chip, ctx, sum, any_sum, true)
}
*/

/// Multi-thread witness generation for multi-scalar multiplication.
///
/// # Assumptions
/// * `points.len() == scalars.len()`
/// * `scalars[i].len() == scalars[j].len()` for all `i, j`
/// * `points` are all on the curve or the point at infinity
/// * `points[i]` is allowed to be (0, 0) to represent the point at infinity (identity point)
/// * Currently implementation assumes that the only point on curve with y-coordinate equal to `0` is identity point
pub fn multi_exp_par<F: PrimeField, FC, C>(
    chip: &FC,
    // these are the "threads" within a single Phase
    builder: &mut GateThreadBuilder<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    scalars: Vec<Vec<AssignedValue<F>>>,
    max_scalar_bits_per_cell: usize,
    // radix: usize, // specialize to radix = 1
    clump_factor: usize,
    phase: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint> + Selectable<F, FC::ReducedFieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    // let (points, bool_scalars) = decompose::<F, _>(chip, ctx, points, scalars, max_scalar_bits_per_cell, radix);

    assert_eq!(points.len(), scalars.len());
    let scalar_bits = max_scalar_bits_per_cell * scalars[0].len();
    // bool_scalars: 2d array `scalar_bits` by `points.len()`
    let mut bool_scalars = vec![Vec::with_capacity(points.len()); scalar_bits];

    // get a main thread
    let ctx = builder.main(phase);
    let witness_gen_only = ctx.witness_gen_only();
    // single-threaded computation:
    for scalar in scalars {
        for (scalar_chunk, bool_chunk) in
            scalar.into_iter().zip(bool_scalars.chunks_mut(max_scalar_bits_per_cell))
        {
            let bits = chip.gate().num_to_bits(ctx, scalar_chunk, max_scalar_bits_per_cell);
            for (bit, bool_bit) in bits.into_iter().zip(bool_chunk.iter_mut()) {
                bool_bit.push(bit);
            }
        }
    }
    // see multi-product comments for explanation of below

    let c = clump_factor;
    let num_rounds = (points.len() + c - 1) / c;
    let any_base = load_random_point::<F, FC, C>(chip, ctx);
    let mut any_points = Vec::with_capacity(num_rounds);
    any_points.push(any_base);
    for _ in 1..num_rounds {
        any_points.push(ec_double(chip, ctx, any_points.last().unwrap()));
    }
    // we will use a different thread per round
    // to prevent concurrency issues with context id, we generate all the ids first
    let thread_ids = (0..num_rounds).map(|_| builder.get_new_thread_id()).collect::<Vec<_>>();
    // now begins multi-threading

    // multi_prods is 2d vector of size `num_rounds` by `scalar_bits`
    let (new_threads, multi_prods): (Vec<_>, Vec<_>) = points
        .par_chunks(c)
        .zip(any_points.par_iter())
        .zip(thread_ids.into_par_iter())
        .enumerate()
        .map(|(round, ((points_clump, any_point), thread_id))| {
            // compute all possible multi-products of elements in points[round * c .. round * (c+1)]
            // create new thread
            let mut thread = Context::new(witness_gen_only, thread_id);
            let ctx = &mut thread;
            // stores { any_point, any_point + points[0], any_point + points[1], any_point + points[0] + points[1] , ... }
            let mut bucket = Vec::with_capacity(1 << c);
            let any_point = into_strict_point(chip, ctx, any_point.clone());
            bucket.push(any_point);
            for (i, point) in points_clump.iter().enumerate() {
                // we allow for points[i] to be the point at infinity, represented by (0, 0) in affine coordinates
                // this can be checked by points[i].y == 0 iff points[i] == O
                let is_infinity = chip.is_zero(ctx, &point.y);
                let point = into_strict_point(chip, ctx, point.clone());

                for j in 0..(1 << i) {
                    let mut new_point = ec_add_unequal(chip, ctx, &bucket[j], &point, true);
                    // if points[i] is point at infinity, do nothing
                    new_point = ec_select(chip, ctx, (&bucket[j]).into(), new_point, is_infinity);
                    let new_point = into_strict_point(chip, ctx, new_point);
                    bucket.push(new_point);
                }
            }
            let multi_prods = bool_scalars
                .iter()
                .map(|bits| {
                    strict_ec_select_from_bits(
                        chip,
                        ctx,
                        &bucket,
                        &bits[round * c..round * c + points_clump.len()],
                    )
                })
                .collect::<Vec<_>>();

            (thread, multi_prods)
        })
        .unzip();
    // we collect the new threads to ensure they are a FIXED order, otherwise later `assign_threads_in` will get confused
    builder.threads[phase].extend(new_threads);

    // agg[j] = sum_{i=0..num_rounds} multi_prods[i][j] for j = 0..scalar_bits
    let thread_ids = (0..scalar_bits).map(|_| builder.get_new_thread_id()).collect::<Vec<_>>();
    let (new_threads, mut agg): (Vec<_>, Vec<_>) = thread_ids
        .into_par_iter()
        .enumerate()
        .map(|(i, thread_id)| {
            let mut thread = Context::new(witness_gen_only, thread_id);
            let ctx = &mut thread;
            let mut acc = multi_prods[0][i].clone();
            for multi_prod in multi_prods.iter().skip(1) {
                let _acc = ec_add_unequal(chip, ctx, &acc, &multi_prod[i], true);
                acc = into_strict_point(chip, ctx, _acc);
            }
            (thread, acc)
        })
        .unzip();
    builder.threads[phase].extend(new_threads);

    // gets the LAST thread for single threaded work
    let ctx = builder.main(phase);
    // we have agg[j] = G'[j] + (2^num_rounds - 1) * any_base
    // let any_point = (2^num_rounds - 1) * any_base
    // TODO: can we remove all these random point operations somehow?
    let mut any_point = ec_double(chip, ctx, any_points.last().unwrap());
    any_point = ec_sub_unequal(chip, ctx, any_point, &any_points[0], true);

    // compute sum_{k=0..scalar_bits} agg[k] * 2^k - (sum_{k=0..scalar_bits} 2^k) * rand_point
    // (sum_{k=0..scalar_bits} 2^k) = (2^scalar_bits - 1)
    let mut sum = agg.pop().unwrap().into();
    let mut any_sum = any_point.clone();
    for g in agg.iter().rev() {
        any_sum = ec_double(chip, ctx, any_sum);
        // cannot use ec_double_and_add_unequal because you cannot guarantee that `sum != g`
        sum = ec_double(chip, ctx, sum);
        sum = ec_add_unequal(chip, ctx, sum, g, true);
    }

    any_sum = ec_double(chip, ctx, any_sum);
    any_sum = ec_sub_unequal(chip, ctx, any_sum, any_point, true);

    ec_sub_strict(chip, ctx, sum, any_sum)
}
