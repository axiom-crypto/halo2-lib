use super::{
    ec_add_unequal, ec_double, ec_select, ec_select_from_bits, ec_sub_unequal, load_random_point,
    EcPoint,
};
use crate::fields::{FieldChip, PrimeField, Selectable};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateInstructions},
    utils::CurveAffineExt,
    AssignedValue, Context,
};
use rayon::prelude::*;
use std::sync::Mutex;

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

// Given points[i] and bool_scalars[j][i],
// compute G'[j] = sum_{i=0..points.len()} points[i] * bool_scalars[j][i]
// output is [ G'[j] + rand_point ]_{j=0..bool_scalars.len()}, rand_point
pub fn multi_product<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[EcPoint<F, FC::FieldPoint>],
    bool_scalars: &[Vec<AssignedValue<F>>],
    clumping_factor: usize,
) -> (Vec<EcPoint<F, FC::FieldPoint>>, EcPoint<F, FC::FieldPoint>)
where
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    let c = clumping_factor; // this is `b` in Section 3 of Bootle

    // to avoid adding two points that are equal or negative of each other,
    // we use a trick from halo2wrong where we load a random C point as witness
    // note that while we load a random point, an adversary could load a specifically chosen point, so we must carefully handle edge cases with constraints
    // TODO: an alternate approach is to use Fiat-Shamir transform (with Poseidon) to hash all the inputs (points, bool_scalars, ...) to get the random point. This could be worth it for large MSMs as we get savings from `add_unequal` in "non-strict" mode. Perhaps not worth the trouble / security concern, though.
    let rand_base = load_random_point::<F, FC, C>(chip, ctx);

    let mut acc = Vec::with_capacity(bool_scalars.len());

    let mut bucket = Vec::with_capacity(1 << c);
    let mut rand_point = rand_base.clone();
    for (round, points_clump) in points.chunks(c).into_iter().enumerate() {
        // compute all possible multi-products of elements in points[round * c .. round * (c+1)]

        // for later addition collision-prevension, we need a different random point per round
        // we take 2^round * rand_base
        if round > 0 {
            rand_point = ec_double(chip, ctx, &rand_point);
        }
        // stores { rand_point, rand_point + points[0], rand_point + points[1], rand_point + points[0] + points[1] , ... }
        // since rand_point is random, we can always use add_unequal (with strict constraint checking that the points are indeed unequal and not negative of each other)
        bucket.clear();
        chip.enforce_less_than(ctx, rand_point.x());
        bucket.push(rand_point.clone());
        for (i, point) in points_clump.iter().enumerate() {
            // we allow for points[i] to be the point at infinity, represented by (0, 0) in affine coordinates
            // this can be checked by points[i].y == 0 iff points[i] == O
            let is_infinity = chip.is_zero(ctx, &point.y);
            chip.enforce_less_than(ctx, point.x());

            for j in 0..(1 << i) {
                let mut new_point = ec_add_unequal(chip, ctx, &bucket[j], point, true);
                // if points[i] is point at infinity, do nothing
                new_point = ec_select(chip, ctx, &bucket[j], &new_point, is_infinity);
                chip.enforce_less_than(ctx, new_point.x());
                bucket.push(new_point);
            }
        }

        // for each j, select using clump in e[j][i=...]
        for (j, bits) in bool_scalars.iter().enumerate() {
            let multi_prod = ec_select_from_bits::<F, _>(
                chip,
                ctx,
                &bucket,
                &bits[round * c..round * c + points_clump.len()],
            );
            // everything in bucket has already been enforced
            if round == 0 {
                acc.push(multi_prod);
            } else {
                acc[j] = ec_add_unequal(chip, ctx, &acc[j], &multi_prod, true);
                chip.enforce_less_than(ctx, acc[j].x());
            }
        }
    }

    // we have acc[j] = G'[j] + (2^num_rounds - 1) * rand_base
    rand_point = ec_double(chip, ctx, &rand_point);
    rand_point = ec_sub_unequal(chip, ctx, &rand_point, &rand_base, false);

    (acc, rand_point)
}

/// Currently does not support if the final answer is actually the point at infinity
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
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
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

    let (mut agg, rand_point) =
        multi_product::<F, FC, C>(chip, ctx, points, &bool_scalars, clump_factor);
    // everything in agg has been enforced

    // compute sum_{k=0..t} agg[k] * 2^{radix * k} - (sum_k 2^{radix * k}) * rand_point
    // (sum_{k=0..t} 2^{radix * k}) = (2^{radix * t} - 1)/(2^radix - 1)
    let mut sum = agg.pop().unwrap();
    let mut rand_sum = rand_point.clone();
    for g in agg.iter().rev() {
        rand_sum = ec_double(chip, ctx, &rand_sum);
        // cannot use ec_double_and_add_unequal because you cannot guarantee that `sum != g`
        sum = ec_double(chip, ctx, &sum);
        chip.enforce_less_than(ctx, sum.x());
        sum = ec_add_unequal(chip, ctx, &sum, g, true);
    }

    rand_sum = ec_double(chip, ctx, &rand_sum);
    // assume 2^scalar_bits != +-1 mod modulus::<F>()
    rand_sum = ec_sub_unequal(chip, ctx, &rand_sum, &rand_point, false);

    chip.enforce_less_than(ctx, sum.x());
    chip.enforce_less_than(ctx, rand_sum.x());
    ec_sub_unequal(chip, ctx, &sum, &rand_sum, true)
}

/// Multi-thread witness generation for multi-scalar multiplication.
/// Should give exact same circuit as `multi_exp`.
///
/// Currently does not support if the final answer is actually the point at infinity
pub fn multi_exp_par<F: PrimeField, FC, C>(
    chip: &FC,
    // we use a Mutex guard for synchronous adding threads to the thread pool
    // these are the threads within a single Phase
    thread_pool: &Mutex<GateThreadBuilder<F>>,
    points: &[EcPoint<F, FC::FieldPoint>],
    scalars: Vec<Vec<AssignedValue<F>>>,
    max_scalar_bits_per_cell: usize,
    // radix: usize, // specialize to radix = 1
    clump_factor: usize,
    phase: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, Point = FC::FieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    // let (points, bool_scalars) = decompose::<F, _>(chip, ctx, points, scalars, max_scalar_bits_per_cell, radix);

    debug_assert_eq!(points.len(), scalars.len());
    let scalar_bits = max_scalar_bits_per_cell * scalars[0].len();
    // bool_scalars: 2d array `scalar_bits` by `points.len()`
    let mut bool_scalars = vec![Vec::with_capacity(points.len()); scalar_bits];

    // get a main thread
    let mut builder = thread_pool.lock().unwrap();
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
    let rand_base = load_random_point::<F, FC, C>(chip, ctx);
    let mut rand_points = Vec::with_capacity(num_rounds);
    rand_points.push(rand_base);
    for _ in 1..num_rounds {
        rand_points.push(ec_double(chip, ctx, rand_points.last().unwrap()));
    }
    // we will use a different thread per round
    // to prevent concurrency issues with context id, we generate all the ids first
    let thread_ids = (0..num_rounds).map(|_| builder.get_new_thread_id()).collect::<Vec<_>>();
    drop(builder);
    // now begins multi-threading

    // multi_prods is 2d vector of size `num_rounds` by `scalar_bits`
    let (new_threads, multi_prods): (Vec<_>, Vec<_>) = points
        .par_chunks(c)
        .zip(rand_points.par_iter())
        .zip(thread_ids.into_par_iter())
        .enumerate()
        .map(|(round, ((points_clump, rand_point), thread_id))| {
            // compute all possible multi-products of elements in points[round * c .. round * (c+1)]
            // create new thread
            let mut thread = Context::new(witness_gen_only, thread_id);
            let ctx = &mut thread;
            // stores { rand_point, rand_point + points[0], rand_point + points[1], rand_point + points[0] + points[1] , ... }
            let mut bucket = Vec::with_capacity(1 << c);
            chip.enforce_less_than(ctx, rand_point.x());
            bucket.push(rand_point.clone());
            for (i, point) in points_clump.iter().enumerate() {
                // we allow for points[i] to be the point at infinity, represented by (0, 0) in affine coordinates
                // this can be checked by points[i].y == 0 iff points[i] == O
                let is_infinity = chip.is_zero(ctx, &point.y);
                chip.enforce_less_than(ctx, point.x());

                for j in 0..(1 << i) {
                    let mut new_point = ec_add_unequal(chip, ctx, &bucket[j], point, true);
                    // if points[i] is point at infinity, do nothing
                    new_point = ec_select(chip, ctx, &bucket[j], &new_point, is_infinity);
                    chip.enforce_less_than(ctx, new_point.x());
                    bucket.push(new_point);
                }
            }
            let multi_prods = bool_scalars
                .iter()
                .map(|bits| {
                    ec_select_from_bits::<F, _>(
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
    thread_pool.lock().unwrap().threads[phase].extend(new_threads);

    // agg[j] = sum_{i=0..num_rounds} multi_prods[i][j] for j = 0..scalar_bits
    // get a main thread
    let mut builder = thread_pool.lock().unwrap();
    let thread_ids = (0..scalar_bits).map(|_| builder.get_new_thread_id()).collect::<Vec<_>>();
    drop(builder);
    let (new_threads, mut agg): (Vec<_>, Vec<_>) = thread_ids
        .into_par_iter()
        .enumerate()
        .map(|(i, thread_id)| {
            let mut thread = Context::new(witness_gen_only, thread_id);
            let ctx = &mut thread;
            let mut acc = if multi_prods.len() == 1 {
                multi_prods[0][i].clone()
            } else {
                ec_add_unequal(chip, ctx, &multi_prods[0][i], &multi_prods[1][i], true)
            };
            chip.enforce_less_than(ctx, acc.x());
            for multi_prod in multi_prods.iter().skip(2) {
                acc = ec_add_unequal(chip, ctx, &acc, &multi_prod[i], true);
                chip.enforce_less_than(ctx, acc.x());
            }
            (thread, acc)
        })
        .unzip();
    thread_pool.lock().unwrap().threads[phase].extend(new_threads);

    // gets the LAST thread for single threaded work
    // warning: don't get any earlier threads, because currently we assume equality constraints in thread i only involves threads <= i
    let mut builder = thread_pool.lock().unwrap();
    let ctx = builder.main(phase);
    // we have agg[j] = G'[j] + (2^num_rounds - 1) * rand_base
    // let rand_point = (2^num_rounds - 1) * rand_base
    // TODO: can we remove all these random point operations somehow?
    let mut rand_point = ec_double(chip, ctx, rand_points.last().unwrap());
    rand_point = ec_sub_unequal(chip, ctx, &rand_point, &rand_points[0], false);

    // compute sum_{k=0..scalar_bits} agg[k] * 2^k - (sum_{k=0..scalar_bits} 2^k) * rand_point
    // (sum_{k=0..scalar_bits} 2^k) = (2^scalar_bits - 1)
    let mut sum = agg.pop().unwrap();
    let mut rand_sum = rand_point.clone();
    for g in agg.iter().rev() {
        rand_sum = ec_double(chip, ctx, &rand_sum);
        // cannot use ec_double_and_add_unequal because you cannot guarantee that `sum != g`
        sum = ec_double(chip, ctx, &sum);
        chip.enforce_less_than(ctx, sum.x());
        sum = ec_add_unequal(chip, ctx, &sum, g, true);
    }

    rand_sum = ec_double(chip, ctx, &rand_sum);
    // assume 2^scalar_bits != +-1 mod modulus::<F>()
    rand_sum = ec_sub_unequal(chip, ctx, &rand_sum, &rand_point, false);

    chip.enforce_less_than(ctx, sum.x());
    chip.enforce_less_than(ctx, rand_sum.x());
    ec_sub_unequal(chip, ctx, &sum, &rand_sum, true)
}
