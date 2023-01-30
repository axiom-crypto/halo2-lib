use super::{
    ec_add_unequal, ec_double, ec_select, ec_select_from_bits, ec_sub_unequal, load_random_point,
    EcPoint,
};
use crate::fields::{FieldChip, Selectable};
use halo2_base::{
    gates::GateInstructions,
    utils::{CurveAffineExt, PrimeField},
    AssignedValue, Context,
};

// Reference: https://jbootle.github.io/Misc/pippenger.pdf

// Reduction to multi-products
// Output:
// * new_points: length `points.len() * radix`
// * new_bool_scalars: 2d array `ceil(scalar_bits / radix)` by `points.len() * radix`
pub fn decompose<'v, F, FC>(
    chip: &FC,
    ctx: &mut Context<'v, F>,
    points: &[EcPoint<F, FC::FieldPoint<'v>>],
    scalars: &[Vec<AssignedValue<'v, F>>],
    max_scalar_bits_per_cell: usize,
    radix: usize,
) -> (Vec<EcPoint<F, FC::FieldPoint<'v>>>, Vec<Vec<AssignedValue<'v, F>>>)
where
    F: PrimeField,
    FC: FieldChip<F>,
{
    assert_eq!(points.len(), scalars.len());
    let scalar_bits = max_scalar_bits_per_cell * scalars[0].len();
    let t = (scalar_bits + radix - 1) / radix;

    let mut new_points = Vec::with_capacity(radix * points.len());
    let mut new_bool_scalars = vec![Vec::with_capacity(radix * points.len()); t];

    let zero_cell = chip.gate().load_zero(ctx);
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
            let mut new_bits = chip.gate().num_to_bits(ctx, x, max_scalar_bits_per_cell);
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

// Given points[i] and bool_scalars[j][i],
// compute G'[j] = sum_{i=0..points.len()} points[i] * bool_scalars[j][i]
// output is [ G'[j] + rand_point ]_{j=0..bool_scalars.len()}, rand_point
pub fn multi_product<'v, F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<'v, F>,
    points: &[EcPoint<F, FC::FieldPoint<'v>>],
    bool_scalars: &[Vec<AssignedValue<'v, F>>],
    clumping_factor: usize,
) -> (Vec<EcPoint<F, FC::FieldPoint<'v>>>, EcPoint<F, FC::FieldPoint<'v>>)
where
    FC: FieldChip<F> + Selectable<F, Point<'v> = FC::FieldPoint<'v>>,
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
                new_point = ec_select(chip, ctx, &bucket[j], &new_point, &is_infinity);
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

pub fn multi_exp<'v, F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<'v, F>,
    points: &[EcPoint<F, FC::FieldPoint<'v>>],
    scalars: &[Vec<AssignedValue<'v, F>>],
    max_scalar_bits_per_cell: usize,
    radix: usize,
    clump_factor: usize,
) -> EcPoint<F, FC::FieldPoint<'v>>
where
    FC: FieldChip<F> + Selectable<F, Point<'v> = FC::FieldPoint<'v>>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    let (points, bool_scalars) =
        decompose::<F, _>(chip, ctx, points, scalars, max_scalar_bits_per_cell, radix);

    /*
    let t = bool_scalars.len();
    let c = {
        let m = points.len();
        let cost = |b: usize| -> usize { (m + b - 1) / b * ((1 << b) + t) };
        let c_max: usize = f64::from(points.len() as u32).log2().ceil() as usize;
        let mut c_best = c_max;
        for b in 1..c_max {
            if cost(b) <= cost(c_best) {
                c_best = b;
            }
        }
        c_best
    };
    #[cfg(feature = "display")]
    dbg!(clump_factor);
    */

    let (mut agg, rand_point) =
        multi_product::<F, FC, C>(chip, ctx, &points, &bool_scalars, clump_factor);
    // everything in agg has been enforced

    // compute sum_{k=0..t} agg[k] * 2^{radix * k} - (sum_k 2^{radix * k}) * rand_point
    // (sum_{k=0..t} 2^{radix * k}) * rand_point = (2^{radix * t} - 1)/(2^radix - 1)
    let mut sum = agg.pop().unwrap();
    let mut rand_sum = rand_point.clone();
    for g in agg.iter().rev() {
        for _ in 0..radix {
            sum = ec_double(chip, ctx, &sum);
            rand_sum = ec_double(chip, ctx, &rand_sum);
        }
        sum = ec_add_unequal(chip, ctx, &sum, g, true);
        chip.enforce_less_than(ctx, sum.x());

        if radix != 1 {
            // Can use non-strict as long as some property of the prime is true?
            rand_sum = ec_add_unequal(chip, ctx, &rand_sum, &rand_point, false);
        }
    }

    if radix == 1 {
        rand_sum = ec_double(chip, ctx, &rand_sum);
        // assume 2^t != +-1 mod modulus::<F>()
        rand_sum = ec_sub_unequal(chip, ctx, &rand_sum, &rand_point, false);
    }

    chip.enforce_less_than(ctx, rand_sum.x());
    ec_sub_unequal(chip, ctx, &sum, &rand_sum, true)
}
