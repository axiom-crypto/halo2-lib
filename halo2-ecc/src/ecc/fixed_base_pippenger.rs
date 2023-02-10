use super::{ec_add_unequal, ec_double, ec_sub_unequal, is_on_curve, EcPoint};
use crate::{
    bigint::{CRTInteger, FixedOverflowInteger, OverflowInteger},
    fields::PrimeFieldChip,
};
use group::{Curve, Group};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{fe_to_biguint, PrimeField},
    AssignedValue, Context,
};
use halo2_proofs::{arithmetic::CurveAffine, circuit::Value};
use num_bigint::{BigInt, BigUint, ToBigInt};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Reference: https://jbootle.github.io/Misc/pippenger.pdf

// Reduction to multi-products
// Output:
// * new_points: length `points.len() * radix`
// * new_bool_scalars: 2d array `ceil(scalar_bits / radix)` by `points.len() * radix`
pub fn decompose<F, C>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    points: &[C],
    scalars: &Vec<Vec<AssignedValue<F>>>,
    max_scalar_bits_per_cell: usize,
    radix: usize,
) -> (Vec<C::Curve>, Vec<Vec<AssignedValue<F>>>)
where
    F: PrimeField,
    C: CurveAffine,
{
    assert_eq!(points.len(), scalars.len());
    let scalar_bits = max_scalar_bits_per_cell * scalars[0].len();
    let t = (scalar_bits + radix - 1) / radix;

    let mut new_points = Vec::with_capacity(radix * points.len());
    let mut new_bool_scalars = vec![Vec::with_capacity(radix * points.len()); t];

    let zero_cell = gate.load_zero(ctx);
    for (point, scalar) in points.iter().zip(scalars.iter()) {
        assert_eq!(scalars[0].len(), scalar.len());
        let mut g = point.to_curve();
        new_points.push(g);
        for _ in 1..radix {
            g += g;
            new_points.push(g);
        }
        let mut bits = Vec::with_capacity(scalar_bits);
        for x in scalar {
            let mut new_bits = gate.num_to_bits(ctx, x, max_scalar_bits_per_cell);
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
pub fn multi_product<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: Vec<C::CurveExt>,
    bool_scalars: Vec<Vec<AssignedValue<F>>>,
    clumping_factor: usize,
) -> (Vec<EcPoint<F, FC::FieldPoint>>, EcPoint<F, FC::FieldPoint>)
where
    FC: PrimeFieldChip<F, FieldPoint = CRTInteger<F>>,
    FC::FieldType: PrimeField,
    C: CurveAffine<Base = FC::FieldType>,
{
    let c = clumping_factor; // this is `b` in Section 3 of Bootle
    let num_rounds = (points.len() + c - 1) / c;

    // to avoid adding two points that are equal or negative of each other,
    // we use a trick from halo2wrong where we load a random `C` point
    // note that while we load a random point, an adversary could load a specifically chosen point, so we must carefully handle edge cases with constraints
    // TODO: an alternate approach is to use Fiat-Shamir transform (with Poseidon) to hash all the inputs (points, bool_scalars, ...) to get the random point. This could be worth it for large MSMs as we get savings from `add_unequal` in "non-strict" mode. Perhaps not worth the trouble / security concern, though.
    let mut base_point = C::CurveExt::random(ChaCha20Rng::from_entropy());
    let rand_base = {
        let (x, y) = get_coordinates(base_point.to_affine());
        let pt_x = FC::fe_to_witness(&Value::known(x));
        let pt_y = FC::fe_to_witness(&Value::known(y));
        let x_overflow = chip.load_private(ctx, pt_x);
        let y_overflow = chip.load_private(ctx, pt_y);
        EcPoint::construct(x_overflow, y_overflow)
    };
    // for above reason we still need to constrain that the witness is on the curve
    is_on_curve::<F, FC, C>(chip, ctx, &rand_base);

    let mut acc = Vec::with_capacity(bool_scalars.len());

    let mut bucket: Vec<C::Curve> = Vec::with_capacity(1 << c);
    let mut rand_point = rand_base.clone();
    for (round, points_clump) in points.chunks(c).into_iter().enumerate() {
        // compute all possible multi-products of elements in points[round * c .. round * (c+1)]

        // for later addition collision-prevension, we need a different random point per round
        // we take 2^round * rand_base
        if round > 0 {
            base_point += base_point;
            rand_point = ec_double(chip, ctx, &rand_point);
        }
        // stores rand_point + { [0], points[0], points[1], points[0] + points[1] , ... }
        // since `points` are fixed elements, this is done outside of the circuit
        bucket.clear();
        bucket.push(base_point);
        for (i, point) in points_clump.iter().enumerate() {
            for j in 0..(1 << (i - round * c)) {
                let new_point = bucket[j] + point;
                bucket.push(new_point);
            }
        }

        let (x_big, y_big): (Vec<_>, Vec<_>) = bucket
            .iter()
            .map(|point| {
                let coord = point.to_affine().coordinates().unwrap();
                (fe_to_biguint(coord.x()), fe_to_biguint(coord.y()))
            })
            .unzip();

        // for each j, select using clump in e[j][i=...]
        for (j, bits) in bool_scalars.iter().enumerate() {
            let ind = chip
                .range()
                .gate()
                .bits_to_indicator(ctx, &bits[round * c..round * c + points_clump.len()]);
            let mut to_crt = |x_big: &[BigUint]| {
                let x_trunc = FixedOverflowInteger::<F>::select_by_indicator(
                    chip.range().gate(),
                    ctx,
                    &x_big
                        .iter()
                        .map(|big| {
                            FixedOverflowInteger::from_native(
                                big,
                                chip.num_limbs(),
                                chip.limb_bits(),
                            )
                        })
                        .collect::<Vec<_>>(),
                    &ind,
                    chip.limb_bits(),
                );
                let x_native = OverflowInteger::<F>::evaluate(
                    chip.range().gate(),
                    ctx,
                    &x_trunc.limbs,
                    chip.limb_bases().iter().cloned(),
                );
                let mut x_val = Value::unknown();
                for (ind, x_big) in ind.iter().zip(x_big.iter()) {
                    ind.value().map(|b| {
                        if !b.is_zero_vartime() {
                            x_val = Value::known(x_big.to_bigint().unwrap());
                        }
                    });
                }
                CRTInteger::construct(x_trunc, x_native, x_val)
            };

            let multi_prod = EcPoint::construct(to_crt(&x_big), to_crt(&y_big));

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

pub fn multi_exp<F: PrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[C],
    scalars: &Vec<Vec<AssignedValue<F>>>,
    max_scalar_bits_per_cell: usize,
    radix: usize,
    clump_factor: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: PrimeFieldChip<F, FieldPoint = CRTInteger<F>>,
    FC::FieldType: PrimeField,
    C: CurveAffine<Base = FC::FieldType>,
{
    dbg!(radix);
    let (points, bool_scalars) = decompose::<F, _>(
        chip.range().gate(),
        ctx,
        points,
        scalars,
        max_scalar_bits_per_cell,
        radix,
    );

    let c = if clump_factor == 0 {
        // let t = bool_scalars.len();
        let m = points.len();
        // cost is (# rounds) * t * (cost of size 2^c select_by_indicator + 1 ec_add)
        let cost = |b: usize| -> usize { ((m + b - 1) / b) * ((1 << b) + 20) }; // factor of 10 not very scientific
        let c_max: usize = f64::from(points.len() as u32).log2().ceil() as usize;
        let mut c_best = c_max;
        for b in 1..c_max {
            if cost(b) <= cost(c_best) {
                c_best = b;
            }
        }
        c_best
    } else {
        clump_factor
    };
    dbg!(c);

    let (mut agg, rand_point) = multi_product::<F, FC, C>(chip, ctx, points, bool_scalars, c);

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
