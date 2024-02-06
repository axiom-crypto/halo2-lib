use halo2_base::{
    gates::{ GateInstructions, RangeChip, RangeInstructions },
    utils::{ log2_ceil, BigPrimeField },
    AssignedValue,
    Context,
};
use num_bigint::BigInt;

use crate::{
    bigint::{
        add_no_carry,
        big_is_equal,
        big_is_even::positive,
        mul_no_carry,
        negative,
        select,
        CRTInteger,
        OverflowInteger,
        ProperCrtUint,
    },
    secp256k1::hash_to_curve::{
        constants::{ get_A, get_B, get_C1, get_C2, get_Z },
        iso_map::iso_map,
    },
};

fn inv_0() {
    // TODO
}

fn sgn_0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    num: OverflowInteger<F>
) -> AssignedValue<F> {
    positive(range, ctx, num.clone(), num.max_limb_bits)
}

fn xy2_selector<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    gx1: ProperCrtUint<F>,
    gx1_sqrt: ProperCrtUint<F>,
    gx2: ProperCrtUint<F>,
    gx2_sqrt: ProperCrtUint<F>,
    x1: ProperCrtUint<F>,
    x2: ProperCrtUint<F>
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let gate = range.gate();
    let one = ctx.load_constant(F::ONE);

    let sq_gx1_sqrt = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            gx1_sqrt.0.clone(),
            gx1_sqrt.0.clone(),
            log2_ceil(gx1_sqrt.limbs().len() as u64)
        )
    );

    let sq_gx2_sqrt = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            gx2_sqrt.0.clone(),
            gx2_sqrt.0.clone(),
            log2_ceil(gx2_sqrt.limbs().len() as u64)
        )
    );

    let s1 = big_is_equal::assign(gate, ctx, sq_gx1_sqrt, gx1.clone());
    let s2 = big_is_equal::assign(gate, ctx, sq_gx2_sqrt, gx2.clone());

    let _one = gate.add(ctx, s1, s2);
    ctx.constrain_equal(&_one, &one);

    let x = ProperCrtUint(select::crt(gate, ctx, x1.0, x2.0, s1));
    let y2 = ProperCrtUint(select::crt(gate, ctx, gx1.0, gx2.0, s1));

    (x, y2)
}

pub fn map_to_curve<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    u: ProperCrtUint<F>,
    gx1_sqrt: ProperCrtUint<F>,
    gx2_sqrt: ProperCrtUint<F>,
    y_pos: ProperCrtUint<F>,
    x_mapped: ProperCrtUint<F>,
    y_mapped: ProperCrtUint<F>
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let gate = range.gate();
    let zero = ctx.load_zero();
    let one = ctx.load_constant(F::ONE);
    let crt_one = ProperCrtUint(
        CRTInteger::new(OverflowInteger::new(vec![one], 64), one, BigInt::from(1u64))
    );

    // Step 1: tv1 = Z * u^2
    let u_sq = ProperCrtUint(
        mul_no_carry::crt(gate, ctx, u.0.clone(), u.0.clone(), log2_ceil(u.limbs().len() as u64))
    );
    let z = get_Z(ctx);
    let tv1 = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            z.0.clone(),
            u_sq.0.clone(),
            log2_ceil(u_sq.limbs().len() as u64)
        )
    );

    // Step 2: tv2 = tv1^2
    let tv2 = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            tv1.0.clone(),
            tv1.0.clone(),
            log2_ceil(tv1.limbs().len() as u64)
        )
    );

    // Step 3: x1 = tv1 + tv2
    let x1 = ProperCrtUint(add_no_carry::crt(gate, ctx, tv1.0, tv2.0));

    // Step 4: x1 = inv0(x1)
    // TODO

    // Step 5: e1 = x1 == 0
    let e1 = gate.is_equal(ctx, x1.0.native, zero);

    // Step 6: x1 = x1 + 1
    let x1 = ProperCrtUint(add_no_carry::crt(gate, ctx, x1.0, crt_one.0));

    // Step 7: x1 = e1 ? c2 : x1
    let c2 = get_C2(ctx);
    let x1 = ProperCrtUint(select::crt(gate, ctx, x1.0, c2.0, e1));

    // Step 8: x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    let c1 = get_C1(ctx);
    assert_eq!(c1.limbs().len(), x1.limbs().len());
    let x1 = ProperCrtUint(
        mul_no_carry::crt(gate, ctx, x1.0.clone(), c1.0.clone(), log2_ceil(c1.limbs().len() as u64))
    );

    // Step 9: gx1 = x1^2
    let gx1 = ProperCrtUint(
        mul_no_carry::crt(gate, ctx, x1.0.clone(), x1.0.clone(), log2_ceil(x1.limbs().len() as u64))
    );

    // Step 10: gx1 = gx1 + A
    let a = get_A(ctx);
    let gx1 = ProperCrtUint(add_no_carry::crt(gate, ctx, gx1.0, a.0));

    // Step 11: gx1 = gx1 * x1
    let gx1 = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            gx1.0.clone(),
            x1.0.clone(),
            log2_ceil(x1.limbs().len() as u64)
        )
    );

    // Step 12: gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    let b = get_B(ctx);
    let gx1 = ProperCrtUint(add_no_carry::crt(gate, ctx, gx1.0, b.0));

    // Step 13: x2 = tv1 * x1            # x2 = Z * u^2 * x1
    let x2 = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            tv1.0.clone(),
            x1.0.clone(),
            log2_ceil(x1.limbs().len() as u64)
        )
    );

    // Step 14: tv2 = tv1 * tv2
    let tv2 = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            tv1.0.clone(),
            tv2.0.clone(),
            log2_ceil(tv1.limbs().len() as u64)
        )
    );

    // Step 15: gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
    let gx2 = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            gx1.0.clone(),
            tv2.0.clone(),
            log2_ceil(tv2.limbs().len() as u64)
        )
    );

    // Steps 16-18:
    //     e2 = is_square(gx1)
    //     x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
    //     y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
    let (x, y2) = xy2_selector(ctx, range, gx1, gx1_sqrt, gx2, gx2_sqrt, x1, x2);

    // Step 19: y = sqrt(y2)
    let y_pos_sq = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            y_pos.0.clone(),
            y_pos.0.clone(),
            log2_ceil(y_pos.limbs().len() as u64)
        )
    );
    ctx.constrain_equal(&big_is_equal::assign(gate, ctx, y_pos_sq, y2.clone()), &one);

    // Step 20: e3 = sgn0(u) == sgn0(y)  # Fix sign of y
    let sgn_u = sgn_0(ctx, range, u.0.truncation);
    let sgn_y = sgn_0(ctx, range, y_pos.0.truncation);
    let e3 = gate.is_equal(ctx, sgn_u, sgn_y);

    // Step 21: y = e3 ? y : -y
    let neg_y_pos = negative::assign(gate, ctx, y_pos.0.truncation);
    let y = ProperCrtUint(select::crt(gate, ctx, y_pos.0, neg_y_pos, e3));

    iso_map(ctx, range, x, y, x_mapped, y_mapped);

    (x_mapped, y_mapped)
}
