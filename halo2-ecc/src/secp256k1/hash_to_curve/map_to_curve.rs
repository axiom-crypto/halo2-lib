use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::BigPrimeField,
    Context,
};
use num_bigint::BigUint;

use crate::{
    bigint::ProperCrtUint,
    fields::{FieldChip, Selectable},
    secp256k1::{
        hash_to_curve::{
            constants::{get_A, get_B, get_C1, get_C2, get_Z},
            iso_map::iso_map,
        },
        FpChip,
    },
};

use super::util::mod_inverse;

fn xy2_selector<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    gx1: ProperCrtUint<F>,
    gx1_sqrt: ProperCrtUint<F>,
    gx2: ProperCrtUint<F>,
    gx2_sqrt: ProperCrtUint<F>,
    x1: ProperCrtUint<F>,
    x2: ProperCrtUint<F>,
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let gate = fp_chip.range.gate();
    let one = ctx.load_constant(F::ONE);

    let sq_gx1_sqrt = fp_chip.mul(ctx, gx1_sqrt.clone(), gx1_sqrt);
    let sq_gx2_sqrt = fp_chip.mul(ctx, gx2_sqrt.clone(), gx2_sqrt);

    let s1 = fp_chip.is_equal(ctx, sq_gx1_sqrt, gx1.clone());
    let s2 = fp_chip.is_equal(ctx, sq_gx2_sqrt, gx2.clone());

    let _one = gate.add(ctx, s1, s2);
    ctx.constrain_equal(&_one, &one);

    let x = fp_chip.select(ctx, x1, x2, s1);
    let y2 = fp_chip.select(ctx, gx1, gx2, s1);

    (x, y2)
}

pub(crate) fn map_to_curve<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    u: ProperCrtUint<F>,
    gx1_sqrt: ProperCrtUint<F>,
    gx2_sqrt: ProperCrtUint<F>,
    y_pos: ProperCrtUint<F>,
    x_mapped: ProperCrtUint<F>,
    y_mapped: ProperCrtUint<F>,
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let range = fp_chip.range();
    let gate = range.gate();

    let one = ctx.load_constant(F::ONE);

    let zero_int = fp_chip.load_constant_uint(ctx, BigUint::from(0u64));
    let one_int = fp_chip.load_constant_uint(ctx, BigUint::from(1u64));

    // Step 1: tv1 = Z * u^2
    let u_sq = fp_chip.mul(ctx, u.clone(), u.clone());
    let z = get_Z(ctx, range);
    let tv1 = fp_chip.mul(ctx, z, u_sq);

    // Step 2: tv2 = tv1^2
    let tv2 = fp_chip.mul(ctx, tv1.clone(), tv1.clone());

    // Step 3: x1 = tv1 + tv2
    let x1 = fp_chip.add_no_carry(ctx, tv1.clone(), tv2.clone());
    let x1 = fp_chip.carry_mod(ctx, x1);

    // Step 4: x1 = inv0(x1)
    let x1 = mod_inverse(ctx, fp_chip, x1);

    // Step 5: e1 = x1 == 0
    let e1 = fp_chip.is_equal(ctx, x1.clone(), zero_int);

    // Step 6: x1 = x1 + 1
    let x1 = fp_chip.add_no_carry(ctx, x1.clone(), one_int);
    let x1 = fp_chip.carry_mod(ctx, x1);

    // Step 7: x1 = e1 ? c2 : x1
    let c2 = get_C2(ctx, range);
    let x1 = fp_chip.select(ctx, c2, x1, e1);

    // Step 8: x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    let c1 = get_C1(ctx, range);
    let x1 = fp_chip.mul(ctx, x1.clone(), c1);

    // Step 9: gx1 = x1^2
    let gx1 = fp_chip.mul(ctx, x1.clone(), x1.clone());

    // Step 10: gx1 = gx1 + A
    let a = get_A(ctx, range);
    let gx1 = fp_chip.add_no_carry(ctx, gx1, a);
    let gx1 = fp_chip.carry_mod(ctx, gx1);

    // Step 11: gx1 = gx1 * x1
    let gx1 = fp_chip.mul(ctx, gx1, x1.clone());

    // Step 12: gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    let b = get_B(ctx, range);
    let gx1 = fp_chip.add_no_carry(ctx, gx1, b);
    let gx1 = fp_chip.carry_mod(ctx, gx1);

    // Step 13: x2 = tv1 * x1            # x2 = Z * u^2 * x1
    let x2 = fp_chip.mul(ctx, tv1.clone(), x1.clone());

    // Step 14: tv2 = tv1 * tv2
    let tv2 = fp_chip.mul(ctx, tv1, tv2);

    // Step 15: gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
    let gx2 = fp_chip.mul(ctx, gx1.clone(), tv2);

    // Steps 16-18:
    //     e2 = is_square(gx1)
    //     x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
    //     y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
    let (x, y2) = xy2_selector(ctx, fp_chip, gx1, gx1_sqrt, gx2, gx2_sqrt, x1, x2);

    // Step 19: y = sqrt(y2)
    let y_pos_sq = fp_chip.mul(ctx, y_pos.clone(), y_pos.clone());
    let e2 = fp_chip.is_equal(ctx, y_pos_sq, y2);
    ctx.constrain_equal(&e2, &one);

    // Step 20: e3 = sgn0(u) == sgn0(y)  # Fix sign of y
    let sgn_u = fp_chip.is_even(ctx, u);
    let sgn_y = fp_chip.is_even(ctx, y_pos.clone());
    let e3 = gate.is_equal(ctx, sgn_u, sgn_y);

    // Step 21: y = e3 ? y : -y
    let neg_y_pos = fp_chip.negate(ctx, y_pos.clone());
    let y = fp_chip.select(ctx, y_pos, neg_y_pos, e3);

    iso_map(ctx, fp_chip, x, y, x_mapped.clone(), y_mapped.clone());

    (x_mapped, y_mapped)
}
