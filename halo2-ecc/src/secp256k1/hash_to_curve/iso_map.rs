use super::constants::{
    get_k_1_0, get_k_1_1, get_k_1_2, get_k_1_3, get_k_2_0, get_k_2_1, get_k_3_0, get_k_3_1,
    get_k_3_2, get_k_3_3, get_k_4_0, get_k_4_1, get_k_4_2,
};
use crate::{bigint::ProperCrtUint, fields::FieldChip, secp256k1::FpChip};
use halo2_base::{utils::BigPrimeField, Context};

fn x_num<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    x: &ProperCrtUint<F>,
    x_2: &ProperCrtUint<F>,
    x_3: &ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let k_1_3 = get_k_1_3(ctx, fp_chip);
    let k_1_2 = get_k_1_2(ctx, fp_chip);
    let k_1_1 = get_k_1_1(ctx, fp_chip);
    let k_1_0 = get_k_1_0(ctx, fp_chip);

    // Step 1: a = k_(1,3) * x'^3
    let a = fp_chip.mul(ctx, k_1_3, x_3);

    // Step 2: b = k_(1,2) * x'^2 +
    let b = fp_chip.mul(ctx, k_1_2, x_2);

    // Step 3: c = k_(1,1) * x' +
    let c = fp_chip.mul(ctx, k_1_1, x);

    // Step 4: a + b
    let a_plus_b = fp_chip.add_no_carry(ctx, a, b);
    let a_plus_b = fp_chip.carry_mod(ctx, a_plus_b);

    // Step 5: a + b + c
    let a_plus_b_plus_c = fp_chip.add_no_carry(ctx, a_plus_b, c);
    let a_plus_b_plus_c = fp_chip.carry_mod(ctx, a_plus_b_plus_c);

    // Step 6: a + b + c + k_1_0
    let a_plus_b_plus_c_plus_k_1_0 = fp_chip.add_no_carry(ctx, a_plus_b_plus_c, k_1_0);
    let a_plus_b_plus_c_plus_k_1_0 = fp_chip.carry_mod(ctx, a_plus_b_plus_c_plus_k_1_0);

    a_plus_b_plus_c_plus_k_1_0
}

fn x_den<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    x: &ProperCrtUint<F>,
    x_2: &ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let k_2_0 = get_k_2_0(ctx, fp_chip);
    let k_2_1 = get_k_2_1(ctx, fp_chip);

    // Step 1: a = x_2 + k_2_0
    let a = fp_chip.add_no_carry(ctx, x_2, k_2_0);
    let a = fp_chip.carry_mod(ctx, a);

    // Step 2: b = x * k_2_1
    let b = fp_chip.mul(ctx, x, k_2_1);

    // Step 3: c = a + b
    let c = fp_chip.add_no_carry(ctx, a, b);
    let c = fp_chip.carry_mod(ctx, c);

    c
}

fn y_num<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    x: &ProperCrtUint<F>,
    x_2: &ProperCrtUint<F>,
    x_3: &ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let k_3_3 = get_k_3_3(ctx, fp_chip);
    let k_3_2 = get_k_3_2(ctx, fp_chip);
    let k_3_1 = get_k_3_1(ctx, fp_chip);
    let k_3_0 = get_k_3_0(ctx, fp_chip);

    // Step 1: a = k_3_3 * x_3
    let a = fp_chip.mul(ctx, k_3_3, x_3);

    // Step 2: b = k_3_2 * x_2
    let b = fp_chip.mul(ctx, k_3_2, x_2);

    // Step 3: c = k_3_1 * x
    let c = fp_chip.mul(ctx, k_3_1, x);

    // Step 4: a + b
    let a_plus_b = fp_chip.add_no_carry(ctx, a, b);
    let a_plus_b = fp_chip.carry_mod(ctx, a_plus_b);

    // Step 5: a + b + c
    let a_plus_b_plus_c = fp_chip.add_no_carry(ctx, a_plus_b, c);
    let a_plus_b_plus_c = fp_chip.carry_mod(ctx, a_plus_b_plus_c);

    // Step 6: a + b + c + k_3_0
    let a_plus_b_plus_c_plus_k_3_0 = fp_chip.add_no_carry(ctx, a_plus_b_plus_c, k_3_0);
    let a_plus_b_plus_c_plus_k_3_0 = fp_chip.carry_mod(ctx, a_plus_b_plus_c_plus_k_3_0);

    a_plus_b_plus_c_plus_k_3_0
}

fn y_den<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    x: &ProperCrtUint<F>,
    x_2: &ProperCrtUint<F>,
    x_3: &ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let k_4_0 = get_k_4_0(ctx, fp_chip);
    let k_4_1 = get_k_4_1(ctx, fp_chip);
    let k_4_2 = get_k_4_2(ctx, fp_chip);

    // Step 1: a = x_3 + k_4_0
    let a = fp_chip.add_no_carry(ctx, x_3, k_4_0);
    let a = fp_chip.carry_mod(ctx, a);

    // Step 2: b = k_4_2 * x_2
    let b = fp_chip.mul(ctx, k_4_2, x_2);

    // Step 3: c = k_4_1 * x
    let c = fp_chip.mul(ctx, k_4_1, x);

    // Step 4: a + b
    let a_plus_b = fp_chip.add_no_carry(ctx, a, b);
    let a_plus_b = fp_chip.carry_mod(ctx, a_plus_b);

    // Step 5: a + b + c
    let a_plus_b_plus_c = fp_chip.add_no_carry(ctx, a_plus_b, c);
    let a_plus_b_plus_c = fp_chip.carry_mod(ctx, a_plus_b_plus_c);

    a_plus_b_plus_c
}

pub(crate) fn iso_map<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    x: &ProperCrtUint<F>,
    y: &ProperCrtUint<F>,
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    // Step 1: calculate x^2
    let x_2 = fp_chip.mul(ctx, x, x);

    // Step 2: calculate x^3
    let x_3 = fp_chip.mul(ctx, x, &x_2);

    // Step 3: calculate x_num
    let x_num = x_num(ctx, fp_chip, x, &x_2, &x_3);

    // Step 4: calculate x_den
    let x_den = x_den(ctx, fp_chip, x, &x_2);

    // Step 5: calculate y_num
    let y_num = y_num(ctx, fp_chip, x, &x_2, &x_3);

    // Step 6: calculate y_den
    let y_den = y_den(ctx, fp_chip, x, &x_2, &x_3);

    let x_mapped = fp_chip.divide(ctx, &x_num, &x_den);
    let y_mapped = fp_chip.divide(ctx, &y_num, &y_den);
    let y_mapped = fp_chip.mul(ctx, &y_mapped, y);

    (x_mapped, y_mapped)
}
