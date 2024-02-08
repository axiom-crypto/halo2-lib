use halo2_base::{utils::BigPrimeField, Context};

use crate::{bigint::ProperCrtUint, fields::FieldChip, secp256k1::FpChip};

use super::constants::{
    get_k_1_0, get_k_1_1, get_k_1_2, get_k_1_3, get_k_2_0, get_k_2_1, get_k_3_0, get_k_3_1,
    get_k_3_2, get_k_3_3, get_k_4_0, get_k_4_1, get_k_4_2,
};

fn x_num<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
    x_3: ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let range = fp_chip.range();

    let k_1_3 = get_k_1_3(ctx, range);
    let k_1_2 = get_k_1_2(ctx, range);
    let k_1_1 = get_k_1_1(ctx, range);
    let k_1_0 = get_k_1_0(ctx, range);

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
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let range = fp_chip.range();

    let k_2_0 = get_k_2_0(ctx, range);
    let k_2_1 = get_k_2_1(ctx, range);

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
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
    x_3: ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let range = fp_chip.range();

    let k_3_3 = get_k_3_3(ctx, range);
    let k_3_2 = get_k_3_2(ctx, range);
    let k_3_1 = get_k_3_1(ctx, range);
    let k_3_0 = get_k_3_0(ctx, range);

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
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
    x_3: ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let range = fp_chip.range();

    let k_4_0 = get_k_4_0(ctx, range);
    let k_4_1 = get_k_4_1(ctx, range);
    let k_4_2 = get_k_4_2(ctx, range);

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
    x: ProperCrtUint<F>,
    y: ProperCrtUint<F>,
    x_mapped: ProperCrtUint<F>,
    y_mapped: ProperCrtUint<F>,
) {
    let one = ctx.load_constant(F::ONE);

    // Step 1: calculate x^2
    let x_2 = fp_chip.mul(ctx, x.clone(), x.clone());

    // Step 2: calculate x^3
    let x_3 = fp_chip.mul(ctx, x.clone(), x_2.clone());

    // Step 3: calculate x_num
    let x_num = x_num(ctx, fp_chip, x.clone(), x_2.clone(), x_3.clone());

    // Step 4: calculate x_den
    let x_den = x_den(ctx, fp_chip, x.clone(), x_2.clone());

    // Step 5: calculate y_num
    let y_num = y_num(ctx, fp_chip, x.clone(), x_2.clone(), x_3.clone());

    // Step 6: calculate y_den
    let y_den = y_den(ctx, fp_chip, x, x_2, x_3);

    // Step 7: x_mapped * x_den === x_num
    let x_check = fp_chip.mul(ctx, x_mapped, x_den);

    // Step 8: y_mapped = y' * y_num / y_den
    // y_mapped * y_den === y' * y_num
    let y_check = fp_chip.mul(ctx, y_mapped, y_den);

    let y_check_2 = fp_chip.mul(ctx, y, y_num);

    // Ensure that the provided x_mapped and y_mapped values are correct
    let check1 = fp_chip.is_equal(ctx, x_check, x_num);
    ctx.constrain_equal(&check1, &one);
    let check_2 = fp_chip.is_equal(ctx, y_check, y_check_2);
    ctx.constrain_equal(&check_2, &one);
}
