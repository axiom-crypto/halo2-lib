use halo2_base::{
    gates::{ RangeChip, RangeInstructions },
    utils::{ log2_ceil, BigPrimeField },
    Context,
};

use crate::bigint::{ add_no_carry, big_is_equal, mul_no_carry, ProperCrtUint };

use super::constants::{
    get_k_1_0,
    get_k_1_1,
    get_k_1_2,
    get_k_1_3,
    get_k_2_0,
    get_k_2_1,
    get_k_3_0,
    get_k_3_1,
    get_k_3_2,
    get_k_3_3,
    get_k_4_0,
    get_k_4_1,
    get_k_4_2,
};

fn x_num<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
    x_3: ProperCrtUint<F>
) -> ProperCrtUint<F> {
    let gate = range.gate();

    let k_1_3 = get_k_1_3(ctx);
    let k_1_2 = get_k_1_2(ctx);
    let k_1_1 = get_k_1_1(ctx);
    let k_1_0 = get_k_1_0(ctx);

    // Step 1: a = k_(1,3) * x'^3
    let a = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            k_1_3.0.clone(),
            x_3.0.clone(),
            log2_ceil(x_3.limbs().len() as u64)
        )
    );

    // Step 2: b = k_(1,2) * x'^2 +
    let b = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            k_1_2.0.clone(),
            x_2.0.clone(),
            log2_ceil(x_2.limbs().len() as u64)
        )
    );

    // Step 3: c = k_(1,1) * x' +
    let c = ProperCrtUint(
        mul_no_carry::crt(
            gate,
            ctx,
            k_1_1.0.clone(),
            x.0.clone(),
            log2_ceil(x.limbs().len() as u64)
        )
    );

    // Step 4: a + b
    let a_plus_b = ProperCrtUint(add_no_carry::crt(gate, ctx, a.0, b.0));

    // Step 5: a + b + c
    let a_plus_b_plus_c = ProperCrtUint(add_no_carry::crt(gate, ctx, a_plus_b.0, c.0));

    // Step 6: a + b + c + k_1_0
    let a_plus_b_plus_c_plus_k_1_0 = ProperCrtUint(
        add_no_carry::crt(gate, ctx, a_plus_b_plus_c.0, k_1_0.0)
    );

    a_plus_b_plus_c_plus_k_1_0
}

fn x_den<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>
) -> ProperCrtUint<F> {
    let k_2_0 = get_k_2_0(ctx);
    let k_2_1 = get_k_2_1(ctx);

    // Step 1: a = x_2 + k_2_0
    let a = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, x_2.0, k_2_0.0));

    // Step 2: b = x * k_2_1
    let b = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            x.0.clone(),
            k_2_1.0.clone(),
            log2_ceil(x.limbs().len() as u64)
        )
    );

    // Step 3: c = a + b
    let c = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, a.0, b.0));

    c
}

fn y_num<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
    x_3: ProperCrtUint<F>
) -> ProperCrtUint<F> {
    let k_3_3 = get_k_3_3(ctx);
    let k_3_2 = get_k_3_2(ctx);
    let k_3_1 = get_k_3_1(ctx);
    let k_3_0 = get_k_3_0(ctx);

    // Step 1: a = k_3_3 * x_3
    let a = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            k_3_3.0.clone(),
            x_3.0.clone(),
            log2_ceil(x_3.limbs().len() as u64)
        )
    );

    // Step 2: b = k_3_2 * x_2
    let b = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            k_3_2.0.clone(),
            x_2.0.clone(),
            log2_ceil(x_2.limbs().len() as u64)
        )
    );

    // Step 3: c = k_3_1 * x
    let c = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            k_3_1.0.clone(),
            x.0.clone(),
            log2_ceil(x.limbs().len() as u64)
        )
    );

    // Step 4: a + b
    let a_plus_b = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, a.0, b.0));

    // Step 5: a + b + c
    let a_plus_b_plus_c = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, a_plus_b.0, c.0));

    // Step 6: a + b + c + k_3_0
    let a_plus_b_plus_c_plus_k_3_0 = ProperCrtUint(
        add_no_carry::crt(range.gate(), ctx, a_plus_b_plus_c.0, k_3_0.0)
    );

    a_plus_b_plus_c_plus_k_3_0
}

fn y_den<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    x: ProperCrtUint<F>,
    x_2: ProperCrtUint<F>,
    x_3: ProperCrtUint<F>
) -> ProperCrtUint<F> {
    let k_4_0 = get_k_4_0(ctx);
    let k_4_1 = get_k_4_1(ctx);
    let k_4_2 = get_k_4_2(ctx);

    // Step 1: a = x_3 + k_4_0
    let a = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, x_3.0, k_4_0.0));

    // Step 2: b = k_4_2 * x_2
    let b = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            k_4_2.0.clone(),
            x_2.0.clone(),
            log2_ceil(x_2.limbs().len() as u64)
        )
    );

    // Step 3: c = k_4_1 * x
    let c = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            k_4_1.0.clone(),
            x.0.clone(),
            log2_ceil(x.limbs().len() as u64)
        )
    );

    // Step 4: a + b
    let a_plus_b = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, a.0, b.0));

    // Step 5: a + b + c
    let a_plus_b_plus_c = ProperCrtUint(add_no_carry::crt(range.gate(), ctx, a_plus_b.0, c.0));

    a_plus_b_plus_c
}

pub fn iso_map<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    x: ProperCrtUint<F>,
    y: ProperCrtUint<F>,
    x_mapped: ProperCrtUint<F>,
    y_mapped: ProperCrtUint<F>
) {
    let gate = range.gate();
    let one = ctx.load_constant(F::ONE);

    // Step 1: calculate x^2
    let x_2 = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            x.0.clone(),
            x.0.clone(),
            log2_ceil(x.limbs().len() as u64)
        )
    );

    // Step 2: calculate x^3
    let x_3 = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            x.0.clone(),
            x_2.0.clone(),
            log2_ceil(x_2.limbs().len() as u64)
        )
    );

    // Step 3: calculate x_num
    let x_num = x_num(ctx, range, x, x_2, x_3);

    // Step 4: calculate x_den
    let x_den = x_den(ctx, range, x, x_2);

    // Step 5: calculate y_num
    let y_num = y_num(ctx, range, x, x_2, x_3);

    // Step 6: calculate y_den
    let y_den = y_den(ctx, range, x, x_2, x_3);

    // Step 7: x_mapped * x_den === x_num
    let x_check = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            x_mapped.0.clone(),
            x_den.0.clone(),
            log2_ceil(x_den.limbs().len() as u64)
        )
    );

    // Step 8: y_mapped = y' * y_num / y_den
    // y_mapped * y_den === y' * y_num
    let y_check = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            y_mapped.0.clone(),
            y_den.0.clone(),
            log2_ceil(y_den.limbs().len() as u64)
        )
    );

    let y_check_2 = ProperCrtUint(
        mul_no_carry::crt(
            range.gate(),
            ctx,
            y.0.clone(),
            y_num.0.clone(),
            log2_ceil(y_num.limbs().len() as u64)
        )
    );

    // Ensure that the provided x_mapped and y_mapped values are correct
    let check1 = big_is_equal::assign(gate, ctx, x_check, x_num);
    ctx.constrain_equal(&check1, &one);
    let check_2 = big_is_equal::assign(gate, ctx, y_check, y_check_2);
    ctx.constrain_equal(&check_2, &one);
}
