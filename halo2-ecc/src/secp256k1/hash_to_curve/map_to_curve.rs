use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::{arithmetic::Field, halo2curves::secp256k1::Fp},
    utils::{BigPrimeField, ScalarField},
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

fn xy2_selector<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    gx1: &ProperCrtUint<F>,
    gx2: &ProperCrtUint<F>,
    x1: &ProperCrtUint<F>,
    x2: &ProperCrtUint<F>,
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let gx1_sqrt = sqrt(ctx, fp_chip, gx1);
    let sq_gx1_sqrt = fp_chip.mul(ctx, &gx1_sqrt, &gx1_sqrt);

    let s1 = fp_chip.is_equal(ctx, &sq_gx1_sqrt, gx1);

    let x = fp_chip.select(ctx, x1.into(), x2.into(), s1);
    let y2 = fp_chip.select(ctx, gx1.into(), gx2.into(), s1);

    (x, y2)
}

fn mod_inverse<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    num: &ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let one = ctx.load_constant(F::ONE);
    let one_int = fp_chip.load_constant(ctx, Fp::ONE);

    let p = fp_chip.p.to_biguint().unwrap();
    let p_minus_two = p.clone() - 2u64;

    let num_native = num.value();
    let inverse_native = num_native.modpow(&p_minus_two, &p);
    assert_eq!((num_native * inverse_native.clone()) % p, BigUint::from(1u64));

    let mod_inverse = fp_chip.load_private(ctx, Fp::from_bytes_le(&inverse_native.to_bytes_le()));
    let is_one = fp_chip.mul(ctx, num, &mod_inverse);
    let is_equal = fp_chip.is_equal(ctx, is_one, one_int);
    assert_eq!(is_equal.value(), &F::ONE);
    ctx.constrain_equal(&is_equal, &one);

    mod_inverse
}

pub(crate) fn sqrt<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    num: &ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let p = fp_chip.p.to_biguint().unwrap();
    assert_eq!(&p % 4u64, BigUint::from(3u64), "p must be congruent to 3 mod 4");

    let p_plus_1 = p.clone() + 1u64;
    let p_plus_1_by_4 = p_plus_1 / 4u64;

    let sqrt_native = num.value().modpow(&p_plus_1_by_4, &p);
    let sqrt = fp_chip.load_private(ctx, Fp::from_bytes_le(&sqrt_native.to_bytes_le()));

    sqrt
}

pub(crate) fn map_to_curve<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    u: &ProperCrtUint<F>,
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let range = fp_chip.range();
    let gate = range.gate();

    let one = ctx.load_constant(F::ONE);

    let zero_int =
        fp_chip.load_constant(ctx, Fp::from_bytes_le(BigUint::from(0u64).to_bytes_le().as_slice()));
    let one_int =
        fp_chip.load_constant(ctx, Fp::from_bytes_le(BigUint::from(1u64).to_bytes_le().as_slice()));

    // Step 1: tv1 = Z * u^2
    let u_sq = fp_chip.mul(ctx, u, u);
    let z = get_Z(ctx, fp_chip);
    let tv1 = fp_chip.mul(ctx, z, u_sq);

    // Step 2: tv2 = tv1^2
    let tv2 = fp_chip.mul(ctx, &tv1, &tv1);

    // Step 3: x1 = tv1 + tv2
    let x1 = fp_chip.add_no_carry(ctx, &tv1, &tv2);
    let x1 = fp_chip.carry_mod(ctx, x1);

    // Step 4: x1 = inv0(x1)
    let x1 = mod_inverse(ctx, fp_chip, &x1);

    // Step 5: e1 = x1 == 0&
    let e1 = fp_chip.is_equal(ctx, &x1, zero_int);

    // Step 6: x1 = x1 + 1
    let x1 = fp_chip.add_no_carry(ctx, &x1, one_int);
    let x1 = fp_chip.carry_mod(ctx, x1);

    // Step 7: x1 = e1 ? c2 : x1
    let c2 = get_C2(ctx, fp_chip);
    let x1 = fp_chip.select(ctx, c2, x1, e1);

    // Step 8: x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    let c1 = get_C1(ctx, fp_chip);
    let x1 = fp_chip.mul(ctx, &x1, c1);

    // Step 9: gx1 = x1^2
    let gx1 = fp_chip.mul(ctx, &x1, &x1);

    // Step 10: gx1 = gx1 + A
    let a = get_A(ctx, fp_chip);
    let gx1 = fp_chip.add_no_carry(ctx, gx1, a);
    let gx1 = fp_chip.carry_mod(ctx, gx1);

    // Step 11: gx1 = gx1 * x1
    let gx1 = fp_chip.mul(ctx, gx1, &x1);

    // Step 12: gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    let b = get_B(ctx, fp_chip);
    let gx1 = fp_chip.add_no_carry(ctx, gx1, b);
    let gx1 = fp_chip.carry_mod(ctx, gx1);

    // Step 13: x2 = tv1 * x1            # x2 = Z * u^2 * x1
    let x2 = fp_chip.mul(ctx, &tv1, &x1);

    // Step 14: tv2 = tv1 * tv2
    let tv2 = fp_chip.mul(ctx, tv1, tv2);

    // Step 15: gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
    let gx2 = fp_chip.mul(ctx, &gx1, tv2);

    // Steps 16-18:
    //     e2 = is_square(gx1)
    //     x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
    //     y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
    let (x, y2) = xy2_selector(ctx, fp_chip, &gx1, &gx2, &x1, &x2);

    // Step 19: y = sqrt(y2)
    let y = sqrt(ctx, fp_chip, &y2);
    let y_sq = fp_chip.mul(ctx, &y, &y);
    let e2 = fp_chip.is_equal(ctx, y_sq, y2);
    assert_eq!(e2.value(), &F::ONE);
    ctx.constrain_equal(&e2, &one);

    // Step 20: e3 = sgn0(u) == sgn0(y)  # Fix sign of y
    let sgn_u = fp_chip.is_even(ctx, u);
    let sgn_y = fp_chip.is_even(ctx, &y);
    let e3 = gate.is_equal(ctx, sgn_u, sgn_y);

    // Step 21: y = e3 ? y : -y
    let neg_y = fp_chip.negate(ctx, y.clone());
    let y = fp_chip.select(ctx, y, neg_y, e3);

    let (x_mapped, y_mapped) = iso_map(ctx, fp_chip, &x, &y);

    (x_mapped, y_mapped)
}
