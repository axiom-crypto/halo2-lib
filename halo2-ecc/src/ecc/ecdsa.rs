use halo2_base::{gates::GateInstructions, utils::CurveAffineExt, AssignedValue, Context};

use crate::bigint::{big_is_equal, big_less_than, FixedOverflowInteger, ProperCrtUint};
use crate::fields::{fp::FpChip, FieldChip, PrimeField};

use super::{fixed_base, EccChip};
use super::{scalar_multiply, EcPoint};
// CF is the coordinate field of GA
// SF is the scalar field of GA
// p = coordinate field modulus
// n = scalar field modulus
// Only valid when p is very close to n in size (e.g. for Secp256k1)
// Assumes `r, s` are proper CRT integers
/// **WARNING**: Only use this function if `1 / (p - n)` is very small (e.g., < 2<sup>-100</sup>)
pub fn ecdsa_verify_no_pubkey_check<F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    pubkey: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    r: ProperCrtUint<F>,
    s: ProperCrtUint<F>,
    msghash: ProperCrtUint<F>,
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> AssignedValue<F>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    // Following https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    let base_chip = chip.field_chip;
    let scalar_chip =
        FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);
    let n = scalar_chip.p.to_biguint().unwrap();
    let n = FixedOverflowInteger::from_native(&n, scalar_chip.num_limbs, scalar_chip.limb_bits);
    let n = n.assign(ctx, base_chip.limb_bits);

    // check r,s are in [1, n - 1]
    let r_valid = scalar_chip.is_soft_nonzero(ctx, &r);
    let s_valid = scalar_chip.is_soft_nonzero(ctx, &s);

    // compute u1 = m s^{-1} mod n and u2 = r s^{-1} mod n
    let u1 = scalar_chip.divide_unsafe(ctx, msghash, &s);
    let u2 = scalar_chip.divide_unsafe(ctx, &r, s);

    // compute u1 * G and u2 * pubkey
    let u1_mul = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &GA::generator(),
        u1.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    let u2_mul = scalar_multiply(
        base_chip,
        ctx,
        pubkey,
        u2.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // check u1 * G != -(u2 * pubkey) but allow u1 * G == u2 * pubkey
    // check (u1 * G).x != (u2 * pubkey).x or (u1 * G).y == (u2 * pubkey).y
    // coordinates of u1_mul and u2_mul are in proper bigint form, and lie in but are not constrained to [0, n)
    // we therefore need hard inequality here
    let x_eq = base_chip.is_equal(ctx, &u1_mul.x, &u2_mul.x);
    let x_neq = base_chip.gate().not(ctx, x_eq);
    let y_eq = base_chip.is_equal(ctx, &u1_mul.y, &u2_mul.y);
    let u1g_u2pk_not_neg = base_chip.gate().or(ctx, x_neq, y_eq);

    // compute (x1, y1) = u1 * G + u2 * pubkey and check (r mod n) == x1 as integers
    // because it is possible for u1 * G == u2 * pubkey, we must use `EccChip::sum`
    let sum = chip.sum::<GA>(ctx, [u1_mul, u2_mul]);
    // WARNING: For optimization reasons, does not reduce x1 mod n, which is
    //          invalid unless p is very close to n in size.
    // enforce x1 < n
    let x1 = scalar_chip.enforce_less_than(ctx, sum.x);
    let equal_check = big_is_equal::assign(base_chip.gate(), ctx, x1.0, r);

    // TODO: maybe the big_less_than is optional?
    let u1_small = big_less_than::assign(
        base_chip.range(),
        ctx,
        u1.0.truncation,
        n.clone(),
        base_chip.limb_bits,
        base_chip.limb_bases[1],
    );
    let u2_small = big_less_than::assign(
        base_chip.range(),
        ctx,
        u2.0.truncation,
        n,
        base_chip.limb_bits,
        base_chip.limb_bases[1],
    );

    // check (r in [1, n - 1]) and (s in [1, n - 1]) and (u1 * G != - u2 * pubkey) and (r == x1 mod n)
    let res1 = base_chip.gate().and(ctx, r_valid, s_valid);
    let res2 = base_chip.gate().and(ctx, res1, u1_small);
    let res3 = base_chip.gate().and(ctx, res2, u2_small);
    let res4 = base_chip.gate().and(ctx, res3, u1g_u2pk_not_neg);
    let res5 = base_chip.gate().and(ctx, res4, equal_check);
    res5
}
