use crate::bigint::{big_is_equal, ProperCrtUint};
use crate::fields::{fp::FpChip, FieldChip, PrimeField};
use halo2_base::{gates::GateInstructions, utils::CurveAffineExt, AssignedValue, Context};

use super::{fixed_base, scalar_multiply, EcPoint, EccChip};

// CF is the coordinate field of GA
// SF is the scalar field of GA
// p = base field modulus
// n = scalar field modulus
/// `pubkey` should not be the identity point
/// follow spec in https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
pub fn schnorr_verify_no_pubkey_check<F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    pubkey: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    r: ProperCrtUint<F>,       // int(sig[0:32]); fail if r ≥ p.
    s: ProperCrtUint<F>,       // int(sig[32:64]); fail if s ≥ n
    msgHash: ProperCrtUint<F>, // int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> AssignedValue<F>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let base_chip = chip.field_chip;
    let scalar_chip =
        FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

    // check r < p
    let r_valid = base_chip.is_less_than_p(ctx, &r);
    // check s < n
    let s_valid = scalar_chip.is_soft_nonzero(ctx, &s);
    // check e < n
    let e_valid = scalar_chip.is_soft_nonzero(ctx, &msgHash);

    // compute s * G and msgHash * pubkey
    let s_G = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &GA::generator(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    let e_P = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        pubkey,
        msgHash.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // check s_G.x != e_P.x, which is a requirement for sub_unequal
    let x_eq = base_chip.is_equal(ctx, &s_G.x, &e_P.x);
    let x_neq = base_chip.gate().not(ctx, x_eq);

    // R = s⋅G - e⋅P
    // R is not infinity point implicitly constrainted by is_strict = true
    let R = chip.sub_unequal(ctx, s_G, e_P, true);

    // check R.y is even
    let R_y = R.y;
    let R_y_is_even: AssignedValue<F> = base_chip.is_even(ctx, &R_y);

    // check R.x == r
    let R_x = scalar_chip.enforce_less_than(ctx, R.x);
    let equal_check = big_is_equal::assign(base_chip.gate(), ctx, R_x.0, r);

    let res1 = base_chip.gate().and(ctx, r_valid, s_valid);
    let res2: AssignedValue<F> = base_chip.gate().and(ctx, res1, e_valid);
    let res3 = base_chip.gate().and(ctx, res2, x_neq);
    let res4: AssignedValue<F> = base_chip.gate().and(ctx, res3, R_y_is_even);
    let res5 = base_chip.gate().and(ctx, res4, equal_check);

    res5
}
