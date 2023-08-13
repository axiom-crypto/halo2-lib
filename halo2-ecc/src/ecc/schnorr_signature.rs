use halo2_base::{
    gates::GateChip, gates::GateInstructions, utils::CurveAffineExt, AssignedValue, Context,
};
use poseidon::PoseidonChip;

use crate::bigint::{big_is_equal, ProperCrtUint, ProperUint};
use crate::fields::{fp::FpChip, FieldChip, PrimeField};

use super::{fixed_base, scalar_multiply, EcPoint, EccChip};

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;

// CF is the coordinate field of GA
// SF is the scalar field of GA
// p = coordinate field modulus
// n = scalar field modulus
// Uses poseidon hash function for hashing H(r || M)
/// `pubkey` should not be the identity point
pub fn schnorr_verify_no_pubkey_check<F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    pubkey: EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    s: ProperCrtUint<F>,
    e: ProperCrtUint<F>,
    msg: ProperCrtUint<F>,
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> AssignedValue<F>
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    // Following https://en.wikipedia.org/wiki/Schnorr_signature
    let base_chip = chip.field_chip;
    let scalar_chip =
        FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);
    // create pseidon chip with default parameter
    let mut poseidon_chip = PoseidonChip::<F, T, RATE>::new(ctx, R_F, R_P).unwrap();
    // create basic gate for arithemtic operations on F
    let gate = GateChip::<F>::default();

    // check r,s are in [1, n - 1]
    let s_valid = scalar_chip.is_soft_nonzero(ctx, &s);
    let e_valid = scalar_chip.is_soft_nonzero(ctx, &e);

    // compute s * G and e * pubkey
    let u1_mul = fixed_base::scalar_multiply(
        base_chip,
        ctx,
        &GA::generator(),
        s.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    let u2_mul = scalar_multiply::<_, _, GA>(
        base_chip,
        ctx,
        pubkey,
        e.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );

    // compute (x1, y1) = u1 * G + u2 * pubkey and check (r mod n) == x1 as integers
    // because it is possible for u1 * G == u2 * pubkey, we must use `EccChip::sum`
    let sum = chip.sum::<GA>(ctx, [u1_mul, u2_mul]);
    // WARNING: For optimization reasons, does not reduce x1 mod n, which is
    //          invalid unless p is very close to n in size.
    // enforce x1 < n
    let x1 = scalar_chip.enforce_less_than(ctx, sum.x);
    // compute H(r.x || M)
    let mut hash_input = x1.inner().limbs().to_vec();
    hash_input.extend(msg.limbs().to_vec());
    poseidon_chip.update(&hash_input);
    let hash = poseidon_chip.squeeze(ctx, &gate).unwrap();
    let equal_check = big_is_equal::assign(base_chip.gate(), ctx, ProperUint(vec![hash]), e);

    // check (s in [1, n - 1]) and (e in [1, n - 1]) and H((s * G + e * pubkey).x || M) == e
    let res1 = base_chip.gate().and(ctx, s_valid, e_valid);
    let res2 = base_chip.gate().and(ctx, res1, equal_check);
    res2
}
