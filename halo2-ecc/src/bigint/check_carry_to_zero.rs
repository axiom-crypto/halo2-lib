use super::OverflowInteger;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{bigint_to_fe, fe_to_bigint, BigPrimeField},
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use num_bigint::BigInt;

// check that `a` carries to `0 mod 2^{a.limb_bits * a.limbs.len()}`
// same as `assign` above except we need to provide `c_{k - 1}` witness as well
// checks there exist d_i = -c_i so that
// a_0 = c_0 * 2^n
// a_i + c_{i - 1} = c_i * 2^n for i = 1..=k - 1
// and c_i \in [-2^{m - n + EPSILON}, 2^{m - n + EPSILON}], with EPSILON >= 1 for i = 0..=k-1
// where m = a.max_limb_size.bits() and we choose EPSILON to round up to the next multiple of the range check table size
//
// translated to d_i, this becomes:
// a_0 + d_0 * 2^n = 0
// a_i + d_i * 2^n = d_{i - 1} for i = 1.. k - 1

// aztec optimization:
// note that a_i + c_{i - 1} = c_i * 2^n can be expanded to
// a_i * 2^{n*w} + a_{i - 1} * 2^{n*(w-1)} + ... + a_{i - w} + c_{i - w - 1} = c_i * 2^{n*(w+1)}
// which is valid as long as `(m - n + EPSILON) + n * (w+1) < native_modulus::<F>().bits() - 1`
// so we only need to range check `c_i` every `w + 1` steps, starting with `i = w`
pub fn truncate<F: BigPrimeField>(
    range: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    limb_bits: usize,
    limb_base: F,
    limb_base_big: &BigInt,
) {
    let k = a.limbs.len();
    let max_limb_bits = a.max_limb_bits;

    let mut carries = Vec::with_capacity(k);

    for a_limb in a.limbs.iter() {
        let a_val_big = fe_to_bigint(a_limb.value());
        let carry = if let Some(carry_val) = carries.last() {
            (a_val_big + carry_val) / limb_base_big
        } else {
            // warning: using >> on negative integer produces undesired effect
            a_val_big / limb_base_big
        };
        carries.push(carry);
    }

    // round `max_limb_bits - limb_bits + EPSILON + 1` up to the next multiple of range.lookup_bits
    const EPSILON: usize = 1;
    let range_bits = max_limb_bits - limb_bits + EPSILON;
    let range_bits =
        ((range_bits + range.lookup_bits()) / range.lookup_bits()) * range.lookup_bits() - 1;
    // `window = w + 1` valid as long as `range_bits + n * (w+1) < native_modulus::<F>().bits() - 1`
    // let window = (F::NUM_BITS as usize - 2 - range_bits) / limb_bits;
    // assert!(window > 0);
    // In practice, we are currently always using window = 1 so the above is commented out

    let shift_val = range.gate().pow_of_two()[range_bits];
    // let num_windows = (k - 1) / window + 1; // = ((k - 1) - (window - 1) + window - 1) / window + 1;

    let mut previous = None;
    for (a_limb, carry) in a.limbs.into_iter().zip(carries.into_iter()) {
        let neg_carry_val = bigint_to_fe(&-carry);
        ctx.assign_region(
            [
                Existing(a_limb),
                Witness(neg_carry_val),
                Constant(limb_base),
                previous.map(Existing).unwrap_or_else(|| Constant(F::zero())),
            ],
            [0],
        );
        let neg_carry = ctx.get(-3);

        // i in 0..num_windows {
        // let idx = std::cmp::min(window * i + window - 1, k - 1);
        // let carry_cell = &neg_carry_assignments[idx];
        let shifted_carry = range.gate().add(ctx, neg_carry, Constant(shift_val));
        range.range_check(ctx, shifted_carry, range_bits + 1);

        previous = Some(neg_carry);
    }
}
