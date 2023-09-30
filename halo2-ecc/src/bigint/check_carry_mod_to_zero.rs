use super::{check_carry_to_zero, CRTInteger, OverflowInteger};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{decompose_bigint, BigPrimeField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::{cmp::max, iter};

// same as carry_mod::crt but `out = 0` so no need to range check
//
// Assumption: the leading two bits (in big endian) are 1, and `a.max_size <= 2^{n * k - 1 + F::NUM_BITS - 2}` (A weaker assumption is also enough)
pub fn crt<F: BigPrimeField>(
    range: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: CRTInteger<F>,
    k_bits: usize, // = a.len().bits()
    modulus: &BigInt,
    mod_vec: &[F],
    mod_native: F,
    limb_bits: usize,
    limb_bases: &[F],
    limb_base_big: &BigInt,
) {
    let n = limb_bits;
    let k = a.truncation.limbs.len();
    let trunc_len = n * k;

    // FIXME: hotfix for BLS12 support
    // debug_assert!(a.value.bits() as usize <= n * k - 1 + (F::NUM_BITS as usize) - 2);

    // see carry_mod.rs for explanation
    let quot_max_bits = trunc_len - 1 + (F::NUM_BITS as usize) - 1 - (modulus.bits() as usize);
    assert!(quot_max_bits < trunc_len);
    // FIXME: hotfix for BLS12 support
    let quot_last_limb_bits = 0; // quot_max_bits - n * (k - 1);

    // these are witness vectors:
    // we need to find `quot_vec` as a proper BigInt with k limbs
    // we need to find `quot_native` as a native F element

    // we need to constrain that `sum_i quot_vec[i] * 2^{n*i} = quot_native` in `F`
    let (quot_val, _out_val) = a.value.div_mod_floor(modulus);

    // only perform safety checks in debug mode
    // FIXME: hotfix for BLS12 support
    // debug_assert_eq!(_out_val, BigInt::zero());
    // debug_assert!(quot_val.abs() < (BigInt::one() << quot_max_bits));

    let quot_vec = decompose_bigint::<F>(&quot_val, k, n);

    debug_assert!(modulus < &(BigInt::one() << (n * k)));

    // We need to show `modulus * quotient - a` is:
    // - congruent to `0 (mod 2^trunc_len)`
    // - equal to 0 in native field `F`

    // Modulo 2^trunc_len, using OverflowInteger:
    // ------------------------------------------
    // Goal: assign cells to `modulus * quotient - a`
    // 1. we effectively do mul_no_carry::truncate(mod_vec, quot_vec) while assigning `mod_vec` and `quot_vec` as we go
    //    call the output `prod` which has len k
    // 2. for prod[i] we can compute prod - a by using the transpose of
    //    | prod | -1 | a | prod - a |

    let mut quot_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);
    let mut check_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);

    // match chip.strategy {
    //    BigIntStrategy::Simple => {
    for (i, (a_limb, quot_v)) in a.truncation.limbs.into_iter().zip(quot_vec).enumerate() {
        let (prod, new_quot_cell) = range.gate().inner_product_left_last(
            ctx,
            quot_assigned.iter().map(|x| Existing(*x)).chain(iter::once(Witness(quot_v))),
            mod_vec[0..=i].iter().rev().map(|c| Constant(*c)),
        );

        // perform step 2: compute prod - a + out
        // transpose of:
        // | prod | -1 | a | prod - a |
        let check_val = *prod.value() - a_limb.value();
        let check_cell =
            ctx.assign_region_last([Constant(-F::ONE), Existing(a_limb), Witness(check_val)], [-1]);

        quot_assigned.push(new_quot_cell);
        check_assigned.push(check_cell);
    }
    //    }
    // }

    // range check that quot_cell in quot_assigned is in [-2^n, 2^n) except for last cell check it's in [-2^quot_last_limb_bits, 2^quot_last_limb_bits)
    for (q_index, quot_cell) in quot_assigned.iter().enumerate() {
        // FIXME: hotfix for BLS12 support
        let limb_bits = if q_index == k - 1 { n /* quot_last_limb_bits */ } else { n };
        let limb_base =
            if q_index == k - 1 { range.gate().pow_of_two()[limb_bits] } else { limb_bases[1] };

        // compute quot_cell + 2^n and range check with n + 1 bits
        let quot_shift = range.gate().add(ctx, *quot_cell, Constant(limb_base));
        range.range_check(ctx, quot_shift, limb_bits + 1);
    }

    let check_overflow_int =
        OverflowInteger::new(check_assigned, max(a.truncation.max_limb_bits, 2 * n + k_bits));

    // check that `modulus * quotient - a == 0 mod 2^{trunc_len}` after carry
    check_carry_to_zero::truncate::<F>(
        range,
        ctx,
        check_overflow_int,
        limb_bits,
        limb_bases[1],
        limb_base_big,
    );

    // Constrain `quot_native = sum_i out_assigned[i] * 2^{n*i}` in `F`
    let quot_native =
        OverflowInteger::evaluate_native(ctx, range.gate(), quot_assigned, limb_bases);

    // Check `0 + modulus * quotient - a = 0` in native field
    // | 0 | modulus | quotient | a |
    ctx.assign_region(
        [Constant(F::ZERO), Constant(mod_native), Existing(quot_native), Existing(a.native)],
        [0],
    );
}
