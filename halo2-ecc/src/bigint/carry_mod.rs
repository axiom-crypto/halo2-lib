use std::{cmp::max, iter};

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{decompose_bigint, BigPrimeField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed};

use super::{check_carry_to_zero, CRTInteger, OverflowInteger, ProperCrtUint, ProperUint};

// Input `a` is `CRTInteger` with `a.truncation` of length `k` with "signed" limbs
// Output is `out = a (mod modulus)` as CRTInteger with
// `out.value = a.value (mod modulus)`
// `out.trunction = (a (mod modulus)) % 2^t` a proper BigInt of length `k` with limbs in [0, 2^limb_bits)`
// The witness for `out.truncation` is a BigInt in [0, modulus), but we do not constrain the inequality
// `out.native = (a (mod modulus)) % (native_modulus::<F>)`
// We constrain `a = out + modulus * quotient` and range check `out` and `quotient`
//
// Assumption: the leading two bits (in big endian) are 1,
/// # Assumptions
/// * abs(a) <= 2<sup>n * k - 1 + F::NUM_BITS - 2</sup> (A weaker assumption is also enough, but this is good enough for forseeable use cases)
/// * `native_modulus::<F>` requires *exactly* `k = a.limbs.len()` limbs to represent

// This is currently optimized for limbs greater than 64 bits, so we need `F` to be a `BigPrimeField`
// In the future we'll need a slightly different implementation for limbs that fit in 32 or 64 bits (e.g., `F` is Goldilocks)
pub fn crt<F: BigPrimeField>(
    range: &impl RangeInstructions<F>,
    // chip: &BigIntConfig<F>,
    ctx: &mut Context<F>,
    a: CRTInteger<F>,
    k_bits: usize, // = a.len().bits()
    modulus: &BigInt,
    mod_vec: &[F],
    mod_native: F,
    limb_bits: usize,
    limb_bases: &[F],
    limb_base_big: &BigInt,
) -> ProperCrtUint<F> {
    let n = limb_bits;
    let k = a.truncation.limbs.len();
    let trunc_len = n * k;

    debug_assert!(a.value.bits() as usize <= n * k - 1 + (F::NUM_BITS as usize) - 2);

    // in order for CRT method to work, we need `abs(out + modulus * quotient - a) < 2^{trunc_len - 1} * native_modulus::<F>`
    // this is ensured if `0 <= out < 2^{n*k}` and
    // `abs(modulus * quotient) < 2^{trunc_len - 1} * native_modulus::<F> - abs(a)
    // which is ensured if
    // `abs(modulus * quotient) < 2^{trunc_len - 1 + F::NUM_BITS - 1} <= 2^{trunc_len - 1} * native_modulus::<F> - abs(a)` given our assumption `abs(a) <= 2^{n * k - 1 + F::NUM_BITS - 2}`
    let quot_max_bits = trunc_len - 1 + (F::NUM_BITS as usize) - 1 - (modulus.bits() as usize);
    debug_assert!(quot_max_bits < trunc_len);
    // Let n' <= quot_max_bits - n(k-1) - 1
    // If quot[i] <= 2^n for i < k - 1 and quot[k-1] <= 2^{n'} then
    // quot < 2^{n(k-1)+1} + 2^{n' + n(k-1)} = (2+2^{n'}) 2^{n(k-1)} < 2^{n'+1} * 2^{n(k-1)} <= 2^{quot_max_bits - n(k-1)} * 2^{n(k-1)}
    let quot_last_limb_bits = quot_max_bits - n * (k - 1);

    let out_max_bits = modulus.bits() as usize;
    // we assume `modulus` requires *exactly* `k` limbs to represent (if `< k` limbs ok, you should just be using that)
    let out_last_limb_bits = out_max_bits - n * (k - 1);

    // these are witness vectors:
    // we need to find `out_vec` as a proper BigInt with k limbs
    // we need to find `quot_vec` as a proper BigInt with k limbs

    let (quot_val, out_val) = a.value.div_mod_floor(modulus);

    debug_assert!(out_val < (BigInt::one() << (n * k)));
    debug_assert!(quot_val.abs() < (BigInt::one() << quot_max_bits));

    // decompose_bigint just throws away signed limbs in index >= k
    let out_vec = decompose_bigint::<F>(&out_val, k, n);
    let quot_vec = decompose_bigint::<F>(&quot_val, k, n);

    // we need to constrain that `sum_i out_vec[i] * 2^{n*i} = out_native` in `F`
    // we need to constrain that `sum_i quot_vec[i] * 2^{n*i} = quot_native` in `F`

    // assert!(modulus < &(BigUint::one() << (n * k)));
    assert_eq!(mod_vec.len(), k);
    // We need to show `out - a + modulus * quotient` is:
    // - congruent to `0 (mod 2^trunc_len)`
    // - equal to 0 in native field `F`

    // Modulo 2^trunc_len, using OverflowInteger:
    // ------------------------------------------
    // Goal: assign cells to `out - a + modulus * quotient`
    // 1. we effectively do mul_no_carry::truncate(mod_vec, quot_vec) while assigning `mod_vec` and `quot_vec` as we go
    //    call the output `prod` which has len k
    // 2. for prod[i] we can compute `prod + out - a`
    //    where we assign `out_vec` as we go

    let mut quot_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);
    let mut out_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);
    let mut check_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);

    // strategies where we carry out school-book multiplication in some form:
    //    BigIntStrategy::Simple => {
    for (i, ((a_limb, quot_v), out_v)) in
        a.truncation.limbs.into_iter().zip(quot_vec).zip(out_vec).enumerate()
    {
        let (prod, new_quot_cell) = range.gate().inner_product_left_last(
            ctx,
            quot_assigned.iter().map(|a| Existing(*a)).chain(iter::once(Witness(quot_v))),
            mod_vec[..=i].iter().rev().map(|c| Constant(*c)),
        );
        // let gate_index = prod.column();

        // perform step 2: compute prod - a + out
        let temp1 = *prod.value() - a_limb.value();
        let check_val = temp1 + out_v;

        // transpose of:
        // | prod | -1 | a | prod - a | 1 | out | prod - a + out
        // where prod is at relative row `offset`
        ctx.assign_region(
            [
                Constant(-F::ONE),
                Existing(a_limb),
                Witness(temp1),
                Constant(F::ONE),
                Witness(out_v),
                Witness(check_val),
            ],
            [-1, 2], // note the NEGATIVE index! this is using gate overlapping with the previous inner product call
        );
        let check_cell = ctx.last().unwrap();
        let out_cell = ctx.get(-2);

        quot_assigned.push(new_quot_cell);
        out_assigned.push(out_cell);
        check_assigned.push(check_cell);
    }
    //    }
    //}

    // range check limbs of `out` are in [0, 2^n) except last limb should be in [0, 2^out_last_limb_bits)
    for (out_index, out_cell) in out_assigned.iter().enumerate() {
        let limb_bits = if out_index == k - 1 { out_last_limb_bits } else { n };
        range.range_check(ctx, *out_cell, limb_bits);
    }

    // range check that quot_cell in quot_assigned is in [-2^n, 2^n) except for last cell check it's in [-2^quot_last_limb_bits, 2^quot_last_limb_bits)
    for (q_index, quot_cell) in quot_assigned.iter().enumerate() {
        let limb_bits = if q_index == k - 1 { quot_last_limb_bits } else { n };
        let limb_base =
            if q_index == k - 1 { range.gate().pow_of_two()[limb_bits] } else { limb_bases[1] };

        // compute quot_cell + 2^n and range check with n + 1 bits
        let quot_shift = range.gate().add(ctx, *quot_cell, Constant(limb_base));
        range.range_check(ctx, quot_shift, limb_bits + 1);
    }

    let check_overflow_int = OverflowInteger::new(
        check_assigned,
        max(max(limb_bits, a.truncation.max_limb_bits) + 1, 2 * n + k_bits),
    );

    // check that `out - a + modulus * quotient == 0 mod 2^{trunc_len}` after carry
    check_carry_to_zero::truncate::<F>(
        range,
        ctx,
        check_overflow_int,
        limb_bits,
        limb_bases[1],
        limb_base_big,
    );

    // Constrain `quot_native = sum_i quot_assigned[i] * 2^{n*i}` in `F`
    let quot_native =
        OverflowInteger::evaluate_native(ctx, range.gate(), quot_assigned, limb_bases);

    // Constrain `out_native = sum_i out_assigned[i] * 2^{n*i}` in `F`
    let out_native =
        OverflowInteger::evaluate_native(ctx, range.gate(), out_assigned.clone(), limb_bases);
    // We save 1 cell by connecting `out_native` computation with the following:

    // Check `out + modulus * quotient - a = 0` in native field
    // | out | modulus | quotient | a |
    ctx.assign_region(
        [Constant(mod_native), Existing(quot_native), Existing(a.native)],
        [-1], // negative index because -1 relative offset is `out_native` assigned value
    );

    ProperCrtUint(CRTInteger::new(
        ProperUint(out_assigned).into_overflow(limb_bits),
        out_native,
        out_val,
    ))
}
