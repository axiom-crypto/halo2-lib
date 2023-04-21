use super::{check_carry_to_zero, CRTInteger, OverflowInteger};
use crate::halo2_proofs::circuit::Value;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{biguint_to_fe, decompose_bigint_option, value_to_option, PrimeField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::{cmp::max, iter};

// same as carry_mod::crt but `out = 0` so no need to range check
//
// Assumption: the leading two bits (in big endian) are 1, and `a.max_size <= 2^{n * k - 1 + F::NUM_BITS - 2}` (A weaker assumption is also enough)
pub fn crt<F: PrimeField>(
    range: &impl RangeInstructions<F>,
    // chip: &BigIntConfig<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
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

    #[cfg(feature = "display")]
    {
        let key = format!("check_carry_mod(crt) length {k}");
        let count = ctx.op_count.entry(key).or_insert(0);
        *count += 1;

        // safety check:
        a.value
            .as_ref()
            .map(|a| assert!(a.bits() as usize <= n * k - 1 + (F::NUM_BITS as usize) - 2));
    }

    // see carry_mod.rs for explanation
    let quot_max_bits = trunc_len - 1 + (F::NUM_BITS as usize) - 1 - (modulus.bits() as usize);
    assert!(quot_max_bits < trunc_len);
    let quot_last_limb_bits = quot_max_bits - n * (k - 1);

    // these are witness vectors:
    // we need to find `quot_vec` as a proper BigInt with k limbs
    // we need to find `quot_native` as a native F element

    // we need to constrain that `sum_i quot_vec[i] * 2^{n*i} = quot_native` in `F`
    let quot_vec = if let Some(a_big) = value_to_option(a.value.as_ref()) {
        let (quot_val, _out_val) = a_big.div_mod_floor(modulus);

        // only perform safety checks in display mode so we can turn them off in production
        debug_assert_eq!(_out_val, BigInt::zero());
        debug_assert!(quot_val.abs() < (BigInt::one() << quot_max_bits));

        decompose_bigint_option::<F>(Value::known(&quot_val), k, n)
    } else {
        vec![Value::unknown(); k]
    };

    //assert!(modulus < &(BigUint::one() << (n * k)));

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
    let mut tmp_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);

    // match chip.strategy {
    //    BigIntStrategy::Simple => {
    for (i, (a_limb, quot_v)) in a.truncation.limbs.iter().zip(quot_vec.into_iter()).enumerate() {
        let (quot_cell, check_cell) = {
            let prod = range.gate().inner_product_left(
                ctx,
                quot_assigned.iter().copied().map(Existing).chain(iter::once(Witness(quot_v))),
                mod_vec[0..=i].iter().rev().map(|c| Constant(*c)),
                &mut tmp_assigned,
            );

            let quot_cell = tmp_assigned.pop().unwrap();
            // perform step 2: compute prod - a + out
            // transpose of:
            // | prod | -1 | a | prod - a |

            // This is to take care of edge case where we switch columns to handle overlap
            let alloc = ctx.advice_alloc.get_mut(range.gate().context_id()).unwrap();
            if alloc.1 + 3 >= ctx.max_rows {
                // edge case, we need to copy the last `prod` cell
                alloc.1 = 0;
                alloc.0 += 1;
                range.gate().assign_region_last(ctx, vec![Existing(prod)], vec![]);
            }

            let check_val = prod.value().zip(a_limb.value()).map(|(prod, a)| *prod - a);
            let check_cell = range.gate().assign_region_last(
                ctx,
                vec![Constant(-F::one()), Existing(*a_limb), Witness(check_val)],
                vec![(-1, None)],
            );

            (quot_cell, check_cell)
        };
        quot_assigned.push(quot_cell);
        check_assigned.push(check_cell);
    }
    //    }
    // }

    // range check that quot_cell in quot_assigned is in [-2^n, 2^n) except for last cell check it's in [-2^quot_last_limb_bits, 2^quot_last_limb_bits)
    for (q_index, quot_cell) in quot_assigned.iter().enumerate() {
        let limb_bits = if q_index == k - 1 { quot_last_limb_bits } else { n };
        let limb_base = if q_index == k - 1 {
            biguint_to_fe(&(BigUint::one() << limb_bits))
        } else {
            limb_bases[1]
        };

        // compute quot_cell + 2^n and range check with n + 1 bits
        let quot_shift = {
            // TODO: unnecessary clone
            let out_val = quot_cell.value().map(|a| limb_base + a);
            // | quot_cell | 2^n | 1 | quot_cell + 2^n |
            range.gate().assign_region_last(
                ctx,
                vec![
                    Existing(*quot_cell),
                    Constant(limb_base),
                    Constant(F::one()),
                    Witness(out_val),
                ],
                vec![(0, None)],
            )
        };
        range.range_check(ctx, &quot_shift, limb_bits + 1);
    }

    let check_overflow_int = &OverflowInteger::construct(
        check_assigned,
        max(a.truncation.max_limb_bits, 2 * n + k_bits),
    );

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
    let quot_native_assigned = OverflowInteger::<F>::evaluate(
        range.gate(),
        /*chip,*/ ctx,
        &quot_assigned,
        limb_bases.iter().cloned(),
    );

    // Check `0 + modulus * quotient - a = 0` in native field
    // | 0 | modulus | quotient | a |
    let _native_computation = range.gate().assign_region(
        ctx,
        vec![
            Constant(F::zero()),
            Constant(mod_native),
            Existing(quot_native_assigned),
            Existing(a.native),
        ],
        vec![(0, None)],
    );
}
