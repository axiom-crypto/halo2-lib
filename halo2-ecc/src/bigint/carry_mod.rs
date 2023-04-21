use super::{check_carry_to_zero, CRTInteger, OverflowInteger};
use crate::halo2_proofs::circuit::Value;
use halo2_base::{
    gates::{range::RangeStrategy, GateInstructions, RangeInstructions},
    utils::{biguint_to_fe, decompose_bigint_option, value_to_option, PrimeField},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed};
use std::{cmp::max, iter};

// Input `a` is `CRTInteger` with `a.truncation` of length `k` with "signed" limbs
// Output is `out = a (mod modulus)` as CRTInteger with
// `out.value = a.value (mod modulus)`
// `out.trunction = (a (mod modulus)) % 2^t` a proper BigInt of length `k` with limbs in [0, 2^limb_bits)`
// The witness for `out.truncation` is a BigInt in [0, modulus), but we do not constrain the inequality
// `out.native = (a (mod modulus)) % (native_modulus::<F>)`
// We constrain `a = out + modulus * quotient` and range check `out` and `quotient`
//
// Assumption: the leading two bits (in big endian) are 1, and `abs(a) <= 2^{n * k - 1 + F::NUM_BITS - 2}` (A weaker assumption is also enough, but this is good enough for forseeable use cases)
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
) -> CRTInteger<F> {
    let n = limb_bits;
    let k = a.truncation.limbs.len();
    let trunc_len = n * k;

    #[cfg(feature = "display")]
    {
        let key = format!("carry_mod(crt) length {k}");
        let count = ctx.op_count.entry(key).or_insert(0);
        *count += 1;

        // safety check:
        a.value
            .as_ref()
            .map(|a| assert!(a.bits() as usize <= n * k - 1 + (F::NUM_BITS as usize) - 2));
    }

    // in order for CRT method to work, we need `abs(out + modulus * quotient - a) < 2^{trunc_len - 1} * native_modulus::<F>`
    // this is ensured if `0 <= out < 2^{n*k}` and
    // `abs(modulus * quotient) < 2^{trunc_len - 1} * native_modulus::<F> - abs(a)
    // which is ensured if
    // `abs(modulus * quotient) < 2^{trunc_len - 1 + F::NUM_BITS - 1} <= 2^{trunc_len - 1} * native_modulus::<F> - abs(a)` given our assumption `abs(a) <= 2^{n * k - 1 + F::NUM_BITS - 2}`
    let quot_max_bits = trunc_len - 1 + (F::NUM_BITS as usize) - 1 - (modulus.bits() as usize);
    assert!(quot_max_bits < trunc_len);
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

    // we need to constrain that `sum_i out_vec[i] * 2^{n*i} = out_native` in `F`
    // we need to constrain that `sum_i quot_vec[i] * 2^{n*i} = quot_native` in `F`
    let (out_val, out_vec, quot_vec) = if let Some(a_big) = value_to_option(a.value.as_ref()) {
        let (quot_val, out_val) = a_big.div_mod_floor(modulus);

        debug_assert!(out_val < (BigInt::one() << (n * k)));
        debug_assert!(quot_val.abs() < (BigInt::one() << quot_max_bits));

        (
            Value::known(out_val.clone()),
            // decompose_bigint_option just throws away signed limbs in index >= k
            decompose_bigint_option::<F>(Value::known(&out_val), k, n),
            decompose_bigint_option::<F>(Value::known(&quot_val), k, n),
        )
    } else {
        (Value::unknown(), vec![Value::unknown(); k], vec![Value::unknown(); k])
    };

    // let out_native = out_val.as_ref().map(|a| bigint_to_fe::<F>(a));
    // let quot_native = quot_val.map(|a| bigint_to_fe::<F>(&a));

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
    let mut tmp_assigned: Vec<AssignedValue<F>> = Vec::with_capacity(k);

    // match chip.strategy {
    // strategies where we carry out school-book multiplication in some form:
    //    BigIntStrategy::Simple => {
    for (i, (a_limb, (quot_v, out_v))) in
        a.truncation.limbs.iter().zip(quot_vec.into_iter().zip(out_vec.into_iter())).enumerate()
    {
        let (quot_cell, out_cell, check_cell) = {
            let prod = range.gate().inner_product_left(
                ctx,
                quot_assigned.iter().map(|a| Existing(*a)).chain(iter::once(Witness(quot_v))),
                mod_vec[..=i].iter().rev().map(|c| Constant(*c)),
                &mut tmp_assigned,
            );
            // let gate_index = prod.column();

            let quot_cell = tmp_assigned.pop().unwrap();
            let out_cell;
            let check_cell;
            // perform step 2: compute prod - a + out
            let temp1 = prod.value().zip(a_limb.value()).map(|(prod, a)| *prod - a);
            let check_val = temp1 + out_v;

            // This is to take care of edge case where we switch columns to handle overlap
            let alloc = ctx.advice_alloc.get_mut(range.gate().context_id()).unwrap();
            if alloc.1 + 6 >= ctx.max_rows {
                // edge case, we need to copy the last `prod` cell
                // dbg!(*alloc);
                alloc.1 = 0;
                alloc.0 += 1;
                range.gate().assign_region_last(ctx, [Existing(prod)], []);
            }
            match range.strategy() {
                RangeStrategy::Vertical => {
                    // transpose of:
                    // | prod | -1 | a | prod - a | 1 | out | prod - a + out
                    // where prod is at relative row `offset`
                    let mut assignments = range.gate().assign_region(
                        ctx,
                        [
                            Constant(-F::one()),
                            Existing(*a_limb),
                            Witness(temp1),
                            Constant(F::one()),
                            Witness(out_v),
                            Witness(check_val),
                        ],
                        [(-1, None), (2, None)],
                    );
                    check_cell = assignments.pop().unwrap();
                    out_cell = assignments.pop().unwrap();
                }
                RangeStrategy::PlonkPlus => {
                    // | prod | a | out | prod - a + out |
                    // selector columns:
                    // | 1    | 0 | 0   |
                    // | 0    | -1| 1   |
                    let mut assignments = range.gate().assign_region(
                        ctx,
                        [Existing(*a_limb), Witness(out_v), Witness(check_val)],
                        [(-1, Some([F::zero(), -F::one(), F::one()]))],
                    );
                    check_cell = assignments.pop().unwrap();
                    out_cell = assignments.pop().unwrap();
                }
            }
            (quot_cell, out_cell, check_cell)
        };
        quot_assigned.push(quot_cell);
        out_assigned.push(out_cell);
        check_assigned.push(check_cell);
    }
    //    }
    //}

    // range check limbs of `out` are in [0, 2^n) except last limb should be in [0, 2^out_last_limb_bits)
    for (out_index, out_cell) in out_assigned.iter().enumerate() {
        let limb_bits = if out_index == k - 1 { out_last_limb_bits } else { n };
        range.range_check(ctx, out_cell, limb_bits);
    }

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
            let out_val = quot_cell.value().map(|a| limb_base + a);
            // | quot_cell | 2^n | 1 | quot_cell + 2^n |
            range.gate().assign_region_last(
                ctx,
                [Existing(*quot_cell), Constant(limb_base), Constant(F::one()), Witness(out_val)],
                [(0, None)],
            )
        };
        range.range_check(ctx, &quot_shift, limb_bits + 1);
    }

    let check_overflow_int = &OverflowInteger::construct(
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

    // Constrain `out_native = sum_i out_assigned[i] * 2^{n*i}` in `F`
    let out_native_assigned = OverflowInteger::<F>::evaluate(
        range.gate(),
        /*chip,*/ ctx,
        &out_assigned,
        limb_bases.iter().cloned(),
    );

    // Constrain `quot_native = sum_i quot_assigned[i] * 2^{n*i}` in `F`
    let quot_native_assigned = OverflowInteger::<F>::evaluate(
        range.gate(),
        /*chip,*/ ctx,
        &quot_assigned,
        limb_bases.iter().cloned(),
    );

    // TODO: we can save 1 cell by connecting `out_native_assigned` computation with the following:

    // Check `out + modulus * quotient - a = 0` in native field
    // | out | modulus | quotient | a |
    let _native_computation = range.gate().assign_region_last(
        ctx,
        [
            Existing(out_native_assigned),
            Constant(mod_native),
            Existing(quot_native_assigned),
            Existing(a.native),
        ],
        [(0, None)],
    );

    CRTInteger::construct(
        OverflowInteger::construct(out_assigned, limb_bits),
        out_native_assigned,
        out_val,
    )
}
