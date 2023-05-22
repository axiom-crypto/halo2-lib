use super::{CRTInteger, OverflowInteger, ProperCrtUint};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use itertools::Itertools;

/// # Assumptions
/// * Should only be called on integers a, b in proper representation with all limbs having at most `limb_bits` number of bits
/// * `a, b` have same nonzero number of limbs
pub fn assign<F: ScalarField>(
    range: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    b: OverflowInteger<F>,
    limb_bits: usize,
    limb_base: F,
) -> (OverflowInteger<F>, AssignedValue<F>) {
    debug_assert!(a.max_limb_bits <= limb_bits);
    debug_assert!(b.max_limb_bits <= limb_bits);
    let k = a.limbs.len();
    let mut out_limbs = Vec::with_capacity(k);

    let mut borrow: Option<AssignedValue<F>> = None;
    for (a_limb, b_limb) in a.limbs.into_iter().zip_eq(b.limbs) {
        let (bottom, lt) = match borrow {
            None => {
                let lt = range.is_less_than(ctx, a_limb, b_limb, limb_bits);
                (b_limb, lt)
            }
            Some(borrow) => {
                let b_plus_borrow = range.gate().add(ctx, b_limb, borrow);
                let lt = range.is_less_than(ctx, a_limb, b_plus_borrow, limb_bits + 1);
                (b_plus_borrow, lt)
            }
        };
        let out_limb = {
            // | a | lt | 2^n | a + lt * 2^n | -1 | bottom | a + lt * 2^n - bottom
            let a_with_borrow_val = limb_base * lt.value() + a_limb.value();
            let out_val = a_with_borrow_val - bottom.value();
            ctx.assign_region_last(
                [
                    Existing(a_limb),
                    Existing(lt),
                    Constant(limb_base),
                    Witness(a_with_borrow_val),
                    Constant(-F::one()),
                    Existing(bottom),
                    Witness(out_val),
                ],
                [0, 3],
            )
        };
        out_limbs.push(out_limb);
        borrow = Some(lt);
    }
    (OverflowInteger::new(out_limbs, limb_bits), borrow.unwrap())
}

// returns (a-b, underflow), where underflow is nonzero iff a < b
/// # Assumptions
/// * `a, b` are proper CRT representations of integers with the same number of limbs
pub fn crt<F: ScalarField>(
    range: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: ProperCrtUint<F>,
    b: ProperCrtUint<F>,
    limb_bits: usize,
    limb_base: F,
) -> (CRTInteger<F>, AssignedValue<F>) {
    let (out_trunc, underflow) =
        assign(range, ctx, a.0.truncation, b.0.truncation, limb_bits, limb_base);
    let out_native = range.gate().sub(ctx, a.0.native, b.0.native);
    let out_val = a.0.value - b.0.value;
    (CRTInteger::new(out_trunc, out_native, out_val), underflow)
}
