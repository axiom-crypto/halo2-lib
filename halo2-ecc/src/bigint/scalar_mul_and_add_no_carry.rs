use super::{CRTInteger, OverflowInteger};
use halo2_base::{
    gates::GateInstructions,
    utils::{log2_ceil, ScalarField},
    Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use std::cmp::max;

/// compute a * c + b = b + a * c
///
/// # Assumptions
/// * `a, b` have same number of limbs
/// * Number of limbs is nonzero
/// * `c_log2_ceil = log2_ceil(c)` where `c` is the BigUint value of `c_f`
// this is uniquely suited for our simple gate
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    b: OverflowInteger<F>,
    c_f: F,
    c_log2_ceil: usize,
) -> OverflowInteger<F> {
    let out_limbs = a
        .limbs
        .into_iter()
        .zip_eq(b.limbs)
        .map(|(a_limb, b_limb)| gate.mul_add(ctx, a_limb, Constant(c_f), b_limb))
        .collect();

    OverflowInteger::new(out_limbs, max(a.max_limb_bits + c_log2_ceil, b.max_limb_bits) + 1)
}

/// compute a * c + b = b + a * c
pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: CRTInteger<F>,
    b: CRTInteger<F>,
    c: i64,
) -> CRTInteger<F> {
    debug_assert_eq!(a.truncation.limbs.len(), b.truncation.limbs.len());

    let (c_f, c_abs) = if c >= 0 {
        let c_abs = u64::try_from(c).unwrap();
        (F::from(c_abs), c_abs)
    } else {
        let c_abs = u64::try_from(-c).unwrap();
        (-F::from(c_abs), c_abs)
    };

    let out_trunc = assign(gate, ctx, a.truncation, b.truncation, c_f, log2_ceil(c_abs));
    let out_native = gate.mul_add(ctx, a.native, Constant(c_f), b.native);
    let out_val = a.value * c + b.value;
    CRTInteger::new(out_trunc, out_native, out_val)
}
