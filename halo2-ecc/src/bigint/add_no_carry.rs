use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::ScalarField, Context};
use itertools::Itertools;
use std::cmp::max;

/// # Assumptions
/// * `a, b` have same number of limbs
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    b: &OverflowInteger<F>,
) -> OverflowInteger<F> {
    let out_limbs = a
        .limbs
        .iter()
        .zip_eq(b.limbs.iter())
        .map(|(&a_limb, &b_limb)| gate.add(ctx, a_limb, b_limb))
        .collect();

    OverflowInteger::construct(out_limbs, max(a.max_limb_bits, b.max_limb_bits) + 1)
}

/// # Assumptions
/// * `a, b` have same number of limbs
// pass by reference to avoid cloning the BigInt in CRTInteger, unclear if this is optimal
pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
) -> CRTInteger<F> {
    let out_trunc = assign::<F>(gate, ctx, &a.truncation, &b.truncation);
    let out_native = gate.add(ctx, a.native, b.native);
    let out_val = &a.value + &b.value;
    CRTInteger::construct(out_trunc, out_native, out_val)
}
