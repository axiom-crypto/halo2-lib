use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};
use itertools::Itertools;
use std::cmp::max;

/// # Assumptions
/// * `a, b` have same number of limbs
/// * Number of limbs is nonzero
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    b: OverflowInteger<F>,
    sel: AssignedValue<F>,
) -> OverflowInteger<F> {
    let out_limbs = a
        .limbs
        .into_iter()
        .zip_eq(b.limbs)
        .map(|(a_limb, b_limb)| gate.select(ctx, a_limb, b_limb, sel))
        .collect();

    OverflowInteger::construct(out_limbs, max(a.max_limb_bits, b.max_limb_bits))
}

pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
    sel: AssignedValue<F>,
) -> CRTInteger<F> {
    debug_assert_eq!(a.truncation.limbs.len(), b.truncation.limbs.len());
    let out_limbs = a
        .truncation
        .limbs
        .iter()
        .zip(b.truncation.limbs.iter())
        .map(|(&a_limb, &b_limb)| gate.select(ctx, a_limb, b_limb, sel))
        .collect();

    let out_trunc = OverflowInteger::construct(
        out_limbs,
        max(a.truncation.max_limb_bits, b.truncation.max_limb_bits),
    );

    let out_native = gate.select(ctx, a.native, b.native, sel);
    let out_val = if sel.value().is_zero_vartime() { b.value.clone() } else { a.value.clone() };
    CRTInteger::construct(out_trunc, out_native, out_val)
}
