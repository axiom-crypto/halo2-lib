use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};
use itertools::Itertools;

/// Given OverflowInteger<F>'s `a` and `b` of the same shape,
/// returns whether `a == b`.
///
/// # Assumptions:
/// * `a, b` have the same number of limbs.
/// * The number of limbs is nonzero.
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    b: &OverflowInteger<F>,
) -> AssignedValue<F> {
    debug_assert!(!a.limbs.is_empty());

    let mut a_limbs = a.limbs.iter();
    let mut b_limbs = b.limbs.iter();
    let mut partial = gate.is_equal(ctx, *a_limbs.next().unwrap(), *b_limbs.next().unwrap());
    for (&a_limb, &b_limb) in a_limbs.zip_eq(b_limbs) {
        let eq_limb = gate.is_equal(ctx, a_limb, b_limb);
        partial = gate.and(ctx, eq_limb, partial);
    }
    partial
}

pub fn wrapper<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
) -> AssignedValue<F> {
    assign(gate, ctx, &a.truncation, &b.truncation)
}

pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
) -> AssignedValue<F> {
    debug_assert_eq!(a.value, b.value);
    let out_trunc = assign::<F>(gate, ctx, &a.truncation, &b.truncation);
    let out_native = gate.is_equal(ctx, a.native, b.native);
    gate.and(ctx, out_trunc, out_native)
}
