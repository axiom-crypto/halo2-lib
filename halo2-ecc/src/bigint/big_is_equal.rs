use super::ProperUint;
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};
use itertools::Itertools;

/// Given [`ProperUint`]s `a` and `b` with the same number of limbs,
/// returns whether `a == b`.
///
/// # Assumptions:
/// * `a, b` have the same number of limbs.
/// * The number of limbs is nonzero.
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: impl Into<ProperUint<F>>,
    b: impl Into<ProperUint<F>>,
) -> AssignedValue<F> {
    let a = a.into();
    let b = b.into();
    debug_assert!(!a.0.is_empty());

    let mut a_limbs = a.0.into_iter();
    let mut b_limbs = b.0.into_iter();
    let mut partial = gate.is_equal(ctx, a_limbs.next().unwrap(), b_limbs.next().unwrap());
    for (a_limb, b_limb) in a_limbs.zip_eq(b_limbs) {
        let eq_limb = gate.is_equal(ctx, a_limb, b_limb);
        partial = gate.and(ctx, eq_limb, partial);
    }
    partial
}
