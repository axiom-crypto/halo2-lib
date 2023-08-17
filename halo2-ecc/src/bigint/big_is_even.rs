use super::OverflowInteger;
use halo2_base::{safe_types::GateInstructions, utils::ScalarField, AssignedValue, Context};

/// # Assumptions
/// * `a` has nonzero number of limbs
pub fn positive<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    assert_ne!(k, 0);
    let first_cell: AssignedValue<F> = a.limbs[0];

    return gate.is_even(ctx, first_cell);
}
