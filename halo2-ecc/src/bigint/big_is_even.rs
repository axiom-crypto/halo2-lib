use super::OverflowInteger;
use halo2_base::{
    safe_types::{GateInstructions, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context,
};
use num_bigint::BigUint;

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

pub fn positive2<F: ScalarField>(
    gate: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    assert_ne!(k, 0);
    let first_cell: AssignedValue<F> = a.limbs[0];

    let (_, rem) = gate.div_mod(ctx, first_cell, BigUint::from(2u64), F::CAPACITY as usize - 1);
    return rem;
}
