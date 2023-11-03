use super::OverflowInteger;
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context,
};

/// # Assumptions
/// * `a` has nonzero number of limbs
pub fn positive<F: ScalarField>(
    range: &RangeChip<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    limb_bits: usize,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    assert_ne!(k, 0);
    let first_cell: AssignedValue<F> = a.limbs[0];

    let last_bit = range.get_last_bit(ctx, first_cell, limb_bits);
    range.gate.not(ctx, last_bit)
}
