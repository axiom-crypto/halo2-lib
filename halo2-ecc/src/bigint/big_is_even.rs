use super::OverflowInteger;
use halo2_base::gates::GateInstructions;
use halo2_base::gates::RangeChip;
use halo2_base::QuantumCell::Constant;
use halo2_base::{safe_types::RangeInstructions, utils::ScalarField, AssignedValue, Context};

/// # Assumptions
/// * `a` has nonzero number of limbs
pub fn positive<F: ScalarField>(
    gate: &RangeChip<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    limb_bits: usize,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    assert_ne!(k, 0);
    let first_cell: AssignedValue<F> = a.limbs[0];

    let last_bit = gate.get_last_bit(ctx, first_cell, limb_bits);
    gate.gate.sub(ctx, Constant(F::one()), last_bit)
}
