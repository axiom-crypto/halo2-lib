use super::OverflowInteger;
use halo2_base::{gates::RangeInstructions, utils::ScalarField, AssignedValue, Context};

// given OverflowInteger<F>'s `a` and `b` of the same shape,
// returns whether `a < b`
pub fn assign<F: ScalarField>(
    range: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    b: OverflowInteger<F>,
    limb_bits: usize,
    limb_base: F,
) -> AssignedValue<F> {
    // a < b iff a - b has underflow
    let (_, underflow) = super::sub::assign(range, ctx, a, b, limb_bits, limb_base);
    underflow
}
