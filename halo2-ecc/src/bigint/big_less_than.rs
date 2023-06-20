use super::OverflowInteger;
use crate::fields::PrimeField;
use halo2_base::{gates::RangeInstructions, AssignedValue, Context};

// given OverflowInteger<F>'s `a` and `b` of the same shape,
// returns whether `a < b`
pub fn assign<F: PrimeField>(
    range: &impl RangeInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    b: &OverflowInteger<F>,
    limb_bits: usize,
    limb_base: F,
) -> AssignedValue<F> {
    // a < b iff a - b has underflow
    let (_, underflow) = super::sub::assign::<F>(range, ctx, a, b, limb_bits, limb_base);
    underflow
}
