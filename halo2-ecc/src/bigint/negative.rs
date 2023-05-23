use super::OverflowInteger;
use halo2_base::{gates::GateInstructions, utils::ScalarField, Context};

pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
) -> OverflowInteger<F> {
    let out_limbs = a.limbs.into_iter().map(|limb| gate.neg(ctx, limb)).collect();
    OverflowInteger::new(out_limbs, a.max_limb_bits)
}
