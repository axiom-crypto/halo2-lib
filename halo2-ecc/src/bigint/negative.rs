use super::OverflowInteger;
use halo2_base::{gates::GateInstructions, utils::PrimeField, Context, QuantumCell::Existing};

pub fn assign<'v, F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<'_, F>,
    a: &OverflowInteger<'v, F>,
) -> OverflowInteger<'v, F> {
    let out_limbs = a.limbs.iter().map(|limb| gate.neg(ctx, Existing(limb))).collect();
    OverflowInteger::construct(out_limbs, a.max_limb_bits)
}
