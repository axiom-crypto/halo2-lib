use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::PrimeField, Context, QuantumCell::Existing};
use std::cmp::max;

pub fn assign<'v, F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<'_, F>,
    a: &OverflowInteger<'v, F>,
    b: &OverflowInteger<'v, F>,
) -> OverflowInteger<'v, F> {
    assert_eq!(a.limbs.len(), b.limbs.len());
    let out_limbs = a
        .limbs
        .iter()
        .zip(b.limbs.iter())
        .map(|(a_limb, b_limb)| gate.sub(ctx, Existing(a_limb), Existing(b_limb)))
        .collect();

    OverflowInteger::construct(out_limbs, max(a.max_limb_bits, b.max_limb_bits) + 1)
}

pub fn crt<'v, F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<'_, F>,
    a: &CRTInteger<'v, F>,
    b: &CRTInteger<'v, F>,
) -> CRTInteger<'v, F> {
    let out_trunc = assign::<F>(gate, ctx, &a.truncation, &b.truncation);
    let out_native = gate.sub(ctx, Existing(&a.native), Existing(&b.native));
    let out_val = a.value.as_ref().zip(b.value.as_ref()).map(|(a, b)| a - b);
    CRTInteger::construct(out_trunc, out_native, out_val)
}
