use super::{CRTInteger, OverflowInteger};
use halo2_base::{
    gates::GateInstructions, utils::PrimeField, AssignedValue, Context, QuantumCell::Existing,
};
use std::cmp::max;

pub fn assign<'v, F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<'_, F>,
    a: &OverflowInteger<'v, F>,
    b: &OverflowInteger<'v, F>,
    sel: &AssignedValue<'v, F>,
) -> OverflowInteger<'v, F> {
    assert_eq!(a.limbs.len(), b.limbs.len());
    let out_limbs = a
        .limbs
        .iter()
        .zip(b.limbs.iter())
        .map(|(a_limb, b_limb)| gate.select(ctx, Existing(a_limb), Existing(b_limb), Existing(sel)))
        .collect();

    OverflowInteger::construct(out_limbs, max(a.max_limb_bits, b.max_limb_bits))
}

pub fn crt<'v, F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<'_, F>,
    a: &CRTInteger<'v, F>,
    b: &CRTInteger<'v, F>,
    sel: &AssignedValue<'v, F>,
) -> CRTInteger<'v, F> {
    assert_eq!(a.truncation.limbs.len(), b.truncation.limbs.len());
    let out_limbs = a
        .truncation
        .limbs
        .iter()
        .zip(b.truncation.limbs.iter())
        .map(|(a_limb, b_limb)| gate.select(ctx, Existing(a_limb), Existing(b_limb), Existing(sel)))
        .collect();

    let out_trunc = OverflowInteger::construct(
        out_limbs,
        max(a.truncation.max_limb_bits, b.truncation.max_limb_bits),
    );

    let out_native = gate.select(ctx, Existing(&a.native), Existing(&b.native), Existing(sel));
    let out_val = a.value.as_ref().zip(b.value.as_ref()).zip(sel.value()).map(|((a, b), s)| {
        if s.is_zero_vartime() {
            b.clone()
        } else {
            a.clone()
        }
    });
    CRTInteger::construct(out_trunc, out_native, out_val)
}
