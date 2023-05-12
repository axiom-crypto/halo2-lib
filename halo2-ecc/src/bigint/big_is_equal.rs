use super::{CRTInteger, OverflowInteger};
use crate::fields::PrimeField;
use halo2_base::{gates::GateInstructions, AssignedValue, Context, QuantumCell::Existing};

// given OverflowInteger<F>'s `a` and `b` of the same shape,
// returns whether `a == b`
pub fn assign<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    b: &OverflowInteger<F>,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    assert_eq!(k, b.limbs.len());
    assert_ne!(k, 0);

    let mut a_limbs = a.limbs.iter();
    let mut b_limbs = b.limbs.iter();
    let mut partial =
        gate.is_equal(ctx, Existing(*a_limbs.next().unwrap()), Existing(*b_limbs.next().unwrap()));
    for (a_limb, b_limb) in a_limbs.zip(b_limbs) {
        let eq_limb = gate.is_equal(ctx, Existing(*a_limb), Existing(*b_limb));
        partial = gate.and(ctx, Existing(eq_limb), Existing(partial));
    }
    partial
}

pub fn wrapper<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
) -> AssignedValue<F> {
    assign(gate, ctx, &a.truncation, &b.truncation)
}

pub fn crt<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
) -> AssignedValue<F> {
    let out_trunc = assign::<F>(gate, ctx, &a.truncation, &b.truncation);
    let out_native = gate.is_equal(ctx, Existing(a.native), Existing(b.native));
    gate.and(ctx, Existing(out_trunc), Existing(out_native))
}
