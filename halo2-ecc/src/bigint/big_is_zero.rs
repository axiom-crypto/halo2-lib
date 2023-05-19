use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};

/// # Assumptions
/// * `a` has nonzero number of limbs
/// * The limbs of `a` are all in [0, 2<sup>a.max_limb_bits</sup>)
/// * a.limbs.len() * 2<sup>a.max_limb_bits</sup> ` is less than modulus of `F`
pub fn positive<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    debug_assert_ne!(k, 0);
    debug_assert!(a.max_limb_bits as u32 + k.ilog2() < F::CAPACITY);

    let sum = gate.sum(ctx, a.limbs.iter().copied());
    gate.is_zero(ctx, sum)
}

/// Given OverflowInteger<F> `a`, returns whether `a == 0`
///
/// # Assumptions
/// * `a` has nonzero number of limbs
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
) -> AssignedValue<F> {
    debug_assert!(!a.limbs.is_empty());

    let mut a_limbs = a.limbs.iter();
    let mut partial = gate.is_zero(ctx, *a_limbs.next().unwrap());
    for &a_limb in a_limbs {
        let limb_is_zero = gate.is_zero(ctx, a_limb);
        partial = gate.and(ctx, limb_is_zero, partial);
    }
    partial
}

pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
) -> AssignedValue<F> {
    let out_trunc = assign::<F>(gate, ctx, &a.truncation);
    let out_native = gate.is_zero(ctx, a.native);
    gate.and(ctx, out_trunc, out_native)
}
