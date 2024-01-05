use super::{OverflowInteger, ProperCrtUint, ProperUint};
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};

/// # Assumptions
/// * `a` has nonzero number of limbs
/// * The limbs of `a` are all in [0, 2<sup>a.max_limb_bits</sup>)
/// * a.limbs.len() * 2<sup>a.max_limb_bits</sup> ` is less than modulus of `F`
pub fn positive<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
) -> AssignedValue<F> {
    let k = a.limbs.len();
    assert_ne!(k, 0);
    assert!(a.max_limb_bits as u32 + k.ilog2() < F::CAPACITY);

    let sum = gate.sum(ctx, a.limbs);
    gate.is_zero(ctx, sum)
}

/// Given `ProperUint<F>` `a`, returns 1 iff every limb of `a` is zero. Returns 0 otherwise.
///
/// It is almost always more efficient to use [`positive`] instead.
///
/// # Assumptions
/// * `a` has nonzero number of limbs
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: ProperUint<F>,
) -> AssignedValue<F> {
    assert!(!a.0.is_empty());

    let mut a_limbs = a.0.into_iter();
    let mut partial = gate.is_zero(ctx, a_limbs.next().unwrap());
    for a_limb in a_limbs {
        let limb_is_zero = gate.is_zero(ctx, a_limb);
        partial = gate.and(ctx, limb_is_zero, partial);
    }
    partial
}

/// Returns 0 or 1. Returns 1 iff the limbs of `a` are identically zero.
/// This just calls [`assign`] on the limbs.
///
/// It is almost always more efficient to use [`positive`] instead.
pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: ProperCrtUint<F>,
) -> AssignedValue<F> {
    assign(gate, ctx, ProperUint(a.0.truncation.limbs))
}
