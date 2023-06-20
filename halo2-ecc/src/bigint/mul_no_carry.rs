use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::ScalarField, Context, QuantumCell::Existing};

/// # Assumptions
/// * `a` and `b` have the same number of limbs `k`
/// * `k` is nonzero
/// * `num_limbs_log2_ceil = log2_ceil(k)`
/// * `log2_ceil(k) + a.max_limb_bits + b.max_limb_bits <= F::NUM_BITS as usize - 2`
pub fn truncate<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    b: OverflowInteger<F>,
    num_limbs_log2_ceil: usize,
) -> OverflowInteger<F> {
    let k = a.limbs.len();
    assert_eq!(k, b.limbs.len());
    debug_assert!(k > 0);

    debug_assert!(
        num_limbs_log2_ceil + a.max_limb_bits + b.max_limb_bits <= F::NUM_BITS as usize - 2
    );

    let out_limbs = (0..k)
        .map(|i| {
            gate.inner_product(
                ctx,
                a.limbs[..=i].iter().copied(),
                b.limbs[..=i].iter().rev().map(|x| Existing(*x)),
            )
        })
        .collect();

    OverflowInteger::new(out_limbs, num_limbs_log2_ceil + a.max_limb_bits + b.max_limb_bits)
}

pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: CRTInteger<F>,
    b: CRTInteger<F>,
    num_limbs_log2_ceil: usize,
) -> CRTInteger<F> {
    let out_trunc = truncate::<F>(gate, ctx, a.truncation, b.truncation, num_limbs_log2_ceil);
    let out_native = gate.mul(ctx, a.native, b.native);
    let out_val = a.value * b.value;

    CRTInteger::new(out_trunc, out_native, out_val)
}
