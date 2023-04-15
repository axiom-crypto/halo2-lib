use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::ScalarField, AssignedValue, Context};
use num_bigint::BigInt;
use num_traits::Zero;
use std::cmp::max;

/// only use case is when coeffs has only a single 1, rest are 0
pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &[OverflowInteger<F>],
    coeffs: &[AssignedValue<F>],
) -> OverflowInteger<F> {
    let k = a[0].limbs.len();

    let out_limbs = (0..k)
        .map(|idx| {
            let int_limbs = a.iter().map(|a| a.limbs[idx]);
            gate.select_by_indicator(ctx, int_limbs, coeffs.iter().copied())
        })
        .collect();

    let max_limb_bits = a.iter().fold(0, |acc, x| max(acc, x.max_limb_bits));

    OverflowInteger::construct(out_limbs, max_limb_bits)
}

/// only use case is when coeffs has only a single 1, rest are 0
pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &[CRTInteger<F>],
    coeffs: &[AssignedValue<F>],
    limb_bases: &[F],
) -> CRTInteger<F> {
    assert_eq!(a.len(), coeffs.len());
    let k = a[0].truncation.limbs.len();

    let out_limbs = (0..k)
        .map(|idx| {
            let int_limbs = a.iter().map(|a| a.truncation.limbs[idx]);
            gate.select_by_indicator(ctx, int_limbs, coeffs.iter().copied())
        })
        .collect();

    let max_limb_bits = a.iter().fold(0, |acc, x| max(acc, x.truncation.max_limb_bits));

    let out_trunc = OverflowInteger::construct(out_limbs, max_limb_bits);
    let out_native = if a.len() > k {
        OverflowInteger::<F>::evaluate(
            gate,
            ctx,
            out_trunc.limbs.iter().copied(),
            limb_bases[..k].iter().copied(),
        )
    } else {
        let a_native = a.iter().map(|x| x.native);
        gate.select_by_indicator(ctx, a_native, coeffs.iter().copied())
    };
    let out_val = a.iter().zip(coeffs.iter()).fold(BigInt::zero(), |acc, (x, y)| {
        if y.value().is_zero_vartime() {
            acc
        } else {
            x.value.clone()
        }
    });

    CRTInteger::construct(out_trunc, out_native, out_val)
}
