use super::{CRTInteger, OverflowInteger};
use halo2_base::{
    gates::GateInstructions,
    utils::{log2_ceil, PrimeField},
    Context,
    QuantumCell::{Constant, Existing, Witness},
};
use std::cmp::max;

/// compute a * c + b = b + a * c
// this is uniquely suited for our simple gate
pub fn assign<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    b: &OverflowInteger<F>,
    c_f: F,
    c_log2_ceil: usize,
) -> OverflowInteger<F> {
    assert_eq!(a.limbs.len(), b.limbs.len());

    let out_limbs = a
        .limbs
        .iter()
        .zip(b.limbs.iter())
        .map(|(a_limb, b_limb)| {
            let out_val = a_limb.value().zip(b_limb.value()).map(|(a, b)| c_f * a + b);
            gate.assign_region_last(
                ctx,
                vec![Existing(*b_limb), Existing(*a_limb), Constant(c_f), Witness(out_val)],
                vec![(0, None)],
            )
        })
        .collect();

    OverflowInteger::construct(out_limbs, max(a.max_limb_bits + c_log2_ceil, b.max_limb_bits) + 1)
}

pub fn crt<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
    c: i64,
) -> CRTInteger<F> {
    assert_eq!(a.truncation.limbs.len(), b.truncation.limbs.len());

    let (c_f, c_abs) = if c >= 0 {
        let c_abs = u64::try_from(c).unwrap();
        (F::from(c_abs), c_abs)
    } else {
        let c_abs = u64::try_from(-c).unwrap();
        (-F::from(c_abs), c_abs)
    };

    let out_trunc = assign::<F>(gate, ctx, &a.truncation, &b.truncation, c_f, log2_ceil(c_abs));
    let out_native = {
        let out_val = b.native.value().zip(a.native.value()).map(|(b, a)| c_f * a + b);
        gate.assign_region_last(
            ctx,
            vec![Existing(b.native), Existing(a.native), Constant(c_f), Witness(out_val)],
            vec![(0, None)],
        )
    };
    let out_val = a.value.as_ref().zip(b.value.as_ref()).map(|(a, b)| a * c + b);
    CRTInteger::construct(out_trunc, out_native, out_val)
}
