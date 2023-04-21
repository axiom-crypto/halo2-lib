use super::{CRTInteger, OverflowInteger};
use halo2_base::{
    gates::GateInstructions,
    utils::{log2_ceil, PrimeField},
    Context,
    QuantumCell::{Constant, Existing},
};

pub fn assign<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    c_f: F,
    c_log2_ceil: usize,
) -> OverflowInteger<F> {
    let out_limbs =
        a.limbs.iter().map(|limb| gate.mul(ctx, Existing(*limb), Constant(c_f))).collect();
    OverflowInteger::construct(out_limbs, a.max_limb_bits + c_log2_ceil)
}

pub fn crt<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    c: i64,
) -> CRTInteger<F> {
    let (c_f, c_abs) = if c >= 0 {
        let c_abs = u64::try_from(c).unwrap();
        (F::from(c_abs), c_abs)
    } else {
        let c_abs = u64::try_from(-c).unwrap();
        (-F::from(c_abs), c_abs)
    };

    let out_limbs = a
        .truncation
        .limbs
        .iter()
        .map(|limb| gate.mul(ctx, Existing(*limb), Constant(c_f)))
        .collect();

    let out_native = gate.mul(ctx, Existing(a.native), Constant(c_f));
    let out_val = a.value.as_ref().map(|a| a * c);

    CRTInteger::construct(
        OverflowInteger::construct(out_limbs, a.truncation.max_limb_bits + log2_ceil(c_abs)),
        out_native,
        out_val,
    )
}
