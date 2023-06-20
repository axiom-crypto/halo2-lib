use super::{CRTInteger, OverflowInteger};
use halo2_base::{
    gates::GateInstructions,
    utils::{log2_ceil, ScalarField},
    Context,
    QuantumCell::Constant,
};

pub fn assign<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: OverflowInteger<F>,
    c_f: F,
    c_log2_ceil: usize,
) -> OverflowInteger<F> {
    let out_limbs = a.limbs.into_iter().map(|limb| gate.mul(ctx, limb, Constant(c_f))).collect();
    OverflowInteger::new(out_limbs, a.max_limb_bits + c_log2_ceil)
}

pub fn crt<F: ScalarField>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    a: CRTInteger<F>,
    c: i64,
) -> CRTInteger<F> {
    let (c_f, c_abs) = if c >= 0 {
        let c_abs = u64::try_from(c).unwrap();
        (F::from(c_abs), c_abs)
    } else {
        let c_abs = u64::try_from(-c).unwrap();
        (-F::from(c_abs), c_abs)
    };

    let out_overflow = assign(gate, ctx, a.truncation, c_f, log2_ceil(c_abs));
    let out_native = gate.mul(ctx, a.native, Constant(c_f));
    let out_val = a.value * c;

    CRTInteger::new(out_overflow, out_native, out_val)
}
