use super::{CRTInteger, OverflowInteger};
use halo2_base::{gates::GateInstructions, utils::PrimeField, Context, QuantumCell::Existing};

pub fn truncate<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    // _chip: &BigIntConfig<F>,
    ctx: &mut Context<F>,
    a: &OverflowInteger<F>,
    b: &OverflowInteger<F>,
    num_limbs_log2_ceil: usize,
) -> OverflowInteger<F> {
    let k = a.limbs.len();
    assert!(k > 0);
    assert_eq!(k, b.limbs.len());

    #[cfg(feature = "display")]
    {
        let key = format!("mul_no_carry(truncate) length {k}");
        let count = ctx.op_count.entry(key).or_insert(0);
        *count += 1;

        assert!(
            num_limbs_log2_ceil + a.max_limb_bits + b.max_limb_bits <= F::NUM_BITS as usize - 2
        );
    }

    let out_limbs = (0..k)
        .map(|i| {
            gate.inner_product(
                ctx,
                a.limbs[..=i].iter().map(Existing),
                b.limbs[..=i].iter().rev().map(Existing),
            )
        })
        .collect();

    OverflowInteger::construct(out_limbs, num_limbs_log2_ceil + a.max_limb_bits + b.max_limb_bits)
}

pub fn crt<F: PrimeField>(
    gate: &impl GateInstructions<F>,
    // chip: &BigIntConfig<F>,
    ctx: &mut Context<F>,
    a: &CRTInteger<F>,
    b: &CRTInteger<F>,
    num_limbs_log2_ceil: usize,
) -> CRTInteger<F> {
    let out_trunc = truncate::<F>(gate, ctx, &a.truncation, &b.truncation, num_limbs_log2_ceil);
    let out_native = gate.mul(ctx, Existing(&a.native), Existing(&b.native));
    let out_val = a.value.as_ref() * b.value.as_ref();

    CRTInteger::construct(out_trunc, out_native, out_val)
}
