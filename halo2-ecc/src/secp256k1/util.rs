use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::plonk::Error,
    utils::{biguint_to_fe, fe_to_biguint, BigPrimeField},
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use num_bigint::BigUint;

pub fn fe_to_bits_le<F: BigPrimeField>(val: &F, size: usize) -> Vec<bool> {
    let val_bytes = fe_to_biguint(val).to_bytes_le();
    let mut bits =
        val_bytes.iter().flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)).collect_vec();
    bits.extend_from_slice(&vec![false; size - bits.len()]);
    bits
}

pub fn bits_le_to_fe<F: BigPrimeField>(bits: &[bool]) -> F {
    let bytes = bits
        .chunks(8)
        .map(|bits| {
            let mut byte = 0u8;
            for idx in 0..8 {
                if bits[idx] {
                    byte += 1 << idx;
                }
            }
            byte
        })
        .collect_vec();
    biguint_to_fe(&BigUint::from_bytes_le(&bytes))
}

pub fn bits_le_to_fe_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> Result<AssignedValue<F>, Error> {
    let gate = range.gate();
    let mut sum = ctx.load_zero();
    for (idx, bit) in bits.iter().enumerate() {
        gate.assert_bit(ctx, *bit);
        sum = gate.mul_add(
            ctx,
            QuantumCell::Existing(*bit),
            QuantumCell::Constant(F::from(1 << idx)),
            QuantumCell::Existing(sum),
        );
    }
    Ok(sum)
}
