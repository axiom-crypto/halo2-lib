use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;

use crate::secp256k1::util::{bits_le_to_fe_assigned, fe_to_bits_le};

pub fn byte_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte: &AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    let bits = fe_to_bits_le(byte.value(), 8);
    let assigned_bits =
        bits.iter().map(|bit| ctx.load_constant(F::from(*bit as u64))).collect_vec();

    let _byte = bits_le_to_fe_assigned(ctx, range, &assigned_bits).unwrap();
    ctx.constrain_equal(byte, &_byte);

    assigned_bits
}

pub fn bytes_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bytes.iter().flat_map(|byte| byte_to_bits_le_assigned(ctx, range, byte)).collect_vec()
}

pub fn bits_le_to_byte_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> AssignedValue<F> {
    assert_eq!(bits.len(), 8);
    let gate = range.gate();
    let mut sum = ctx.load_zero();
    for (idx, bit) in bits.iter().enumerate() {
        sum = gate.mul_add(ctx, *bit, QuantumCell::Constant(F::from(1 << idx)), sum);
    }
    sum
}

pub fn bits_le_to_bytes_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bits.chunks(8).map(|chunk| bits_le_to_byte_assigned(ctx, range, chunk)).collect_vec()
}
