use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::{fe_to_biguint, BigPrimeField},
    AssignedValue, Context,
};
use itertools::Itertools;
use num_bigint::{BigUint, ToBigInt};

use crate::{
    bigint::{CRTInteger, OverflowInteger, ProperCrtUint},
    fields::FieldChip,
    secp256k1::FpChip,
};

pub(crate) fn byte_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte: &AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    range.range_check(ctx, *byte, 8);
    range.gate().num_to_bits(ctx, *byte, 8)
}

pub(crate) fn bytes_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bytes.iter().flat_map(|byte| byte_to_bits_le_assigned(ctx, range, byte)).collect_vec()
}

pub(crate) fn bits_le_to_byte_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> AssignedValue<F> {
    assert_eq!(bits.len(), 8);
    let _ = bits.iter().map(|bit| range.gate().assert_bit(ctx, *bit));
    range.gate().bits_to_num(ctx, bits)
}

pub(crate) fn bits_le_to_bytes_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bits.chunks(8).map(|chunk| bits_le_to_byte_assigned(ctx, range, chunk)).collect_vec()
}

pub(crate) fn limbs_le_to_bn<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    limbs: &[AssignedValue<F>],
    max_limb_bits: usize,
) -> ProperCrtUint<F> {
    let mut value = BigUint::from(0u64);
    for i in 0..limbs.len() {
        value += (BigUint::from(1u64) << (max_limb_bits * i)) * fe_to_biguint(limbs[i].value());
    }

    let assigned_uint = OverflowInteger::new(limbs.to_vec(), max_limb_bits);
    let assigned_native = OverflowInteger::evaluate_native(
        ctx,
        fp_chip.range().gate(),
        limbs.to_vec(),
        &fp_chip.limb_bases,
    );
    let assigned_uint = CRTInteger::new(assigned_uint, assigned_native, value.to_bigint().unwrap());

    fp_chip.carry_mod(ctx, assigned_uint)
}
