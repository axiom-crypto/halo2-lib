use super::expand_message_xmd::expand_message_xmd;
use crate::{
    bigint::ProperCrtUint,
    fields::FieldChip,
    secp256k1::{hash_to_curve::util::limbs_le_to_bn, sha256::Sha256Chip, FpChip},
};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use num_bigint::BigUint;

fn bytes_le_to_limbs<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let gate = fp_chip.range().gate();

    let limb_bytes = fp_chip.limb_bits() / 8;
    let byte_base =
        (0..limb_bytes).map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8])).collect_vec();
    let limbs = bytes
        .chunks(limb_bytes)
        .map(|chunk| gate.inner_product(ctx, chunk.to_vec(), byte_base[..chunk.len()].to_vec()))
        .collect::<Vec<_>>();

    limbs
}

fn bytes_to_registers<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    bytes: &[AssignedValue<F>],
) -> ProperCrtUint<F> {
    let limbs = bytes_le_to_limbs(ctx, fp_chip, bytes);

    let lo_limbs = limbs[..3].to_vec();

    let mut hi_limbs = limbs[3..].to_vec();
    hi_limbs.push(ctx.load_zero());

    let lo = limbs_le_to_bn(ctx, fp_chip, lo_limbs.as_slice(), fp_chip.limb_bits());
    let hi = limbs_le_to_bn(ctx, fp_chip, hi_limbs.as_slice(), fp_chip.limb_bits());

    let two_power_264 = fp_chip.load_constant_uint(ctx, BigUint::from(2u8).pow(264));

    let num = fp_chip.mul_no_carry(ctx, hi, two_power_264);
    let num = fp_chip.add_no_carry(ctx, num, lo);
    let num = fp_chip.carry_mod(ctx, num);

    num
}

pub(crate) fn hash_to_field<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>],
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let expanded_msg_bytes = expand_message_xmd(ctx, fp_chip.range, sha256_chip, msg_bytes);
    assert_eq!(expanded_msg_bytes.len(), 96);

    let u1 = bytes_to_registers(ctx, fp_chip, &expanded_msg_bytes[0..48]);
    let u0 = bytes_to_registers(ctx, fp_chip, &expanded_msg_bytes[48..96]);

    (u0, u1)
}
