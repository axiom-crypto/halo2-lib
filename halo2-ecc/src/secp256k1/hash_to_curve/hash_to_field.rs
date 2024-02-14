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
use num_bigint::BigUint;
use num_integer::div_ceil;

fn bytes_le_to_limbs<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let mut limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(bytes.len(), 8));
    for chunk in bytes.chunks(8) {
        let mut limb = ctx.load_zero();
        for i in 0..8 {
            if chunk.len() < 8 && i >= chunk.len() {
                break;
            }
            limb = fp_chip.range().gate().mul_add(
                ctx,
                chunk[i],
                QuantumCell::Constant(F::from(1 << (8 * i))),
                limb,
            );
        }
        limbs.push(limb);
    }

    limbs
}

fn bytes_to_registers<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    bytes: &[AssignedValue<F>],
) -> ProperCrtUint<F> {
    let limbs = bytes_le_to_limbs(ctx, fp_chip, bytes);

    let mut lo_limbs = limbs[..3].to_vec();
    lo_limbs.push(ctx.load_zero());

    let mut hi_limbs = limbs[3..].to_vec();
    hi_limbs.push(ctx.load_zero());

    let lo = limbs_le_to_bn(ctx, fp_chip, lo_limbs.as_slice());
    let hi = limbs_le_to_bn(ctx, fp_chip, hi_limbs.as_slice());

    let two_power_192 = fp_chip.load_constant_uint(ctx, BigUint::from(2u8).pow(192));

    let num = fp_chip.mul_no_carry(ctx, hi, two_power_192);
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
