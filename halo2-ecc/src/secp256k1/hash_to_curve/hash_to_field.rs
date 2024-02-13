use halo2_base::{
    gates::{ GateInstructions, RangeInstructions },
    utils::BigPrimeField,
    AssignedValue,
    Context,
    QuantumCell,
};
use itertools::Itertools;
use num_bigint::BigUint;
use num_integer::div_ceil;

use crate::{
    bigint::ProperCrtUint,
    fields::FieldChip,
    secp256k1::{ hash_to_curve::util::limbs_le_to_bigint, sha256::Sha256Chip, FpChip },
};

use super::expand_message_xmd::expand_message_xmd;

pub(crate) fn hash_to_field<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>]
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let expanded_msg_bytes = expand_message_xmd(ctx, fp_chip.range, sha256_chip, msg_bytes);

    let u0 = bytes_to_registers(ctx, fp_chip, &expanded_msg_bytes[0..48]);
    let u1 = bytes_to_registers(ctx, fp_chip, &expanded_msg_bytes[48..96]);

    (u0, u1)
}

fn bytes_to_registers<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    bytes: &[AssignedValue<F>]
) -> ProperCrtUint<F> {
    let mut limbs = Vec::<AssignedValue<F>>::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks(11) {
        let mut limb = ctx.load_zero();
        for i in 0..11 {
            if chunk.len() < 11 && i >= chunk.len() {
                break;
            }
            limb = fp_chip
                .range()
                .gate()
                .mul_add(ctx, chunk[i], QuantumCell::Constant(F::from(1 << (8 * i))), limb);
        }
        limbs.push(limb);
    }

    let assigned_ints = limbs
        .iter()
        .map(|limb| { limbs_le_to_bigint(ctx, fp_chip.range(), fp_chip, &[*limb], 88) })
        .collect_vec();

    // let mut assigned_int = assigned_ints[0];
    // for (i, int) in assigned_ints.iter().enumerate() {
    //     let multiplier = fp_chip.load_constant_uint(ctx, BigUint::from(2u8).pow((88 * i) as u32));
    //     let limb = fp_chip.mul_no_carry(ctx, *int, multiplier);
    //     assigned_int = fp_chip.add_no_carry(ctx, assigned_int, limb);
    // }

    fp_chip.load_constant_uint(ctx, BigUint::from(1u64)) // TODO
}
