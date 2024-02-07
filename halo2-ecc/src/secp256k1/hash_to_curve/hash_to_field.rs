use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};

use crate::{
    bigint::ProperCrtUint,
    fields::FieldChip,
    secp256k1::{hash_to_curve::util::limbs_le_to_bigint, sha256::Sha256Chip, FpChip},
};

use super::expand_message_xmd::expand_message_xmd;

pub fn hash_to_field<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>],
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let expanded_msg_bytes = expand_message_xmd(ctx, fp_chip.range, sha256_chip, msg_bytes);

    let u0 = bytes_to_registers(ctx, fp_chip, &expanded_msg_bytes[0..48]);
    let u1 = bytes_to_registers(ctx, fp_chip, &expanded_msg_bytes[48..96]);

    (u0, u1)
}

fn bytes_to_registers<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    bytes: &[AssignedValue<F>],
) -> ProperCrtUint<F> {
    assert_eq!(bytes.len(), 48);

    let range = fp_chip.range;
    let gate = range.gate();

    let mut assigned_int = Vec::<AssignedValue<F>>::new();
    for (_, chunk) in bytes.chunks(8).enumerate() {
        let mut assigned_u64 = ctx.load_zero();
        for (j, byte) in chunk.iter().enumerate() {
            assigned_u64 = gate.mul_add(
                ctx,
                QuantumCell::Existing(*byte),
                QuantumCell::Constant(F::from(1 << (8 * j))),
                QuantumCell::Existing(assigned_u64),
            );
        }
        assigned_int.push(assigned_u64);
    }

    let int = limbs_le_to_bigint(ctx, range, &assigned_int, 64);

    fp_chip.carry_mod(ctx, int.into())
}
