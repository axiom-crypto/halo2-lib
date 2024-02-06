use halo2_base::{
    gates::{ GateInstructions, RangeChip, RangeInstructions },
    utils::BigPrimeField,
    AssignedValue,
    Context,
    QuantumCell,
};

use crate::{ bigint::{ ProperCrtUint, ProperUint }, secp256k1::sha256::Sha256Chip };

use super::expand_message_xmd::expand_message_xmd;

pub fn hash_to_field<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>]
) -> (ProperCrtUint<F>, ProperCrtUint<F>) {
    let expanded_msg_bytes = expand_message_xmd(ctx, range, sha256_chip, msg_bytes);

    let u0 = bytes_to_registers(ctx, range, &expanded_msg_bytes[0..48]);
    let u1 = bytes_to_registers(ctx, range, &expanded_msg_bytes[48..96]);

    (u0, u1)
}

fn bytes_to_registers<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>]
) -> ProperCrtUint<F> {
    assert_eq!(bytes.len(), 48);

    let gate = range.gate();

    let mut assigned_int = Vec::<AssignedValue<F>>::new();
    for (_, chunk) in bytes.chunks(8).enumerate() {
        let mut assigned_u64 = ctx.load_zero();
        for (j, byte) in chunk.iter().enumerate() {
            assigned_u64 = gate.mul_add(
                ctx,
                QuantumCell::Existing(*byte),
                QuantumCell::Constant(F::from(1 << (8 * j))),
                QuantumCell::Existing(assigned_u64)
            );
        }
        assigned_int.push(assigned_u64);
    }

    // TODO: calculate, out = assigned_int (mod SECP_MODULUS)
    let mut int_bases = Vec::<F>::with_capacity(assigned_int.len());
    for i in 0..assigned_int.len() {
        int_bases.push(F::from(1 << (64 * i)));
    }

    let assigned_int = ProperUint(assigned_int);

    assigned_int
}
