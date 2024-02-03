use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};

use crate::secp256k1::sha256::Sha256Chip;

use super::{
    constants::{get_dst_prime, get_lib_str, get_z_pad},
    util::{bits_le_to_bytes_assigned, bytes_to_bits_le_assigned},
};

fn msg_prime<F: BigPrimeField>(
    ctx: &mut Context<F>,
    msg_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let zero = ctx.load_zero();

    let z_pad = get_z_pad(ctx);
    let lib_str = get_lib_str(ctx);
    let dst_prime = get_dst_prime(ctx);

    let mut msg_prime = Vec::<AssignedValue<F>>::new();

    // msg_prme = z_pad ...
    msg_prime.extend(z_pad);

    // msg_prme = z_pad || msg ...
    msg_prime.extend(msg_bytes);

    // msg_prme = z_pad || msg || lib_str ...
    msg_prime.extend(lib_str);

    // msg_prme = z_pad || msg || lib_str || 0 ...
    msg_prime.push(zero);

    // msg_prme = z_pad || msg || lib_str || 0 || dst_prime
    msg_prime.extend(dst_prime);

    msg_prime
}

fn hash_msg_prime_to_b0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    sha256_chip: &Sha256Chip<'_, F>,
    msg_prime_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let msg_prime_bytes = msg_prime_bytes.iter().map(|byte| QuantumCell::Existing(*byte));
    let hash = sha256_chip.digest(ctx, msg_prime_bytes).unwrap();
    hash
}

fn hash_bi<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    sha256_chip: &Sha256Chip<F>,
    b_idx_byte: &AssignedValue<F>,
    b0_bytes: &[AssignedValue<F>],
    bi_minus_one_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let b0_bits = bytes_to_bits_le_assigned(ctx, range, b0_bytes);
    let bi_minus_one_bits = bytes_to_bits_le_assigned(ctx, range, bi_minus_one_bytes);

    let mut xor_bits = Vec::<AssignedValue<F>>::new();
    for (bo_bit, bi_minus_one_bit) in b0_bits.iter().zip(bi_minus_one_bits.iter()) {
        let res = range.gate().xor(ctx, *bo_bit, *bi_minus_one_bit);
        xor_bits.push(res);
    }
    let xor_bytes = bits_le_to_bytes_assigned(ctx, range, &xor_bits);

    let bi_bytes = hash_b(ctx, sha256_chip, b_idx_byte, &xor_bytes);

    bi_bytes
}

fn hash_b<'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    sha256_chip: &Sha256Chip<'a, F>,
    b_idx_byte: &AssignedValue<F>,
    b_bytes: &Vec<AssignedValue<F>>,
) -> Vec<AssignedValue<F>> {
    let dst_prime = get_dst_prime(ctx);

    let mut preimage = Vec::<AssignedValue<F>>::new();
    preimage.extend(b_bytes);
    preimage.push(*b_idx_byte);
    preimage.extend(dst_prime);

    let preimage = preimage.iter().map(|byte| QuantumCell::Existing(*byte));
    let hash = sha256_chip.digest(ctx, preimage).unwrap();

    hash
}

fn str_xor<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    a_bits: &[AssignedValue<F>],
    b_bits: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    assert_eq!(a_bits.len(), b_bits.len());

    let gate = range.gate();

    let mut xor = Vec::<AssignedValue<F>>::new();
    for (a_bit, b_bit) in a_bits.iter().zip(b_bits.iter()) {
        let res = gate.xor(ctx, *a_bit, *b_bit);
        xor.push(res);
    }

    xor
}

fn expand_message_xmd<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let one = ctx.load_constant(F::from(1));
    let two = ctx.load_constant(F::from(2));
    let three = ctx.load_constant(F::from(3));

    let msg_prime_bytes = msg_prime(ctx, msg_bytes);
    let b0 = hash_msg_prime_to_b0(ctx, sha256_chip, &msg_prime_bytes);
    let b1 = hash_b(ctx, sha256_chip, &one, &b0);
    let b2 = hash_bi(ctx, range, sha256_chip, &two, &b0, &b1);
    let b3 = hash_bi(ctx, range, sha256_chip, &three, &b0, &b2);

    [b1, b2, b3].concat()
}
