use halo2_base::{
    gates::GateInstructions, utils::BigPrimeField, AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use num_bigint::BigUint;

use crate::bigint::{ProperCrtUint, ProperUint};

/// Integer to Octet Stream (numberToBytesBE)
pub fn i2osp<F: BigPrimeField>(
    mut value: u128,
    length: usize,
    mut f: impl FnMut(F) -> AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    let mut octet_string = vec![0; length];
    for i in (0..length).rev() {
        octet_string[i] = value & 0xff;
        value >>= 8;
    }
    octet_string.into_iter().map(|b| f(F::from(b as u64))).collect()
}

pub fn strxor<F: BigPrimeField>(
    a: impl IntoIterator<Item = AssignedValue<F>>,
    b: impl IntoIterator<Item = AssignedValue<F>>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> Vec<AssignedValue<F>> {
    a.into_iter().zip(b).map(|(a, b)| bitwise_xor::<_, 8>(a, b, gate, ctx)).collect()
}

pub fn bitwise_xor<F: BigPrimeField, const BITS: usize>(
    a: AssignedValue<F>,
    b: AssignedValue<F>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> AssignedValue<F> {
    let a_bits = gate.num_to_bits(ctx, a, BITS);
    let b_bits = gate.num_to_bits(ctx, b, BITS);

    let xor_bits =
        a_bits.into_iter().zip(b_bits).map(|(a, b)| gate.xor(ctx, a, b)).collect_vec();

    bits_to_num(gate, ctx, xor_bits)
}

pub fn bits_to_num<F: BigPrimeField, I: IntoIterator<Item = AssignedValue<F>>>(
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
    bits: I,
) -> AssignedValue<F>
where
    I::IntoIter: DoubleEndedIterator + ExactSizeIterator,
{
    let bits_iter = bits.into_iter();
    assert!(bits_iter.len() <= F::NUM_BITS as usize);
    bits_iter.rev().fold(ctx.load_zero(), |acc, bit| {
        gate.mul_add(ctx, acc, QuantumCell::Constant(F::from(2u64)), bit)
    })
}

/// Converts assigned bytes into biginterger
/// Warning: method does not perform any checks on input `bytes`.
pub fn decode_into_field<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: Vec<AssignedValue<F>>,
    limb_bases: &[F],
    limb_bits: usize,
) -> ProperCrtUint<F> {
    let limb_bytes = limb_bits / 8;
    let bits = limb_bases.len() * limb_bits;

    let value =
        BigUint::from_bytes_le(&bytes.iter().map(|v| v.value().get_lower_32() as u8).collect_vec());

    // inputs is a bool or uint8.
    let assigned_uint = if bits == 1 || limb_bytes == 8 {
        ProperUint(bytes)
    } else {
        let byte_base =
            (0..limb_bytes).map(|i| QuantumCell::Constant(gate.pow_of_two()[i * 8])).collect_vec();
        let limbs = bytes
            .chunks(limb_bytes)
            .map(|chunk| gate.inner_product(ctx, chunk.to_vec(), byte_base[..chunk.len()].to_vec()))
            .collect::<Vec<_>>();
        ProperUint(limbs)
    };

    assigned_uint.into_crt(ctx, gate, value, limb_bases, limb_bits)
}

pub fn decode_into_field_be<F: BigPrimeField, I: IntoIterator<Item = AssignedValue<F>>>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: I,
    limb_bases: &[F],
    limb_bits: usize,
) -> ProperCrtUint<F>
where
    I::IntoIter: DoubleEndedIterator,
{
    let bytes = bytes.into_iter().rev().collect_vec();
    decode_into_field::<F>(ctx, gate, bytes, limb_bases, limb_bits)
}
