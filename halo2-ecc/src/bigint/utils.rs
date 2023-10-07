use halo2_base::{utils::BigPrimeField, Context, gates::GateInstructions, AssignedValue, QuantumCell};
use itertools::Itertools;
use num_bigint::BigUint;

use super::{ProperCrtUint, ProperUint};


/// Converts assigned bytes in little-endian into biginterger
/// Warning: method does not perform any checks on input `bytes`.
pub fn decode_into_bn<F: BigPrimeField>(
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
