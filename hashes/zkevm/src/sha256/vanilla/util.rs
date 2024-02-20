use halo2_base::halo2_proofs::plonk::Expression;

use crate::util::eth_types::Field;

use super::param::*;

/// The number of 512-bit blocks of SHA-256 necessary to hash an _unpadded_ byte array of `byte_length`,
/// where the number of blocks does account for padding.
pub const fn get_num_sha2_blocks(byte_length: usize) -> usize {
    // ceil( (byte_length + 1 + NUM_BYTES_PADDING_LENGTH) / RATE)
    (byte_length + NUM_BYTES_PADDING_LENGTH) / RATE + 1
}

/// The number of 512-bit blocks of SHA-256 that can be done in a circuit
/// with `num_rows` usable rows. Usable rows means rows without blinding factors.
pub const fn get_sha2_capacity(num_rows: usize) -> usize {
    num_rows / SHA256_NUM_ROWS
}

/// Decodes be bits
pub mod decode {
    use super::{Expression, Field};
    use crate::util::expression::Expr;

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>]) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for bit in bits.iter().rev() {
            value = value + bit.expr() * multiplier;
            multiplier *= F::from(2);
        }
        value
    }

    pub(crate) fn value(bits: &[u8]) -> u64 {
        let mut value = 0u64;
        for (idx, &bit) in bits.iter().rev().enumerate() {
            value += (bit as u64) << idx;
        }
        value
    }
}

/// Rotates bits to the right
pub mod rotate {
    use super::{Expression, Field};

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>], count: usize) -> Vec<Expression<F>> {
        let mut rotated = bits.to_vec();
        rotated.rotate_right(count);
        rotated
    }

    pub(crate) fn value(value: u64, count: u32) -> u64 {
        ((value as u32).rotate_right(count)) as u64
    }
}

/// Shifts bits to the right
pub mod shift {
    use super::NUM_BITS_PER_WORD;
    use super::{Expression, Field};
    use crate::util::expression::Expr;

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>], count: usize) -> Vec<Expression<F>> {
        let mut res = vec![0.expr(); count];
        res.extend_from_slice(&bits[0..NUM_BITS_PER_WORD - count]);
        res
    }

    pub(crate) fn value(value: u64, count: u32) -> u64 {
        ((value as u32) >> count) as u64
    }
}

/// Convert big-endian bits to big-endian bytes
pub mod to_be_bytes {
    use crate::util::to_bytes;

    use super::{Expression, Field};

    pub(crate) fn expr<F: Field>(bits: &[Expression<F>]) -> Vec<Expression<F>> {
        to_bytes::expr(&bits.iter().rev().cloned().collect::<Vec<_>>())
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
    }
}

/// Converts bytes into bits
pub(super) fn into_be_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits: Vec<u8> = vec![0; bytes.len() * 8];
    for (byte_idx, byte) in bytes.iter().enumerate() {
        for idx in 0u64..8 {
            bits[byte_idx * 8 + (idx as usize)] = (*byte >> (7 - idx)) & 1;
        }
    }
    bits
}
