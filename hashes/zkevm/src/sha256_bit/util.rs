use super::*;

pub const NUM_BITS_PER_BYTE: usize = 8;
pub const NUM_BYTES_PER_WORD: usize = 4;
pub const NUM_BITS_PER_WORD: usize = NUM_BYTES_PER_WORD * NUM_BITS_PER_BYTE;
pub const NUM_BITS_PER_WORD_W: usize = NUM_BITS_PER_WORD + 2;
pub const NUM_BITS_PER_WORD_EXT: usize = NUM_BITS_PER_WORD + 3;
pub const NUM_ROUNDS: usize = 64;
pub const RATE: usize = 16 * NUM_BYTES_PER_WORD;
pub const RATE_IN_BITS: usize = RATE * NUM_BITS_PER_BYTE;
pub const NUM_WORDS_TO_ABSORB: usize = 16;
pub const NUM_WORDS_TO_SQUEEZE: usize = 8;
pub const NUM_BYTES_TO_SQUEEZE: usize = NUM_WORDS_TO_SQUEEZE * NUM_BYTES_PER_WORD;
pub const ABSORB_WIDTH_PER_ROW_BYTES: usize = 4;
pub const NUM_BITS_PADDING_LENGTH: usize = NUM_BYTES_PADDING_LENGTH * NUM_BITS_PER_BYTE;
pub const NUM_BYTES_PADDING_LENGTH: usize = 8;
pub const NUM_START_ROWS: usize = 4;
pub const NUM_END_ROWS: usize = 4;
/// Total number of rows per 512-bit chunk of SHA-256 circuit.
/// Currently this is a fixed constant.
pub const SHA256_NUM_ROWS: usize = NUM_ROUNDS + NUM_START_ROWS + NUM_END_ROWS;

pub(super) const MAX_DEGREE: usize = 5;

pub const ROUND_CST: [u32; NUM_ROUNDS] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const fn get_num_sha2_chunks(byte_length: usize) -> usize {
    // ceil( (byte_length + 1 + NUM_BYTES_PADDING_LENGTH))
    (byte_length + NUM_BYTES_PADDING_LENGTH) / RATE + 1
}

/// The number of 512-bit chunks of SHA-256 that can be done in a circuit
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
        let mut multiplier = F::one();
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
