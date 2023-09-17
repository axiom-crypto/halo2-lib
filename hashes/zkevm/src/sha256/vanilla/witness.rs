use getset::Getters;
use halo2_base::{
    halo2_proofs::circuit::{Region, Value},
    utils::halo2::{raw_assign_advice, raw_assign_fixed, Halo2AssignedCell},
};
use itertools::Itertools;
use log::debug;
use rayon::prelude::*;

use crate::{
    sha256::vanilla::util::{decode, into_be_bits, rotate, shift},
    util::{eth_types::Field, word::Word},
};

use super::{columns::Sha256CircuitConfig, param::*, util::get_num_sha2_blocks};

/// The values of a row _to be assigned_ in the SHA-256 circuit.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VirtualShaRow {
    w: [bool; NUM_BITS_PER_WORD_W],
    a: [bool; NUM_BITS_PER_WORD_EXT],
    e: [bool; NUM_BITS_PER_WORD_EXT],
    pub(crate) is_paddings: [bool; ABSORB_WIDTH_PER_ROW_BYTES],
    pub is_final: bool,
    pub length: usize,
    /// A SHA-256 word (32 bytes) of the input, in little endian, when `q_input` is true.
    /// Unconstrained when `q_input` is false.
    pub word_value: u32,
    /// Hash digest (32 bytes) in hi-lo form.
    pub hash: Word<u128>,
}

/// The assigned cells of [VirtualShaRow] that belong in [ShaTable]. We only keep the [ShaTable] parts since
/// those may be used externally.
#[derive(Clone, Debug)]
struct AssignedShaTableRow<'v, F: Field> {
    /// Only set is_enabled to true when is_final is true and it's a squeeze row
    /// is_enabled := q_squeeze && is_final
    /// Only constrained when `q_enable` true
    is_enabled: Halo2AssignedCell<'v, F>,
    /// Hash digest (32 bytes) in hi-lo form.
    output: Word<Halo2AssignedCell<'v, F>>,
    /// u32 input word, little-endian
    /// Only constrained on rows with `q_input` true.
    word_value: Halo2AssignedCell<'v, F>,
    /// Length in bytes of the input processed so far. Does not include padding.
    /// Only constrained on rows with `q_input` true.
    length: Halo2AssignedCell<'v, F>,
}

/// The assigned cells from a chunk of `SHA256_NUM_ROWS` rows corresponding to a 512-bit SHA-256 input block.
/// We get the relevant cells from the correct rows, so the user doesn't need to think about circuit internal logic.
#[derive(Clone, Debug, Getters)]
pub struct AssignedSha256Block<'v, F: Field> {
    /// This input block is the last one for a variable length input.
    #[getset(get = "pub")]
    pub(crate) is_final: Halo2AssignedCell<'v, F>,
    /// Hash digest (32 bytes) in hi-lo form. Should **not** be used if `is_final` is false.
    #[getset(get = "pub")]
    pub(crate) output: Word<Halo2AssignedCell<'v, F>>,
    /// Input words (u32) of this block, each u32 consists of the input bytes **in little-endian**
    #[getset(get = "pub")]
    pub(crate) word_values: [Halo2AssignedCell<'v, F>; NUM_WORDS_TO_ABSORB],
    /// Length in bytes of the input processed so far. Does not include padding.
    /// This should only be used if `is_final` is true.
    #[getset(get = "pub")]
    pub(crate) length: Halo2AssignedCell<'v, F>,
}

// Functions for assigning witnesses to Halo2AssignedCells.
// Skip below this block to see the witness generation logic functions themselves.
impl<F: Field> Sha256CircuitConfig<F> {
    /// Computes witnesses for computing SHA-256 for each bytearray in `bytes`
    /// and assigns the witnesses to Halo2 cells, starting from a blank region.
    pub fn multi_sha256<'v>(
        &self,
        region: &mut Region<'_, F>,
        bytes: Vec<Vec<u8>>,
        capacity: Option<usize>,
    ) -> Vec<AssignedSha256Block<'v, F>> {
        self.multi_sha256_shifted(region, bytes, capacity, 0)
    }

    /// Computes witnesses for computing SHA-256 for each bytearray in `bytes`
    /// and assigns the witnesses to Halo2 cells, starting from row offset `start_offset`.
    ///
    /// **Warning:** Low level call. User needs to supply `start_offset` correctly.
    pub fn multi_sha256_shifted<'v>(
        &self,
        region: &mut Region<'_, F>,
        bytes: Vec<Vec<u8>>,
        capacity: Option<usize>,
        start_offset: usize,
    ) -> Vec<AssignedSha256Block<'v, F>> {
        let virtual_rows = generate_witnesses_multi_sha256(bytes, capacity);
        let assigned_rows: Vec<_> = virtual_rows
            .into_iter()
            .enumerate()
            .map(|(offset, row)| self.set_row(region, start_offset + offset, row))
            .collect();
        debug_assert_eq!(assigned_rows.len() % SHA256_NUM_ROWS, 0);
        assigned_rows
            .chunks_exact(SHA256_NUM_ROWS)
            .map(|rows| {
                let last_row = rows.last();
                let is_final = last_row.unwrap().is_enabled.clone();
                let output = last_row.unwrap().output.clone();
                let input_rows = &rows[NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB];
                let word_values: [_; NUM_WORDS_TO_ABSORB] = input_rows
                    .iter()
                    .map(|row| row.word_value.clone())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let length = input_rows.last().unwrap().length.clone();
                AssignedSha256Block { is_final, output, word_values, length }
            })
            .collect()
    }

    /// Phase 0 (= FirstPhase) assignment of row to Halo2 assigned cells.
    /// Output is `length` at that row
    fn set_row<'v>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: VirtualShaRow,
    ) -> AssignedShaTableRow<'v, F> {
        let round = offset % SHA256_NUM_ROWS;
        let q_squeeze = round == SHA256_NUM_ROWS - 1;

        // Fixed values
        for (_name, column, value) in &[
            ("q_enable", self.q_enable, F::from(true)),
            ("q_first", self.q_first, F::from(offset == 0)),
            (
                "q_extend",
                self.q_extend,
                F::from(
                    (NUM_START_ROWS + NUM_WORDS_TO_ABSORB..NUM_START_ROWS + NUM_ROUNDS)
                        .contains(&round),
                ),
            ),
            ("q_start", self.q_start, F::from(round < NUM_START_ROWS)),
            (
                "q_compression",
                self.q_compression,
                F::from((NUM_START_ROWS..NUM_ROUNDS + NUM_START_ROWS).contains(&round)),
            ),
            ("q_end", self.q_end, F::from(round >= NUM_ROUNDS + NUM_START_ROWS)),
            (
                "q_input",
                self.q_input,
                F::from((NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB).contains(&round)),
            ),
            (
                "q_input_last",
                self.q_input_last,
                F::from(round == NUM_START_ROWS + NUM_WORDS_TO_ABSORB - 1),
            ),
            ("q_squeeze", self.q_squeeze, F::from(q_squeeze)),
            (
                "round_cst",
                self.round_cst,
                F::from(if (NUM_START_ROWS..NUM_START_ROWS + NUM_ROUNDS).contains(&round) {
                    ROUND_CST[round - NUM_START_ROWS] as u64
                } else {
                    0
                }),
            ),
            ("Ha", self.h_a, F::from(if round < 4 { H[3 - round] as u64 } else { 0 })),
            ("He", self.h_e, F::from(if round < 4 { H[7 - round] as u64 } else { 0 })),
        ] {
            raw_assign_fixed(region, *column, offset, *value);
        }

        // Advice values
        for (_name, columns, values) in [
            ("w bits", self.word_w.as_slice(), row.w.as_slice()),
            ("a bits", self.word_a.as_slice(), row.a.as_slice()),
            ("e bits", self.word_e.as_slice(), row.e.as_slice()),
            ("padding selectors", self.is_paddings.as_slice(), row.is_paddings.as_slice()),
            ("is_final", [self.is_final].as_slice(), [row.is_final].as_slice()),
        ] {
            for (value, column) in values.iter().zip_eq(columns.iter()) {
                raw_assign_advice(region, *column, offset, Value::known(F::from(*value)));
            }
        }

        let is_enabled = row.is_final && q_squeeze;
        let [is_enabled, hash_lo, hash_hi, word_value, length] = [
            (self.hash_table.is_enabled, F::from(is_enabled)),
            (self.hash_table.output.lo(), F::from_u128(row.hash.lo())),
            (self.hash_table.output.hi(), F::from_u128(row.hash.hi())),
            (self.hash_table.word_value, F::from(row.word_value as u64)),
            (self.hash_table.length, F::from(row.length as u64)),
        ]
        .map(|(column, value)| raw_assign_advice(region, column, offset, Value::known(value)));

        AssignedShaTableRow {
            is_enabled,
            output: Word::new([hash_lo, hash_hi]),
            word_value,
            length,
        }
    }
}

/// Generates virtual rows of witnesses necessary for computing SHA256(input_bytes)
/// and appends them to `rows`.
///
/// Not generally recommended to call this function directly.
pub fn generate_witnesses_sha256(rows: &mut Vec<VirtualShaRow>, input_bytes: &[u8]) {
    let mut bits = into_be_bits(input_bytes);

    // Padding
    let length = bits.len();
    let mut length_in_bits = into_be_bits(&(length as u64).to_be_bytes());
    assert_eq!(length_in_bits.len(), NUM_BITS_PADDING_LENGTH);
    bits.push(1);
    while (bits.len() + NUM_BITS_PADDING_LENGTH) % RATE_IN_BITS != 0 {
        bits.push(0);
    }
    bits.append(&mut length_in_bits);
    assert_eq!(bits.len() % RATE_IN_BITS, 0);

    // Set the initial state
    let mut hs: [u64; 8] = H.iter().map(|v| *v as u64).collect::<Vec<_>>().try_into().unwrap();
    let mut length = 0usize;
    let mut in_padding = false;

    let zero_hash = [0; NUM_BYTES_TO_SQUEEZE];
    let mut hash_bytes = zero_hash;
    // Process each block
    let chunks = bits.chunks(RATE_IN_BITS);
    let num_chunks = chunks.len();
    for (idx, chunk) in chunks.enumerate() {
        // Adds a row
        let mut add_row = |w: u64,
                           a: u64,
                           e: u64,
                           is_final,
                           length,
                           is_paddings,
                           hash_bytes: [u8; NUM_BYTES_TO_SQUEEZE]| {
            let word_to_bits = |value: u64, num_bits: usize| {
                into_be_bits(&value.to_be_bytes())[64 - num_bits..64]
                    .iter()
                    .map(|b| *b != 0)
                    .collect::<Vec<_>>()
            };
            let mut word_bytes_be = (w as u32).to_be_bytes();
            for (byte, is_padding) in word_bytes_be.iter_mut().zip(is_paddings) {
                *byte = if is_padding { 0 } else { *byte };
            }
            let word_value = u32::from_le_bytes(word_bytes_be);
            let hash_lo = u128::from_be_bytes(hash_bytes[16..].try_into().unwrap());
            let hash_hi = u128::from_be_bytes(hash_bytes[..16].try_into().unwrap());
            rows.push(VirtualShaRow {
                w: word_to_bits(w, NUM_BITS_PER_WORD_W).try_into().unwrap(),
                a: word_to_bits(a, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                e: word_to_bits(e, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                is_final,
                length,
                is_paddings,
                word_value,
                hash: Word::new([hash_lo, hash_hi]),
            });
        };

        // Last block for this hash
        let is_final_block = idx == num_chunks - 1;

        // Set the state
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7]);

        // Add start rows
        let mut add_row_start = |a: u64, e: u64, is_final| {
            add_row(0, a, e, is_final, length, [false, false, false, in_padding], zero_hash)
        };
        add_row_start(d, h, idx == 0);
        add_row_start(c, g, idx == 0);
        add_row_start(b, f, idx == 0);
        add_row_start(a, e, idx == 0);

        let mut ws = Vec::new();
        for (round, round_cst) in ROUND_CST.iter().enumerate() {
            // Padding/Length
            let mut is_paddings = [false; ABSORB_WIDTH_PER_ROW_BYTES];
            if round < NUM_WORDS_TO_ABSORB {
                // padding/length
                for is_padding in is_paddings.iter_mut() {
                    *is_padding = if length == input_bytes.len() {
                        true
                    } else {
                        length += 1;
                        false
                    };
                }
                in_padding = *is_paddings.last().unwrap();
            }
            // w
            let w_ext = if round < NUM_WORDS_TO_ABSORB {
                decode::value(&chunk[round * 32..(round + 1) * 32])
            } else {
                let get_w = |offset: usize| ws[ws.len() - offset] & 0xFFFFFFFF;
                let s0 = rotate::value(get_w(15), 7)
                    ^ rotate::value(get_w(15), 18)
                    ^ shift::value(get_w(15), 3);
                let s1 = rotate::value(get_w(2), 17)
                    ^ rotate::value(get_w(2), 19)
                    ^ shift::value(get_w(2), 10);
                get_w(16) + s0 + get_w(7) + s1
            };
            // Masking to ensure word is 32 bits
            let w = w_ext & 0xFFFFFFFF;
            ws.push(w);

            // compression
            let s1 = rotate::value(e, 6) ^ rotate::value(e, 11) ^ rotate::value(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h + s1 + ch + (*round_cst as u64) + w;
            let s0 = rotate::value(a, 2) ^ rotate::value(a, 13) ^ rotate::value(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;

            // Add the row
            add_row(
                w_ext,
                a,
                e,
                false,
                if round < NUM_WORDS_TO_ABSORB { length } else { 0 },
                is_paddings,
                zero_hash,
            );

            // Truncate the newly calculated values
            a &= 0xFFFFFFFF;
            e &= 0xFFFFFFFF;
        }

        // Accumulate
        hs[0] += a;
        hs[1] += b;
        hs[2] += c;
        hs[3] += d;
        hs[4] += e;
        hs[5] += f;
        hs[6] += g;
        hs[7] += h;

        // Squeeze
        hash_bytes = if is_final_block {
            hs.iter()
                .flat_map(|h| (*h as u32).to_be_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        } else {
            zero_hash
        };

        // Add end rows
        let mut add_row_end = |a: u64, e: u64| {
            add_row(0, a, e, false, 0, [false; ABSORB_WIDTH_PER_ROW_BYTES], zero_hash)
        };
        add_row_end(hs[3], hs[7]);
        add_row_end(hs[2], hs[6]);
        add_row_end(hs[1], hs[5]);
        add_row(
            0,
            hs[0],
            hs[4],
            is_final_block,
            length,
            [false, false, false, in_padding],
            hash_bytes,
        );

        // Now truncate the results
        for h in hs.iter_mut() {
            *h &= 0xFFFFFFFF;
        }
    }

    debug!("hash: {:x?}", hash_bytes);
}

/// Does multi-threaded witness generation by calling [sha256] on each input in `multi_input_bytes` in parallel.
/// Returns `rows` needs to be assigned using `set_row` inside a circuit.
/// The order of `rows` is the same as `multi_input_bytes` (hence it is deterministic).
///
/// If `capacity` is specified, then extra dummy inputs of empty bytearray ("") are added until
/// the total number of SHA-256 blocks "absorbed" is equal to `capacity`.
pub fn generate_witnesses_multi_sha256(
    multi_input_bytes: Vec<Vec<u8>>,
    capacity: Option<usize>,
) -> Vec<VirtualShaRow> {
    // Actual SHA-256, FirstPhase
    let rows: Vec<_> = multi_input_bytes
        .par_iter()
        .map(|input_bytes| {
            let num_chunks = get_num_sha2_blocks(input_bytes.len());
            let mut rows = Vec::with_capacity(num_chunks * SHA256_NUM_ROWS);
            generate_witnesses_sha256(&mut rows, input_bytes);
            rows
        })
        .collect();
    let mut rows = rows.concat();

    if let Some(capacity) = capacity {
        // Pad with no data hashes to the expected capacity
        while rows.len() < capacity * SHA256_NUM_ROWS {
            generate_witnesses_sha256(&mut rows, &[]);
        }
        // Check that we are not over capacity
        if rows.len() > capacity * SHA256_NUM_ROWS {
            panic!("SHA-256 Circuit Over Capacity");
        }
    }
    rows
}
