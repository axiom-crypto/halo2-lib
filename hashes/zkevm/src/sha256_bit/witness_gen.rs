use crate::util::rlc;

use super::*;

use itertools::Itertools;
use rayon::prelude::*;

/// First phase witness, returns the final `length` after each 512-bit chunk of SHA-256 permutation.
/// This is the `length` in the last row of every [`SHA256_NUM_ROWS`] chunk of rows.
#[derive(Clone, Debug)]
pub struct MultiSha256Witness<'v, F: Field> {
    pub input_len: Vec<ShaAssignedValue<'v, F>>,
    // artifacts:
    pub original_input: Vec<Vec<u8>>,
    /// Hash digests as bytes
    // Currently digests.len() = number of different distinct (variable length) inputs
    // Then digests[i].len() is the number of chunks in that input
    pub digests: Vec<Vec<[u8; NUM_BYTES_TO_SQUEEZE]>>,
}

#[derive(Clone, Debug)]
pub struct MultiSha256Trace<'v, F: Field> {
    pub input_rlcs: Vec<ShaAssignedValue<'v, F>>,
    pub output_rlcs: Vec<ShaAssignedValue<'v, F>>,
}

impl<F: Field> Sha256BitConfig<F> {
    /// Computes FirstPhase witnesses for computes SHA-256 for each bytearray in `bytes`
    /// and assigns the witnesses to Halo2 cells
    pub fn multi_sha256_phase0<'v>(
        &self,
        region: &mut Region<'_, F>,
        bytes: Vec<Vec<u8>>,
        capacity: Option<usize>,
    ) -> MultiSha256Witness<'v, F> {
        let artifact = multi_sha256_phase0(bytes, capacity);
        self.assign_phase0(region, artifact)
    }

    pub fn multi_sha256_phase1<'v>(
        &self,
        region: &mut Region<'_, F>,
        witness: MultiSha256Witness<'_, F>,
        challenge: Value<F>,
    ) -> MultiSha256Trace<'v, F> {
        let artifact = multi_sha256_phase1(witness, challenge);
        self.assign_phase1(region, &artifact.rows)
    }

    pub fn assign_phase0<'v>(
        &self,
        region: &mut Region<'_, F>,
        witness: MultiSha256ArtifactFirstPhase<F>,
    ) -> MultiSha256Witness<'v, F> {
        let lengths: Vec<_> = witness
            .rows
            .iter()
            .enumerate()
            .map(|(offset, row)| self.set_row_phase0(region, offset, row))
            .collect();
        debug_assert_eq!(lengths.len() % SHA256_NUM_ROWS, 0);
        let input_len =
            lengths.into_iter().skip(SHA256_NUM_ROWS - 1).step_by(SHA256_NUM_ROWS).collect();
        MultiSha256Witness {
            input_len,
            original_input: witness.original_input,
            digests: witness.digests,
        }
    }

    pub fn assign_phase1<'v>(
        &self,
        region: &mut Region<'_, F>,
        rows: &[ShaRowSecondPhase<F>],
    ) -> MultiSha256Trace<'v, F> {
        let rlcs =
            rows.iter().enumerate().map(|(offset, row)| self.set_row_phase1(region, offset, row));
        let (input_rlcs, output_rlcs): (Vec<_>, Vec<_>) = rlcs
            .into_iter()
            .skip(SHA256_NUM_ROWS - 1)
            .step_by(SHA256_NUM_ROWS)
            .map(|[input, output]| (input, output))
            .unzip();
        MultiSha256Trace { input_rlcs, output_rlcs }
    }

    /// Phase 0 (= FirstPhase) assignment of row to Halo2 assigned cells.
    /// Output is `length` at that row
    pub fn set_row_phase0<'v>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &ShaRowFirstPhase,
    ) -> ShaAssignedValue<'v, F> {
        let round = offset % SHA256_NUM_ROWS;

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
                "q_padding",
                self.q_padding,
                F::from((NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB).contains(&round)),
            ),
            (
                "q_padding_last",
                self.q_padding_last,
                F::from(round == NUM_START_ROWS + NUM_WORDS_TO_ABSORB - 1),
            ),
            ("q_squeeze", self.q_squeeze, F::from(round == SHA256_NUM_ROWS - 1)),
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
            assign_fixed_custom(region, *column, offset, *value);
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
                assign_advice_custom(region, *column, offset, Value::known(F::from(*value)));
            }
        }

        // Keccak data
        let [_is_enabled, length] = self.hash_table.assign_row_phase0(
            region,
            offset,
            row.is_final && round == NUM_ROUNDS + 7,
            row.length,
        );

        length
    }

    /// Output is the [input_rlc, output_rlc] at that row
    pub fn set_row_phase1<'v>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &ShaRowSecondPhase<F>,
    ) -> [ShaAssignedValue<'v, F>; 2] {
        // Intermediate data rlcs, each data rlc is separate column, all in same row
        for (data_rlc, column) in row.data_rlcs.iter().zip(self.data_rlcs.iter()) {
            assign_advice_custom(region, *column, offset, Value::known(*data_rlc));
        }

        // Input and Output RLCs
        self.hash_table.assign_row_phase1(region, offset, row.data_rlc, row.hash_rlc)
    }
}

/// `digests` are the hash digests per sha256 chunk, in bytes
pub fn sha256_phase0<F: Field>(
    rows: &mut Vec<ShaRowFirstPhase>,
    digests: &mut Vec<[u8; NUM_BYTES_TO_SQUEEZE]>,
    bytes: &[u8],
) {
    let mut bits = into_be_bits(bytes);

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

    // Process each block
    let chunks = bits.chunks(RATE_IN_BITS);
    let num_chunks = chunks.len();
    for (idx, chunk) in chunks.enumerate() {
        // Adds a row
        let mut add_row = |w: u64, a: u64, e: u64, is_final, length, is_paddings| {
            let word_to_bits = |value: u64, num_bits: usize| {
                into_be_bits(&value.to_be_bytes())[64 - num_bits..64]
                    .iter()
                    .map(|b| *b != 0)
                    .into_iter()
                    .collect::<Vec<_>>()
            };
            rows.push(ShaRowFirstPhase {
                w: word_to_bits(w, NUM_BITS_PER_WORD_W).try_into().unwrap(),
                a: word_to_bits(a, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                e: word_to_bits(e, NUM_BITS_PER_WORD_EXT).try_into().unwrap(),
                is_final,
                length,
                is_paddings,
            });
        };

        // Last block for this hash
        let is_final_block = idx == num_chunks - 1;

        // Set the state
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (hs[0], hs[1], hs[2], hs[3], hs[4], hs[5], hs[6], hs[7]);

        // Add start rows
        let mut add_row_start = |a: u64, e: u64, is_final| {
            add_row(0, a, e, is_final, length, [false, false, false, in_padding])
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
                    *is_padding = if length == bytes.len() {
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
        let hash_bytes: [u8; NUM_BYTES_TO_SQUEEZE] = if is_final_block {
            hs.iter()
                .flat_map(|h| (*h as u32).to_be_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        } else {
            [0; NUM_BYTES_TO_SQUEEZE]
        };
        digests.push(hash_bytes);

        // Add end rows
        let mut add_row_end =
            |a: u64, e: u64| add_row(0, a, e, false, 0, [false; ABSORB_WIDTH_PER_ROW_BYTES]);
        add_row_end(hs[3], hs[7]);
        add_row_end(hs[2], hs[6]);
        add_row_end(hs[1], hs[5]);
        add_row(0, hs[0], hs[4], is_final_block, length, [false, false, false, in_padding]);

        // Now truncate the results
        for h in hs.iter_mut() {
            *h &= 0xFFFFFFFF;
        }
    }

    debug!("hash: {:x?}", digests.last().unwrap());
}

pub fn sha256_phase1<F: Field>(
    rows: &mut Vec<ShaRowSecondPhase<F>>,
    bytes: &[u8],
    challenge: Value<F>,
    digests: &[[u8; NUM_BYTES_TO_SQUEEZE]],
) {
    let mut r = F::zero();
    challenge.map(|c| r = c);

    let num_chunks = get_num_sha2_chunks(bytes.len());
    assert_eq!(num_chunks, digests.len());

    let mut byte_idx = 0;
    let mut data_rlc = F::zero();

    for hash_bytes in digests {
        // Adds a row
        let mut add_row = |data_rlc, hash_rlc, data_rlcs| {
            rows.push(ShaRowSecondPhase { data_rlc, hash_rlc, data_rlcs })
        };

        // Add start rows
        let mut add_row_start =
            || add_row(data_rlc, F::zero(), [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES]);
        add_row_start(); // (d, h, idx == 0)
        add_row_start(); // (c, g, idx == 0)
        add_row_start(); // (b, f, idx == 0)
        add_row_start(); // (a, e, idx == 0)

        for round in 0..NUM_ROUNDS {
            // Data(=input) RLC
            let mut data_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
            if round < NUM_WORDS_TO_ABSORB {
                // data rlc
                data_rlcs[0] = data_rlc;
                for idx in 0..ABSORB_WIDTH_PER_ROW_BYTES {
                    if byte_idx < bytes.len() {
                        data_rlc = data_rlc * r + F::from(bytes[byte_idx] as u64);
                    }
                    byte_idx += 1;
                    if idx < data_rlcs.len() - 1 {
                        data_rlcs[idx + 1] = data_rlc;
                    }
                }
            }
            // Add the row
            add_row(
                if round < NUM_WORDS_TO_ABSORB { data_rlc } else { F::zero() },
                F::zero(),
                data_rlcs,
            );
        }

        // Squeeze / hash RLC
        let hash_rlc = rlc::value(hash_bytes, r);

        // Add end rows
        let mut add_row_end =
            || add_row(F::zero(), F::zero(), [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES]);
        add_row_end(); // (hs[3], hs[7]);
        add_row_end(); // (hs[2], hs[6]);
        add_row_end(); // (hs[1], hs[5]);
        add_row(data_rlc, hash_rlc, [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES]);
    }
    debug!("data rlc: {:x?}", data_rlc);
}

#[derive(Clone, Debug)]
pub struct MultiSha256ArtifactFirstPhase<F: Field> {
    pub original_input: Vec<Vec<u8>>,
    pub rows: Vec<ShaRowFirstPhase>,
    /// Hash digests as bytes
    // Currently digests.len() = number of different distinct (variable length) inputs
    // Then digests[i].len() is the number of chunks in that input
    pub digests: Vec<Vec<[u8; NUM_BYTES_TO_SQUEEZE]>>,
    _marker: PhantomData<F>,
}

/// Returns [`MultiSha256ArtifactPhase0`], which consists of `rows` and `digests`.
/// - `rows` needs to be assigned using `set_row` inside a circuit
/// - `digests` should be passed onto [`multi_sha256_phase1`] to compute hash RLCs.
pub fn multi_sha256_phase0<F: Field>(
    bytes: Vec<Vec<u8>>,
    capacity: Option<usize>,
) -> MultiSha256ArtifactFirstPhase<F> {
    // Actual SHA-256, FirstPhase
    let (rows, mut digests): (Vec<_>, Vec<_>) = bytes
        .par_iter()
        .map(|bytes| {
            let num_chunks = get_num_sha2_chunks(bytes.len());
            let mut digests = Vec::with_capacity(num_chunks);
            let mut rows = Vec::with_capacity(num_chunks * SHA256_NUM_ROWS);
            sha256_phase0::<F>(&mut rows, &mut digests, bytes);
            (rows, digests)
        })
        .unzip();
    let mut rows = rows.concat();

    if let Some(capacity) = capacity {
        // Pad with no data hashes to the expected capacity
        while rows.len() < capacity * SHA256_NUM_ROWS {
            let mut dummy_digest = Vec::new();
            sha256_phase0::<F>(&mut rows, &mut dummy_digest, &[]);
            digests.push(dummy_digest);
        }
        // Check that we are not over capacity
        if rows.len() > capacity * SHA256_NUM_ROWS {
            panic!("SHA-256 Circuit Over Capacity");
        }
    }
    MultiSha256ArtifactFirstPhase { original_input: bytes, rows, digests, _marker: PhantomData }
}

#[derive(Clone, Debug)]
pub struct MultiSha256ArtifactSecondPhase<F: Field> {
    pub rows: Vec<ShaRowSecondPhase<F>>,
}

/// Computes and assigns the input and output RLC values.
pub fn multi_sha256_phase1<F: Field>(
    witness: MultiSha256Witness<F>,
    challenge: Value<F>,
) -> MultiSha256ArtifactSecondPhase<F> {
    let MultiSha256Witness { input_len: _, original_input: mut bytes, digests } = witness;
    assert!(bytes.len() <= digests.len());
    while bytes.len() != digests.len() {
        bytes.push(vec![]);
    }

    let rows: Vec<_> = bytes
        .par_iter()
        .zip(digests.into_par_iter())
        .map(|(bytes, digests)| {
            let mut rows = Vec::with_capacity(digests.len());
            sha256_phase1(&mut rows, bytes, challenge, &digests);
            rows
        })
        .collect();

    let rows = rows.concat();
    MultiSha256ArtifactSecondPhase { rows }
}
