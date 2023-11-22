// This file is moved out from mod.rs.
use super::*;

/// Witness generation for multiple keccak hashes of little-endian `bytes`.
pub fn multi_keccak<F: Field>(
    bytes: &[Vec<u8>],
    capacity: Option<usize>,
    parameters: KeccakConfigParams,
) -> (Vec<KeccakRow<F>>, Vec<[F; NUM_WORDS_TO_SQUEEZE]>) {
    let num_rows_per_round = parameters.rows_per_round;
    let mut rows =
        Vec::with_capacity((1 + capacity.unwrap_or(0) * (NUM_ROUNDS + 1)) * num_rows_per_round);
    // Dummy first row so that the initial data is absorbed
    // The initial data doesn't really matter, `is_final` just needs to be disabled.
    rows.append(&mut KeccakRow::dummy_rows(num_rows_per_round));
    // Actual keccaks
    let artifacts = bytes
        .par_iter()
        .map(|bytes| {
            let num_keccak_f = get_num_keccak_f(bytes.len());
            let mut squeeze_digests = Vec::with_capacity(num_keccak_f);
            let mut rows = Vec::with_capacity(num_keccak_f * (NUM_ROUNDS + 1) * num_rows_per_round);
            keccak(&mut rows, &mut squeeze_digests, bytes, parameters);
            (rows, squeeze_digests)
        })
        .collect::<Vec<_>>();

    let mut squeeze_digests = Vec::with_capacity(capacity.unwrap_or(0));
    for (rows_part, squeezes) in artifacts {
        rows.extend(rows_part);
        squeeze_digests.extend(squeezes);
    }

    if let Some(capacity) = capacity {
        // Pad with no data hashes to the expected capacity
        while rows.len() < (1 + capacity * (NUM_ROUNDS + 1)) * num_rows_per_round {
            keccak(&mut rows, &mut squeeze_digests, &[], parameters);
        }
        // Check that we are not over capacity
        if rows.len() > (1 + capacity * (NUM_ROUNDS + 1)) * num_rows_per_round {
            panic!("{:?}", Error::BoundsFailure);
        }
    }
    (rows, squeeze_digests)
}
/// Witness generation for keccak hash of little-endian `bytes`.
fn keccak<F: Field>(
    rows: &mut Vec<KeccakRow<F>>,
    squeeze_digests: &mut Vec<[F; NUM_WORDS_TO_SQUEEZE]>,
    bytes: &[u8],
    parameters: KeccakConfigParams,
) {
    let k = parameters.k;
    let num_rows_per_round = parameters.rows_per_round;

    let mut bits = into_bits(bytes);
    let mut s = [[F::ZERO; 5]; 5];
    let absorb_positions = get_absorb_positions();
    let num_bytes_in_last_block = bytes.len() % RATE;
    let two = F::from(2u64);

    // Padding
    bits.push(1);
    while (bits.len() + 1) % RATE_IN_BITS != 0 {
        bits.push(0);
    }
    bits.push(1);

    // running length of absorbed input in bytes
    let mut length = 0;
    let chunks = bits.chunks(RATE_IN_BITS);
    let num_chunks = chunks.len();

    let mut cell_managers = Vec::with_capacity(NUM_ROUNDS + 1);
    let mut regions = Vec::with_capacity(NUM_ROUNDS + 1);
    // keeps track of running lengths over all rounds in an absorb step
    let mut round_lengths = Vec::with_capacity(NUM_ROUNDS + 1);
    let mut hash_words = [F::ZERO; NUM_WORDS_TO_SQUEEZE];
    let mut hash = Word::default();

    for (idx, chunk) in chunks.enumerate() {
        let is_final_block = idx == num_chunks - 1;

        let mut absorb_rows = Vec::new();
        // Absorb
        for (idx, &(i, j)) in absorb_positions.iter().enumerate() {
            let absorb = pack(&chunk[idx * 64..(idx + 1) * 64]);
            let from = s[i][j];
            s[i][j] = field_xor(s[i][j], absorb);
            absorb_rows.push(AbsorbData { from, absorb, result: s[i][j] });
        }

        // better memory management to clear already allocated Vecs
        cell_managers.clear();
        regions.clear();
        round_lengths.clear();

        for round in 0..NUM_ROUNDS + 1 {
            let mut cell_manager = CellManager::new(num_rows_per_round);
            let mut region = KeccakRegion::new();

            let mut absorb_row = AbsorbData::default();
            if round < NUM_WORDS_TO_ABSORB {
                absorb_row = absorb_rows[round].clone();
            }

            // State data
            for s in &s {
                for s in s {
                    let cell = cell_manager.query_cell_value();
                    cell.assign(&mut region, 0, *s);
                }
            }

            // Absorb data
            let absorb_from = cell_manager.query_cell_value();
            let absorb_data = cell_manager.query_cell_value();
            let absorb_result = cell_manager.query_cell_value();
            absorb_from.assign(&mut region, 0, absorb_row.from);
            absorb_data.assign(&mut region, 0, absorb_row.absorb);
            absorb_result.assign(&mut region, 0, absorb_row.result);

            // Absorb
            cell_manager.start_region();
            let part_size = get_num_bits_per_absorb_lookup(k);
            let input = absorb_row.from + absorb_row.absorb;
            let absorb_fat =
                split::value(&mut cell_manager, &mut region, input, 0, part_size, false, None);
            cell_manager.start_region();
            let _absorb_result = transform::value(
                &mut cell_manager,
                &mut region,
                absorb_fat.clone(),
                true,
                |v| v & 1,
                true,
            );

            // Padding
            cell_manager.start_region();
            // Unpack a single word into bytes (for the absorption)
            // Potential optimization: could do multiple bytes per lookup
            let packed =
                split::value(&mut cell_manager, &mut region, absorb_row.absorb, 0, 8, false, None);
            cell_manager.start_region();
            let input_bytes =
                transform::value(&mut cell_manager, &mut region, packed, false, |v| *v, true);
            cell_manager.start_region();
            let is_paddings =
                input_bytes.iter().map(|_| cell_manager.query_cell_value()).collect::<Vec<_>>();
            debug_assert_eq!(is_paddings.len(), NUM_BYTES_PER_WORD);
            if round < NUM_WORDS_TO_ABSORB {
                for (padding_idx, is_padding) in is_paddings.iter().enumerate() {
                    let byte_idx = round * NUM_BYTES_PER_WORD + padding_idx;
                    let padding = if is_final_block && byte_idx >= num_bytes_in_last_block {
                        true
                    } else {
                        length += 1;
                        false
                    };
                    is_padding.assign(&mut region, 0, F::from(padding));
                }
            }
            cell_manager.start_region();

            if round != NUM_ROUNDS {
                // Theta
                let part_size = get_num_bits_per_theta_c_lookup(k);
                let mut bcf = Vec::new();
                for s in &s {
                    let c = s[0] + s[1] + s[2] + s[3] + s[4];
                    let bc_fat =
                        split::value(&mut cell_manager, &mut region, c, 1, part_size, false, None);
                    bcf.push(bc_fat);
                }
                cell_manager.start_region();
                let mut bc = Vec::new();
                for bc_fat in bcf {
                    let bc_norm = transform::value(
                        &mut cell_manager,
                        &mut region,
                        bc_fat.clone(),
                        true,
                        |v| v & 1,
                        true,
                    );
                    bc.push(bc_norm);
                }
                cell_manager.start_region();
                let mut os = [[F::ZERO; 5]; 5];
                for i in 0..5 {
                    let t = decode::value(bc[(i + 4) % 5].clone())
                        + decode::value(rotate(bc[(i + 1) % 5].clone(), 1, part_size));
                    for j in 0..5 {
                        os[i][j] = s[i][j] + t;
                    }
                }
                s = os;
                cell_manager.start_region();

                // Rho/Pi
                let part_size = get_num_bits_per_base_chi_lookup(k);
                let target_word_sizes = target_part_sizes(part_size);
                let num_word_parts = target_word_sizes.len();
                let mut rho_pi_chi_cells: [[[Vec<Cell<F>>; 5]; 5]; 3] =
                    array_init::array_init(|_| {
                        array_init::array_init(|_| array_init::array_init(|_| Vec::new()))
                    });
                let mut column_starts = [0usize; 3];
                for p in 0..3 {
                    column_starts[p] = cell_manager.start_region();
                    let mut row_idx = 0;
                    for j in 0..5 {
                        for _ in 0..num_word_parts {
                            for i in 0..5 {
                                rho_pi_chi_cells[p][i][j]
                                    .push(cell_manager.query_cell_value_at_row(row_idx as i32));
                            }
                            row_idx = (row_idx + 1) % num_rows_per_round;
                        }
                    }
                }
                cell_manager.start_region();
                let mut os_parts: [[Vec<PartValue<F>>; 5]; 5] =
                    array_init::array_init(|_| array_init::array_init(|_| Vec::new()));
                for (j, os_part) in os_parts.iter_mut().enumerate() {
                    for i in 0..5 {
                        let s_parts = split_uniform::value(
                            &rho_pi_chi_cells[0][j][(2 * i + 3 * j) % 5],
                            &mut cell_manager,
                            &mut region,
                            s[i][j],
                            RHO_MATRIX[i][j],
                            part_size,
                            true,
                        );

                        let s_parts = transform_to::value(
                            &rho_pi_chi_cells[1][j][(2 * i + 3 * j) % 5],
                            &mut region,
                            s_parts.clone(),
                            true,
                            |v| v & 1,
                        );
                        os_part[(2 * i + 3 * j) % 5] = s_parts.clone();
                    }
                }
                cell_manager.start_region();

                // Chi
                let part_size_base = get_num_bits_per_base_chi_lookup(k);
                let three_packed = pack::<F>(&vec![3u8; part_size_base]);
                let mut os = [[F::ZERO; 5]; 5];
                for j in 0..5 {
                    for i in 0..5 {
                        let mut s_parts = Vec::new();
                        for ((part_a, part_b), part_c) in os_parts[i][j]
                            .iter()
                            .zip(os_parts[(i + 1) % 5][j].iter())
                            .zip(os_parts[(i + 2) % 5][j].iter())
                        {
                            let value =
                                three_packed - two * part_a.value + part_b.value - part_c.value;
                            s_parts.push(PartValue {
                                num_bits: part_size_base,
                                rot: j as i32,
                                value,
                            });
                        }
                        os[i][j] = decode::value(transform_to::value(
                            &rho_pi_chi_cells[2][i][j],
                            &mut region,
                            s_parts.clone(),
                            true,
                            |v| CHI_BASE_LOOKUP_TABLE[*v as usize],
                        ));
                    }
                }
                s = os;
                cell_manager.start_region();

                // iota
                let part_size = get_num_bits_per_absorb_lookup(k);
                let input = s[0][0] + pack_u64::<F>(ROUND_CST[round]);
                let iota_parts = split::value::<F>(
                    &mut cell_manager,
                    &mut region,
                    input,
                    0,
                    part_size,
                    false,
                    None,
                );
                cell_manager.start_region();
                s[0][0] = decode::value(transform::value(
                    &mut cell_manager,
                    &mut region,
                    iota_parts.clone(),
                    true,
                    |v| v & 1,
                    true,
                ));
            }

            // Assign the hash result
            let is_final = is_final_block && round == NUM_ROUNDS;
            hash = if is_final {
                let hash_bytes_le = s
                    .into_iter()
                    .take(4)
                    .flat_map(|a| to_bytes::value(&unpack(a[0])))
                    .rev()
                    .collect::<Vec<_>>();

                let word: Word<Value<F>> =
                    Word::from(eth_types::Word::from_little_endian(hash_bytes_le.as_slice()))
                        .map(Value::known);
                word
            } else {
                Word::default().into_value()
            };

            // The words to squeeze out: this is the hash digest as words with
            // NUM_BYTES_PER_WORD (=8) bytes each
            for (hash_word, a) in hash_words.iter_mut().zip(s.iter()) {
                *hash_word = a[0];
            }

            round_lengths.push(length);

            cell_managers.push(cell_manager);
            regions.push(region);
        }

        // Now that we know the state at the end of the rounds, set the squeeze data
        let num_rounds = cell_managers.len();
        for (idx, word) in hash_words.iter().enumerate() {
            let cell_manager = &mut cell_managers[num_rounds - 2 - idx];
            let region = &mut regions[num_rounds - 2 - idx];

            cell_manager.start_region();
            let squeeze_packed = cell_manager.query_cell_value();
            squeeze_packed.assign(region, 0, *word);

            cell_manager.start_region();
            let packed = split::value(cell_manager, region, *word, 0, 8, false, None);
            cell_manager.start_region();
            transform::value(cell_manager, region, packed, false, |v| *v, true);
        }
        squeeze_digests.push(hash_words);

        for round in 0..NUM_ROUNDS + 1 {
            let round_cst = pack_u64(ROUND_CST[round]);

            for row_idx in 0..num_rows_per_round {
                let word_value = if round < NUM_WORDS_TO_ABSORB && row_idx == 0 {
                    let byte_idx = (idx * NUM_WORDS_TO_ABSORB + round) * NUM_BYTES_PER_WORD;
                    if byte_idx >= bytes.len() {
                        0
                    } else {
                        let end = std::cmp::min(byte_idx + NUM_BYTES_PER_WORD, bytes.len());
                        let mut word_bytes = bytes[byte_idx..end].to_vec().clone();
                        word_bytes.resize(NUM_BYTES_PER_WORD, 0);
                        u64::from_le_bytes(word_bytes.try_into().unwrap())
                    }
                } else {
                    0
                };
                let byte_idx = if round < NUM_WORDS_TO_ABSORB {
                    round * NUM_BYTES_PER_WORD + std::cmp::min(row_idx, NUM_BYTES_PER_WORD - 1)
                } else {
                    NUM_WORDS_TO_ABSORB * NUM_BYTES_PER_WORD
                } + idx * NUM_WORDS_TO_ABSORB * NUM_BYTES_PER_WORD;
                let bytes_left = if byte_idx >= bytes.len() { 0 } else { bytes.len() - byte_idx };
                rows.push(KeccakRow {
                    q_enable: row_idx == 0,
                    q_round: row_idx == 0 && round < NUM_ROUNDS,
                    q_absorb: row_idx == 0 && round == NUM_ROUNDS,
                    q_round_last: row_idx == 0 && round == NUM_ROUNDS,
                    q_input: row_idx == 0 && round < NUM_WORDS_TO_ABSORB,
                    q_input_last: row_idx == 0 && round == NUM_WORDS_TO_ABSORB - 1,
                    round_cst,
                    is_final: is_final_block && round == NUM_ROUNDS && row_idx == 0,
                    cell_values: regions[round].rows.get(row_idx).unwrap_or(&vec![]).clone(),
                    hash,
                    bytes_left: F::from_u128(bytes_left as u128),
                    word_value: F::from_u128(word_value as u128),
                });
                #[cfg(debug_assertions)]
                {
                    let mut r = rows.last().unwrap().clone();
                    r.cell_values.clear();
                    log::trace!("offset {:?} row idx {} row {:?}", rows.len() - 1, row_idx, r);
                }
            }
            log::trace!(" = = = = = = round {} end", round);
        }
        log::trace!(" ====================== chunk {} end", idx);
    }

    #[cfg(debug_assertions)]
    {
        let hash_bytes = s
            .into_iter()
            .take(4)
            .map(|a| {
                pack_with_base::<F>(&unpack(a[0]), 2)
                    .to_bytes_le()
                    .into_iter()
                    .take(8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        debug!("hash: {:x?}", &(hash_bytes[0..4].concat()));
        assert_eq!(length, bytes.len());
    }
}
