use self::{cell_manager::*, keccak_packed_multi::*, param::*, table::*, util::*};
use crate::{
    halo2_proofs::{
        circuit::{Layouter, Region, Value},
        halo2curves::ff::PrimeField,
        plonk::{Column, ConstraintSystem, Error, Expression, Fixed, TableColumn, VirtualCells},
        poly::Rotation,
    },
    util::{
        constraint_builder::BaseConstraintBuilder,
        eth_types::{self, Field},
        expression::{and, from_bytes, not, select, sum, Expr},
        word::{self, Word, WordExpr},
    },
};
use halo2_base::utils::halo2::{raw_assign_advice, raw_assign_fixed};
use itertools::Itertools;
use log::{debug, info};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::marker::PhantomData;

pub mod cell_manager;
pub mod keccak_packed_multi;
pub mod param;
pub mod table;
#[cfg(test)]
mod tests;
pub mod util;
/// Module for witness generation.
pub mod witness;

/// Configuration parameters to define [`KeccakCircuitConfig`]
#[derive(Copy, Clone, Debug, Default)]
pub struct KeccakConfigParams {
    /// The circuit degree, i.e., circuit has 2<sup>k</sup> rows
    pub k: u32,
    /// The number of rows to use for each round in the keccak_f permutation
    pub rows_per_round: usize,
}

/// KeccakConfig
#[derive(Clone, Debug)]
pub struct KeccakCircuitConfig<F> {
    // Bool. True on 1st row of each round.
    q_enable: Column<Fixed>,
    // Bool. True on 1st row.
    q_first: Column<Fixed>,
    // Bool. True on 1st row of all rounds except last rounds.
    q_round: Column<Fixed>,
    // Bool. True on 1st row of last rounds.
    q_absorb: Column<Fixed>,
    // Bool. True on 1st row of last rounds.
    q_round_last: Column<Fixed>,
    // Bool. True on 1st row of rounds which might contain inputs.
    // Note: first NUM_WORDS_TO_ABSORB rounds of each chunk might contain inputs.
    // It "might" contain inputs because it's possible that a round only have paddings.
    q_input: Column<Fixed>,
    // Bool. True on 1st row of all last input round.
    q_input_last: Column<Fixed>,

    pub keccak_table: KeccakTable,

    cell_manager: CellManager<F>,
    round_cst: Column<Fixed>,
    normalize_3: [TableColumn; 2],
    normalize_4: [TableColumn; 2],
    normalize_6: [TableColumn; 2],
    chi_base_table: [TableColumn; 2],
    pack_table: [TableColumn; 2],

    // config parameters for convenience
    pub parameters: KeccakConfigParams,

    _marker: PhantomData<F>,
}

impl<F: Field> KeccakCircuitConfig<F> {
    /// Return a new KeccakCircuitConfig
    pub fn new(meta: &mut ConstraintSystem<F>, parameters: KeccakConfigParams) -> Self {
        let k = parameters.k;
        let num_rows_per_round = parameters.rows_per_round;

        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_round = meta.fixed_column();
        let q_absorb = meta.fixed_column();
        let q_round_last = meta.fixed_column();
        let q_input = meta.fixed_column();
        let q_input_last = meta.fixed_column();
        let round_cst = meta.fixed_column();
        let keccak_table = KeccakTable::construct(meta);

        let is_final = keccak_table.is_enabled;
        let hash_word = keccak_table.output;

        let normalize_3 = array_init::array_init(|_| meta.lookup_table_column());
        let normalize_4 = array_init::array_init(|_| meta.lookup_table_column());
        let normalize_6 = array_init::array_init(|_| meta.lookup_table_column());
        let chi_base_table = array_init::array_init(|_| meta.lookup_table_column());
        let pack_table = array_init::array_init(|_| meta.lookup_table_column());

        let mut cell_manager = CellManager::new(num_rows_per_round);
        let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        let mut total_lookup_counter = 0;

        let start_new_hash = |meta: &mut VirtualCells<F>, rot| {
            // A new hash is started when the previous hash is done or on the first row
            meta.query_fixed(q_first, rot) + meta.query_advice(is_final, rot)
        };

        // Round constant
        let mut round_cst_expr = 0.expr();
        meta.create_gate("Query round cst", |meta| {
            round_cst_expr = meta.query_fixed(round_cst, Rotation::cur());
            vec![0u64.expr()]
        });
        // State data
        let mut s = vec![vec![0u64.expr(); 5]; 5];
        let mut s_next = vec![vec![0u64.expr(); 5]; 5];
        for i in 0..5 {
            for j in 0..5 {
                let cell = cell_manager.query_cell(meta);
                s[i][j] = cell.expr();
                s_next[i][j] = cell.at_offset(meta, num_rows_per_round as i32).expr();
            }
        }
        // Absorb data
        let absorb_from = cell_manager.query_cell(meta);
        let absorb_data = cell_manager.query_cell(meta);
        let absorb_result = cell_manager.query_cell(meta);
        let mut absorb_from_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        let mut absorb_data_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        let mut absorb_result_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        for i in 0..NUM_WORDS_TO_ABSORB {
            let rot = ((i + 1) * num_rows_per_round) as i32;
            absorb_from_next[i] = absorb_from.at_offset(meta, rot).expr();
            absorb_data_next[i] = absorb_data.at_offset(meta, rot).expr();
            absorb_result_next[i] = absorb_result.at_offset(meta, rot).expr();
        }

        // Store the pre-state
        let pre_s = s.clone();

        // Absorb
        // The absorption happening at the start of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 17 of the 24 rounds) a
        // single word is absorbed so the work is spread out. The absorption is
        // done simply by doing state + data and then normalizing the result to [0,1].
        // We also need to convert the input data into bytes to calculate the input data
        // rlc.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size = get_num_bits_per_absorb_lookup(k);
        let input = absorb_from.expr() + absorb_data.expr();
        let absorb_fat =
            split::expr(meta, &mut cell_manager, &mut cb, input, 0, part_size, false, None);
        cell_manager.start_region();
        let absorb_res = transform::expr(
            "absorb",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            absorb_fat,
            normalize_3,
            true,
        );
        cb.require_equal("absorb result", decode::expr(absorb_res), absorb_result.expr());
        info!("- Post absorb:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Squeeze
        // The squeezing happening at the end of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 4 of the 24 rounds) a
        // single word is converted to bytes.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        // Potential optimization: could do multiple bytes per lookup
        let packed_parts =
            split::expr(meta, &mut cell_manager, &mut cb, absorb_data.expr(), 0, 8, false, None);
        cell_manager.start_region();
        // input_bytes.len() = packed_parts.len() = 64 / 8 = 8 = NUM_BYTES_PER_WORD
        let input_bytes = transform::expr(
            "squeeze unpack",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            packed_parts,
            pack_table.into_iter().rev().collect::<Vec<_>>().try_into().unwrap(),
            true,
        );
        debug_assert_eq!(input_bytes.len(), NUM_BYTES_PER_WORD);

        // Padding data
        cell_manager.start_region();
        let is_paddings = input_bytes.iter().map(|_| cell_manager.query_cell(meta)).collect_vec();
        info!("- Post padding:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Theta
        // Calculate
        // - `c[i] = s[i][0] + s[i][1] + s[i][2] + s[i][3] + s[i][4]`
        // - `bc[i] = normalize(c)`.
        // - `t[i] = bc[(i + 4) % 5] + rot(bc[(i + 1)% 5], 1)`
        // This is done by splitting the bc values in parts in a way
        // that allows us to also calculate the rotated value "for free".
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size_c = get_num_bits_per_theta_c_lookup(k);
        let mut c_parts = Vec::new();
        for s in s.iter() {
            // Calculate c and split into parts
            let c = s[0].clone() + s[1].clone() + s[2].clone() + s[3].clone() + s[4].clone();
            c_parts.push(split::expr(
                meta,
                &mut cell_manager,
                &mut cb,
                c,
                1,
                part_size_c,
                false,
                None,
            ));
        }
        // Now calculate `bc` by normalizing `c`
        cell_manager.start_region();
        let mut bc = Vec::new();
        for c in c_parts {
            // Normalize c
            bc.push(transform::expr(
                "theta c",
                meta,
                &mut cell_manager,
                &mut lookup_counter,
                c,
                normalize_6,
                true,
            ));
        }
        // Now do `bc[(i + 4) % 5] + rot(bc[(i + 1) % 5], 1)` using just expressions.
        // We don't normalize the result here. We do it as part of the rho/pi step, even
        // though we would only have to normalize 5 values instead of 25, because of the
        // way the rho/pi and chi steps can be combined it's more efficient to
        // do it there (the max value for chi is 4 already so that's the
        // limiting factor).
        let mut os = vec![vec![0u64.expr(); 5]; 5];
        for i in 0..5 {
            let t = decode::expr(bc[(i + 4) % 5].clone())
                + decode::expr(rotate(bc[(i + 1) % 5].clone(), 1, part_size_c));
            for j in 0..5 {
                os[i][j] = s[i][j].clone() + t.clone();
            }
        }
        s = os.clone();
        info!("- Post theta:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Rho/Pi
        // For the rotation of rho/pi we split up the words like expected, but in a way
        // that allows reusing the same parts in an optimal way for the chi step.
        // We can save quite a few columns by not recombining the parts after rho/pi and
        // re-splitting the words again before chi. Instead we do chi directly
        // on the output parts of rho/pi. For rho/pi specically we do
        // `s[j][2 * i + 3 * j) % 5] = normalize(rot(s[i][j], RHOM[i][j]))`.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size = get_num_bits_per_base_chi_lookup(k);
        // To combine the rho/pi/chi steps we have to ensure a specific layout so
        // query those cells here first.
        // For chi we have to do `s[i][j] ^ ((~s[(i+1)%5][j]) & s[(i+2)%5][j])`. `j`
        // remains static but `i` is accessed in a wrap around manner. To do this using
        // multiple rows with lookups in a way that doesn't require any
        // extra additional cells or selectors we have to put all `s[i]`'s on the same
        // row. This isn't that strong of a requirement actually because we the
        // words are split into multipe parts, and so only the parts at the same
        // position of those words need to be on the same row.
        let target_word_sizes = target_part_sizes(part_size);
        let num_word_parts = target_word_sizes.len();
        let mut rho_pi_chi_cells: [[[Vec<Cell<F>>; 5]; 5]; 3] = array_init::array_init(|_| {
            array_init::array_init(|_| array_init::array_init(|_| Vec::new()))
        });
        let mut num_columns = 0;
        let mut column_starts = [0usize; 3];
        for p in 0..3 {
            column_starts[p] = cell_manager.start_region();
            let mut row_idx = 0;
            num_columns = 0;
            for j in 0..5 {
                for _ in 0..num_word_parts {
                    for i in 0..5 {
                        rho_pi_chi_cells[p][i][j]
                            .push(cell_manager.query_cell_at_row(meta, row_idx));
                    }
                    if row_idx == 0 {
                        num_columns += 1;
                    }
                    row_idx = (((row_idx as usize) + 1) % num_rows_per_round) as i32;
                }
            }
        }
        // Do the transformation, resulting in the word parts also being normalized.
        let pi_region_start = cell_manager.start_region();
        let mut os_parts = vec![vec![Vec::new(); 5]; 5];
        for (j, os_part) in os_parts.iter_mut().enumerate() {
            for i in 0..5 {
                // Split s into parts
                let s_parts = split_uniform::expr(
                    meta,
                    &rho_pi_chi_cells[0][j][(2 * i + 3 * j) % 5],
                    &mut cell_manager,
                    &mut cb,
                    s[i][j].clone(),
                    RHO_MATRIX[i][j],
                    part_size,
                    true,
                );
                // Normalize the data to the target cells
                let s_parts = transform_to::expr(
                    "rho/pi",
                    meta,
                    &rho_pi_chi_cells[1][j][(2 * i + 3 * j) % 5],
                    &mut lookup_counter,
                    s_parts.clone(),
                    normalize_4,
                    true,
                );
                os_part[(2 * i + 3 * j) % 5] = s_parts.clone();
            }
        }
        let pi_region_end = cell_manager.start_region();
        // Pi parts range checks
        // To make the uniform stuff work we had to combine some parts together
        // in new cells (see split_uniform). Here we make sure those parts are range
        // checked. Potential improvement: Could combine multiple smaller parts
        // in a single lookup but doesn't save that much.
        for c in pi_region_start..pi_region_end {
            meta.lookup("pi part range check", |_| {
                vec![(cell_manager.columns()[c].expr.clone(), normalize_4[0])]
            });
            lookup_counter += 1;
        }
        info!("- Post rho/pi:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Chi
        // In groups of 5 columns, we have to do `s[i][j] ^ ((~s[(i+1)%5][j]) &
        // s[(i+2)%5][j])` five times, on each row (no selector needed).
        // This is calculated by making use of `CHI_BASE_LOOKUP_TABLE`.
        let mut lookup_counter = 0;
        let part_size_base = get_num_bits_per_base_chi_lookup(k);
        for idx in 0..num_columns {
            // First fetch the cells we wan to use
            let mut input: [Expression<F>; 5] = array_init::array_init(|_| 0.expr());
            let mut output: [Expression<F>; 5] = array_init::array_init(|_| 0.expr());
            for c in 0..5 {
                input[c] = cell_manager.columns()[column_starts[1] + idx * 5 + c].expr.clone();
                output[c] = cell_manager.columns()[column_starts[2] + idx * 5 + c].expr.clone();
            }
            // Now calculate `a ^ ((~b) & c)` by doing `lookup[3 - 2*a + b - c]`
            for i in 0..5 {
                let input = scatter::expr(3, part_size_base) - 2.expr() * input[i].clone()
                    + input[(i + 1) % 5].clone()
                    - input[(i + 2) % 5].clone();
                let output = output[i].clone();
                meta.lookup("chi base", |_| {
                    vec![(input.clone(), chi_base_table[0]), (output.clone(), chi_base_table[1])]
                });
                lookup_counter += 1;
            }
        }
        // Now just decode the parts after the chi transformation done with the lookups
        // above.
        let mut os = vec![vec![0u64.expr(); 5]; 5];
        for (i, os) in os.iter_mut().enumerate() {
            for (j, os) in os.iter_mut().enumerate() {
                let mut parts = Vec::new();
                for idx in 0..num_word_parts {
                    parts.push(Part {
                        num_bits: part_size_base,
                        cell: rho_pi_chi_cells[2][i][j][idx].clone(),
                        expr: rho_pi_chi_cells[2][i][j][idx].expr(),
                    });
                }
                *os = decode::expr(parts);
            }
        }
        s = os.clone();

        // iota
        // Simply do the single xor on state [0][0].
        cell_manager.start_region();
        let part_size = get_num_bits_per_absorb_lookup(k);
        let input = s[0][0].clone() + round_cst_expr.clone();
        let iota_parts =
            split::expr(meta, &mut cell_manager, &mut cb, input, 0, part_size, false, None);
        cell_manager.start_region();
        // Could share columns with absorb which may end up using 1 lookup/column
        // fewer...
        s[0][0] = decode::expr(transform::expr(
            "iota",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            iota_parts,
            normalize_3,
            true,
        ));
        // Final results stored in the next row
        for i in 0..5 {
            for j in 0..5 {
                cb.require_equal("next row check", s[i][j].clone(), s_next[i][j].clone());
            }
        }
        info!("- Post chi:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        let mut lookup_counter = 0;
        cell_manager.start_region();

        // Squeeze data
        let squeeze_from = cell_manager.query_cell(meta);
        let mut squeeze_from_prev = vec![0u64.expr(); NUM_WORDS_TO_SQUEEZE];
        for (idx, squeeze_from_prev) in squeeze_from_prev.iter_mut().enumerate() {
            let rot = (-(idx as i32) - 1) * num_rows_per_round as i32;
            *squeeze_from_prev = squeeze_from.at_offset(meta, rot).expr();
        }
        // Squeeze
        // The squeeze happening at the end of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 4 of the 24 rounds) a
        // single word is converted to bytes.
        // Potential optimization: could do multiple bytes per lookup
        cell_manager.start_region();
        // Unpack a single word into bytes (for the squeeze)
        // Potential optimization: could do multiple bytes per lookup
        let squeeze_from_parts =
            split::expr(meta, &mut cell_manager, &mut cb, squeeze_from.expr(), 0, 8, false, None);
        cell_manager.start_region();
        let squeeze_bytes = transform::expr(
            "squeeze unpack",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            squeeze_from_parts,
            pack_table.into_iter().rev().collect::<Vec<_>>().try_into().unwrap(),
            true,
        );
        info!("- Post squeeze:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // The round constraints that we've been building up till now
        meta.create_gate("round", |meta| cb.gate(meta.query_fixed(q_round, Rotation::cur())));

        // Absorb
        meta.create_gate("absorb", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let continue_hash = not::expr(start_new_hash(meta, Rotation::cur()));
            let absorb_positions = get_absorb_positions();
            let mut a_slice = 0;
            for j in 0..5 {
                for i in 0..5 {
                    if absorb_positions.contains(&(i, j)) {
                        cb.condition(continue_hash.clone(), |cb| {
                            cb.require_equal(
                                "absorb verify input",
                                absorb_from_next[a_slice].clone(),
                                pre_s[i][j].clone(),
                            );
                        });
                        cb.require_equal(
                            "absorb result copy",
                            select::expr(
                                continue_hash.clone(),
                                absorb_result_next[a_slice].clone(),
                                absorb_data_next[a_slice].clone(),
                            ),
                            s_next[i][j].clone(),
                        );
                        a_slice += 1;
                    } else {
                        cb.require_equal(
                            "absorb state copy",
                            pre_s[i][j].clone() * continue_hash.clone(),
                            s_next[i][j].clone(),
                        );
                    }
                }
            }
            cb.gate(meta.query_fixed(q_absorb, Rotation::cur()))
        });

        // Collect the bytes that are spread out over previous rows
        let mut hash_bytes = Vec::new();
        for i in 0..NUM_WORDS_TO_SQUEEZE {
            for byte in squeeze_bytes.iter() {
                let rot = (-(i as i32) - 1) * num_rows_per_round as i32;
                hash_bytes.push(byte.cell.at_offset(meta, rot).expr());
            }
        }

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let start_new_hash = start_new_hash(meta, Rotation::cur());
            // The words to squeeze
            let hash_words: Vec<_> =
                pre_s.into_iter().take(4).map(|a| a[0].clone()).take(4).collect();
            // Verify if we converted the correct words to bytes on previous rows
            for (idx, word) in hash_words.iter().enumerate() {
                cb.condition(start_new_hash.clone(), |cb| {
                    cb.require_equal(
                        "squeeze verify packed",
                        word.clone(),
                        squeeze_from_prev[idx].clone(),
                    );
                });
            }

            let hash_bytes_le = hash_bytes.into_iter().rev().collect::<Vec<_>>();
            cb.condition(start_new_hash, |cb| {
                cb.require_equal_word(
                    "output check",
                    word::Word32::new(hash_bytes_le.try_into().expect("32 limbs")).to_word(),
                    hash_word.map(|col| meta.query_advice(col, Rotation::cur())),
                );
            });
            cb.gate(meta.query_fixed(q_round_last, Rotation::cur()))
        });

        // Some general input checks
        meta.create_gate("input checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_boolean("boolean is_final", meta.query_advice(is_final, Rotation::cur()));
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // Enforce fixed values on the first row
        meta.create_gate("first row", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_zero(
                "is_final needs to be disabled on the first row",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
        });

        // some utility query functions
        let q = |col: Column<Fixed>, meta: &mut VirtualCells<'_, F>| {
            meta.query_fixed(col, Rotation::cur())
        };
        /*
        eg：
            data:
                get_num_rows_per_round: 18
                input: "12345678abc"
            table:
                Note[1]: be careful: is_paddings is not column here! It is [Cell; 8] and it will be constrained later.
                Note[2]: only first row of each round has constraints on bytes_left. This example just shows how witnesses are filled.
        offset word_value bytes_left  is_paddings q_enable q_input_last
        18     0x87654321    11          0         1        0 // 1st round begin
        19        0          10          0         0        0
        20        0          9           0         0        0
        21        0          8           0         0        0
        22        0          7           0         0        0
        23        0          6           0         0        0
        24        0          5           0         0        0
        25        0          4           0         0        0
        26        0          4           NA        0        0
        ...
        35        0          4           NA        0        0  // 1st round end
        36      0xcba        3           0         1        1  // 2nd round begin
        37        0          2           0         0        0
        38        0          1           0         0        0
        39        0          0           1         0        0
        40        0          0           1         0        0
        41        0          0           1         0        0
        42        0          0           1         0        0
        43        0          0           1         0        0
        */

        meta.create_gate("word_value", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let masked_input_bytes = input_bytes
                .iter()
                .zip_eq(is_paddings.clone())
                .map(|(input_byte, is_padding)| {
                    input_byte.expr.clone() * not::expr(is_padding.expr().clone())
                })
                .collect_vec();
            let input_word = from_bytes::expr(&masked_input_bytes);
            cb.require_equal(
                "word value",
                input_word,
                meta.query_advice(keccak_table.word_value, Rotation::cur()),
            );
            cb.gate(q(q_input, meta))
        });
        meta.create_gate("bytes_left", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let bytes_left_expr = meta.query_advice(keccak_table.bytes_left, Rotation::cur());

            // bytes_left is 0 in the absolute first `rows_per_round` of the entire circuit, i.e., the first dummy round.
            cb.condition(q(q_first, meta), |cb| {
                cb.require_zero(
                    "bytes_left needs to be zero on the absolute first dummy round",
                    meta.query_advice(keccak_table.bytes_left, Rotation::cur()),
                );
            });
            // is_final ==> bytes_left == 0.
            // Note: is_final = true only in the last round, which doesn't have any data to absorb.
            cb.condition(meta.query_advice(is_final, Rotation::cur()), |cb| {
                cb.require_zero("bytes_left should be 0 when is_final", bytes_left_expr.clone());
            });
            // q_input[cur] ==> bytes_left[cur + num_rows_per_round] + word_len == bytes_left[cur]
            cb.condition(q(q_input, meta), |cb| {
                // word_len = NUM_BYTES_PER_WORD - sum(is_paddings)
                let word_len = NUM_BYTES_PER_WORD.expr() - sum::expr(is_paddings.clone());
                let bytes_left_next_expr =
                    meta.query_advice(keccak_table.bytes_left, Rotation(num_rows_per_round as i32));
                cb.require_equal(
                    "if there is a word in this round, bytes_left[curr + num_rows_per_round] + word_len == bytes_left[curr]",
                    bytes_left_expr.clone(),
                    bytes_left_next_expr + word_len,
                );
            });
            // Logically here we want !q_input[cur] && !start_new_hash(cur) ==> bytes_left[cur + num_rows_per_round] == bytes_left[cur]
            // In practice, in order to save a degree we use !(q_input[cur] ^ start_new_hash(cur)) ==> bytes_left[cur + num_rows_per_round] == bytes_left[cur]
            // When q_input[cur] is true, the above constraint q_input[cur] ==> bytes_left[cur + num_rows_per_round] + word_len == bytes_left[cur] has 
            // already been enabled. Even is_final in start_new_hash(cur) is true, it's just over-constrainted.
            // Note: At the first row of any round except the last round, is_final could be either true or false.
            cb.condition(not::expr(q(q_input, meta) + start_new_hash(meta, Rotation::cur())), |cb| {
                let bytes_left_next_expr =
                    meta.query_advice(keccak_table.bytes_left, Rotation(num_rows_per_round as i32));
                cb.require_equal(
                    "if no input and not starting new hash, bytes_left should keep the same",
                    bytes_left_expr,
                    bytes_left_next_expr,
                );
            });

            cb.gate(q(q_enable, meta))
        });

        // Enforce logic for when this block is the last block for a hash
        let last_is_padding_in_block = is_paddings.last().unwrap().at_offset(
            meta,
            -(((NUM_ROUNDS + 1 - NUM_WORDS_TO_ABSORB) * num_rows_per_round) as i32),
        );
        meta.create_gate("is final", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // All absorb rows except the first row
            cb.condition(
                meta.query_fixed(q_absorb, Rotation::cur())
                    - meta.query_fixed(q_first, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "is_final needs to be the same as the last is_padding in the block",
                        meta.query_advice(is_final, Rotation::cur()),
                        last_is_padding_in_block.expr(),
                    );
                },
            );
            // For all the rows of a round, only the first row can have `is_final == 1`.
            cb.condition(
                (1..num_rows_per_round as i32)
                    .map(|i| meta.query_fixed(q_enable, Rotation(-i)))
                    .fold(0.expr(), |acc, elem| acc + elem),
                |cb| {
                    cb.require_zero(
                        "is_final only when q_enable",
                        meta.query_advice(is_final, Rotation::cur()),
                    );
                },
            );
            cb.gate(1.expr())
        });

        // Padding
        // May be cleaner to do this padding logic in the byte conversion lookup but
        // currently easier to do it like this.
        let prev_is_padding =
            is_paddings.last().unwrap().at_offset(meta, -(num_rows_per_round as i32));
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_input = meta.query_fixed(q_input, Rotation::cur());
            let q_input_last = meta.query_fixed(q_input_last, Rotation::cur());

            // All padding selectors need to be boolean
            for is_padding in is_paddings.iter() {
                cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
                    cb.require_boolean("is_padding boolean", is_padding.expr());
                });
            }
            // This last padding selector will be used on the first round row so needs to be
            // zero
            cb.condition(meta.query_fixed(q_absorb, Rotation::cur()), |cb| {
                cb.require_zero(
                    "last is_padding should be zero on absorb rows",
                    is_paddings.last().unwrap().expr(),
                );
            });
            // Now for each padding selector
            for idx in 0..is_paddings.len() {
                // Previous padding selector can be on the previous row
                let is_padding_prev =
                    if idx == 0 { prev_is_padding.expr() } else { is_paddings[idx - 1].expr() };
                let is_first_padding = is_paddings[idx].expr() - is_padding_prev.clone();

                // Check padding transition 0 -> 1 done only once
                cb.condition(q_input.expr(), |cb| {
                    cb.require_boolean("padding step boolean", is_first_padding.clone());
                });

                // Padding start/intermediate/end byte checks
                if idx == is_paddings.len() - 1 {
                    // These can be combined in the future, but currently this would increase the
                    // degree by one Padding start/intermediate byte, all
                    // padding rows except the last one
                    cb.condition(
                        and::expr([q_input.expr() - q_input_last.expr(), is_paddings[idx].expr()]),
                        |cb| {
                            // Input bytes need to be zero, or one if this is the first padding byte
                            cb.require_equal(
                                "padding start/intermediate byte last byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr(),
                            );
                        },
                    );
                    // Padding start/end byte, only on the last padding row
                    cb.condition(and::expr([q_input_last.expr(), is_paddings[idx].expr()]), |cb| {
                        // The input byte needs to be 128, unless it's also the first padding
                        // byte then it's 129
                        cb.require_equal(
                            "padding start/end byte",
                            input_bytes[idx].expr.clone(),
                            is_first_padding.expr() + 128.expr(),
                        );
                    });
                } else {
                    // Padding start/intermediate byte
                    cb.condition(and::expr([q_input.expr(), is_paddings[idx].expr()]), |cb| {
                        // Input bytes need to be zero, or one if this is the first padding byte
                        cb.require_equal(
                            "padding start/intermediate byte",
                            input_bytes[idx].expr.clone(),
                            is_first_padding.expr(),
                        );
                    });
                }
            }
            cb.gate(1.expr())
        });

        info!("Degree: {}", meta.degree());
        info!("Minimum rows: {}", meta.minimum_rows());
        info!("Total Lookups: {}", total_lookup_counter);
        #[cfg(feature = "display")]
        {
            println!("Total Keccak Columns: {}", cell_manager.get_width());
            std::env::set_var("KECCAK_ADVICE_COLUMNS", cell_manager.get_width().to_string());
        }
        #[cfg(not(feature = "display"))]
        info!("Total Keccak Columns: {}", cell_manager.get_width());
        info!("num unused cells: {}", cell_manager.get_num_unused_cells());
        info!("part_size absorb: {}", get_num_bits_per_absorb_lookup(k));
        info!("part_size theta: {}", get_num_bits_per_theta_c_lookup(k));
        info!("part_size theta c: {}", get_num_bits_per_lookup(THETA_C_LOOKUP_RANGE, k));
        info!("part_size theta t: {}", get_num_bits_per_lookup(4, k));
        info!("part_size rho/pi: {}", get_num_bits_per_rho_pi_lookup(k));
        info!("part_size chi base: {}", get_num_bits_per_base_chi_lookup(k));
        info!("uniform part sizes: {:?}", target_part_sizes(get_num_bits_per_theta_c_lookup(k)));

        KeccakCircuitConfig {
            q_enable,
            q_first,
            q_round,
            q_absorb,
            q_round_last,
            q_input,
            q_input_last,
            keccak_table,
            cell_manager,
            round_cst,
            normalize_3,
            normalize_4,
            normalize_6,
            chi_base_table,
            pack_table,
            parameters,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct KeccakAssignedRow<'v, F: Field> {
    pub is_final: KeccakAssignedValue<'v, F>,
    pub hash_lo: KeccakAssignedValue<'v, F>,
    pub hash_hi: KeccakAssignedValue<'v, F>,
    pub bytes_left: KeccakAssignedValue<'v, F>,
    pub word_value: KeccakAssignedValue<'v, F>,
    pub _marker: PhantomData<&'v ()>,
}

impl<F: Field> KeccakCircuitConfig<F> {
    /// Returns vector of `is_final`, `length`, `hash.lo`, `hash.hi` for assigned rows
    pub fn assign<'v>(
        &self,
        region: &mut Region<F>,
        witness: &[KeccakRow<F>],
    ) -> Vec<KeccakAssignedRow<'v, F>> {
        witness
            .iter()
            .enumerate()
            .map(|(offset, keccak_row)| self.set_row(region, offset, keccak_row))
            .collect()
    }

    /// Output is `is_final`, `length`, `hash.lo`, `hash.hi` at that row
    pub fn set_row<'v>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        row: &KeccakRow<F>,
    ) -> KeccakAssignedRow<'v, F> {
        // Fixed selectors
        for (_, column, value) in &[
            ("q_enable", self.q_enable, F::from(row.q_enable)),
            ("q_first", self.q_first, F::from(offset == 0)),
            ("q_round", self.q_round, F::from(row.q_round)),
            ("q_round_last", self.q_round_last, F::from(row.q_round_last)),
            ("q_absorb", self.q_absorb, F::from(row.q_absorb)),
            ("q_input", self.q_input, F::from(row.q_input)),
            ("q_input_last", self.q_input_last, F::from(row.q_input_last)),
        ] {
            raw_assign_fixed(region, *column, offset, *value);
        }

        // Keccak data
        let [is_final, hash_lo, hash_hi, bytes_left, word_value] = [
            ("is_final", self.keccak_table.is_enabled, Value::known(F::from(row.is_final))),
            ("hash_lo", self.keccak_table.output.lo(), row.hash.lo()),
            ("hash_hi", self.keccak_table.output.hi(), row.hash.hi()),
            ("bytes_left", self.keccak_table.bytes_left, Value::known(row.bytes_left)),
            ("word_value", self.keccak_table.word_value, Value::known(row.word_value)),
        ]
        .map(|(_name, column, value)| raw_assign_advice(region, column, offset, value));

        // Cell values
        row.cell_values.iter().zip(self.cell_manager.columns()).for_each(|(bit, column)| {
            raw_assign_advice(region, column.advice, offset, Value::known(*bit));
        });

        // Round constant
        raw_assign_fixed(region, self.round_cst, offset, row.round_cst);

        KeccakAssignedRow {
            is_final,
            hash_lo,
            hash_hi,
            bytes_left,
            word_value,
            _marker: PhantomData,
        }
    }

    pub fn load_aux_tables(&self, layouter: &mut impl Layouter<F>, k: u32) -> Result<(), Error> {
        load_normalize_table(layouter, "normalize_6", &self.normalize_6, 6u64, k)?;
        load_normalize_table(layouter, "normalize_4", &self.normalize_4, 4u64, k)?;
        load_normalize_table(layouter, "normalize_3", &self.normalize_3, 3u64, k)?;
        load_lookup_table(
            layouter,
            "chi base",
            &self.chi_base_table,
            get_num_bits_per_base_chi_lookup(k),
            &CHI_BASE_LOOKUP_TABLE,
        )?;
        load_pack_table(layouter, &self.pack_table)
    }
}
