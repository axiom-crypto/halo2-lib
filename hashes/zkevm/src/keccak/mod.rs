use self::{cell_manager::*, keccak_packed_multi::*, param::*, table::*, util::*};
use super::util::{
    constraint_builder::BaseConstraintBuilder,
    eth_types::{self, Field},
    expression::{and, not, select, Expr},
};
use crate::{
    halo2_proofs::{
        circuit::{Layouter, Region, Value},
        halo2curves::ff::PrimeField,
        plonk::{Column, ConstraintSystem, Error, Expression, Fixed, TableColumn, VirtualCells},
        poly::Rotation,
    },
    util::word::{self, Word, WordExpr},
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
    // // Bool. True on every row of all valid rounds.
    // q_enable_row: Column<Fixed>,
    // Bool. True on 1st row.
    q_first: Column<Fixed>,
    // Bool. True on 1st row of all rounds except last rounds.
    q_round: Column<Fixed>,
    // Bool. True on 1st row of last rounds.
    q_absorb: Column<Fixed>,
    // Bool. True on 1st row of last rounds.
    q_round_last: Column<Fixed>,
    // Bool. True on 1st row of padding rounds.
    q_padding: Column<Fixed>,
    // Bool. True on 1st row of last padding rounds.
    q_padding_last: Column<Fixed>,

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
        // let q_enable_row = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_round = meta.fixed_column();
        let q_absorb = meta.fixed_column();
        let q_round_last = meta.fixed_column();
        let q_padding = meta.fixed_column();
        let q_padding_last = meta.fixed_column();
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
        let q_in_round = |col: Column<Fixed>, meta: &mut VirtualCells<'_, F>| {
            (0..num_rows_per_round as i32)
                .map(|i| meta.query_fixed(col, Rotation(-i)))
                .fold(0.expr(), |acc, elem| acc + elem)
        };

        /*
        eg：
            data:
                get_num_rows_per_round: 18
                input: "12345678abc"
            table:
                Note[1]: be careful: is_paddings is not column here! It is [Cell; 8].
        offset  value bytes_left  is_paddings q_enable q_padding_last
        18        1      11          0         1        0 // 1st round begin
        19        2      10          0         0        0
        20        3      9           0         0        0
        21        4      8           0         0        0
        22        5      7           0         0        0
        23        6      6           0         0        0
        24        7      5           0         0        0
        25        8      4           0         0        0
        26        8      4           NA        0        0
        ...
        35        8      4           NA        0        0  // 1st round end
        36        a      3           0         1        1  // 2nd round begin
        37        b      2           0         0        0
        38        c      1           0         0        0
        39        0      0           1         0        0
        40        0      0           1         0        0
        41        0      0           1         0        0
        42        0      0           1         0        0
        43        0      0           1         0        0
        */

        meta.create_gate("byte_value", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            for idx in 0..num_rows_per_round {
                // q_padding[idx] && !is_paddings[min(i+1, NUM_BYTES_PER_WORD - 1)] => byte_value[idx] == input_bytes[min(i+1, NUM_BYTES_PER_WORD - 1)]
                // Length of is_paddings is NUM_BYTES_PER_WORD so NUM_BYTES_PER_WORD - 1 means the last byte.
                cb.condition(
                    q(q_padding, meta)
                        * not::expr(is_paddings[std::cmp::min(idx, NUM_BYTES_PER_WORD - 1)].expr()),
                    |cb| {
                        cb.require_equal(
                            "input byte",
                            input_bytes[std::cmp::min(idx, NUM_BYTES_PER_WORD - 1)].expr.clone(),
                            meta.query_advice(keccak_table.byte_value, Rotation(idx as i32)),
                        );
                    },
                );
            }
            cb.gate(q(q_enable, meta))
        });
        meta.create_gate("bytes_left", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // q_first[i] == 0 => bytes_left[i] == 0
            cb.condition(q_in_round(q_first, meta), |cb| {
                cb.require_zero(
                    "bytes_left needs to be zero on the first row",
                    meta.query_advice(keccak_table.bytes_left, Rotation::cur()),
                );
            });
            // is_paddings only be true when
            cb.condition(q(q_padding, meta), |cb| {
                for i in 0..num_rows_per_round {
                    let bytes_left = meta.query_advice(keccak_table.bytes_left, Rotation(i as i32));
                    let bytes_left_next =
                        meta.query_advice(keccak_table.bytes_left, Rotation(i as i32 + 1));
                    // real input only when !is_paddings[i] && i < NUM_BYTES_PER_WORD
                    cb.require_equal(
                        "if not padding, bytes_left decreases by 1, else, stay same",
                        bytes_left_next,
                        bytes_left.clone()
                            - if i < 7 || i == num_rows_per_round - 1 {
                                not::expr(
                                    is_paddings[std::cmp::min(i, NUM_BYTES_PER_WORD - 1)].expr(),
                                )
                            } else {
                                0.expr()
                            },
                    );
                    cb.require_zero(
                        "bytes_left should be 0 when padding",
                        bytes_left * is_paddings[std::cmp::min(i, NUM_BYTES_PER_WORD - 1)].expr(),
                    );
                }
            });
            cb.condition(
                (q_in_round(q_enable, meta)
                    - q_in_round(q_padding, meta)
                    - q_in_round(q_first, meta))
                    * meta.query_advice(is_final, Rotation::next()),
                |cb| {
                    let bytes_left = meta.query_advice(keccak_table.bytes_left, Rotation::cur());
                    let bytes_left_next =
                        meta.query_advice(keccak_table.bytes_left, Rotation::next());
                    cb.require_equal(
                        "bytes_left should stay same on non absorb round",
                        bytes_left,
                        bytes_left_next,
                    );
                },
            );
            cb.condition(q(q_enable, meta) * meta.query_advice(is_final, Rotation::cur()), |cb| {
                let bytes_left = meta.query_advice(keccak_table.bytes_left, Rotation::cur());
                cb.require_zero("bytes_left should be 0 when is_final", bytes_left);
            });
            cb.gate(1.expr())
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
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let q_padding_last = meta.query_fixed(q_padding_last, Rotation::cur());

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
                cb.condition(q_padding.expr(), |cb| {
                    cb.require_boolean("padding step boolean", is_first_padding.clone());
                });

                // Padding start/intermediate/end byte checks
                if idx == is_paddings.len() - 1 {
                    // These can be combined in the future, but currently this would increase the
                    // degree by one Padding start/intermediate byte, all
                    // padding rows except the last one
                    cb.condition(
                        and::expr([
                            q_padding.expr() - q_padding_last.expr(),
                            is_paddings[idx].expr(),
                        ]),
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
                    cb.condition(
                        and::expr([q_padding_last.expr(), is_paddings[idx].expr()]),
                        |cb| {
                            // The input byte needs to be 128, unless it's also the first padding
                            // byte then it's 129
                            cb.require_equal(
                                "padding start/end byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr() + 128.expr(),
                            );
                        },
                    );
                } else {
                    // Padding start/intermediate byte
                    cb.condition(and::expr([q_padding.expr(), is_paddings[idx].expr()]), |cb| {
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
            q_padding,
            q_padding_last,
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

#[allow(dead_code)]
#[derive(Clone)]
pub struct KeccakAssignedRow<'v, F: Field> {
    pub(crate) is_final: KeccakAssignedValue<'v, F>,
    pub(crate) hash_lo: KeccakAssignedValue<'v, F>,
    pub(crate) hash_hi: KeccakAssignedValue<'v, F>,
    pub(crate) bytes_left: KeccakAssignedValue<'v, F>,
    pub(crate) byte_value: KeccakAssignedValue<'v, F>,
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
            ("q_padding", self.q_padding, F::from(row.q_padding)),
            ("q_padding_last", self.q_padding_last, F::from(row.q_padding_last)),
        ] {
            raw_assign_fixed(region, *column, offset, *value);
        }

        // Keccak data
        let [is_final, hash_lo, hash_hi, bytes_left, byte_value] = [
            ("is_final", self.keccak_table.is_enabled, Value::known(F::from(row.is_final))),
            ("hash_lo", self.keccak_table.output.lo(), row.hash.lo()),
            ("hash_hi", self.keccak_table.output.hi(), row.hash.hi()),
            ("bytes_left", self.keccak_table.bytes_left, Value::known(row.bytes_left)),
            ("value", self.keccak_table.byte_value, Value::known(row.byte_value)),
        ]
        .map(|(_name, column, value)| raw_assign_advice(region, column, offset, value));

        // Cell values
        row.cell_values.iter().zip(self.cell_manager.columns()).for_each(|(bit, column)| {
            raw_assign_advice(region, column.advice, offset, Value::known(*bit));
        });

        // Round constant
        raw_assign_fixed(region, self.round_cst, offset, row.round_cst);

        KeccakAssignedRow { is_final, hash_lo, hash_hi, bytes_left, byte_value }
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
                let byte_idx = if round < NUM_WORDS_TO_ABSORB {
                    round * 8 + std::cmp::min(row_idx, NUM_BYTES_PER_WORD - 1)
                } else {
                    NUM_WORDS_TO_ABSORB * 8
                } + idx * NUM_WORDS_TO_ABSORB * 8;

                let byte = if byte_idx >= bytes.len() { 0 } else { bytes[byte_idx] };
                let bytes_left = if byte_idx >= bytes.len() { 0 } else { bytes.len() - byte_idx };
                rows.push(KeccakRow {
                    q_enable: row_idx == 0,
                    // q_enable_row: true,
                    q_round: row_idx == 0 && round < NUM_ROUNDS,
                    q_absorb: row_idx == 0 && round == NUM_ROUNDS,
                    q_round_last: row_idx == 0 && round == NUM_ROUNDS,
                    q_padding: row_idx == 0 && round < NUM_WORDS_TO_ABSORB,
                    q_padding_last: row_idx == 0 && round == NUM_WORDS_TO_ABSORB - 1,
                    round_cst,
                    is_final: is_final_block && round == NUM_ROUNDS && row_idx == 0,
                    cell_values: regions[round].rows.get(row_idx).unwrap_or(&vec![]).clone(),
                    hash,
                    bytes_left: F::from_u128(bytes_left as u128),
                    byte_value: F::from_u128(byte as u128),
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
                    .to_vec()
            })
            .collect::<Vec<_>>();
        debug!("hash: {:x?}", &(hash_bytes[0..4].concat()));
        assert_eq!(length, bytes.len());
    }
}

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
