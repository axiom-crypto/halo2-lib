use super::{cell_manager::*, param::*, table::*};
use crate::{
    halo2_proofs::{
        circuit::{Region, Value},
        halo2curves::ff::PrimeField,
        plonk::{Advice, Column, ConstraintSystem, Expression, Fixed},
    },
    util::{
        constraint_builder::BaseConstraintBuilder, eth_types::Field, expression::Expr, word::Word,
    },
};
use halo2_base::halo2_proofs::{circuit::AssignedCell, plonk::Assigned};

pub(crate) fn get_num_bits_per_absorb_lookup(k: u32) -> usize {
    get_num_bits_per_lookup(ABSORB_LOOKUP_RANGE, k)
}

pub(crate) fn get_num_bits_per_theta_c_lookup(k: u32) -> usize {
    get_num_bits_per_lookup(THETA_C_LOOKUP_RANGE, k)
}

pub(crate) fn get_num_bits_per_rho_pi_lookup(k: u32) -> usize {
    get_num_bits_per_lookup(CHI_BASE_LOOKUP_RANGE.max(RHO_PI_LOOKUP_RANGE), k)
}

pub(crate) fn get_num_bits_per_base_chi_lookup(k: u32) -> usize {
    get_num_bits_per_lookup(CHI_BASE_LOOKUP_RANGE.max(RHO_PI_LOOKUP_RANGE), k)
}

/// The number of keccak_f's that can be done in this circuit
///
/// `num_rows` should be number of usable rows without blinding factors
pub fn get_keccak_capacity(num_rows: usize, rows_per_round: usize) -> usize {
    // - 1 because we have a dummy round at the very beginning of multi_keccak
    // - NUM_WORDS_TO_ABSORB because `absorb_data_next` and `absorb_result_next` query `NUM_WORDS_TO_ABSORB * num_rows_per_round` beyond any row where `q_absorb == 1`
    (num_rows / rows_per_round - 1 - NUM_WORDS_TO_ABSORB) / (NUM_ROUNDS + 1)
}

pub fn get_num_keccak_f(byte_length: usize) -> usize {
    // ceil( (byte_length + 1) / RATE )
    byte_length / RATE + 1
}

/// AbsorbData
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct AbsorbData<F: PrimeField> {
    pub(crate) from: F,
    pub(crate) absorb: F,
    pub(crate) result: F,
}

/// SqueezeData
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct SqueezeData<F: PrimeField> {
    packed: F,
}

/// KeccakRow. Field definitions could be found in [KeccakCircuitConfig].
#[derive(Clone, Debug)]
pub struct KeccakRow<F: PrimeField> {
    pub(crate) q_enable: bool,
    // pub(crate) q_enable_row: bool,
    pub(crate) q_round: bool,
    pub(crate) q_absorb: bool,
    pub(crate) q_round_last: bool,
    pub(crate) q_padding: bool,
    pub(crate) q_padding_last: bool,
    pub(crate) round_cst: F,
    pub(crate) is_final: bool,
    pub(crate) cell_values: Vec<F>,
    // SecondPhase values will be assigned separately
    // pub(crate) data_rlc: Value<F>,
    pub(crate) hash: Word<Value<F>>,
    pub(crate) bytes_left: F,
    pub(crate) word_value: F,
}

impl<F: PrimeField> KeccakRow<F> {
    pub fn dummy_rows(num_rows: usize) -> Vec<Self> {
        (0..num_rows)
            .map(|idx| KeccakRow {
                q_enable: idx == 0,
                q_round: false,
                q_absorb: idx == 0,
                q_round_last: false,
                q_padding: false,
                q_padding_last: false,
                round_cst: F::ZERO,
                is_final: false,
                cell_values: Vec::new(),
                hash: Word::default().into_value(),
                bytes_left: F::ZERO,
                word_value: F::ZERO,
            })
            .collect()
    }
}

/// Part
#[derive(Clone, Debug)]
pub(crate) struct Part<F: PrimeField> {
    pub(crate) cell: Cell<F>,
    pub(crate) expr: Expression<F>,
    pub(crate) num_bits: usize,
}

/// Part Value
#[derive(Clone, Copy, Debug)]
pub(crate) struct PartValue<F: PrimeField> {
    pub(crate) value: F,
    pub(crate) rot: i32,
    pub(crate) num_bits: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct KeccakRegion<F> {
    pub(crate) rows: Vec<Vec<F>>,
}

impl<F: PrimeField> KeccakRegion<F> {
    pub(crate) fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub(crate) fn assign(&mut self, column: usize, offset: usize, value: F) {
        while offset >= self.rows.len() {
            self.rows.push(Vec::new());
        }
        let row = &mut self.rows[offset];
        while column >= row.len() {
            row.push(F::ZERO);
        }
        row[column] = value;
    }
}

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Keccak hash of input
    pub output: Word<Column<Advice>>,
    /// Raw word bytes of inputs
    pub word_value: Column<Advice>,
    /// Number of bytes left of a input
    pub bytes_left: Column<Advice>,
}

impl KeccakTable {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let input_len = meta.advice_column();
        let word_value = meta.advice_column();
        let bytes_left = meta.advice_column();
        meta.enable_equality(input_len);
        Self {
            is_enabled: meta.advice_column(),
            output: Word::new([meta.advice_column(), meta.advice_column()]),
            word_value,
            bytes_left,
        }
    }
}

#[cfg(feature = "halo2-axiom")]
pub(crate) type KeccakAssignedValue<'v, F> = AssignedCell<&'v Assigned<F>, F>;
#[cfg(not(feature = "halo2-axiom"))]
pub(crate) type KeccakAssignedValue<'v, F> = AssignedCell<F, F>;

pub fn assign_advice_custom<'v, F: Field>(
    region: &mut Region<F>,
    column: Column<Advice>,
    offset: usize,
    value: Value<F>,
) -> KeccakAssignedValue<'v, F> {
    #[cfg(feature = "halo2-axiom")]
    {
        region.assign_advice(column, offset, value)
    }
    #[cfg(feature = "halo2-pse")]
    {
        region
            .assign_advice(|| format!("assign advice {}", offset), column, offset, || value)
            .unwrap()
    }
}

pub fn assign_fixed_custom<F: Field>(
    region: &mut Region<F>,
    column: Column<Fixed>,
    offset: usize,
    value: F,
) {
    #[cfg(feature = "halo2-axiom")]
    {
        region.assign_fixed(column, offset, value);
    }
    #[cfg(feature = "halo2-pse")]
    {
        region
            .assign_fixed(
                || format!("assign fixed {}", offset),
                column,
                offset,
                || Value::known(value),
            )
            .unwrap();
    }
}

/// Recombines parts back together
pub(crate) mod decode {
    use super::{Expr, Part, PartValue, PrimeField};
    use crate::{halo2_proofs::plonk::Expression, keccak::param::*};

    pub(crate) fn expr<F: PrimeField>(parts: Vec<Part<F>>) -> Expression<F> {
        parts.iter().rev().fold(0.expr(), |acc, part| {
            acc * F::from(1u64 << (BIT_COUNT * part.num_bits)) + part.expr.clone()
        })
    }

    pub(crate) fn value<F: PrimeField>(parts: Vec<PartValue<F>>) -> F {
        parts.iter().rev().fold(F::ZERO, |acc, part| {
            acc * F::from(1u64 << (BIT_COUNT * part.num_bits)) + part.value
        })
    }
}

/// Splits a word into parts
pub(crate) mod split {
    use super::{
        decode, BaseConstraintBuilder, CellManager, Expr, Field, KeccakRegion, Part, PartValue,
        PrimeField,
    };
    use crate::{
        halo2_proofs::plonk::{ConstraintSystem, Expression},
        keccak::util::{pack, pack_part, unpack, WordParts},
    };

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        cell_manager: &mut CellManager<F>,
        cb: &mut BaseConstraintBuilder<F>,
        input: Expression<F>,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
        row: Option<usize>,
    ) -> Vec<Part<F>> {
        let word = WordParts::new(target_part_size, rot, normalize);
        let mut parts = Vec::with_capacity(word.parts.len());
        for word_part in word.parts {
            let cell = if let Some(row) = row {
                cell_manager.query_cell_at_row(meta, row as i32)
            } else {
                cell_manager.query_cell(meta)
            };
            parts.push(Part {
                num_bits: word_part.bits.len(),
                cell: cell.clone(),
                expr: cell.expr(),
            });
        }
        // Input parts need to equal original input expression
        cb.require_equal("split", decode::expr(parts.clone()), input);
        parts
    }

    pub(crate) fn value<F: Field>(
        cell_manager: &mut CellManager<F>,
        region: &mut KeccakRegion<F>,
        input: F,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
        row: Option<usize>,
    ) -> Vec<PartValue<F>> {
        let input_bits = unpack(input);
        debug_assert_eq!(pack::<F>(&input_bits), input);
        let word = WordParts::new(target_part_size, rot, normalize);
        let mut parts = Vec::with_capacity(word.parts.len());
        for word_part in word.parts {
            let value = pack_part(&input_bits, &word_part);
            let cell = if let Some(row) = row {
                cell_manager.query_cell_value_at_row(row as i32)
            } else {
                cell_manager.query_cell_value()
            };
            cell.assign(region, 0, F::from(value));
            parts.push(PartValue {
                num_bits: word_part.bits.len(),
                rot: cell.rotation,
                value: F::from(value),
            });
        }
        debug_assert_eq!(decode::value(parts.clone()), input);
        parts
    }
}

// Split into parts, but storing the parts in a specific way to have the same
// table layout in `output_cells` regardless of rotation.
pub(crate) mod split_uniform {
    use super::decode;
    use crate::{
        halo2_proofs::plonk::{ConstraintSystem, Expression},
        keccak::{
            param::*,
            target_part_sizes,
            util::{pack, pack_part, rotate, rotate_rev, unpack, WordParts},
            BaseConstraintBuilder, Cell, CellManager, Expr, KeccakRegion, Part, PartValue,
            PrimeField,
        },
        util::eth_types::Field,
    };

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        output_cells: &[Cell<F>],
        cell_manager: &mut CellManager<F>,
        cb: &mut BaseConstraintBuilder<F>,
        input: Expression<F>,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
    ) -> Vec<Part<F>> {
        let mut input_parts = Vec::new();
        let mut output_parts = Vec::new();
        let word = WordParts::new(target_part_size, rot, normalize);

        let word = rotate(word.parts, rot, target_part_size);

        let target_sizes = target_part_sizes(target_part_size);
        let mut word_iter = word.iter();
        let mut counter = 0;
        while let Some(word_part) = word_iter.next() {
            if word_part.bits.len() == target_sizes[counter] {
                // Input and output part are the same
                let part = Part {
                    num_bits: target_sizes[counter],
                    cell: output_cells[counter].clone(),
                    expr: output_cells[counter].expr(),
                };
                input_parts.push(part.clone());
                output_parts.push(part);
                counter += 1;
            } else if let Some(extra_part) = word_iter.next() {
                // The two parts combined need to have the expected combined length
                debug_assert_eq!(
                    word_part.bits.len() + extra_part.bits.len(),
                    target_sizes[counter]
                );

                // Needs two cells here to store the parts
                // These still need to be range checked elsewhere!
                let part_a = cell_manager.query_cell(meta);
                let part_b = cell_manager.query_cell(meta);

                // Make sure the parts combined equal the value in the uniform output
                let expr = part_a.expr()
                    + part_b.expr()
                        * F::from((BIT_SIZE as u32).pow(word_part.bits.len() as u32) as u64);
                cb.require_equal("rot part", expr, output_cells[counter].expr());

                // Input needs the two parts because it needs to be able to undo the rotation
                input_parts.push(Part {
                    num_bits: word_part.bits.len(),
                    cell: part_a.clone(),
                    expr: part_a.expr(),
                });
                input_parts.push(Part {
                    num_bits: extra_part.bits.len(),
                    cell: part_b.clone(),
                    expr: part_b.expr(),
                });
                // Output only has the combined cell
                output_parts.push(Part {
                    num_bits: target_sizes[counter],
                    cell: output_cells[counter].clone(),
                    expr: output_cells[counter].expr(),
                });
                counter += 1;
            } else {
                unreachable!();
            }
        }
        let input_parts = rotate_rev(input_parts, rot, target_part_size);
        // Input parts need to equal original input expression
        cb.require_equal("split", decode::expr(input_parts), input);
        // Uniform output
        output_parts
    }

    pub(crate) fn value<F: Field>(
        output_cells: &[Cell<F>],
        cell_manager: &mut CellManager<F>,
        region: &mut KeccakRegion<F>,
        input: F,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
    ) -> Vec<PartValue<F>> {
        let input_bits = unpack(input);
        debug_assert_eq!(pack::<F>(&input_bits), input);

        let mut input_parts = Vec::new();
        let mut output_parts = Vec::new();
        let word = WordParts::new(target_part_size, rot, normalize);

        let word = rotate(word.parts, rot, target_part_size);

        let target_sizes = target_part_sizes(target_part_size);
        let mut word_iter = word.iter();
        let mut counter = 0;
        while let Some(word_part) = word_iter.next() {
            if word_part.bits.len() == target_sizes[counter] {
                let value = pack_part(&input_bits, word_part);
                output_cells[counter].assign(region, 0, F::from(value));
                input_parts.push(PartValue {
                    num_bits: word_part.bits.len(),
                    rot: output_cells[counter].rotation,
                    value: F::from(value),
                });
                output_parts.push(PartValue {
                    num_bits: word_part.bits.len(),
                    rot: output_cells[counter].rotation,
                    value: F::from(value),
                });
                counter += 1;
            } else if let Some(extra_part) = word_iter.next() {
                debug_assert_eq!(
                    word_part.bits.len() + extra_part.bits.len(),
                    target_sizes[counter]
                );

                let part_a = cell_manager.query_cell_value();
                let part_b = cell_manager.query_cell_value();

                let value_a = pack_part(&input_bits, word_part);
                let value_b = pack_part(&input_bits, extra_part);

                part_a.assign(region, 0, F::from(value_a));
                part_b.assign(region, 0, F::from(value_b));

                let value = value_a + value_b * (BIT_SIZE as u64).pow(word_part.bits.len() as u32);

                output_cells[counter].assign(region, 0, F::from(value));

                input_parts.push(PartValue {
                    num_bits: word_part.bits.len(),
                    value: F::from(value_a),
                    rot: part_a.rotation,
                });
                input_parts.push(PartValue {
                    num_bits: extra_part.bits.len(),
                    value: F::from(value_b),
                    rot: part_b.rotation,
                });
                output_parts.push(PartValue {
                    num_bits: target_sizes[counter],
                    value: F::from(value),
                    rot: output_cells[counter].rotation,
                });
                counter += 1;
            } else {
                unreachable!();
            }
        }
        let input_parts = rotate_rev(input_parts, rot, target_part_size);
        debug_assert_eq!(decode::value(input_parts), input);
        output_parts
    }
}

// Transform values using a lookup table
pub(crate) mod transform {
    use super::{transform_to, CellManager, Field, KeccakRegion, Part, PartValue, PrimeField};
    use crate::halo2_proofs::plonk::{ConstraintSystem, TableColumn};
    use itertools::Itertools;

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: PrimeField>(
        name: &'static str,
        meta: &mut ConstraintSystem<F>,
        cell_manager: &mut CellManager<F>,
        lookup_counter: &mut usize,
        input: Vec<Part<F>>,
        transform_table: [TableColumn; 2],
        uniform_lookup: bool,
    ) -> Vec<Part<F>> {
        let cells = input
            .iter()
            .map(|input_part| {
                if uniform_lookup {
                    cell_manager.query_cell_at_row(meta, input_part.cell.rotation)
                } else {
                    cell_manager.query_cell(meta)
                }
            })
            .collect_vec();
        transform_to::expr(
            name,
            meta,
            &cells,
            lookup_counter,
            input,
            transform_table,
            uniform_lookup,
        )
    }

    pub(crate) fn value<F: Field>(
        cell_manager: &mut CellManager<F>,
        region: &mut KeccakRegion<F>,
        input: Vec<PartValue<F>>,
        do_packing: bool,
        f: fn(&u8) -> u8,
        uniform_lookup: bool,
    ) -> Vec<PartValue<F>> {
        let cells = input
            .iter()
            .map(|input_part| {
                if uniform_lookup {
                    cell_manager.query_cell_value_at_row(input_part.rot)
                } else {
                    cell_manager.query_cell_value()
                }
            })
            .collect_vec();
        transform_to::value(&cells, region, input, do_packing, f)
    }
}

// Transfroms values to cells
pub(crate) mod transform_to {
    use crate::{
        halo2_proofs::plonk::{ConstraintSystem, TableColumn},
        keccak::{
            util::{pack, to_bytes, unpack},
            {Cell, Expr, Field, KeccakRegion, Part, PartValue, PrimeField},
        },
    };

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: PrimeField>(
        name: &'static str,
        meta: &mut ConstraintSystem<F>,
        cells: &[Cell<F>],
        lookup_counter: &mut usize,
        input: Vec<Part<F>>,
        transform_table: [TableColumn; 2],
        uniform_lookup: bool,
    ) -> Vec<Part<F>> {
        let mut output = Vec::with_capacity(input.len());
        for (idx, input_part) in input.iter().enumerate() {
            let output_part = cells[idx].clone();
            if !uniform_lookup || input_part.cell.rotation == 0 {
                meta.lookup(name, |_| {
                    vec![
                        (input_part.expr.clone(), transform_table[0]),
                        (output_part.expr(), transform_table[1]),
                    ]
                });
                *lookup_counter += 1;
            }
            output.push(Part {
                num_bits: input_part.num_bits,
                cell: output_part.clone(),
                expr: output_part.expr(),
            });
        }
        output
    }

    pub(crate) fn value<F: Field>(
        cells: &[Cell<F>],
        region: &mut KeccakRegion<F>,
        input: Vec<PartValue<F>>,
        do_packing: bool,
        f: fn(&u8) -> u8,
    ) -> Vec<PartValue<F>> {
        let mut output = Vec::new();
        for (idx, input_part) in input.iter().enumerate() {
            let input_bits = &unpack(input_part.value)[0..input_part.num_bits];
            let output_bits = input_bits.iter().map(f).collect::<Vec<_>>();
            let value = if do_packing {
                pack(&output_bits)
            } else {
                F::from(to_bytes::value(&output_bits)[0] as u64)
            };
            let output_part = cells[idx].clone();
            output_part.assign(region, 0, value);
            output.push(PartValue {
                num_bits: input_part.num_bits,
                rot: output_part.rotation,
                value,
            });
        }
        output
    }
}
