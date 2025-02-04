//! The columns of the Sha256 circuit
use std::marker::PhantomData;

use halo2_base::halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed};

use crate::util::eth_types::Field;

use super::param::*;

/// ShaTable, copied from KeccakTable. However note that `NUM_BYTES_PER_WORD` is different for SHA256
#[derive(Clone, Debug)]
pub struct ShaTable {
    /// Selector always turned on except in blinding rows.
    pub(super) q_enable: Column<Fixed>,
    /// Single shared column containing different IO data depending on the `offset` within
    /// a SHA256 input block ([SHA256_NUM_ROWS] = 72 rows): If offset is in
    /// Encoded input:
    /// - [NUM_START_ROWS]..[NUM_START_ROWS] + [NUM_WORDS_TO_ABSORB]: Raw SHA256 word([NUM_BYTES_PER_WORD] bytes) of inputs
    ///
    /// SHA256 hash of input in hi-lo format:
    /// - [SHA256_NUM_ROWS] - 2: output.hi()
    /// - [SHA256_NUM_ROWS] - 1: output.lo()
    pub io: Column<Advice>,
    /// Length in bytes of the input processed so far. Does not include padding.
    pub length: Column<Advice>,
    /// Advice to represent if this input block is the last one for a variable length input.
    /// The advice value should only be used in the last row of each [SHA256_NUM_ROWS] block.
    pub(super) is_final: Column<Advice>,
}

impl ShaTable {
    /// Construct a new ShaTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let q_enable = meta.fixed_column();
        let io = meta.advice_column();
        let length = meta.advice_column();
        let hash_lo = meta.advice_column();
        let hash_hi = meta.advice_column();
        meta.enable_equality(io);
        meta.enable_equality(length);
        meta.enable_equality(hash_lo);
        meta.enable_equality(hash_hi);
        let is_final = meta.advice_column();
        Self { q_enable, io, length, is_final }
    }
}

/// Columns for the Sha256 circuit
#[derive(Clone, Debug)]
pub struct Sha256CircuitConfig<F> {
    pub(super) q_first: Column<Fixed>,
    pub(super) q_extend: Column<Fixed>,
    pub(super) q_start: Column<Fixed>,
    pub(super) q_compression: Column<Fixed>,
    pub(super) q_end: Column<Fixed>,
    // Bool. True on rows NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB per input block.
    // These are the rounds when input might be absorbed.
    // It "might" contain inputs because it's possible that a round only have paddings.
    pub(super) q_input: Column<Fixed>,
    // Bool. True on row NUM_START_ROWS + NUM_WORDS_TO_ABSORB - 1 for each input block.
    // This is the last round when input is absorbed.
    pub(super) q_input_last: Column<Fixed>,
    pub(super) q_squeeze: Column<Fixed>,
    pub(super) word_w: [Column<Advice>; NUM_BITS_PER_WORD_W],
    pub(super) word_a: [Column<Advice>; NUM_BITS_PER_WORD_EXT],
    pub(super) word_e: [Column<Advice>; NUM_BITS_PER_WORD_EXT],
    pub(super) is_paddings: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    pub(super) round_cst: Column<Fixed>,
    pub(super) h_a: Column<Fixed>,
    pub(super) h_e: Column<Fixed>,
    /// The columns for other circuits to lookup hash results
    pub hash_table: ShaTable,
    pub(super) _marker: PhantomData<F>,
}
