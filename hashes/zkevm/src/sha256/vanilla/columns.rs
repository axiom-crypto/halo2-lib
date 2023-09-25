//! The columns of the Sha256 circuit
use std::marker::PhantomData;

use halo2_base::halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed};

use crate::util::{eth_types::Field, word::Word};

use super::param::*;

/// ShaTable, copied from KeccakTable. However note that `NUM_BYTES_PER_WORD` is different for SHA256
#[derive(Clone, Debug)]
pub struct ShaTable {
    /// Selector always turned on except in blinding rows.
    pub(super) q_enable: Column<Fixed>,
    /// is_enabled := q_squeeze && is_final
    /// q_squeeze is selector for dedicated row per input block for squeezing
    /// is_final is flag for whether this block actually is the last block of an input
    pub is_enabled: Column<Advice>,
    /// SHA256 hash of input
    pub output: Word<Column<Advice>>,
    /// Raw SHA256 word(NUM_BYTES_PER_WORD bytes) of inputs
    pub word_value: Column<Advice>,
    /// Length in bytes of the input processed so far. Does not include padding.
    pub length: Column<Advice>,
}

impl ShaTable {
    /// Construct a new ShaTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let q_enable = meta.fixed_column();
        let is_enabled = meta.advice_column();
        let word_value = meta.advice_column();
        let length = meta.advice_column();
        let hash_lo = meta.advice_column();
        let hash_hi = meta.advice_column();
        meta.enable_equality(is_enabled);
        meta.enable_equality(word_value);
        meta.enable_equality(length);
        meta.enable_equality(hash_lo);
        meta.enable_equality(hash_hi);
        Self { q_enable, is_enabled, output: Word::new([hash_lo, hash_hi]), word_value, length }
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
    pub(super) is_final: Column<Advice>,
    pub(super) is_paddings: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    pub(super) round_cst: Column<Fixed>,
    pub(super) h_a: Column<Fixed>,
    pub(super) h_e: Column<Fixed>,
    /// The columns for other circuits to lookup hash results
    pub hash_table: ShaTable,
    pub(super) _marker: PhantomData<F>,
}
