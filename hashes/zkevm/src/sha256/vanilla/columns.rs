//! The columns of the Sha256 circuit
use std::marker::PhantomData;

use halo2_base::halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed};

use crate::util::{eth_types::Field, word::Word};

use super::param::*;

/// ShaTable, copied from KeccakTable. However note that `NUM_BYTES_PER_WORD` is different for SHA256
#[derive(Clone, Debug)]
pub struct ShaTable {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// SHA256 hash of input
    pub output: Word<Column<Advice>>,
    /// Raw SHA256 word(NUM_BYTES_PER_WORD bytes) of inputs
    pub word_value: Column<Advice>,
    /// Number of bytes left of a input
    pub bytes_left: Column<Advice>,
}

impl ShaTable {
    /// Construct a new ShaTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let is_enabled = meta.advice_column();
        let word_value = meta.advice_column();
        let bytes_left = meta.advice_column();
        let hash_lo = meta.advice_column();
        let hash_hi = meta.advice_column();
        meta.enable_equality(is_enabled);
        meta.enable_equality(word_value);
        meta.enable_equality(bytes_left);
        meta.enable_equality(hash_lo);
        meta.enable_equality(hash_hi);
        Self { is_enabled, output: Word::new([hash_lo, hash_hi]), word_value, bytes_left }
    }
}

/// Configuration parameters to define [`Sha256BitConfig`]
#[derive(Copy, Clone, Debug, Default)]
pub struct Sha256ConfigParams {
    pub k: u32,
}

/// Columns for the Sha256 circuit
#[derive(Clone, Debug)]
pub struct Sha256CircuitConfig<F> {
    pub(super) q_enable: Column<Fixed>,
    pub(super) q_first: Column<Fixed>,
    pub(super) q_extend: Column<Fixed>,
    pub(super) q_start: Column<Fixed>,
    pub(super) q_compression: Column<Fixed>,
    pub(super) q_end: Column<Fixed>,
    pub(super) q_padding: Column<Fixed>,
    pub(super) q_padding_last: Column<Fixed>,
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
    /// Circuit configuration parameters
    pub parameters: Sha256ConfigParams,
    _marker: PhantomData<F>,
}
