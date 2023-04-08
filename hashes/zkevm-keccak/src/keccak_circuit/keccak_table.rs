use super::util::eth_types::Field;
use crate::halo2_proofs::plonk::{Advice, Column, ConstraintSystem, SecondPhase};

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    // Byte array input length
    // pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
}

impl KeccakTable {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let input_rlc = meta.advice_column_in(SecondPhase);
        let output_rlc = meta.advice_column_in(SecondPhase);
        meta.enable_equality(input_rlc);
        meta.enable_equality(output_rlc);
        Self {
            is_enabled: meta.advice_column(),
            input_rlc,
            // input_len: meta.advice_column(),
            output_rlc,
        }
    }
}
