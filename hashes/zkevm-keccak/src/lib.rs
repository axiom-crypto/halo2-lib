//! The zkEVM keccak circuit implementation, with some minor modifications
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit

use halo2_base::halo2_proofs;

/// Util
pub mod util;

pub use keccak_circuit::KeccakCircuitConfig as KeccakConfig;

// ---- refactored
mod keccak_circuit;
pub mod keccak_table;
