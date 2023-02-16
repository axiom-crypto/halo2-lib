//! The zkEVM keccak circuit implementation, with some minor modifications
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit

use halo2_base::halo2_proofs;

/// Keccak packed multi
pub mod keccak_packed_multi;
/// Util
pub mod util;

pub mod keccak_f;
pub mod control;

pub use keccak_packed_multi::KeccakCircuitConfig as KeccakConfig;
