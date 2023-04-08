//! The zkEVM keccak circuit implementation, with some minor modifications
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit

use halo2_base::halo2_proofs;

mod keccak_circuit;

/// Keccak packed multi
pub use keccak_circuit::keccak_packed_multi;
/// Util
pub use keccak_circuit::util;

pub use keccak_circuit::KeccakCircuitConfig as KeccakConfig;
