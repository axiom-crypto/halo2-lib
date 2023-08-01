//! The zkEVM keccak circuit implementation, with some minor modifications
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit

#![feature(array_zip)]

use halo2_base::halo2_proofs::{self, circuit::AssignedCell, plonk::Assigned};

/// Keccak packed multi
pub mod keccak_packed_multi;
/// SHA-256 bit
pub mod sha256_bit;
/// Util
pub mod util;

pub use keccak_packed_multi::KeccakCircuitConfig as KeccakConfig;
pub use sha256_bit::Sha256BitConfig as Sha256Config;

#[cfg(feature = "halo2-axiom")]
pub type Halo2AssignedCell<'v, F> = AssignedCell<&'v Assigned<F>, F>;
#[cfg(not(feature = "halo2-axiom"))]
pub type Halo2AssignedCell<'v, F> = AssignedCell<F, F>;
