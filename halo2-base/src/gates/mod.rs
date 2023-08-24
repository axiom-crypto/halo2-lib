/// Module implementing our simple custom gate and common functions using it
pub mod flex_gate;
/// Module using a single lookup table for range checks
pub mod range;

/// Tests
#[cfg(test)]
pub mod tests;

pub use flex_gate::{GateChip, GateInstructions};
pub use range::{RangeChip, RangeInstructions};

/// Defines stage of circuit building.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitBuilderStage {
    /// Keygen phase
    Keygen,
    /// Prover Circuit
    Prover,
    /// Mock Circuit
    Mock,
}

impl CircuitBuilderStage {
    /// Returns true if the circuit is used for witness generation only.
    pub fn witness_gen_only(&self) -> bool {
        matches!(self, CircuitBuilderStage::Prover)
    }
}
