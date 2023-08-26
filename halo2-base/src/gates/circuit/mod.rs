/// Module that helps auto-build circuits
pub mod builder;

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
