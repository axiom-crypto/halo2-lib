use getset::Getters;
use itertools::Itertools;

use crate::{
    gates::{builder::CircuitBuilderStage, flex_gate::FlexGateConfigParams},
    utils::ScalarField,
    virtual_region::copy_constraints::SharedCopyConstraintManager,
    Context,
};

use super::SinglePhaseGateManager;

/// Virtual region manager for [FlexGateConfig] in multiple phases.
#[derive(Clone, Debug, Default, Getters)]
pub struct GateThreadBuilder<F: ScalarField> {
    /// Virtual region for each challenge phase. These cannot be shared across threads while keeping circuit deterministic.
    pub phase_manager: Vec<SinglePhaseGateManager<F>>,
    /// Global shared copy manager
    pub copy_manager: SharedCopyConstraintManager<F>,
    /// Flag for witness generation. If true, the gate thread builder is used for witness generation only.
    #[getset(get = "pub")]
    pub witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    #[getset(get = "pub")]
    use_unknown: bool,
}

impl<F: ScalarField> GateThreadBuilder<F> {
    /// Creates a new [GateThreadBuilder] and spawns a main thread in phase 0.
    /// * `witness_gen_only`: If true, the [GateThreadBuilder] is used for witness generation only.
    ///     * If true, the gate thread builder only does witness asignments and does not store constraint information -- this should only be used for the real prover.
    ///     * If false, the gate thread builder is used for keygen and mock prover (it can also be used for real prover) and the builder stores circuit information (e.g. copy constraints, fixed columns, enabled selectors).
    ///         * These values are fixed for the circuit at key generation time, and they do not need to be re-computed by the prover in the actual proving phase.
    pub fn new(witness_gen_only: bool) -> Self {
        let phase_manager = vec![SinglePhaseGateManager::new(witness_gen_only)];
        Self {
            phase_manager,
            witness_gen_only,
            use_unknown: false,
            copy_manager: Default::default(),
        }
    }

    /// Creates a new [GateThreadBuilder] depending on the stage of circuit building. If the stage is [CircuitBuilderStage::Prover], the [GateThreadBuilder] is used for witness generation only.
    pub fn from_stage(stage: CircuitBuilderStage) -> Self {
        Self::new(stage.witness_gen_only()).unknown(stage == CircuitBuilderStage::Keygen)
    }

    /// Sets a new copy manager
    pub fn copy_manager(mut self, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        for pm in &mut self.phase_manager {
            pm.copy_manager = copy_manager.clone();
        }
        self.copy_manager = copy_manager;
        self
    }

    /// Creates a new [GateThreadBuilder] with `use_unknown` flag set.
    /// * `use_unknown`: If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    pub fn unknown(mut self, use_unknown: bool) -> Self {
        self.use_unknown = use_unknown;
        for pm in &mut self.phase_manager {
            pm.use_unknown = use_unknown;
        }
        self
    }

    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    /// * `phase`: The challenge phase (as an index) of the gate thread.
    pub fn main(&mut self, phase: usize) -> &mut Context<F> {
        self.touch(phase);
        self.phase_manager[phase].main()
    }

    /// Spawns a new thread for a new given `phase`. Returns a mutable reference to the [Context] of the new thread.
    /// * `phase`: The phase (index) of the gate thread.
    pub fn new_thread(&mut self, phase: usize) -> &mut Context<F> {
        self.touch(phase);
        self.phase_manager[phase].new_thread()
    }

    /// Populate `self` up to Phase `phase` (inclusive)
    fn touch(&mut self, phase: usize) {
        while self.phase_manager.len() <= phase {
            let _phase = self.phase_manager.len();
            let pm = SinglePhaseGateManager::new(self.witness_gen_only)
                .copy_manager(self.copy_manager.clone())
                .in_phase(_phase);
            self.phase_manager.push(pm);
        }
    }

    /// Returns some statistics about the virtual region.
    pub fn statistics(&self) -> GateStatistics {
        let total_advice_per_phase =
            self.phase_manager.iter().map(|pm| pm.total_advice()).collect::<Vec<_>>();

        let total_fixed: usize = self
            .copy_manager
            .lock()
            .unwrap()
            .constant_equalities
            .iter()
            .map(|(c, _)| *c)
            .sorted()
            .dedup()
            .count();

        GateStatistics { total_advice_per_phase, total_fixed }
    }

    /// Auto-calculates configuration parameters for the circuit
    ///
    /// * `k`: The number of in the circuit (i.e. numeber of rows = 2<sup>k</sup>)
    /// * `minimum_rows`: The minimum number of rows in the circuit that cannot be used for witness assignments and contain random `blinding factors` to ensure zk property, defaults to 0.
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        let max_rows = (1 << k) - minimum_rows.unwrap_or(0);
        // set usable rows here as convenience for later use in `assign_raw`
        for pm in &self.phase_manager {
            pm.usable_rows.set(max_rows).unwrap();
        }
        let stats = self.statistics();
        // we do a rough estimate by taking ceil(advice_cells_per_phase / 2^k )
        // if this is too small, manual configuration will be needed
        let num_advice_per_phase = stats
            .total_advice_per_phase
            .iter()
            .map(|count| (count + max_rows - 1) / max_rows)
            .collect::<Vec<_>>();
        let num_fixed = (stats.total_fixed + (1 << k) - 1) >> k;

        let params = FlexGateConfigParams { num_advice_per_phase, num_fixed, k };
        #[cfg(feature = "display")]
        {
            for (phase, num_advice) in num_advice_per_phase.iter().enumerate() {
                println!("Gate Chip | Phase {phase}: {num_advice} advice cells",);
            }
            println!("Total {} fixed cells", stats.total_fixed);
            log::info!("Auto-calculated config params:\n {params:#?}");
        }
        params
    }
}

/// Basic statistics
pub struct GateStatistics {
    pub total_advice_per_phase: Vec<usize>,
    pub total_fixed: usize,
}
