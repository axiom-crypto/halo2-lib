use crate::{
    gates::{
        flex_gate::{
            threads::{GateStatistics, MultiPhaseCoreManager, SinglePhaseCoreManager},
            MultiPhaseThreadBreakPoints, MAX_PHASE,
        },
        range::{BaseConfig, BaseConfigParams, PublicBaseConfig, RangeConfig},
        CircuitBuilderStage, RangeChip,
    },
    halo2_proofs::{
        circuit::{Layouter, Region, SimpleFloorPlanner},
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    },
    utils::ScalarField,
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, lookups::LookupAnyManager,
        manager::VirtualRegionManager,
    },
    AssignedValue, Context,
};
use getset::{Getters, MutGetters, Setters};
use itertools::Itertools;

/// Keeping the naming `RangeCircuitBuilder` for backwards compatibility.
pub type RangeCircuitBuilder<F> = BaseCircuitBuilder<F, 0>;
/// [RangeCircuitBuilder] with 1 instance column.
pub type RangeWithInstanceCircuitBuilder<F> = BaseCircuitBuilder<F, 1>;

/// A circuit builder is a collection of virtual region managers that together assign virtual
/// regions into a single physical circuit.
///
/// [BaseCircuitBuilder] is a circuit builder to create a circuit where the columns correspond to [PublicBaseConfig].
/// This builder can hold multiple threads, but the [Circuit] implementation only evaluates the first phase.
/// The user will have to implement a separate [Circuit] with multi-phase witness generation logic.
///
/// This is used to manage the virtual region corresponding to [FlexGateConfig] and (optionally) [RangeConfig].
/// This can be used even if only using [GateChip] without [RangeChip].
///
/// The circuit will have `NI` public instance (aka public inputs+outputs) columns.
#[derive(Clone, Debug, Getters, MutGetters, Setters)]
pub struct BaseCircuitBuilder<F: ScalarField, const NI: usize> {
    /// Virtual region for each challenge phase. These cannot be shared across threads while keeping circuit deterministic.
    #[getset(get = "pub", get_mut = "pub", set = "pub")]
    core: MultiPhaseCoreManager<F>,
    /// The range lookup manager
    #[getset(get = "pub", get_mut = "pub", set = "pub")]
    lookup_manager: [LookupAnyManager<F, 1>; MAX_PHASE],
    /// Configuration parameters for the circuit shape
    pub config_params: BaseConfigParams,
    /// The assigned instances to expose publicly at the end of circuit synthesis
    pub assigned_instances: [Vec<AssignedValue<F>>; NI],
}

impl<F: ScalarField, const NI: usize> Default for BaseCircuitBuilder<F, NI> {
    /// Quick start default circuit builder which can be used for MockProver, Keygen, and real prover.
    /// For best performance during real proof generation, we recommend using [BaseCircuitBuilder::prover] instead.
    fn default() -> Self {
        Self::new(false)
    }
}

impl<F: ScalarField, const NI: usize> BaseCircuitBuilder<F, NI> {
    /// Creates a new [BaseCircuitBuilder] with all default managers.
    /// * `witness_gen_only`:
    ///     * If true, the builder only does witness asignments and does not store constraint information -- this should only be used for the real prover.
    ///     * If false, the builder also imposes constraints (selectors, fixed columns, copy constraints). Primarily used for keygen and mock prover (but can also be used for real prover).
    ///
    /// By default, **no** circuit configuration parameters have been set.
    /// These should be set separately using [use_params], or [use_k], [use_lookup_bits], and [config].
    ///
    /// Upon construction, there are no public instances (aka all witnesses are private).
    /// The intended usage is that _before_ calling `synthesize`, witness generation can be done to populate
    /// assigned instances, which are supplied as `assigned_instances` to this struct.
    /// The [`Circuit`] implementation for this struct will then expose these instances and constrain
    /// them using the Halo2 API.
    pub fn new(witness_gen_only: bool) -> Self {
        let core = MultiPhaseCoreManager::new(witness_gen_only);
        let lookup_manager = [(); MAX_PHASE]
            .map(|_| LookupAnyManager::new(witness_gen_only, core.copy_manager.clone()));
        Self {
            core,
            lookup_manager,
            config_params: Default::default(),
            assigned_instances: [(); NI].map(|_| Vec::new()),
        }
    }

    /// Creates a new [MultiPhaseCoreManager] depending on the stage of circuit building. If the stage is [CircuitBuilderStage::Prover], the [MultiPhaseCoreManager] is used for witness generation only.
    pub fn from_stage(stage: CircuitBuilderStage) -> Self {
        Self::new(stage.witness_gen_only()).unknown(stage == CircuitBuilderStage::Keygen)
    }

    /// Creates a new [BaseCircuitBuilder] with a pinned circuit configuration given by `config_params` and `break_points`.
    pub fn prover(
        config_params: BaseConfigParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self::new(true).use_params(config_params).use_break_points(break_points)
    }

    /// The log_2 size of the lookup table, if using.
    pub fn lookup_bits(&self) -> Option<usize> {
        self.config_params.lookup_bits
    }

    /// Set lookup bits
    pub fn set_lookup_bits(&mut self, lookup_bits: usize) {
        self.config_params.lookup_bits = Some(lookup_bits);
    }

    /// Returns new with lookup bits
    pub fn use_lookup_bits(mut self, lookup_bits: usize) -> Self {
        self.set_lookup_bits(lookup_bits);
        self
    }

    /// Returns new with `k` set
    pub fn use_k(mut self, k: usize) -> Self {
        self.config_params.k = k;
        self
    }

    /// Set config params
    pub fn set_params(&mut self, params: BaseConfigParams) {
        self.config_params = params;
    }

    /// Returns new with config params
    pub fn use_params(mut self, params: BaseConfigParams) -> Self {
        self.set_params(params);
        self
    }

    /// The break points of the circuit.
    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.core
            .phase_manager
            .iter()
            .map(|pm| pm.break_points.get().expect("break points not set").clone())
            .collect()
    }

    /// Sets the break points of the circuit.
    pub fn set_break_points(&mut self, break_points: MultiPhaseThreadBreakPoints) {
        for (pm, bp) in self.core.phase_manager.iter().zip_eq(break_points) {
            pm.break_points.set(bp).unwrap();
        }
    }

    /// Returns new with break points
    pub fn use_break_points(mut self, break_points: MultiPhaseThreadBreakPoints) -> Self {
        self.set_break_points(break_points);
        self
    }

    /// Returns `self` with a gven copy manager
    pub fn use_copy_manager(mut self, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        for lm in &mut self.lookup_manager {
            lm.copy_manager = copy_manager.clone();
        }
        self.core = self.core.use_copy_manager(copy_manager);
        self
    }

    /// Returns if the circuit is only used for witness generation.
    pub fn witness_gen_only(&self) -> bool {
        self.core.witness_gen_only()
    }

    /// Creates a new [MultiPhaseCoreManager] with `use_unknown` flag set.
    /// * `use_unknown`: If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    pub fn unknown(mut self, use_unknown: bool) -> Self {
        self.core = self.core.unknown(use_unknown);
        self
    }

    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    /// * `phase`: The challenge phase (as an index) of the gate thread.
    pub fn main(&mut self, phase: usize) -> &mut Context<F> {
        self.core.main(phase)
    }

    /// Returns [SinglePhaseCoreManager] with the virtual region with all core threads in the given phase.
    pub fn pool(&mut self, phase: usize) -> &mut SinglePhaseCoreManager<F> {
        self.core.phase_manager.get_mut(phase).unwrap()
    }

    /// Spawns a new thread for a new given `phase`. Returns a mutable reference to the [Context] of the new thread.
    /// * `phase`: The phase (index) of the gate thread.
    pub fn new_thread(&mut self, phase: usize) -> &mut Context<F> {
        self.core.new_thread(phase)
    }

    /// Returns some statistics about the virtual region.
    pub fn statistics(&self) -> RangeStatistics {
        let gate = self.core.statistics();
        let total_lookup_advice_per_phase = self.total_lookup_advice_per_phase();
        RangeStatistics { gate, total_lookup_advice_per_phase }
    }

    fn total_lookup_advice_per_phase(&self) -> Vec<usize> {
        self.lookup_manager.iter().map(|lm| lm.total_rows()).collect()
    }

    /// Auto-calculates configuration parameters for the circuit and sets them.
    ///
    /// * `k`: The number of in the circuit (i.e. numeber of rows = 2<sup>k</sup>)
    /// * `minimum_rows`: The minimum number of rows in the circuit that cannot be used for witness assignments and contain random `blinding factors` to ensure zk property, defaults to 0.
    /// * `lookup_bits`: The fixed lookup table will consist of [0, 2<sup>lookup_bits</sup>)
    pub fn config(&mut self, minimum_rows: Option<usize>) -> BaseConfigParams {
        let k = self.config_params.k;
        assert_ne!(k, 0, "k must be set");
        let max_rows = (1 << k) - minimum_rows.unwrap_or(0);
        let gate_params = self.core.config(k, minimum_rows);
        let total_lookup_advice_per_phase = self.total_lookup_advice_per_phase();
        let num_lookup_advice_per_phase = total_lookup_advice_per_phase
            .iter()
            .map(|count| (count + max_rows - 1) / max_rows)
            .collect::<Vec<_>>();

        let params = BaseConfigParams {
            k: gate_params.k,
            num_advice_per_phase: gate_params.num_advice_per_phase,
            num_fixed: gate_params.num_fixed,
            num_lookup_advice_per_phase,
            lookup_bits: self.lookup_bits(),
        };
        self.config_params = params.clone();
        #[cfg(feature = "display")]
        {
            println!("Total range check advice cells to lookup per phase: {total_lookup_advice_per_phase:?}");
            log::info!("Auto-calculated config params:\n {params:#?}");
        }
        params
    }

    /// Copies `assigned_instances` to the instance columns. Should only be called at the very end of
    /// `synthesize` after virtual `assigned_instances` have been assigned to physical circuit.
    pub fn assign_instances(
        &self,
        instance_columns: &[Column<Instance>; NI],
        mut layouter: impl Layouter<F>,
    ) {
        if !self.core.witness_gen_only() {
            // expose public instances
            for (instances, instance_col) in self.assigned_instances.iter().zip(instance_columns) {
                for (i, instance) in instances.iter().enumerate() {
                    let cell = instance.cell.unwrap();
                    let copy_manager = self.core.copy_manager.lock().unwrap();
                    let (cell, _) =
                        copy_manager.assigned_advices.get(&cell).expect("instance not assigned");
                    layouter.constrain_instance(*cell, *instance_col, i);
                }
            }
        }
    }

    /// Creates a new [RangeChip] sharing the same [LookupAnyManager]s as `self`.
    pub fn range_chip(&self) -> RangeChip<F> {
        RangeChip::new(
            self.config_params.lookup_bits.expect("lookup bits not set"),
            self.lookup_manager.clone(),
        )
    }

    /// Copies the queued cells to be range looked up in phase `phase` to special advice lookup columns
    /// using [LookupAnyManager].
    ///
    /// ## Special case
    /// Just for [RangeConfig], we have special handling for the case where there is a single (physical)
    /// advice column in [FlexGateConfig]. In this case, `RangeConfig` does not create extra lookup advice columns,
    /// the single advice column has lookup enabled, and there is a selector to toggle when lookup should
    /// be turned on.
    pub fn assign_lookups_in_phase(
        &self,
        config: &RangeConfig<F>,
        region: &mut Region<F>,
        phase: usize,
    ) {
        let lookup_manager = self.lookup_manager.get(phase).expect("too many phases");
        if lookup_manager.total_rows() == 0 {
            return;
        }
        if let Some(q_lookup) = config.q_lookup.get(phase).and_then(|q| *q) {
            // if q_lookup is Some, that means there should be a single advice column and it has lookup enabled
            assert_eq!(config.gate.basic_gates[phase].len(), 1);
            if !self.witness_gen_only() {
                let cells_to_lookup = lookup_manager.cells_to_lookup.lock().unwrap();
                for advice in cells_to_lookup.iter().flat_map(|(_, advices)| advices) {
                    let cell = advice[0].cell.as_ref().unwrap();
                    let copy_manager = self.core.copy_manager.lock().unwrap();
                    let (acell, row_offset) = copy_manager.assigned_advices[cell];
                    #[cfg(feature = "halo2-axiom")]
                    assert_eq!(row_offset, acell.row_offset());
                    q_lookup.enable(region, row_offset).unwrap();
                }
            }
        } else {
            let lookup_cols = config
                .lookup_advice
                .get(phase)
                .expect("No special lookup advice columns")
                .iter()
                .map(|c| [*c])
                .collect_vec();
            lookup_manager.assign_raw(&lookup_cols, region);
        }
        let _ = lookup_manager.assigned.set(());
    }
}

/// Basic statistics
pub struct RangeStatistics {
    /// Number of advice cells for the basic gate and total constants used
    pub gate: GateStatistics,
    /// Total special advice cells that need to be looked up, per phase
    pub total_lookup_advice_per_phase: Vec<usize>,
}

impl<F: ScalarField, const NI: usize> Circuit<F> for BaseCircuitBuilder<F, NI> {
    type Config = PublicBaseConfig<F, NI>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseConfigParams;

    fn params(&self) -> Self::Params {
        self.config_params.clone()
    }

    /// Creates a new instance of the [RangeCircuitBuilder] without witnesses by setting the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`BaseConfigParams`]
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        PublicBaseConfig::configure(meta, params)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("You must use configure_with_params");
    }

    /// Performs the actual computation on the circuit (e.g., witness generation), populating the lookup table and filling in all the advice values for a particular proof.
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // only load lookup table if we are actually doing lookups
        if let BaseConfig::WithRange(config) = &config.base {
            config.load_lookup_table(&mut layouter).expect("load lookup table should not fail");
        }
        // Only FirstPhase (phase 0)
        layouter
            .assign_region(
                || "BaseCircuitBuilder generated circuit",
                |mut region| {
                    let usable_rows = config.gate().max_rows;
                    self.core.phase_manager[0].assign_raw(
                        &(config.gate().basic_gates[0].clone(), usable_rows),
                        &mut region,
                    );
                    // Only assign cells to lookup if we're sure we're doing range lookups
                    if let BaseConfig::WithRange(config) = &config.base {
                        self.assign_lookups_in_phase(config, &mut region, 0);
                    }
                    // Impose equality constraints
                    if !self.core.witness_gen_only() {
                        self.core.copy_manager.assign_raw(config.constants(), &mut region);
                        // When keygen_vk and keygen_pk are both run, you need to clear assigned constants
                        // so the second run still assigns constants in the pk
                        self.core.copy_manager.lock().unwrap().assigned_constants.clear();
                    }
                    Ok(())
                },
            )
            .unwrap();

        self.assign_instances(&config.instance, layouter.namespace(|| "expose"));
        Ok(())
    }
}
