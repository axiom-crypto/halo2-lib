use super::{
    flex_gate::{FlexGateConfig, MAX_PHASE},
    range::BaseConfig,
};
use crate::{
    halo2_proofs::{
        circuit::{self, Layouter, Region, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    },
    utils::ScalarField,
    AssignedValue, Context, SKIP_FIRST_PASS,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

mod parallelize;
pub mod threads;

pub use parallelize::*;
pub use threads::multi_phase::{GateStatistics, GateThreadBuilder};

/// Vector of thread advice column break points
pub type ThreadBreakPoints = Vec<usize>;
/// Vector of vectors tracking the thread break points across different halo2 phases
pub type MultiPhaseThreadBreakPoints = Vec<ThreadBreakPoints>;

/*
    /// Auto-calculates configuration parameters for the circuit
    ///
    /// * `k`: The number of in the circuit (i.e. numeber of rows = 2<sup>k</sup>)
    /// * `minimum_rows`: The minimum number of rows in the circuit that cannot be used for witness assignments and contain random `blinding factors` to ensure zk property, defaults to 0.
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> BaseConfigParams {
        let max_rows = (1 << k) - minimum_rows.unwrap_or(0);
        let total_advice_per_phase = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.advice.len()).sum::<usize>())
            .collect::<Vec<_>>();
        // we do a rough estimate by taking ceil(advice_cells_per_phase / 2^k )
        // if this is too small, manual configuration will be needed
        let num_advice_per_phase = total_advice_per_phase
            .iter()
            .map(|count| (count + max_rows - 1) / max_rows)
            .collect::<Vec<_>>();

        let total_lookup_advice_per_phase = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.cells_to_lookup.len()).sum::<usize>())
            .collect::<Vec<_>>();
        let num_lookup_advice_per_phase = total_lookup_advice_per_phase
            .iter()
            .map(|count| (count + max_rows - 1) / max_rows)
            .collect::<Vec<_>>();

        let total_fixed: usize = HashSet::<F>::from_iter(self.threads.iter().flat_map(|threads| {
            threads.iter().flat_map(|ctx| ctx.constant_equality_constraints.iter().map(|(c, _)| *c))
        }))
        .len();
        let num_fixed = (total_fixed + (1 << k) - 1) >> k;

        let params = BaseConfigParams {
            strategy: GateStrategy::Vertical,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed,
            k,
            lookup_bits: None,
        };
        #[cfg(feature = "display")]
        {
            for phase in 0..MAX_PHASE {
                if total_advice_per_phase[phase] != 0 || total_lookup_advice_per_phase[phase] != 0 {
                    println!(
                        "Gate Chip | Phase {}: {} advice cells , {} lookup advice cells",
                        phase, total_advice_per_phase[phase], total_lookup_advice_per_phase[phase],
                    );
                }
            }
            println!("Total {total_fixed} fixed cells");
            log::info!("Auto-calculated config params:\n {params:#?}");
        }
        params
    }

    /// Assigns all advice and fixed cells, turns on selectors, and imposes equality constraints.
    ///
    /// Returns the assigned advices, and constants in the form of [KeygenAssignments].
    ///
    /// Assumes selector and advice columns are already allocated and of the same length.
    ///
    /// Note: `assign_all()` **should** be called during keygen or if using mock prover. It also works for the real prover, but there it is more optimal to use [`assign_threads_in`] instead.
    /// * `config`: The [FlexGateConfig] of the circuit.
    /// * `lookup_advice`: The lookup advice columns.
    /// * `q_lookup`: The lookup advice selectors.
    /// * `region`: The [Region] of the circuit.
    /// * `assigned_advices`: The assigned advice cells.
    /// * `assigned_constants`: The assigned fixed cells.
    /// * `break_points`: The break points of the circuit.
    pub fn assign_all(
        &self,
        config: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        region: &mut Region<F>,
        KeygenAssignments {
            mut assigned_advices,
            mut assigned_constants,
            mut break_points
        }: KeygenAssignments<F>,
    ) -> KeygenAssignments<F> {
        let use_unknown = self.use_unknown;
        let max_rows = config.max_rows;
        let mut fixed_col = 0;
        let mut fixed_offset = 0;
        for (phase, threads) in self.threads.iter().enumerate() {
            let mut break_point = vec![];
            let mut gate_index = 0;
            let mut row_offset = 0;
            for ctx in threads {
                if !ctx.advice.is_empty() {
                    let mut basic_gate = config.basic_gates[phase]
                        .get(gate_index)
                        .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}. Perhaps blinding factors were not taken into account. The max non-poisoned rows is {max_rows}"));
                    assert_eq!(ctx.selector.len(), ctx.advice.len());

                    for (i, (advice, &q)) in ctx.advice.iter().zip(ctx.selector.iter()).enumerate()
                    {
                        let column = basic_gate.value;
                        let value =
                            if use_unknown { Value::unknown() } else { Value::known(advice) };
                        #[cfg(feature = "halo2-axiom")]
                        let cell = *region.assign_advice(column, row_offset, value).cell();
                        #[cfg(not(feature = "halo2-axiom"))]
                        let cell = region
                            .assign_advice(|| "", column, row_offset, || value.map(|v| *v))
                            .unwrap()
                            .cell();
                        assigned_advices.insert((ctx.context_id, i), (cell, row_offset));

                        // If selector enabled and row_offset is valid add break point to Keygen Assignments, account for break point overlap, and enforce equality constraint for gate outputs.
                        if (q && row_offset + 4 > max_rows) || row_offset >= max_rows - 1 {
                            break_point.push(row_offset);
                            row_offset = 0;
                            gate_index += 1;

                            // when there is a break point, because we may have two gates that overlap at the current cell, we must copy the current cell to the next column for safety
                            basic_gate = config.basic_gates[phase]
                        .get(gate_index)
                        .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}. Perhaps blinding factors were not taken into account. The max non-poisoned rows is {max_rows}"));
                            let column = basic_gate.value;

                            #[cfg(feature = "halo2-axiom")]
                            {
                                let ncell = region.assign_advice(column, row_offset, value);
                                region.constrain_equal(ncell.cell(), &cell);
                            }
                            #[cfg(not(feature = "halo2-axiom"))]
                            {
                                let ncell = region
                                    .assign_advice(|| "", column, row_offset, || value.map(|v| *v))
                                    .unwrap()
                                    .cell();
                                region.constrain_equal(ncell, cell).unwrap();
                            }
                        }

                        if q {
                            basic_gate
                                .q_enable
                                .enable(region, row_offset)
                                .expect("enable selector should not fail");
                        }

                        row_offset += 1;
                    }
                }
            }
            break_points.push(break_point);
        }
        // we constrain equality constraints in a separate loop in case context `i` contains references to context `j` for `j > i`
        for (phase, threads) in self.threads.iter().enumerate() {
            let mut lookup_offset = 0;
            let mut lookup_col = 0;
            for ctx in threads {
                for advice in &ctx.cells_to_lookup {
                    // if q_lookup is Some, that means there should be a single advice column and it has lookup enabled
                    let cell = advice.cell.unwrap();
                    let (acell, row_offset) = assigned_advices[&(cell.context_id, cell.offset)];
                    if let Some(q_lookup) = q_lookup[phase] {
                        assert_eq!(config.basic_gates[phase].len(), 1);
                        q_lookup.enable(region, row_offset).unwrap();
                        continue;
                    }
                    // otherwise, we copy the advice value to the special lookup_advice columns
                    if lookup_offset >= max_rows {
                        lookup_offset = 0;
                        lookup_col += 1;
                    }
                    let value = advice.value;
                    let value = if use_unknown { Value::unknown() } else { Value::known(value) };
                    let column = lookup_advice[phase][lookup_col];

                    #[cfg(feature = "halo2-axiom")]
                    {
                        let bcell = region.assign_advice(column, lookup_offset, value);
                        region.constrain_equal(&acell, bcell.cell());
                    }
                    #[cfg(not(feature = "halo2-axiom"))]
                    {
                        let bcell = region
                            .assign_advice(|| "", column, lookup_offset, || value)
                            .expect("assign_advice should not fail")
                            .cell();
                        region.constrain_equal(acell, bcell).unwrap();
                    }
                    lookup_offset += 1;
                }
            }
        }
        KeygenAssignments { assigned_advices, assigned_constants, break_points }
    }
}

/// Assigns threads to regions of advice column.
///
/// Uses preprocessed `break_points` to assign where to divide the advice column into a new column for each thread.
///
/// Performs only witness generation, so should only be evoked during proving not keygen.
///
/// Assumes that the advice columns are already assigned.
/// * `phase` - the phase of the circuit
/// * `threads` - [Vec] threads to assign
/// * `config` - immutable reference to the configuration of the circuit
/// * `lookup_advice` - Slice of lookup advice columns
/// * `region` - mutable reference to the region to assign threads to
/// * `break_points` - the preprocessed break points for the threads
pub fn assign_threads_in<F: ScalarField>(
    phase: usize,
    threads: Vec<Context<F>>,
    config: &FlexGateConfig<F>,
    lookup_advice: &[Column<Advice>],
    region: &mut Region<F>,
    break_points: ThreadBreakPoints,
) {
    if config.basic_gates[phase].is_empty() {
        assert_eq!(
            threads.iter().map(|ctx| ctx.advice.len()).sum::<usize>(),
            0,
            "Trying to assign threads in a phase with no columns"
        );
        return;
    }

    let mut break_points = break_points.into_iter();
    let mut break_point = break_points.next();

    let mut gate_index = 0;
    let mut column = config.basic_gates[phase][gate_index].value;
    let mut row_offset = 0;

    let mut lookup_offset = 0;
    let mut lookup_advice = lookup_advice.iter();
    let mut lookup_column = lookup_advice.next();
    for ctx in threads {
        // if lookup_column is [None], that means there should be a single advice column and it has lookup enabled, so we don't need to copy to special lookup advice columns
        if lookup_column.is_some() {
            for advice in ctx.cells_to_lookup {
                if lookup_offset >= config.max_rows {
                    lookup_offset = 0;
                    lookup_column = lookup_advice.next();
                }
                // Assign the lookup advice values to the lookup_column
                let value = advice.value;
                let lookup_column = *lookup_column.unwrap();
                #[cfg(feature = "halo2-axiom")]
                region.assign_advice(lookup_column, lookup_offset, Value::known(value));
                #[cfg(not(feature = "halo2-axiom"))]
                region
                    .assign_advice(|| "", lookup_column, lookup_offset, || Value::known(value))
                    .unwrap();

                lookup_offset += 1;
            }
        }
        // Assign advice values to the advice columns in each [Context]
        for advice in ctx.advice {
            #[cfg(feature = "halo2-axiom")]
            region.assign_advice(column, row_offset, Value::known(advice));
            #[cfg(not(feature = "halo2-axiom"))]
            region.assign_advice(|| "", column, row_offset, || Value::known(advice)).unwrap();

            if break_point == Some(row_offset) {
                break_point = break_points.next();
                row_offset = 0;
                gate_index += 1;
                column = config.basic_gates[phase][gate_index].value;

                #[cfg(feature = "halo2-axiom")]
                region.assign_advice(column, row_offset, Value::known(advice));
                #[cfg(not(feature = "halo2-axiom"))]
                region.assign_advice(|| "", column, row_offset, || Value::known(advice)).unwrap();
            }

            row_offset += 1;
        }
    }
}
*/

/// A Config struct defining the parameters for a halo2-base circuit
/// - this is used to configure either FlexGateConfig or RangeConfig.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct BaseConfigParams {
    /// Specifies the number of rows in the circuit to be 2<sup>k</sup>
    pub k: usize,
    /// The number of advice columns per phase
    pub num_advice_per_phase: Vec<usize>,
    /// The number of fixed columns per phase
    pub num_fixed: usize,
    /// The number of bits that can be ranged checked using a special lookup table with values [0, 2<sup>lookup_bits</sup>), if using.
    /// The number of special advice columns that have range lookup enabled per phase
    pub num_lookup_advice_per_phase: Vec<usize>,
    /// This is `None` if no lookup table is used.
    pub lookup_bits: Option<usize>,
}

/// A wrapper struct to auto-build a circuit from a `GateThreadBuilder`.
#[derive(Clone, Debug)]
pub struct GateCircuitBuilder<F: ScalarField> {
    /// The Thread Builder for the circuit
    pub builder: RefCell<GateThreadBuilder<F>>, // `RefCell` is just to trick circuit `synthesize` to take ownership of the inner builder
    /// Configuration parameters for the circuit shape
    pub config_params: BaseConfigParams,
}

impl<F: ScalarField> GateCircuitBuilder<F> {
    /// Creates a new [GateCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to true.
    pub fn keygen(builder: GateThreadBuilder<F>, config_params: BaseConfigParams) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(true)),
            config_params,
            break_points: Default::default(),
        }
    }

    /// Creates a new [GateCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to false.
    pub fn mock(builder: GateThreadBuilder<F>, config_params: BaseConfigParams) -> Self {
        Self {
            builder: RefCell::new(builder.unknown(false)),
            config_params,
            break_points: Default::default(),
        }
    }

    /// Creates a new [GateCircuitBuilder] with a pinned circuit configuration given by `config_params` and `break_points`.
    pub fn prover(
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self {
            builder: RefCell::new(builder),
            config_params,
            break_points: RefCell::new(break_points),
        }
    }

    /// Synthesizes from the [GateCircuitBuilder] by populating the advice column and assigning new threads if witness generation is performed.
    pub fn sub_synthesize(
        &self,
        gate: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        layouter: &mut impl Layouter<F>,
    ) -> HashMap<(usize, usize), (circuit::Cell, usize)> {
        let mut first_pass = SKIP_FIRST_PASS;
        let mut assigned_advices = HashMap::new();
        layouter
            .assign_region(
                || "GateCircuitBuilder generated circuit",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    // only support FirstPhase in this Builder because getting challenge value requires more specialized witness generation during synthesize
                    // If we are not performing witness generation only, we can skip the first pass and assign threads directly
                    if !self.builder.borrow().witness_gen_only {
                        // clone the builder so we can re-use the circuit for both vk and pk gen
                        let builder = self.builder.borrow().clone();
                        for threads in builder.threads.iter().skip(1) {
                            assert!(
                                threads.is_empty(),
                                "GateCircuitBuilder only supports FirstPhase for now"
                            );
                        }
                        let assignments = builder.assign_all(
                            gate,
                            lookup_advice,
                            q_lookup,
                            &mut region,
                            Default::default(),
                        );
                        *self.break_points.borrow_mut() = assignments.break_points;
                        assigned_advices = assignments.assigned_advices;
                    } else {
                        // If we are only generating witness, we can skip the first pass and assign threads directly
                        let builder = self.builder.take();
                        let break_points = self.break_points.take();
                        for (phase, (threads, break_points)) in
                            builder.threads.into_iter().zip(break_points).enumerate().take(1)
                        {
                            assign_threads_in(
                                phase,
                                threads,
                                gate,
                                lookup_advice.get(phase).unwrap_or(&vec![]),
                                &mut region,
                                break_points,
                            );
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
        assigned_advices
    }
}

/// A wrapper struct to auto-build a circuit from a `GateThreadBuilder`.
#[derive(Clone, Debug)]
pub struct RangeCircuitBuilder<F: ScalarField>(pub GateCircuitBuilder<F>);

impl<F: ScalarField> RangeCircuitBuilder<F> {
    /// Convenience function to create a new [RangeCircuitBuilder] with a given [CircuitBuilderStage].
    pub fn from_stage(
        stage: CircuitBuilderStage,
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        break_points: Option<MultiPhaseThreadBreakPoints>,
    ) -> Self {
        match stage {
            CircuitBuilderStage::Keygen => Self::keygen(builder, config_params),
            CircuitBuilderStage::Mock => Self::mock(builder, config_params),
            CircuitBuilderStage::Prover => Self::prover(
                builder,
                config_params,
                break_points.expect("break points must be pre-calculated for prover"),
            ),
        }
    }

    /// Creates an instance of the [RangeCircuitBuilder] and executes in keygen mode.
    pub fn keygen(builder: GateThreadBuilder<F>, config_params: BaseConfigParams) -> Self {
        Self(GateCircuitBuilder::keygen(builder, config_params))
    }

    /// Creates a mock instance of the [RangeCircuitBuilder].
    pub fn mock(builder: GateThreadBuilder<F>, config_params: BaseConfigParams) -> Self {
        Self(GateCircuitBuilder::mock(builder, config_params))
    }

    /// Creates an instance of the [RangeCircuitBuilder] and executes in prover mode.
    pub fn prover(
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self(GateCircuitBuilder::prover(builder, config_params, break_points))
    }

    /// Auto-configures the circuit configuration parameters. Mutates the configuration parameters of the circuit
    /// and also returns a copy of the new configuration.
    pub fn config(&mut self, minimum_rows: Option<usize>) -> BaseConfigParams {
        let lookup_bits = self.0.config_params.lookup_bits;
        self.0.config_params = self.0.builder.borrow().config(self.0.config_params.k, minimum_rows);
        self.0.config_params.lookup_bits = lookup_bits;
        self.0.config_params.clone()
    }
}

impl<F: ScalarField> Circuit<F> for RangeCircuitBuilder<F> {
    type Config = BaseConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseConfigParams;

    fn params(&self) -> Self::Params {
        self.0.config_params.clone()
    }

    /// Creates a new instance of the [RangeCircuitBuilder] without witnesses by setting the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`BaseConfigParams`]
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        BaseConfig::configure(meta, params)
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
        if let BaseConfig::WithRange(config) = &config {
            config.load_lookup_table(&mut layouter).expect("load lookup table should not fail");
        }
        self.0.sub_synthesize(
            config.gate(),
            config.lookup_advice(),
            config.q_lookup(),
            &mut layouter,
        );
        Ok(())
    }
}

/// Configuration with [`BaseConfig`] and a single public instance column.
#[derive(Clone, Debug)]
pub struct PublicBaseConfig<F: ScalarField> {
    /// The underlying range configuration
    pub base: BaseConfig<F>,
    /// The public instance column
    pub instance: Column<Instance>,
}

/// This is an extension of [`RangeCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
#[derive(Clone, Debug)]
pub struct RangeWithInstanceCircuitBuilder<F: ScalarField> {
    /// The underlying circuit builder
    pub circuit: RangeCircuitBuilder<F>,
    /// The assigned instances to expose publicly at the end of circuit synthesis
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> RangeWithInstanceCircuitBuilder<F> {
    /// Convenience function to create a new [RangeWithInstanceCircuitBuilder] with a given [CircuitBuilderStage].
    pub fn from_stage(
        stage: CircuitBuilderStage,
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        assigned_instances: Vec<AssignedValue<F>>,
    ) -> Self {
        Self {
            circuit: RangeCircuitBuilder::from_stage(stage, builder, config_params, break_points),
            assigned_instances,
        }
    }

    /// See [`RangeCircuitBuilder::keygen`]
    pub fn keygen(
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        assigned_instances: Vec<AssignedValue<F>>,
    ) -> Self {
        Self { circuit: RangeCircuitBuilder::keygen(builder, config_params), assigned_instances }
    }

    /// See [`RangeCircuitBuilder::mock`]
    pub fn mock(
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        assigned_instances: Vec<AssignedValue<F>>,
    ) -> Self {
        Self { circuit: RangeCircuitBuilder::mock(builder, config_params), assigned_instances }
    }

    /// See [`RangeCircuitBuilder::prover`]
    pub fn prover(
        builder: GateThreadBuilder<F>,
        config_params: BaseConfigParams,
        break_points: MultiPhaseThreadBreakPoints,
        assigned_instances: Vec<AssignedValue<F>>,
    ) -> Self {
        Self {
            circuit: RangeCircuitBuilder::prover(builder, config_params, break_points),
            assigned_instances,
        }
    }

    /// Creates a new instance of the [RangeWithInstanceCircuitBuilder].
    pub fn new(circuit: RangeCircuitBuilder<F>, assigned_instances: Vec<AssignedValue<F>>) -> Self {
        Self { circuit, assigned_instances }
    }

    /// Gets the break points of the circuit.
    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.circuit.0.break_points.borrow().clone()
    }

    /// Gets the number of instances.
    pub fn instance_count(&self) -> usize {
        self.assigned_instances.len()
    }

    /// Gets the instances.
    pub fn instance(&self) -> Vec<F> {
        self.assigned_instances.iter().map(|v| *v.value()).collect()
    }

    /// Auto-configures the circuit configuration parameters. Mutates the configuration parameters of the circuit
    /// and also returns a copy of the new configuration.
    pub fn config(&mut self, minimum_rows: Option<usize>) -> BaseConfigParams {
        self.circuit.config(minimum_rows)
    }
}

impl<F: ScalarField> Circuit<F> for RangeWithInstanceCircuitBuilder<F> {
    type Config = PublicBaseConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseConfigParams;

    fn params(&self) -> Self::Params {
        self.circuit.0.config_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let base = BaseConfig::configure(meta, params);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        PublicBaseConfig { base, instance }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("You must use configure_with_params")
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // copied from RangeCircuitBuilder::synthesize but with extra logic to expose public instances
        let instance_col = config.instance;
        let config = config.base;
        let circuit = &self.circuit.0;
        // only load lookup table if we are actually doing lookups
        if let BaseConfig::WithRange(config) = &config {
            config.load_lookup_table(&mut layouter).expect("load lookup table should not fail");
        }
        // we later `take` the builder, so we need to save this value
        let witness_gen_only = circuit.builder.borrow().witness_gen_only();
        let assigned_advices = circuit.sub_synthesize(
            config.gate(),
            config.lookup_advice(),
            config.q_lookup(),
            &mut layouter,
        );

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, instance_col, i);
            }
        }
        Ok(())
    }
}

/// Defines stage of the circuit builder.
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
    pub fn witness_gen_only(&self) -> bool {
        matches!(self, CircuitBuilderStage::Prover)
    }
}
