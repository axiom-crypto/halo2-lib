use super::{
    flex_gate::{FlexGateConfig, GateStrategy, MAX_PHASE},
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
pub use parallelize::*;

/// Vector of thread advice column break points
pub type ThreadBreakPoints = Vec<usize>;
/// Vector of vectors tracking the thread break points across different halo2 phases
pub type MultiPhaseThreadBreakPoints = Vec<ThreadBreakPoints>;

thread_local! {
    /// This is used as a thread-safe way to auto-configure a circuit's shape and then pass the configuration to `Circuit::configure`.
    pub static BASE_CONFIG_PARAMS: RefCell<BaseConfigParams> = RefCell::new(Default::default());
}

/// Sets the thread-local number of bits to be range checkable via a lookup table with entries [0, 2<sup>lookup_bits</sup>)
pub fn set_lookup_bits(lookup_bits: usize) {
    BASE_CONFIG_PARAMS.with(|conf| conf.borrow_mut().lookup_bits = Some(lookup_bits));
}

/// Stores the cell values loaded during the Keygen phase of a halo2 proof and breakpoints for multi-threading
#[derive(Clone, Debug, Default)]
pub struct KeygenAssignments<F: ScalarField> {
    /// Advice assignments
    pub assigned_advices: HashMap<(usize, usize), (circuit::Cell, usize)>, // (key = ContextCell, value = (circuit::Cell, row offset))
    /// Constant assignments in Fixes Assignments
    pub assigned_constants: HashMap<F, circuit::Cell>, // (key = constant, value = circuit::Cell)
    /// Advice column break points for threads in each phase.
    pub break_points: MultiPhaseThreadBreakPoints,
}

/// Builds the process for gate threading
#[derive(Clone, Debug, Default)]
pub struct GateThreadBuilder<F: ScalarField> {
    /// Threads for each challenge phase
    pub threads: [Vec<Context<F>>; MAX_PHASE],
    /// Max number of threads
    thread_count: usize,
    /// Flag for witness generation. If true, the gate thread builder is used for witness generation only.
    pub witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    use_unknown: bool,
}

impl<F: ScalarField> GateThreadBuilder<F> {
    /// Creates a new [GateThreadBuilder] and spawns a main thread in phase 0.
    /// * `witness_gen_only`: If true, the [GateThreadBuilder] is used for witness generation only.
    ///     * If true, the gate thread builder only does witness asignments and does not store constraint information -- this should only be used for the real prover.
    ///     * If false, the gate thread builder is used for keygen and mock prover (it can also be used for real prover) and the builder stores circuit information (e.g. copy constraints, fixed columns, enabled selectors).
    ///         * These values are fixed for the circuit at key generation time, and they do not need to be re-computed by the prover in the actual proving phase.
    pub fn new(witness_gen_only: bool) -> Self {
        let mut threads = [(); MAX_PHASE].map(|_| vec![]);
        // start with a main thread in phase 0
        threads[0].push(Context::new(witness_gen_only, 0));
        Self { threads, thread_count: 1, witness_gen_only, use_unknown: false }
    }

    /// Creates a new [GateThreadBuilder] with `witness_gen_only` set to false.
    ///
    /// Performs the witness assignment computations and then checks using normal programming logic whether the gate constraints are all satisfied.
    pub fn mock() -> Self {
        Self::new(false)
    }

    /// Creates a new [GateThreadBuilder] with `witness_gen_only` set to false.
    ///
    /// Performs the witness assignment computations and generates prover and verifier keys.
    pub fn keygen() -> Self {
        Self::new(false)
    }

    /// Creates a new [GateThreadBuilder] with `witness_gen_only` set to true.
    ///
    /// Performs the witness assignment computations and then runs the proving system.
    pub fn prover() -> Self {
        Self::new(true)
    }

    /// Creates a new [GateThreadBuilder] with `use_unknown` flag set.
    /// * `use_unknown`: If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    pub fn unknown(self, use_unknown: bool) -> Self {
        Self { use_unknown, ..self }
    }

    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    /// * `phase`: The challenge phase (as an index) of the gate thread.
    pub fn main(&mut self, phase: usize) -> &mut Context<F> {
        if self.threads[phase].is_empty() {
            self.new_thread(phase)
        } else {
            self.threads[phase].last_mut().unwrap()
        }
    }

    /// Returns the `witness_gen_only` flag.
    pub fn witness_gen_only(&self) -> bool {
        self.witness_gen_only
    }

    /// Returns the `use_unknown` flag.
    pub fn use_unknown(&self) -> bool {
        self.use_unknown
    }

    /// Returns the current number of threads in the [GateThreadBuilder].
    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Creates a new thread id by incrementing the `thread count`
    pub fn get_new_thread_id(&mut self) -> usize {
        let thread_id = self.thread_count;
        self.thread_count += 1;
        thread_id
    }

    /// Spawns a new thread for a new given `phase`. Returns a mutable reference to the [Context] of the new thread.
    /// * `phase`: The phase (index) of the gate thread.
    pub fn new_thread(&mut self, phase: usize) -> &mut Context<F> {
        let thread_id = self.thread_count;
        self.thread_count += 1;
        self.threads[phase].push(Context::new(self.witness_gen_only, thread_id));
        self.threads[phase].last_mut().unwrap()
    }

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

        let mut params = BaseConfigParams {
            strategy: GateStrategy::Vertical,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed,
            k,
            lookup_bits: None,
        };
        BASE_CONFIG_PARAMS.with(|conf| {
            params.lookup_bits = conf.borrow().lookup_bits;
            *conf.borrow_mut() = params.clone();
        });
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

    pub fn config_from_params(&self, mut params: BaseConfigParams) -> BaseConfigParams {
        BASE_CONFIG_PARAMS.with(|conf| {
            // params.lookup_bits = conf.borrow().lookup_bits;
            *conf.borrow_mut() = params.clone();
        });
        params
    }

    pub fn get_circuit_stats(&self) -> (usize, usize, usize) {
        let total_advice_per_phase = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.advice.len()).sum::<usize>())
            .collect::<Vec<_>>();
        let total_lookup_advice_per_phase = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.cells_to_lookup.len()).sum::<usize>())
            .collect::<Vec<_>>();
        let total_fixed: usize = HashSet::<F>::from_iter(self.threads.iter().flat_map(|threads| {
            threads.iter().flat_map(|ctx| ctx.constant_equality_constraints.iter().map(|(c, _)| *c))
        }))
        .len();
        (total_advice_per_phase[0], total_lookup_advice_per_phase[0], total_fixed)
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
                            region.assign_fixed(basic_gate.q_enable, row_offset, F::from(true));
                        }

                        row_offset += 1;
                    }
                }
                // Assign fixed cells
                for (c, _) in ctx.constant_equality_constraints.iter() {
                    if assigned_constants.get(c).is_none() {
                        #[cfg(feature = "halo2-axiom")]
                        let cell =
                            region.assign_fixed(config.constants[fixed_col], fixed_offset, c);
                        #[cfg(not(feature = "halo2-axiom"))]
                        let cell = region
                            .assign_fixed(
                                || "",
                                config.constants[fixed_col],
                                fixed_offset,
                                || Value::known(*c),
                            )
                            .unwrap()
                            .cell();
                        assigned_constants.insert(*c, cell);
                        fixed_col += 1;
                        if fixed_col >= config.constants.len() {
                            fixed_col = 0;
                            fixed_offset += 1;
                        }
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
                for (left, right) in &ctx.advice_equality_constraints {
                    let (left, _) = assigned_advices[&(left.context_id, left.offset)];
                    let (right, _) = assigned_advices[&(right.context_id, right.offset)];
                    #[cfg(feature = "halo2-axiom")]
                    region.constrain_equal(&left, &right);
                    #[cfg(not(feature = "halo2-axiom"))]
                    region.constrain_equal(left, right).unwrap();
                }
                for (left, right) in &ctx.constant_equality_constraints {
                    let left = assigned_constants[left];
                    let (right, _) = assigned_advices[&(right.context_id, right.offset)];
                    #[cfg(feature = "halo2-axiom")]
                    region.constrain_equal(&left, &right);
                    #[cfg(not(feature = "halo2-axiom"))]
                    region.constrain_equal(left, right).unwrap();
                }

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

/// A Config struct defining the parameters for a halo2-base circuit
/// - this is used to configure either FlexGateConfig or RangeConfig.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct BaseConfigParams {
    /// The gate strategy used for the advice column of the circuit and applied at every row.
    pub strategy: GateStrategy,
    /// Specifies the number of rows in the circuit to be 2<sup>k</sup>
    pub k: usize,
    /// The number of advice columns per phase
    pub num_advice_per_phase: Vec<usize>,
    /// The number of advice columns that do not have lookup enabled per phase
    pub num_lookup_advice_per_phase: Vec<usize>,
    /// The number of fixed columns per phase
    pub num_fixed: usize,
    /// The number of bits that can be ranged checked using a special lookup table with values [0, 2<sup>lookup_bits</sup>), if using.
    /// This is `None` if no lookup table is used.
    pub lookup_bits: Option<usize>,
}

/// A wrapper struct to auto-build a circuit from a `GateThreadBuilder`.
#[derive(Clone, Debug)]
pub struct GateCircuitBuilder<F: ScalarField> {
    /// The Thread Builder for the circuit
    pub builder: RefCell<GateThreadBuilder<F>>, // `RefCell` is just to trick circuit `synthesize` to take ownership of the inner builder
    /// Break points for threads within the circuit
    pub break_points: RefCell<MultiPhaseThreadBreakPoints>, // `RefCell` allows the circuit to record break points in a keygen call of `synthesize` for use in later witness gen
}

impl<F: ScalarField> GateCircuitBuilder<F> {
    /// Creates a new [GateCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to true.
    pub fn keygen(builder: GateThreadBuilder<F>) -> Self {
        Self { builder: RefCell::new(builder.unknown(true)), break_points: RefCell::new(vec![]) }
    }

    /// Creates a new [GateCircuitBuilder] with `use_unknown` of [GateThreadBuilder] set to false.
    pub fn mock(builder: GateThreadBuilder<F>) -> Self {
        Self { builder: RefCell::new(builder.unknown(false)), break_points: RefCell::new(vec![]) }
    }

    /// Creates a new [GateCircuitBuilder].
    pub fn prover(
        builder: GateThreadBuilder<F>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self { builder: RefCell::new(builder), break_points: RefCell::new(break_points) }
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
                        for (phase, (threads, break_points)) in builder
                            .threads
                            .into_iter()
                            .zip(break_points.into_iter())
                            .enumerate()
                            .take(1)
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
    /// Creates an instance of the [RangeCircuitBuilder] and executes in keygen mode.
    pub fn keygen(builder: GateThreadBuilder<F>) -> Self {
        Self(GateCircuitBuilder::keygen(builder))
    }

    /// Creates a mock instance of the [RangeCircuitBuilder].
    pub fn mock(builder: GateThreadBuilder<F>) -> Self {
        Self(GateCircuitBuilder::mock(builder))
    }

    /// Creates an instance of the [RangeCircuitBuilder] and executes in prover mode.
    pub fn prover(
        builder: GateThreadBuilder<F>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self(GateCircuitBuilder::prover(builder, break_points))
    }
}

impl<F: ScalarField> Circuit<F> for RangeCircuitBuilder<F> {
    type Config = BaseConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    /// Creates a new instance of the [RangeCircuitBuilder] without witnesses by setting the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`BaseConfigParams`]
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = BASE_CONFIG_PARAMS
            .try_with(|config| config.borrow().clone())
            .expect("You need to call config() to configure the halo2-base circuit shape first");
        BaseConfig::configure(meta, params)
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
pub struct PublicBaseConfig<const NI: usize, F: ScalarField> {
    /// The underlying range configuration
    pub base: BaseConfig<F>,
    /// The public instance column
    pub instances: [Column<Instance>; NI],
}

pub const MAX_BLINDING_FACTORS: usize = 109;

/// This is an extension of [`RangeCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
#[derive(Clone, Debug)]
pub struct RangeWithMultipleInstancesCircuitBuilder<const NI: usize, F: ScalarField> {
    /// The underlying circuit builder
    pub circuit: RangeCircuitBuilder<F>,
    /// The assigned instances to expose publicly at the end of circuit synthesis
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<const NI: usize, F: ScalarField> RangeWithMultipleInstancesCircuitBuilder<NI, F> {
    /// See [`RangeCircuitBuilder::keygen`]
    pub fn keygen(
        builder: GateThreadBuilder<F>,
        assigned_instances: Vec<AssignedValue<F>>,
    ) -> Self {
        Self { circuit: RangeCircuitBuilder::keygen(builder), assigned_instances }
    }

    /// See [`RangeCircuitBuilder::mock`]
    pub fn mock(builder: GateThreadBuilder<F>, assigned_instances: Vec<AssignedValue<F>>) -> Self {
        Self { circuit: RangeCircuitBuilder::mock(builder), assigned_instances }
    }

    /// See [`RangeCircuitBuilder::prover`]
    pub fn prover(
        builder: GateThreadBuilder<F>,
        assigned_instances: Vec<AssignedValue<F>>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self { circuit: RangeCircuitBuilder::prover(builder, break_points), assigned_instances }
    }

    /// Creates a new instance of the [RangeWithInstanceCircuitBuilder].
    pub fn new(circuit: RangeCircuitBuilder<F>, assigned_instances: Vec<AssignedValue<F>>) -> Self {
        Self { circuit, assigned_instances }
    }

    /// Calls [`GateThreadBuilder::config`]
    pub fn config(&self, k: u32, minimum_rows: Option<usize>) -> BaseConfigParams {
        self.circuit.0.builder.borrow().config(k as usize, minimum_rows)
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

    pub fn instances(&self) -> Vec<Vec<F>> {
        let mut processed = Vec::<Vec<F>>::new();
        let params = BASE_CONFIG_PARAMS
            .try_with(|config| config.borrow().clone())
            .expect("You need to call config() to configure the halo2-base circuit shape first");
        let k = params.k;
        let mut assigned_instances_iter =
            self.assigned_instances.chunks((1 << k) - (MAX_BLINDING_FACTORS)).into_iter();
        for _ in 0..NI {
            let next_chunk = assigned_instances_iter.next();
            let processed_chunk = if let Some(next_chunk) = next_chunk {
                next_chunk.iter().map(|v| *v.value()).collect()
            } else {
                vec![]
            };
            processed.push(processed_chunk);
        }
        if assigned_instances_iter.next().is_some() {
            panic!("too many public instances");
        }
        processed
    }
}

impl<const NI: usize, F: ScalarField> Circuit<F>
    for RangeWithMultipleInstancesCircuitBuilder<NI, F>
{
    type Config = PublicBaseConfig<NI, F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let base = RangeCircuitBuilder::configure(meta);
        let instances: [Column<Instance>; NI] = [0; NI].map(|_| meta.instance_column());
        for i in 0..NI {
            meta.enable_equality(instances[i]);
        }
        PublicBaseConfig { base, instances }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // copied from RangeCircuitBuilder::synthesize but with extra logic to expose public instances
        let instance_cols = config.instances;
        let config = config.base;
        let circuit = &self.circuit.0;
        let params = BASE_CONFIG_PARAMS
            .try_with(|config| config.borrow().clone())
            .expect("You need to call config() to configure the halo2-base circuit shape first");
        let k = params.k;
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
            // todo: calculate optimal chunk size using meta.blinding_factors
            let mut assigned_instances_iter =
                self.assigned_instances.chunks((1 << k) - (MAX_BLINDING_FACTORS)).into_iter();
            for instance_col in instance_cols.iter() {
                let next_chunk = assigned_instances_iter.next();
                if let Some(next_chunk) = next_chunk {
                    for (i, instance) in next_chunk.iter().enumerate() {
                        let cell = instance.cell.unwrap();
                        let (cell, _) = assigned_advices
                            .get(&(cell.context_id, cell.offset))
                            .expect("instance not assigned");
                        layouter.constrain_instance(*cell, *instance_col, i);
                    }
                }
            }
            if assigned_instances_iter.next().is_some() {
                panic!("too many public instances");
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

pub type RangeWithInstanceCircuitBuilder<F> = RangeWithMultipleInstancesCircuitBuilder<1, F>;
