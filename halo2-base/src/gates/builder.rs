use super::{
    flex_gate::{FlexGateConfig, GateStrategy, MAX_PHASE},
    range::{RangeConfig, RangeStrategy},
};
use crate::{
    halo2_proofs::{
        circuit::{Layouter, Region, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    },
    utils::ScalarField,
    Context, SKIP_FIRST_PASS,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::HashMap};

pub type ThreadBreakPoints = Vec<usize>;
pub type MultiPhaseThreadBreakPoints = Vec<ThreadBreakPoints>;

#[derive(Clone, Debug, Default)]
pub struct GateThreadBuilder<F: ScalarField> {
    /// Threads for each challenge phase
    pub threads: [Vec<Context<F>>; MAX_PHASE],
    thread_count: usize,
    witness_gen_only: bool,
    use_unknown: bool,
}

impl<F: ScalarField> GateThreadBuilder<F> {
    pub fn new(witness_gen_only: bool) -> Self {
        let mut threads = [(); MAX_PHASE].map(|_| vec![]);
        // start with a main thread in phase 0
        threads[0].push(Context::new(witness_gen_only, 0));
        Self { threads, thread_count: 1, witness_gen_only, use_unknown: false }
    }

    pub fn mock() -> Self {
        Self::new(false)
    }

    pub fn keygen() -> Self {
        Self::new(false)
    }

    pub fn prover() -> Self {
        Self::new(true)
    }

    pub fn unknown(self, use_unknown: bool) -> Self {
        Self { use_unknown, ..self }
    }

    pub fn main(&mut self, phase: usize) -> &mut Context<F> {
        if self.threads[phase].is_empty() {
            self.new_thread(phase)
        } else {
            self.threads[phase].last_mut().unwrap()
        }
    }

    pub fn witness_gen_only(&self) -> bool {
        self.witness_gen_only
    }

    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    pub fn get_new_thread_id(&mut self) -> usize {
        let thread_id = self.thread_count;
        self.thread_count += 1;
        thread_id
    }

    pub fn new_thread(&mut self, phase: usize) -> &mut Context<F> {
        let thread_id = self.thread_count;
        self.thread_count += 1;
        self.threads[phase].push(Context::new(self.witness_gen_only, thread_id));
        self.threads[phase].last_mut().unwrap()
    }

    /// Auto-calculate configuration parameters for the circuit
    pub fn config(&self, k: usize, minimum_rows: Option<usize>) -> FlexGateConfigParams {
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

        let total_fixed: usize = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.constants.len()).sum::<usize>())
            .sum();
        let num_fixed = (total_fixed + (1 << k) - 1) >> k;

        let params = FlexGateConfigParams {
            strategy: GateStrategy::Vertical,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed,
            k,
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
            println!("Auto-calculated config params:\n {params:#?}");
        }
        std::env::set_var("FLEX_GATE_CONFIG_PARAMS", serde_json::to_string(&params).unwrap());
        params
    }

    /// Assigns all advice and fixed cells, turns on selectors, imposes equality constraints.
    /// This should only be called during keygen.
    pub fn assign_all(
        self,
        config: &FlexGateConfig<F>,
        lookup_advice: &[Vec<Column<Advice>>],
        q_lookup: &[Option<Selector>],
        region: &mut Region<F>,
    ) -> MultiPhaseThreadBreakPoints {
        assert!(!self.witness_gen_only);
        let use_unknown = self.use_unknown;
        let max_rows = config.max_rows;
        let mut break_points = vec![];
        let mut assigned_advices = HashMap::new();
        let mut assigned_constants = HashMap::new();
        let mut fixed_col = 0;
        let mut fixed_offset = 0;
        for (phase, threads) in self.threads.into_iter().enumerate() {
            let mut break_point = vec![];
            let mut gate_index = 0;
            let mut row_offset = 0;
            let mut lookup_offset = 0;
            let mut lookup_col = 0;
            for mut ctx in threads {
                let mut basic_gate = config.basic_gates[phase]
                        .get(gate_index)
                        .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}. Perhaps blinding factors were not taken into account. The max non-poisoned rows is {max_rows}"));
                ctx.selector.resize(ctx.advice.len(), false);

                for (i, (advice, q)) in ctx.advice.iter().zip(ctx.selector.into_iter()).enumerate()
                {
                    let column = basic_gate.value;
                    let value = if use_unknown { Value::unknown() } else { Value::known(advice) };
                    #[cfg(feature = "halo2-axiom")]
                    let cell = region.assign_advice(column, row_offset, value);
                    #[cfg(not(feature = "halo2-axiom"))]
                    let cell =
                        region.assign_advice(|| "", column, row_offset, || value).unwrap().cell();
                    assigned_advices.insert((ctx.context_id, i), (cell, row_offset));

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
                            region.constrain_equal(&ncell, &cell);
                        }
                        #[cfg(not(feature = "halo2-axiom"))]
                        {
                            let ncell = region
                                .assign_advice(|| "", column, row_offset, || value)
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
                for (c, i) in ctx.constants.into_iter() {
                    #[cfg(feature = "halo2-axiom")]
                    let cell = region.assign_fixed(config.constants[fixed_col], fixed_offset, c);
                    #[cfg(not(feature = "halo2-axiom"))]
                    let cell = region
                        .assign_fixed(
                            || "",
                            config.constants[fixed_col],
                            fixed_offset,
                            || Value::known(c),
                        )
                        .unwrap()
                        .cell();
                    assigned_constants.insert((ctx.context_id, i), cell);
                    fixed_col += 1;
                    if fixed_col >= config.constants.len() {
                        fixed_col = 0;
                        fixed_offset += 1;
                    }
                }

                // warning: currently we assume equality constraints in thread i only involves threads <= i
                // I guess a fix is to just rerun this several times?
                for (left, right) in ctx.advice_equality_constraints {
                    let (left, _) = assigned_advices[&(left.context_id, left.offset)];
                    let (right, _) = assigned_advices[&(right.context_id, right.offset)];
                    #[cfg(feature = "halo2-axiom")]
                    region.constrain_equal(&left, &right);
                    #[cfg(not(feature = "halo2-axiom"))]
                    region.constrain_equal(left, right).unwrap();
                }
                for (left, right) in ctx.constant_equality_constraints {
                    let left = assigned_constants[&(left.context_id, left.offset)];
                    let (right, _) = assigned_advices[&(right.context_id, right.offset)];
                    #[cfg(feature = "halo2-axiom")]
                    region.constrain_equal(&left, &right);
                    #[cfg(not(feature = "halo2-axiom"))]
                    region.constrain_equal(left, right).unwrap();
                }

                for advice in ctx.cells_to_lookup {
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
                        region.constrain_equal(&acell, &bcell);
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
            break_points.push(break_point);
        }
        break_points
    }
}

/// Pure advice witness assignment in a single phase. Uses preprocessed `break_points` to determine when
/// to split a thread into a new column.
pub fn assign_threads_in<F: ScalarField>(
    phase: usize,
    threads: Vec<Context<F>>,
    config: &FlexGateConfig<F>,
    lookup_advice: &[Column<Advice>],
    region: &mut Region<F>,
    break_points: ThreadBreakPoints,
) {
    if config.basic_gates[phase].is_empty() {
        assert!(threads.is_empty(), "Trying to assign threads in a phase with no columns");
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
        for advice in ctx.cells_to_lookup {
            if lookup_offset >= config.max_rows {
                lookup_offset = 0;
                lookup_column = lookup_advice.next();
            }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlexGateConfigParams {
    pub strategy: GateStrategy,
    pub k: usize,
    pub num_advice_per_phase: Vec<usize>,
    pub num_lookup_advice_per_phase: Vec<usize>,
    pub num_fixed: usize,
}

/// A wrapper struct to auto-build a circuit from a `GateThreadBuilder`.
#[derive(Clone, Debug)]
pub struct GateCircuitBuilder<F: ScalarField> {
    pub builder: RefCell<GateThreadBuilder<F>>, // `RefCell` is just to trick circuit `synthesize` to take ownership of the inner builder
    pub break_points: RefCell<MultiPhaseThreadBreakPoints>, // `RefCell` allows the circuit to record break points in a keygen call of `synthesize` for use in later witness gen
}

impl<F: ScalarField> GateCircuitBuilder<F> {
    pub fn keygen(builder: GateThreadBuilder<F>) -> Self {
        Self { builder: RefCell::new(builder.unknown(true)), break_points: RefCell::new(vec![]) }
    }

    pub fn mock(builder: GateThreadBuilder<F>) -> Self {
        Self { builder: RefCell::new(builder.unknown(false)), break_points: RefCell::new(vec![]) }
    }

    pub fn prover(
        builder: GateThreadBuilder<F>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self { builder: RefCell::new(builder), break_points: RefCell::new(break_points) }
    }
}

impl<F: ScalarField> Circuit<F> for GateCircuitBuilder<F> {
    type Config = FlexGateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> FlexGateConfig<F> {
        let FlexGateConfigParams {
            strategy,
            num_advice_per_phase,
            num_lookup_advice_per_phase: _,
            num_fixed,
            k,
        } = serde_json::from_str(&std::env::var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        FlexGateConfig::configure(meta, strategy, &num_advice_per_phase, num_fixed, k)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "GateCircuitBuilder generated circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                // only support FirstPhase in this Builder because getting challenge value requires more specialized witness generation during synthesize
                if !self.builder.borrow().witness_gen_only {
                    // clone the builder so we can re-use the circuit for both vk and pk gen
                    let builder = self.builder.borrow().clone();
                    for threads in builder.threads.iter().skip(1) {
                        assert!(
                            threads.is_empty(),
                            "GateCircuitBuilder only supports FirstPhase for now"
                        );
                    }
                    *self.break_points.borrow_mut() =
                        builder.assign_all(&config, &[], &[], &mut region);
                } else {
                    let builder = self.builder.take();
                    let break_points = self.break_points.take();
                    for (phase, (threads, break_points)) in builder
                        .threads
                        .into_iter()
                        .zip(break_points.into_iter())
                        .enumerate()
                        .take(1)
                    {
                        assign_threads_in(phase, threads, &config, &[], &mut region, break_points);
                    }
                }
                Ok(())
            },
        )
    }
}

/// A wrapper struct to auto-build a circuit from a `GateThreadBuilder`.
#[derive(Clone, Debug)]
pub struct RangeCircuitBuilder<F: ScalarField>(pub GateCircuitBuilder<F>);

impl<F: ScalarField> RangeCircuitBuilder<F> {
    pub fn keygen(builder: GateThreadBuilder<F>) -> Self {
        Self(GateCircuitBuilder::keygen(builder))
    }

    pub fn mock(builder: GateThreadBuilder<F>) -> Self {
        Self(GateCircuitBuilder::mock(builder))
    }

    pub fn prover(
        builder: GateThreadBuilder<F>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self(GateCircuitBuilder::prover(builder, break_points))
    }
}

impl<F: ScalarField> Circuit<F> for RangeCircuitBuilder<F> {
    type Config = RangeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let FlexGateConfigParams {
            strategy,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_fixed,
            k,
        } = serde_json::from_str(&std::env::var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        let strategy = match strategy {
            GateStrategy::Vertical => RangeStrategy::Vertical,
        };
        let lookup_bits = std::env::var("LOOKUP_BITS").unwrap().parse().unwrap();
        RangeConfig::configure(
            meta,
            strategy,
            &num_advice_per_phase,
            &num_lookup_advice_per_phase,
            num_fixed,
            lookup_bits,
            k,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_lookup_table(&mut layouter).expect("load lookup table should not fail");

        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "RangeCircuitBuilder generated circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                // only support FirstPhase in this Builder because getting challenge value requires more specialized witness generation during synthesize
                if !self.0.builder.borrow().witness_gen_only {
                    // clone the builder so we can re-use the circuit for both vk and pk gen
                    let builder = self.0.builder.borrow().clone();
                    for threads in builder.threads.iter().skip(1) {
                        assert!(
                            threads.is_empty(),
                            "GateCircuitBuilder only supports FirstPhase for now"
                        );
                    }
                    *self.0.break_points.borrow_mut() = builder.assign_all(
                        &config.gate,
                        &config.lookup_advice,
                        &config.q_lookup,
                        &mut region,
                    );
                } else {
                    #[cfg(feature = "display")]
                    let start0 = std::time::Instant::now();
                    let builder = self.0.builder.take();
                    let break_points = self.0.break_points.take();
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
                            &config.gate,
                            &config.lookup_advice[phase],
                            &mut region,
                            break_points,
                        );
                    }
                    #[cfg(feature = "display")]
                    println!("assign threads in {:?}", start0.elapsed());
                }
                Ok(())
            },
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CircuitBuilderStage {
    Keygen,
    Prover,
    Mock,
}
