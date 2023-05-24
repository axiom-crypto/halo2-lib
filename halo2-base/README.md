# Halo2-base


Halo2-base provides a streamlined interface for interacting with the Halo2 API. It simplifies circuit programming to declaring constraints over a single advice and selector column and providing built-in circuit configuring and column splitting for proof parallelization.

Programmed circuit constraints are stored in multiple `Context`'s held by `GateThreadBuilder` which tracks all assigned witness values and constraints. Before circuit synthesis the number of rows and columns in the circuit is pre-computed by calling `config()` in `GateThreadBuilder`. The two columns are split into mulitple columns at `breakpoints`. All assigned values in the circuit are then assigned by calling `synthesize()` in `GateCircuitBuilder` which in turn invokes `assign_all()` or `assign_threads_in` in `GateThreadBuilder` to assign the witness values tracked in the `Context` to there respective `Column` in the circuit within the Halo2 proving system.

Pre-computing the number of rows and columns eliminates the necessity to manually specify columns ahead of time and leads to better proving performance through parallelizing advice columns.

Witness computation is also parallelized in Halo2-base allowing for faster generation of circuit output. This is accomplished by splitting the single advice and selector column into multiple columns to solely compute the resulting witness value. This process is parallelization process is distinct from the final configuration of the circuit columns previously mentioned.

Halo2-base also provides pre-built [Chips](https://zcash.github.io/halo2/concepts/chips.html) for common arithmetic operations in `GateChip` and lookup arguments in `RangeChip`. 

The structure of Halo2-base is outlines as follows:

- `builder.rs`: Contains `GateThreadBuilder`, `GateCircuitBuilder`, and `RangeCircuitBuilder` which implement the logic to split the single advice and selector columns and there respective constraints across multiple columns for effective parellelization.
- `lib.rs`: Defines the `QuantumCell`, `ContextCell`, `AssignedValue`, and `Context` types which track assigned values within a circuit across multiple columns and provide a streamlined interface to assign witness values directly to the advice column.
- `utils.rs`: Contains `BigPrimeField`, `BigUint`, and `ScalerField` traits which represent field elements within halo2 and provides methods to decompose Field elements into `u64`  limbs.
- `flex_gate.rs`: Contains the implemenation of `GateChip` and the `GateInstructions` trait which provide circuits for basic arithmetic operations within halo2.
- `range.rs:`: Implements `RangeChip` and the `RangeInstructions` trait which provide circuits for performing range check and other lookup argument values.

This readme compliments the in-line documentation of Halo2-base providing an overview of `builder.rs` and `lib.rs`.

<br>

## [Context](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/lib.rs#L128)

`Context` holds all information of an execution trace (circuit and its witness values). `Context` objects store the constraint information for a sub-section of the two columns in Halo2-base. Storing the circuit information in a `Context` allows for the rearrangement of the `single column` into multiple parallelizable columns while preserving the underlying circuit information. This allows witness computation and the precomputation of a circuits size. In Halo2-base the `single column` is split into sections at `breakpoints` each represented by a different `Context`. During circuit `synthesis()`, the cell assignments of a `Context` are extracted and assigned to a `region()` using the Halo2 API.

```rust ignore
pub struct Context<F: ScalarField> {

    witness_gen_only: bool,

    pub context_id: usize,

    pub advice: Vec<Assigned<F>>,

    pub cells_to_lookup: Vec<AssignedValue<F>>,

    pub zero_cell: Option<AssignedValue<F>>,

    pub selector: Vec<bool>,

    pub advice_equality_constraints: Vec<(ContextCell, ContextCell)>,
    
    pub constant_equality_constraints: Vec<(F, ContextCell)>,
}
```
The `witness_gen_only` is set for witness computation, such as during Mock proving. Otherwise it is set to false.

The `Context` holds all equality and constant constraints as a `Vec` of `ContextCell` tuples representing the positions of the two cells to constrain. `advice`, `selector`, store the respective columns values of the `Context`'s section of the two columns. `cells_to_lookup` tracks `AssignedValue`'s of cells marked for use in a lookup table within the `Context`.

[ContextCell](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/lib.rs#L94) is a pointer to a specific cell within a `Context` identified by the Context's `context_id` and the cells relative `offset` from the first cell of the advice column of the Context.

``` rust ignore
#[derive(Clone, Copy, Debug)]
pub struct ContextCell {
    /// Identifier of the [Context] that this cell belongs to.
    pub context_id: usize,
    /// Relative offset of the cell within this [Context] advice column.
    pub offset: usize,
}
```

[AssignedValue](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/lib.rs#L105) represents a specific `Assigned` value assigned to a cell within a specific `Context` of a circuit referenced by a `ContextCell`. 
```rust ignore
pub struct AssignedValue<F: ScalarField> {
    pub value: Assigned<F>,

    pub cell: Option<ContextCell>,
}
```
    
[Assigned](https://github.com/zcash/halo2/blob/main/halo2_proofs/src/plonk/assigned.rs#L11) is a wrapper enum for values assigned to a cell within a circuit which stores the value as a fraction and marks it for batched inversion using Montgomery's trick https://zcash.github.io/halo2/background/fields.html#montgomerys-trick. Performing batched inversion allows for the computation of the inverse of all marked values with a single inversion operation.
```rust ignore
pub enum Assigned<F> {
    /// The field element zero.
    Zero,
    /// A value that does not require inversion to evaluate.
    Trivial(F),
    /// A value stored as a fraction to enable batch inversion.
    Rational(F, F),
}
```
    
<br>

## [QuantumCell](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/lib.rs#L53)

QuantumCell is a helper enum that abstracts the scenarios in which a value is assigned to the advice column in Halo2-base. Assigning existing or constant values to the advice column requires manually specifying the enforeced constraints on top of assigning the value leading to bloated code. QuantumCell handles these technical operations for you, all a developer needs to do is specify which enum option in `QuantumCell` there value corresponds to. The `assign_cell()` method `Context` then handles the technical operations for you.

```rust ignore
pub enum QuantumCell<F: ScalarField> {

    Existing(AssignedValue<F>),

    Witness(F),

    WitnessFraction(Assigned<F>),

    Constant(F),
}
```
QuantumCell contains the following enum variants.

- **Existing**:
    Assigns a value to the advice column that exists within the advice column. The value is an existing value from some previous part of your computation already in the advice column in the form of an AssignedValue. When you add an existing cell a into the table a new cell will be assigned into the advice column with value equal to the existing value. An equality constraint will then be added between the new cell and the cell of a so the Verifier has a guarantee that these two cells are always equal.
    ```rust ignore
    QuantumCell::Existing(acell) => {
        self.advice.push(acell.value);

        if !self.witness_gen_only {
            let new_cell =
                ContextCell { context_id: self.context_id, offset: self.advice.len() - 1 };
                self.advice_equality_constraints.push((new_cell, acell.cell.unwrap()));
            }
    }
    ```
- **Witness**:
    Assigns an entirely new number into the advice column, such as a private input. When `assign_cell` is called the value is wrapped in as an `Assigned::Trivial()`` which marks it for exclusion from batch inversion.
    ``` rust ignore
    QuantumCell::Witness(val) => {
        self.advice.push(Assigned::Trivial(val));
    }
    ```
- **WitnessFraction**:
    Assigns an entirely new witness value to the advice column. `WitnessFraction` exists for optimization purposes and accepts Assigned values wrapped in `Assigned::Rational()`` marked for batch inverion.
    ``` rust ignore
    QuantumCell::WitnessFraction(val) => {
        self.advice.push(val);
    }
    ```
- **Constant**:
    A value that is a "known" constant. A "known" refers to known at circuit creation time to both the Prover and Verifier. When you assign a constant value there is exists another secret "Fixed" column in the circuit constraint table whose values are fixed at circuit creation time. When you assign a Constant value, you are adding this value to the Fixed column, adding the value as a witness to the Advice column, and then imposing an equality constraint between the two corresponding cells in the `Fixed` and `Advice` columns.
``` rust ignore
QuantumCell::Constant(c) => {
    self.advice.push(Assigned::Trivial(c));
        // If witness generation is not performed, enforce equality constraints between the existing cell and the new cell
    if !self.witness_gen_only {
    let new_cell =
        ContextCell { context_id: self.context_id, offset: self.advice.len() - 1 };
        self.constant_equality_constraints.push((c, new_cell));
        }
}
```

<br>

## [GateThreadBuilder](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/gates/builder.rs#L49) & [GateCircuitBuilder](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/gates/builder.rs#L462)

GateThreadBuilder tracks the cell assignments of a circuit as a `Context` allowing for the pre-computation of a circuits size and splitting the two column into multiple columns for parallelization.

```rust ignore
#[derive(Clone, Debug, Default)]
pub struct GateThreadBuilder<F: ScalarField> {
    /// Threads for each challenge phase
    pub threads: [Vec<Context<F>>; MAX_PHASE],
    /// Max number of threads
    thread_count: usize,
    /// Flag for witness generation. If true, the gate thread builder is used for witness generation only.
    witness_gen_only: bool,
    /// The `unknown` flag is used during key generation. If true, during key generation witness [Value]s are replaced with Value::unknown() for safety.
    use_unknown: bool,
}
```
GateThreadBuilder tracks circuit assignment as an array of `threads` consisting of `Vec` of `Context`'s. Halo2's proving system has distinct phases each of which its own unique column. To accomodate this `GateThreadBuilder` tracks a `thread` for each phase of the proving system. Each `Context` in a `thread` defines a sub-section of the two column split at a breakpoint stored in `break_points`.

Once a `GateThreadBuilder` is created, gates may be assigned to a `Context` in `threads`. Once the circuit is created `config()` is called to pre-computes the circuits size and sets the circuits environment variables.

[config()](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/gates/builder.rs#L137)
```rust ignore
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

        let total_fixed: usize = HashSet::<F>::from_iter(self.threads.iter().flat_map(|threads| {
            threads.iter().flat_map(|ctx| ctx.constant_equality_constraints.iter().map(|(c, _)| *c))
        }))
        .len();
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
```
For circuit creation the a `GateCircuitBuilder` is created by passing the created `GateThreadBuilder` as an argument to `GateCircuitBuilder`'s `keygen`,`mock`, or `prover` functions. `GateCircuitBuilder` acts as a middleman between `GateThreadBuilder` and the Halo2 API by implementing the `Circuit` Trait of the Halo2 API and calling into `GateThreadBuilder` to perform circuit assignment.

```rust ignore
/// Vector of vectors tracking the thread break points across different halo2 phases
pub type MultiPhaseThreadBreakPoints = Vec<ThreadBreakPoints>;

#[derive(Clone, Debug)]
pub struct GateCircuitBuilder<F: ScalarField> {
    /// The Thread Builder for the circuit
    pub builder: RefCell<GateThreadBuilder<F>>,
    /// Break points for threads within the circuit
    pub break_points: RefCell<MultiPhaseThreadBreakPoints>,
}

impl<F: ScalarField> Circuit<F> for GateCircuitBuilder<F> {
    type Config = FlexGateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    
    /// Creates a new instance of the circuit without withnesses filled in.
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using the the parameters specified [Config].
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

    /// Performs the actual computation on the circuit (e.g., witness generation), filling in all the advice values for a particular proof.
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.sub_synthesize(&config, &[], &[], &mut layouter);
        Ok(())
    }
}
```
`GateCircuitBuilder` contains a list of breakpoints for each thread across all phases in and `GateThreadBuilder` itself. Both are wrapped in a `RefCell` allowing them to be borrowed mutably so `break_points` can be recorded during circuit creation for later use and the function performing circuit creation can take ownership of `builder`.

During circuit creation `synthesize()` is invoked which passes into `sub_synthesize` a `FlexGateConfig` containing the circuits columns and a mutable reference to a Layouter from the Halo2 API which facilitates the final assignment of circuit cells.

[sub_synthesize()](https://github.com/PatStiles/halo2-lib/blob/release-0.3.0/halo2-base/src/gates/builder.rs#LL490C2-L490C2)
```rust ignore
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

```
`layouter`'s `assign_region()` function is invoked which yields a mutable reference to `Region`. `region` is used to assign of a contiguous region of cells representing the circuit within Halo2's proving system.

If `witnes_gen_only` is not set within the `builder` (during keygen, and mock proving) `sub_synthesize` takes ownership of the `builder`, asserts all threads but the thread corresponding to the first phase are empty, and calls `assign_all()` to assign all cells within this `thread`'s context to the circuit. The resulting column breakpoints are recorded in `GateCircuitBuilder`'s `break_points` field. 

It should be noted this process is only compatible with the first phase of Halo2's proving system as retrieving witness challenges in later phases requires more specialized witness generation during synthesis.

`assign_all()` iterates over each `Context` within a thread and assigns the values and constraints of the advice, selector, fixed, and lookup columns to the circuit using `region`.

Breakpoints for the advice column are assigned sequentially if the `row_offset` of the cell value being currently assigned exceeds the maximum amount of rows allowed in a column.

[assign_all()](https://github.com/axiom-crypto/halo2-lib/blob/release-0.3.0/halo2-base/src/gates/builder.rs#L205)
```rust ignore
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
        ...
        for (phase, threads) in self.threads.iter().enumerate() {
            let mut break_point = vec![];
            let mut gate_index = 0;
            let mut row_offset = 0;
            for ctx in threads {
                let mut basic_gate = config.basic_gates[phase]
                        .get(gate_index)
                        .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}. Perhaps blinding factors were not taken into account. The max non-poisoned rows is {max_rows}"));
                assert_eq!(ctx.selector.len(), ctx.advice.len());

                for (i, (advice, &q)) in ctx.advice.iter().zip(ctx.selector.iter()).enumerate() {
                    let column = basic_gate.value;
                    let value = if use_unknown { Value::unknown() } else { Value::known(advice) };
                    #[cfg(feature = "halo2-axiom")]
                    let cell = *region.assign_advice(column, row_offset, value).cell();
                    #[cfg(not(feature = "halo2-axiom"))]
                    let cell = region
                        .assign_advice(|| "", column, row_offset, || value.map(|v| *v))
                        .unwrap()
                        .cell();
                    assigned_advices.insert((ctx.context_id, i), (cell, row_offset));
            ...
                    
```
In the case a breakpoint falls on the overlap between two gates (such as chained addition of two values) the cells the breakpoint falls on must be copied to the next column and a new equality constraint enforced between the value of the cell in the old column and the copied cell in the new column. This prevents the circuit from being undersconstratined and preserves the equality constraint from the overlapping gates.
```rust ignore
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

```

If `witness_gen_only` flag is set witness generation is only performed. `sub_synthesize` calls `assign_threads_in()` to assign threads directly.

`assign_threads_in` assumes that break points have been pre-computed. It iterates over all the `Context` within a thread and assigns lookup and advice column values to the circuit using `region`. 

[assign_threads_in()](https://github.com/PatStiles/halo2-lib/blob/release-0.3.0/halo2-base/src/gates/builder.rs#L378)
```rust ignore
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

```
If a breakpoint is reached, a new column is created by incrementing `gate_index` and assigning `column` to a new advice column found at `config.basic_gates[phase][gate_index].value`.