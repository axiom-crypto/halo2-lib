use super::{
    AssignedValue, Context, GateInstructions,
    QuantumCell::{self, Constant, Existing, Witness},
};
use crate::halo2_proofs::{
    circuit::Value,
    plonk::{
        Advice, Assigned, Column, ConstraintSystem, FirstPhase, Fixed, SecondPhase, Selector,
        ThirdPhase,
    },
    poly::Rotation,
};
use crate::utils::ScalarField;
use itertools::Itertools;
use std::{
    iter::{self, once},
    marker::PhantomData,
};

/// The maximum number of phases halo2 currently supports
pub const MAX_PHASE: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GateStrategy {
    Vertical,
    PlonkPlus,
}

#[derive(Clone, Debug)]
pub struct BasicGateConfig<F: ScalarField> {
    // `q_enable` will have either length 1 or 2, depending on the strategy

    // If strategy is Vertical, then this is the basic vertical gate
    // `q_0 * (a + b * c - d) = 0`
    // where
    // * a = value[0], b = value[1], c = value[2], d = value[3]
    // * q = q_enable[0]
    // * q_i is either 0 or 1 so this is just a simple selector
    // We chose `a + b * c` instead of `a * b + c` to allow "chaining" of gates, i.e., the output of one gate because `a` in the next gate

    // If strategy is PlonkPlus, then this is a slightly extended version of the vanilla plonk (vertical) gate
    // `q_io * (a + q_left * b + q_right * c + q_mul * b * c - d)`
    // where
    // * a = value[0], b = value[1], c = value[2], d = value[3]
    // * the q_{} can be any fixed values in F, placed in two fixed columns
    // * it is crucial that q_io goes in its own selector column! we need it to be 0, 1 to turn on/off the gate
    pub q_enable: Selector,
    pub q_enable_plus: Vec<Column<Fixed>>,
    // one column to store the inputs and outputs of the gate
    pub value: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: ScalarField> BasicGateConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, strategy: GateStrategy, phase: u8) -> Self {
        let value = match phase {
            0 => meta.advice_column_in(FirstPhase),
            1 => meta.advice_column_in(SecondPhase),
            2 => meta.advice_column_in(ThirdPhase),
            _ => panic!("Currently BasicGate only supports {MAX_PHASE} phases"),
        };
        meta.enable_equality(value);

        let q_enable = meta.selector();

        match strategy {
            GateStrategy::Vertical => {
                let config = Self { q_enable, q_enable_plus: vec![], value, _marker: PhantomData };
                config.create_gate(meta);
                config
            }
            GateStrategy::PlonkPlus => {
                let q_aux = meta.fixed_column();
                let config =
                    Self { q_enable, q_enable_plus: vec![q_aux], value, _marker: PhantomData };
                config.create_plonk_gate(meta);
                config
            }
        }
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("1 column a * b + c = out", |meta| {
            let q = meta.query_selector(self.q_enable);

            let a = meta.query_advice(self.value, Rotation::cur());
            let b = meta.query_advice(self.value, Rotation::next());
            let c = meta.query_advice(self.value, Rotation(2));
            let out = meta.query_advice(self.value, Rotation(3));

            vec![q * (a + b * c - out)]
        })
    }

    fn create_plonk_gate(&self, meta: &mut ConstraintSystem<F>) {
        meta.create_gate("plonk plus", |meta| {
            // q_io * (a + q_left * b + q_right * c + q_mul * b * c - d)
            // the gate is turned "off" as long as q_io = 0
            let q_io = meta.query_selector(self.q_enable);

            let q_mul = meta.query_fixed(self.q_enable_plus[0], Rotation::cur());
            let q_left = meta.query_fixed(self.q_enable_plus[0], Rotation::next());
            let q_right = meta.query_fixed(self.q_enable_plus[0], Rotation(2));

            let a = meta.query_advice(self.value, Rotation::cur());
            let b = meta.query_advice(self.value, Rotation::next());
            let c = meta.query_advice(self.value, Rotation(2));
            let d = meta.query_advice(self.value, Rotation(3));

            vec![q_io * (a + q_left * b.clone() + q_right * c.clone() + q_mul * b * c - d)]
        })
    }
}

#[derive(Clone, Debug)]
pub struct FlexGateConfig<F: ScalarField> {
    pub basic_gates: [Vec<BasicGateConfig<F>>; MAX_PHASE],
    // `constants` is a vector of fixed columns for allocating constant values
    pub constants: Vec<Column<Fixed>>,
    pub num_advice: [usize; MAX_PHASE],
    strategy: GateStrategy,
    gate_len: usize,
    pub context_id: usize,
    pub max_rows: usize,

    pub pow_of_two: Vec<F>,
    /// To avoid Montgomery conversion in `F::from` for common small numbers, we keep a cache of field elements
    pub field_element_cache: Vec<F>,
}

impl<F: ScalarField> FlexGateConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        strategy: GateStrategy,
        num_advice: &[usize],
        num_fixed: usize,
        context_id: usize,
        // log2_ceil(# rows in circuit)
        circuit_degree: usize,
    ) -> Self {
        let mut constants = Vec::with_capacity(num_fixed);
        for _i in 0..num_fixed {
            let c = meta.fixed_column();
            meta.enable_equality(c);
            // meta.enable_constant(c);
            constants.push(c);
        }
        let mut pow_of_two = Vec::with_capacity(F::NUM_BITS as usize);
        let two = F::from(2);
        pow_of_two.push(F::one());
        pow_of_two.push(two);
        for _ in 2..F::NUM_BITS {
            pow_of_two.push(two * pow_of_two.last().unwrap());
        }
        let field_element_cache = (0..1024).map(|i| F::from(i)).collect();

        match strategy {
            GateStrategy::Vertical | GateStrategy::PlonkPlus => {
                let mut basic_gates = [(); MAX_PHASE].map(|_| vec![]);
                let mut num_advice_array = [0usize; MAX_PHASE];
                for ((phase, &num_columns), gates) in
                    num_advice.iter().enumerate().zip(basic_gates.iter_mut())
                {
                    *gates = (0..num_columns)
                        .map(|_| BasicGateConfig::configure(meta, strategy, phase as u8))
                        .collect();
                    num_advice_array[phase] = num_columns;
                }
                Self {
                    basic_gates,
                    constants,
                    num_advice: num_advice_array,
                    strategy,
                    gate_len: 4,
                    context_id,
                    /// Warning: this needs to be updated if you create more advice columns after this `FlexGateConfig` is created
                    max_rows: (1 << circuit_degree) - meta.minimum_rows(),
                    pow_of_two,
                    field_element_cache,
                }
            }
        }
    }

    pub fn inner_product_simple<'a>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = QuantumCell<'a, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, F>>,
    ) -> AssignedValue<F> {
        let mut sum;
        let mut a = a.into_iter();
        let mut b = b.into_iter().peekable();

        let cells = if matches!(b.peek(), Some(Constant(c)) if c == &F::one()) {
            b.next();
            let start_a = a.next().unwrap();
            sum = start_a.value().copied();
            iter::once(start_a)
        } else {
            sum = Value::known(F::zero());
            iter::once(Constant(F::zero()))
        }
        .chain(a.zip(b).flat_map(|(a, b)| {
            sum = sum + a.value().zip(b.value()).map(|(a, b)| *a * b);
            [a, b, Witness(sum)]
        }));

        let (lo, hi) = cells.size_hint();
        debug_assert_eq!(Some(lo), hi);
        let len = lo / 3;
        let gate_offsets = (0..len).map(|i| (3 * i as isize, None));
        self.assign_region_last(ctx, cells, gate_offsets)
    }

    pub fn inner_product_simple_with_assignments<'a>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = QuantumCell<'a, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, F>>,
    ) -> (Vec<AssignedValue<F>>, AssignedValue<F>) {
        let mut sum;
        let mut a = a.into_iter();
        let mut b = b.into_iter().peekable();

        let cells = if matches!(b.peek(), Some(Constant(c)) if c == &F::one()) {
            b.next();
            let start_a = a.next().unwrap();
            sum = start_a.value().copied();
            iter::once(start_a)
        } else {
            sum = Value::known(F::zero());
            iter::once(Constant(F::zero()))
        }
        .chain(a.zip(b).flat_map(|(a, b)| {
            sum = sum + a.value().zip(b.value()).map(|(a, b)| *a * b);
            [a, b, Witness(sum)]
        }));

        let (lo, hi) = cells.size_hint();
        debug_assert_eq!(Some(lo), hi);
        let len = lo / 3;
        let gate_offsets = (0..len).map(|i| (3 * i as isize, None));
        let mut assignments = self.assign_region(ctx, cells, gate_offsets);
        let last = assignments.pop().unwrap();
        (assignments, last)
    }

    fn inner_product_with_assignments<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = QuantumCell<'a, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, F>>,
    ) -> (Vec<AssignedValue<F>>, AssignedValue<F>) {
        // we will do special handling of the cases where one of the vectors is all constants
        match self.strategy {
            GateStrategy::PlonkPlus => {
                let vec_a = a.into_iter().collect::<Vec<_>>();
                let vec_b = b.into_iter().collect::<Vec<_>>();
                if vec_b.iter().all(|b| matches!(b, Constant(_))) {
                    let vec_b: Vec<F> = vec_b
                        .into_iter()
                        .map(|b| if let Constant(c) = b { c } else { unreachable!() })
                        .collect();
                    let k = vec_a.len();
                    let gate_segment = self.gate_len - 2;

                    // Say a = [a0, .., a4] for example
                    // Then to compute <a, b> we use transpose of
                    // | 0  | a0 | a1 | x | a2 | a3 | y | a4 | 0 | <a,b> |
                    // while letting q_enable equal transpose of
                    // | *  |    |    | * |    |    | * |    |   |       |
                    // | 0  | b0 | b1 | 0 | b2 | b3 | 0 | b4 | 0 |

                    // we effect a small optimization if we know the constant b0 == 1: then instead of starting from 0 we can start from a0
                    // this is a peculiarity of our plonk-plus gate
                    let start_ida: usize = (vec_b[0] == F::one()).into();
                    if start_ida == 1 && k == 1 {
                        // this is just a0 * 1 = a0; you're doing nothing, why are you calling this function?
                        return (vec![], self.assign_region_last(ctx, vec_a, vec![]));
                    }
                    let k_chunks = (k - start_ida + gate_segment - 1) / gate_segment;
                    let mut cells = Vec::with_capacity(1 + (gate_segment + 1) * k_chunks);
                    let mut gate_offsets = Vec::with_capacity(k_chunks);
                    let mut running_sum =
                        if start_ida == 1 { vec_a[0].clone() } else { Constant(F::zero()) };
                    cells.push(running_sum.clone());
                    for i in 0..k_chunks {
                        let window = (start_ida + i * gate_segment)
                            ..std::cmp::min(k, start_ida + (i + 1) * gate_segment);
                        // we add a 0 at the start for q_mul = 0
                        let mut c_window = [&[F::zero()], &vec_b[window.clone()]].concat();
                        c_window.extend((c_window.len()..(gate_segment + 1)).map(|_| F::zero()));
                        // c_window should have length gate_segment + 1
                        gate_offsets.push((
                            (i * (gate_segment + 1)) as isize,
                            Some(c_window.try_into().expect("q_coeff should be correct len")),
                        ));

                        cells.extend(window.clone().map(|j| vec_a[j].clone()));
                        cells.extend((window.len()..gate_segment).map(|_| Constant(F::zero())));
                        running_sum = Witness(
                            window.into_iter().fold(running_sum.value().copied(), |sum, j| {
                                sum + Value::known(vec_b[j]) * vec_a[j].value()
                            }),
                        );
                        cells.push(running_sum.clone());
                    }
                    let mut assignments = self.assign_region(ctx, cells, gate_offsets);
                    let last = assignments.pop().unwrap();
                    (assignments, last)
                } else if vec_a.iter().all(|a| matches!(a, Constant(_))) {
                    self.inner_product_with_assignments(ctx, vec_b, vec_a)
                } else {
                    self.inner_product_simple_with_assignments(ctx, vec_a, vec_b)
                }
            }
            _ => self.inner_product_simple_with_assignments(ctx, a, b),
        }
    }
}

impl<F: ScalarField> GateInstructions<F> for FlexGateConfig<F> {
    fn strategy(&self) -> GateStrategy {
        self.strategy
    }
    fn context_id(&self) -> usize {
        self.context_id
    }
    fn pow_of_two(&self) -> &[F] {
        &self.pow_of_two
    }
    fn get_field_element(&self, n: u64) -> F {
        let get = self.field_element_cache.get(n as usize);
        if let Some(fe) = get {
            *fe
        } else {
            F::from(n)
        }
    }
    /// All indices in `gate_offsets` are with respect to `inputs` indices
    /// * `gate_offsets` specifies indices to enable selector for the gate
    /// * `gate_offsets` specifies (index, Option<[q_left, q_right, q_mul, q_const, q_out]>)
    /// * second coordinate should only be set if using strategy PlonkPlus; if not set, default to [1, 0, 0]
    /// * allow the index in `gate_offsets` to be negative in case we want to do advanced overlapping
    /// * gate_index can either be set if you know the specific column you want to assign to, or None if you want to auto-select index
    /// * only selects from advice columns in `ctx.current_phase`
    // same as `assign_region` except you can specify the `phase` to assign in
    fn assign_region_in<'a>(
        &self,
        ctx: &mut Context<F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, F>>,
        gate_offsets: impl IntoIterator<Item = (isize, Option<[F; 3]>)>,
        phase: usize,
    ) -> Vec<AssignedValue<F>> {
        // We enforce the pattern that you should assign everything in current phase at once and then move onto next phase
        debug_assert_eq!(phase, ctx.current_phase());

        let inputs = inputs.into_iter();
        let (len, hi) = inputs.size_hint();
        debug_assert_eq!(Some(len), hi);
        // we index into `advice_alloc` twice so this assert should save a bound check
        assert!(self.context_id < ctx.advice_alloc.len(), "context id out of bounds");

        let (gate_index, row_offset) = {
            let alloc = ctx.advice_alloc.get_mut(self.context_id).unwrap();

            if alloc.1 + len >= ctx.max_rows {
                alloc.1 = 0;
                alloc.0 += 1;
            }
            *alloc
        };

        let basic_gate = self.basic_gates[phase]
            .get(gate_index)
            .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}"));
        let column = basic_gate.value;
        let assignments = inputs
            .enumerate()
            .map(|(i, input)| {
                ctx.assign_cell(
                    input,
                    column,
                    #[cfg(feature = "display")]
                    self.context_id,
                    row_offset + i,
                    #[cfg(feature = "halo2-pse")]
                    (phase as u8),
                )
            })
            .collect::<Vec<_>>();

        for (i, q_coeff) in gate_offsets.into_iter() {
            basic_gate
                .q_enable
                .enable(&mut ctx.region, (row_offset as isize + i) as usize)
                .expect("enable selector should not fail");

            if self.strategy == GateStrategy::PlonkPlus {
                let q_coeff = q_coeff.unwrap_or([F::one(), F::zero(), F::zero()]);
                for (j, q_coeff) in q_coeff.into_iter().enumerate() {
                    #[cfg(feature = "halo2-axiom")]
                    {
                        ctx.region.assign_fixed(
                            basic_gate.q_enable_plus[0],
                            ((row_offset as isize) + i) as usize + j,
                            Assigned::Trivial(q_coeff),
                        );
                    }
                    #[cfg(feature = "halo2-pse")]
                    {
                        ctx.region
                            .assign_fixed(
                                || "",
                                basic_gate.q_enable_plus[0],
                                ((row_offset as isize) + i) as usize + j,
                                || Value::known(q_coeff),
                            )
                            .unwrap();
                    }
                }
            }
        }

        ctx.advice_alloc[self.context_id].1 += assignments.len();

        #[cfg(feature = "display")]
        {
            ctx.total_advice += assignments.len();
        }

        assignments
    }

    fn assign_region_last_in<'a>(
        &self,
        ctx: &mut Context<F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, F>>,
        gate_offsets: impl IntoIterator<Item = (isize, Option<[F; 3]>)>,
        phase: usize,
    ) -> AssignedValue<F> {
        // We enforce the pattern that you should assign everything in current phase at once and then move onto next phase
        debug_assert_eq!(phase, ctx.current_phase());

        let inputs = inputs.into_iter();
        let (len, hi) = inputs.size_hint();
        debug_assert_eq!(hi, Some(len));
        debug_assert_ne!(len, 0);
        // we index into `advice_alloc` twice so this assert should save a bound check
        assert!(self.context_id < ctx.advice_alloc.len(), "context id out of bounds");

        let (gate_index, row_offset) = {
            let alloc = ctx.advice_alloc.get_mut(self.context_id).unwrap();

            if alloc.1 + len >= ctx.max_rows {
                alloc.1 = 0;
                alloc.0 += 1;
            }
            *alloc
        };

        let basic_gate = self.basic_gates[phase]
            .get(gate_index)
            .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}"));
        let column = basic_gate.value;
        let mut out = None;
        for (i, input) in inputs.enumerate() {
            out = Some(ctx.assign_cell(
                input,
                column,
                #[cfg(feature = "display")]
                self.context_id,
                row_offset + i,
                #[cfg(feature = "halo2-pse")]
                (phase as u8),
            ));
        }

        for (i, q_coeff) in gate_offsets.into_iter() {
            basic_gate
                .q_enable
                .enable(&mut ctx.region, (row_offset as isize + i) as usize)
                .expect("selector enable should not fail");

            if self.strategy == GateStrategy::PlonkPlus {
                let q_coeff = q_coeff.unwrap_or([F::one(), F::zero(), F::zero()]);
                for (j, q_coeff) in q_coeff.into_iter().enumerate() {
                    #[cfg(feature = "halo2-axiom")]
                    {
                        ctx.region.assign_fixed(
                            basic_gate.q_enable_plus[0],
                            ((row_offset as isize) + i) as usize + j,
                            Assigned::Trivial(q_coeff),
                        );
                    }
                    #[cfg(feature = "halo2-pse")]
                    {
                        ctx.region
                            .assign_fixed(
                                || "",
                                basic_gate.q_enable_plus[0],
                                ((row_offset as isize) + i) as usize + j,
                                || Value::known(q_coeff),
                            )
                            .unwrap();
                    }
                }
            }
        }

        ctx.advice_alloc[self.context_id].1 += len;

        #[cfg(feature = "display")]
        {
            ctx.total_advice += len;
        }

        out.unwrap()
    }

    // Takes two vectors of `QuantumCell` and constrains a witness output to the inner product of `<vec_a, vec_b>`
    // outputs are (assignments except last, out_cell)
    // Currently the only places `assignments` is used are: `num_to_bits, range_check, carry_mod, check_carry_mod_to_zero`
    fn inner_product<'a>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = QuantumCell<'a, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, F>>,
    ) -> AssignedValue<F> {
        // we will do special handling of the cases where one of the vectors is all constants
        match self.strategy {
            GateStrategy::PlonkPlus => {
                let (_, out) = self.inner_product_with_assignments(ctx, a, b);
                out
            }
            _ => self.inner_product_simple(ctx, a, b),
        }
    }

    fn inner_product_with_sums<'a>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = QuantumCell<'a, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, F>>,
    ) -> Box<dyn Iterator<Item = AssignedValue<F>>> {
        let mut b = b.into_iter().peekable();
        let flag = matches!(b.peek(), Some(&Constant(c)) if c == F::one());
        let (assignments_without_last, last) =
            self.inner_product_simple_with_assignments(ctx, a, b);
        if flag {
            Box::new(assignments_without_last.into_iter().step_by(3).chain(once(last)))
        } else {
            // in this case the first assignment is 0 so we skip it
            Box::new(assignments_without_last.into_iter().step_by(3).skip(1).chain(once(last)))
        }
    }

    fn inner_product_left<'a>(
        &self,
        ctx: &mut Context<F>,
        a: impl IntoIterator<Item = QuantumCell<'a, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, F>>,
        a_assigned: &mut Vec<AssignedValue<F>>,
    ) -> AssignedValue<F> {
        match self.strategy {
            GateStrategy::PlonkPlus => {
                let a = a.into_iter();
                let (len, _) = a.size_hint();
                let (assignments, acc) = self.inner_product_with_assignments(ctx, a, b);
                let mut assignments = assignments.into_iter();
                a_assigned.clear();
                assert!(a_assigned.capacity() >= len);
                a_assigned.extend(
                    iter::once(assignments.next().unwrap())
                        .chain(
                            assignments
                                .chunks(3)
                                .into_iter()
                                .flat_map(|chunk| chunk.into_iter().take(2)),
                        )
                        .take(len),
                );
                acc
            }
            _ => {
                let mut a = a.into_iter();
                let mut b = b.into_iter().peekable();
                let (len, hi) = b.size_hint();
                debug_assert_eq!(Some(len), hi);
                // we do not use `assign_region` and implement directly to avoid `collect`ing the vector of assignments
                let phase = ctx.current_phase();
                assert!(self.context_id < ctx.advice_alloc.len(), "context id out of bounds");

                let (gate_index, mut row_offset) = {
                    let alloc = ctx.advice_alloc.get_mut(self.context_id).unwrap();
                    if alloc.1 + 3 * len + 1 >= ctx.max_rows {
                        alloc.1 = 0;
                        alloc.0 += 1;
                    }
                    *alloc
                };
                let basic_gate = self.basic_gates[phase]
                    .get(gate_index)
                    .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}"));
                let column = basic_gate.value;
                let q_enable = basic_gate.q_enable;

                let mut right_one = false;
                let start = ctx.assign_cell(
                    if matches!(b.peek(), Some(&Constant(x)) if x == F::one()) {
                        right_one = true;
                        b.next();
                        a.next().unwrap()
                    } else {
                        Constant(F::zero())
                    },
                    column,
                    #[cfg(feature = "display")]
                    self.context_id,
                    row_offset,
                    #[cfg(feature = "halo2-pse")]
                    (phase as u8),
                );

                row_offset += 1;
                let mut acc = start.value().copied();
                a_assigned.clear();
                assert!(a_assigned.capacity() >= len);
                if right_one {
                    a_assigned.push(start);
                }
                let mut last = None;

                for (a, b) in a.zip(b) {
                    q_enable
                        .enable(&mut ctx.region, row_offset - 1)
                        .expect("enable selector should not fail");

                    acc = acc + a.value().zip(b.value()).map(|(a, b)| *a * b);
                    let [a, _, c] = [(a, 0), (b, 1), (Witness(acc), 2)].map(|(qcell, idx)| {
                        ctx.assign_cell(
                            qcell,
                            column,
                            #[cfg(feature = "display")]
                            self.context_id,
                            row_offset + idx,
                            #[cfg(feature = "halo2-pse")]
                            (phase as u8),
                        )
                    });
                    last = Some(c);
                    row_offset += 3;
                    a_assigned.push(a);
                }
                ctx.advice_alloc[self.context_id].1 = row_offset;

                #[cfg(feature = "display")]
                {
                    ctx.total_advice += 3 * (len - usize::from(right_one)) + 1;
                }
                last.unwrap_or_else(|| a_assigned[0].clone())
            }
        }
    }

    fn sum_products_with_coeff_and_var<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<F>,
        values: impl IntoIterator<Item = (F, QuantumCell<'a, F>, QuantumCell<'a, F>)>,
        var: QuantumCell<'a, F>,
    ) -> AssignedValue<F> {
        // TODO: optimize
        match self.strategy {
            GateStrategy::PlonkPlus => {
                let mut cells = Vec::new();
                let mut gate_offsets = Vec::new();
                let mut acc = var.value().copied();
                cells.push(var);
                for (i, (c, a, b)) in values.into_iter().enumerate() {
                    acc = acc + Value::known(c) * a.value() * b.value();
                    cells.append(&mut vec![a, b, Witness(acc)]);
                    gate_offsets.push((3 * i as isize, Some([c, F::zero(), F::zero()])));
                }
                self.assign_region_last(ctx, cells, gate_offsets)
            }
            GateStrategy::Vertical => {
                let (a, b): (Vec<_>, Vec<_>) = std::iter::once((var, Constant(F::one())))
                    .chain(values.into_iter().filter_map(|(c, va, vb)| {
                        if c == F::one() {
                            Some((va, vb))
                        } else if c != F::zero() {
                            let prod = self.mul(ctx, va, vb);
                            Some((QuantumCell::ExistingOwned(prod), Constant(c)))
                        } else {
                            None
                        }
                    }))
                    .unzip();
                self.inner_product(ctx, a, b)
            }
        }
    }

    /// assumes sel is boolean
    /// returns
    ///   a * sel + b * (1 - sel)
    fn select(
        &self,
        ctx: &mut Context<F>,
        a: QuantumCell<F>,
        b: QuantumCell<F>,
        sel: QuantumCell<F>,
    ) -> AssignedValue<F> {
        let diff_val: Value<F> = a.value().zip(b.value()).map(|(a, b)| *a - b);
        let out_val = diff_val * sel.value() + b.value();
        match self.strategy {
            // | a - b | 1 | b | a |
            // | b | sel | a - b | out |
            GateStrategy::Vertical => {
                let cells = vec![
                    Witness(diff_val),
                    Constant(F::one()),
                    b.clone(),
                    a,
                    b,
                    sel,
                    Witness(diff_val),
                    Witness(out_val),
                ];
                let mut assigned_cells =
                    self.assign_region_smart(ctx, cells, vec![0, 4], vec![(0, 6), (2, 4)], vec![]);
                assigned_cells.pop().unwrap()
            }
            // | 0 | a | a - b | b | sel | a - b | out |
            // selectors
            // | 1 | 0 | 0     | 1 | 0   | 0
            // | 0 | 1 | -1    | 1 | 0   | 0
            GateStrategy::PlonkPlus => {
                let mut assignments = self.assign_region(
                    ctx,
                    vec![
                        Constant(F::zero()),
                        a,
                        Witness(diff_val),
                        b,
                        sel,
                        Witness(diff_val),
                        Witness(out_val),
                    ],
                    vec![(0, Some([F::zero(), F::one(), -F::one()])), (3, None)],
                );
                ctx.region.constrain_equal(assignments[2].cell(), assignments[5].cell()).unwrap();
                assignments.pop().unwrap()
            }
        }
    }

    /// returns: a || (b && c)
    // | 1 - b c | b | c | 1 | a - 1 | 1 - b c | out | a - 1 | 1 | 1 | a |
    fn or_and(
        &self,
        ctx: &mut Context<F>,
        a: QuantumCell<F>,
        b: QuantumCell<F>,
        c: QuantumCell<F>,
    ) -> AssignedValue<F> {
        let bc_val = b.value().zip(c.value()).map(|(b, c)| *b * c);
        let not_bc_val = bc_val.map(|x| F::one() - x);
        let not_a_val = a.value().map(|x| *x - F::one());
        let out_val = bc_val + a.value() - bc_val * a.value();
        let cells = vec![
            Witness(not_bc_val),
            b,
            c,
            Constant(F::one()),
            Witness(not_a_val),
            Witness(not_bc_val),
            Witness(out_val),
            Witness(not_a_val),
            Constant(F::one()),
            Constant(F::one()),
            a,
        ];
        let assigned_cells =
            self.assign_region_smart(ctx, cells, vec![0, 3, 7], vec![(4, 7), (0, 5)], vec![]);
        assigned_cells.into_iter().nth(6).unwrap()
    }

    // returns little-endian bit vectors
    fn num_to_bits(
        &self,
        ctx: &mut Context<F>,
        a: &AssignedValue<F>,
        range_bits: usize,
    ) -> Vec<AssignedValue<F>> {
        let bits = a
            .value()
            .map(|a| {
                a.to_repr()
                    .as_ref()
                    .iter()
                    .flat_map(|byte| (0..8).map(|i| (*byte as u64 >> i) & 1))
                    .take(range_bits)
                    .map(|x| F::from(x))
                    .collect::<Vec<_>>()
            })
            .transpose_vec(range_bits);

        let mut bit_cells = Vec::with_capacity(range_bits);

        let acc = self.inner_product_left(
            ctx,
            bits.into_iter().map(|x| Witness(x)),
            self.pow_of_two[..range_bits].iter().map(|c| Constant(*c)),
            &mut bit_cells,
        );
        ctx.region.constrain_equal(a.cell(), acc.cell()).unwrap();

        for bit_cell in &bit_cells {
            self.assign_region(
                ctx,
                vec![
                    Constant(F::zero()),
                    Existing(bit_cell),
                    Existing(bit_cell),
                    Existing(bit_cell),
                ],
                vec![(0, None)],
            );
        }
        bit_cells
    }
}
