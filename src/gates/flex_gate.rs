use super::{
    AssignedValue, Context, GateInstructions,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Value,
    plonk::{Advice, Column, ConstraintSystem, Error, FirstPhase, Fixed, SecondPhase, ThirdPhase},
    poly::Rotation,
};
use std::{marker::PhantomData, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GateStrategy {
    Vertical,
    PlonkPlus,
}

#[derive(Clone, Debug)]
pub struct BasicGateConfig<F: FieldExt> {
    // `q_enable` will have either length 1 or 2, depending on the strategy

    // If strategy is Vertical, then this is the basic vertical gate
    // `q_0 * (a + b * c - d) = 0`
    // where
    // * a = value[0], b = value[1], c = value[2], d = value[3]
    // * q = q_enable[0]
    // * q is either 0 or 1 so this is just a simple selector
    // We chose `a + b * c` instead of `a * b + c` to allow "chaining" of gates, i.e., the output of one gate because `a` in the next gate

    // If strategy is PlonkPlus, then this is a slightly extended version of the vanilla plonk (vertical) gate
    // `q_io * (a + q_left * b + q_right * c + q_mul * b * c - d)`
    // where
    // * a = value[0], b = value[1], c = value[2], d = value[3]
    // * the q_{} can be any fixed values in F, placed in two fixed columns (see `create_plonk_gate` for details)
    // * it is crucial that q_io goes in its own selector column! we need it to be 0, 1 to turn on/off the gate
    pub q_enable: Vec<Column<Fixed>>,
    // one column to store the inputs and outputs of the gate
    pub value: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BasicGateConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, strategy: GateStrategy, phase: u8) -> Self {
        let value = match phase {
            0 => meta.advice_column_in(FirstPhase),
            1 => meta.advice_column_in(SecondPhase),
            2 => meta.advice_column_in(ThirdPhase),
            _ => panic!(),
        };
        meta.enable_equality(value);
        let q = meta.fixed_column();

        match strategy {
            GateStrategy::Vertical => {
                let config = Self {
                    q_enable: vec![q],
                    value,
                    _marker: PhantomData,
                };
                config.create_gate(meta);
                config
            }
            GateStrategy::PlonkPlus => {
                let q_aux = meta.fixed_column();
                let config = Self {
                    q_enable: vec![q, q_aux],
                    value,
                    _marker: PhantomData,
                };
                config.create_plonk_gate(meta);
                config
            }
        }
    }

    fn create_gate(&self, meta: &mut ConstraintSystem<F>) {
        assert_eq!(self.q_enable.len(), 1);
        meta.create_gate("1 column a * b + c = out", |meta| {
            let q = meta.query_fixed(self.q_enable[0], Rotation::cur());

            let a = meta.query_advice(self.value, Rotation::cur());
            let b = meta.query_advice(self.value, Rotation::next());
            let c = meta.query_advice(self.value, Rotation(2));
            let out = meta.query_advice(self.value, Rotation(3));

            vec![q * (a + b * c - out)]
        })
    }

    fn create_plonk_gate(&self, meta: &mut ConstraintSystem<F>) {
        assert_eq!(self.q_enable.len(), 2);
        meta.create_gate("plonk plus", |meta| {
            // q_io * (a + q_left * b + q_right * c + q_mul * b * c - d)
            // the gate is turned "off" as long as q_io = 0
            let q_io = meta.query_fixed(self.q_enable[0], Rotation::cur());

            let q_mul = meta.query_fixed(self.q_enable[1], Rotation::cur());
            let q_left = meta.query_fixed(self.q_enable[1], Rotation::next());
            let q_right = meta.query_fixed(self.q_enable[1], Rotation(2));

            let a = meta.query_advice(self.value, Rotation::cur());
            let b = meta.query_advice(self.value, Rotation::next());
            let c = meta.query_advice(self.value, Rotation(2));
            let d = meta.query_advice(self.value, Rotation(3));

            vec![q_io * (a + q_left * b.clone() + q_right * c.clone() + q_mul * b * c - d)]
        })
    }
}

#[derive(Clone, Debug)]
pub struct FlexGateConfig<F: FieldExt> {
    pub basic_gates: Vec<BasicGateConfig<F>>,
    // `constants` is a vector of fixed columns for allocating constant values
    pub constants: Vec<Column<Fixed>>,
    pub num_advice: usize,
    strategy: GateStrategy,
    gate_len: usize,
    pub context_id: Rc<String>,
}

impl<F: FieldExt> FlexGateConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        strategy: GateStrategy,
        num_advice: &[usize],
        num_fixed: usize,
        context_id: String,
    ) -> Self {
        let mut constants = Vec::with_capacity(num_fixed);
        for _i in 0..num_fixed {
            let c = meta.fixed_column();
            meta.enable_equality(c);
            constants.push(c);
        }
        match strategy {
            GateStrategy::Vertical | GateStrategy::PlonkPlus => {
                let mut basic_gates = Vec::new();
                for (phase, &num_columns) in num_advice.iter().enumerate() {
                    basic_gates.extend(
                        (0..num_columns)
                            .map(|_| BasicGateConfig::configure(meta, strategy, phase as u8)),
                    );
                }
                let num_advice = basic_gates.len();
                Self {
                    basic_gates,
                    constants,
                    num_advice,
                    strategy,
                    gate_len: 4,
                    context_id: Rc::new(context_id),
                }
            }
        }
    }
}

impl<F: FieldExt> FlexGateConfig<F> {
    /// call this at the very end of synthesize!
    /// allocates constants to fixed columns
    /// returns (max rows used by a fixed column, total number of constants assigned)
    pub fn finalize(&self, ctx: &mut Context<'_, F>) -> Result<(usize, usize), Error> {
        #[cfg(feature = "display")]
        println!("{:#?}", ctx.op_count);

        ctx.assign_and_constrain_constants(&self.constants)
    }

    /// returns leftmost `i` where `advice_rows[context_id][i]` is minimum amongst all `i` where `column[i]` is in phase `phase`
    fn min_gate_index_in(&self, ctx: &Context<'_, F>, phase: u8) -> usize {
        let advice_rows = ctx.advice_rows_get(&self.context_id);

        self.basic_gates
            .iter()
            .enumerate()
            .filter(|(_, basic_gate)| basic_gate.value.column_type().phase() == phase)
            .min_by(|(i, _), (j, _)| advice_rows[*i].cmp(&advice_rows[*j]))
            .map(|(i, _)| i)
            .expect(format!("Should exist advice column in phase {}", phase).as_str())
    }
}

impl<F: FieldExt> GateInstructions<F> for FlexGateConfig<F> {
    fn strategy(&self) -> GateStrategy {
        self.strategy
    }
    /// All indices in `gate_offsets` are with respect to `inputs` indices
    /// * `gate_offsets` specifies indices to enable selector for the gate
    /// * `gate_offsets` specifies (index, Option<[q_left, q_right, q_mul, q_const, q_out]>)
    /// * second coordinate should only be set if using strategy PlonkPlus; if not set, default to [1, 0, 0]
    /// * allow the index in `gate_offsets` to be negative in case we want to do advanced overlapping
    /// * gate_index can either be set if you know the specific column you want to assign to, or None if you want to auto-select index
    /// * only selects from advice columns in `ctx.current_phase`
    fn assign_region(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        gate_offsets: Vec<(isize, Option<[F; 3]>)>,
        gate_index: Option<usize>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        self.assign_region_in(ctx, inputs, gate_offsets, gate_index, ctx.current_phase())
    }

    // same as `assign_region` except you can specify the `phase` to assign in
    fn assign_region_in(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        gate_offsets: Vec<(isize, Option<[F; 3]>)>,
        gate_index: Option<usize>,
        phase: u8,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gate_index = if let Some(id) = gate_index {
            assert_eq!(phase, self.basic_gates[id].value.column_type().phase());
            id
        } else {
            self.min_gate_index_in(ctx, phase)
        };
        let row_offset = ctx.advice_rows_get(&self.context_id)[gate_index];

        let mut assignments = Vec::with_capacity(inputs.len());
        for (i, input) in inputs.iter().enumerate() {
            let assigned = ctx.assign_cell(
                input.clone(),
                self.basic_gates[gate_index].value,
                &self.context_id,
                gate_index,
                row_offset + i,
                phase,
            )?;
            assignments.push(assigned);
        }
        for (i, q_coeff) in &gate_offsets {
            ctx.region.assign_fixed(
                || "",
                self.basic_gates[gate_index].q_enable[0],
                (row_offset as isize + i) as usize,
                || Value::known(F::one()),
            )?;

            if self.strategy == GateStrategy::PlonkPlus {
                let q_coeff = q_coeff.unwrap_or([F::one(), F::zero(), F::zero()]);
                for j in 0..3 {
                    ctx.region.assign_fixed(
                        || "",
                        self.basic_gates[gate_index].q_enable[1],
                        ((row_offset as isize) + i) as usize + j,
                        || Value::known(q_coeff[j]),
                    )?;
                }
            }
        }

        ctx.advice_rows_get_mut(&self.context_id)[gate_index] += inputs.len();

        Ok(assignments)
    }

    /// Only call this if ctx.region is not in shape mode, i.e., if not using simple layouter or ctx.first_pass = false
    ///
    /// All indices in `gate_offsets`, `equality_offsets`, `external_equality` are with respect to `inputs` indices
    /// - `gate_offsets` specifies indices to enable selector for the gate; assume `gate_offsets` is sorted in increasing order
    /// - `equality_offsets` specifies pairs of indices to constrain equality
    /// - `external_equality` specifies an existing cell to constrain equality with the cell at a certain index
    fn assign_region_smart(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        gate_offsets: Vec<usize>,
        equality_offsets: Vec<(usize, usize)>,
        external_equality: Vec<(&AssignedValue<F>, usize)>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let assignments = match self.strategy {
            GateStrategy::Vertical | GateStrategy::PlonkPlus => self
                .assign_region(
                    ctx,
                    inputs,
                    gate_offsets.iter().map(|i| (*i as isize, None)).collect(),
                    None,
                )
                .expect("assign region should not fail"),
        };
        for (offset1, offset2) in equality_offsets {
            ctx.region.constrain_equal(
                assignments[offset1].clone().cell(),
                assignments[offset2].clone().cell(),
            )?;
        }
        for (assigned, eq_offset) in external_equality {
            ctx.region
                .constrain_equal(assigned.cell(), assignments[eq_offset].cell())?;
        }
        Ok(assignments)
    }

    fn load_zero(&self, ctx: &mut Context<'_, F>) -> Result<AssignedValue<F>, Error> {
        if let Some(zcell) = &ctx.zero_cell {
            return Ok(zcell.clone());
        }
        let zero_cells =
            self.assign_region_smart(ctx, vec![Constant(F::from(0))], vec![], vec![], vec![])?;
        ctx.zero_cell = Some(zero_cells[0].clone());
        Ok(zero_cells[0].clone())
    }

    /// Copies a, b and constrains `a + b * 1 = out`
    // | a | b | 1 | a + b |
    fn add(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            a.clone(),
            b.clone(),
            QuantumCell::Constant(F::from(1)),
            QuantumCell::Witness(a.value().zip(b.value()).map(|(av, bv)| (*av) + (*bv))),
        ];
        let assigned_cells = self.assign_region_smart(ctx, cells, vec![0], vec![], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
    }

    /// Copies a, b and constrains `a + b * (-1) = out`
    // | a | b | -1 | a - b |
    fn sub(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            a.clone(),
            b.clone(),
            QuantumCell::Constant(-F::from(1)),
            QuantumCell::Witness(a.value().zip(b.value()).map(|(av, bv)| (*av) - (*bv))),
        ];
        let assigned_cells = self.assign_region_smart(ctx, cells, vec![0], vec![], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
    }

    // | 0 | a | -1 | -a |
    fn neg(&self, ctx: &mut Context<'_, F>, a: &QuantumCell<F>) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            QuantumCell::Constant(F::from(0)),
            a.clone(),
            QuantumCell::Constant(-F::from(1)),
            QuantumCell::Witness(a.value().map(|av| -(*av))),
        ];
        let assigned_cells = self.assign_region_smart(ctx, cells, vec![0], vec![], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
    }

    /// Copies a, b and constrains `0 + a * b = out`
    // | 0 | a | b | a * b |
    fn mul(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            QuantumCell::Constant(F::from(0)),
            a.clone(),
            b.clone(),
            QuantumCell::Witness(a.value().zip(b.value()).map(|(av, bv)| (*av) * (*bv))),
        ];
        let assigned_cells = self.assign_region_smart(ctx, cells, vec![0], vec![], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
    }

    fn mul_add(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        c: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let assignments = self.assign_region_smart(
            ctx,
            vec![
                c.clone(),
                a.clone(),
                b.clone(),
                Witness(a.value().copied() * b.value() + c.value()),
            ],
            vec![0],
            vec![],
            vec![],
        )?;
        Ok(assignments.last().unwrap().clone())
    }

    fn assert_equal(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<(), Error> {
        self.assign_region_smart(
            ctx,
            vec![
                a.clone(),
                b.clone(),
                Constant(-F::one()),
                Constant(F::zero()),
            ],
            vec![0],
            vec![],
            vec![],
        )?;
        Ok(())
    }
    // Takes two vectors of `QuantumCell` and constrains a witness output to the inner product of `<vec_a, vec_b>`
    // outputs are vec<(a_cell, a_relative_index)>, vec<(b_cell, b_relative_index)>, out_cell
    fn inner_product(
        &self,
        ctx: &mut Context<'_, F>,
        vec_a: &Vec<QuantumCell<F>>,
        vec_b: &Vec<QuantumCell<F>>,
    ) -> Result<
        (
            Option<Vec<AssignedValue<F>>>,
            Option<Vec<AssignedValue<F>>>,
            AssignedValue<F>,
        ),
        Error,
    > {
        assert_eq!(vec_a.len(), vec_b.len());
        // don't try to call this function with empty inputs!
        if vec_a.len() == 0 {
            return Err(Error::Synthesis);
        }
        // we will do special handling of the cases where one of the vectors is all constants
        if self.strategy == GateStrategy::PlonkPlus
            && vec_b.iter().all(|b| {
                if matches!(b, Constant(_)) {
                    true
                } else {
                    false
                }
            })
        {
            let vec_b: Vec<F> = vec_b
                .iter()
                .map(|b| {
                    if let Constant(c) = b {
                        *c
                    } else {
                        unreachable!()
                    }
                })
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
            let start_ida: usize = if vec_b[0] == F::one() { 1 } else { 0 };
            if start_ida == 1 && k == 1 {
                // this is just a0 * 1 = a0; you're doing nothing, why are you calling this function?
                let assignment = self.assign_region(ctx, vec![vec_a[0].clone()], vec![], None)?;
                return Ok((Some(assignment.clone()), None, assignment[0].clone()));
            }
            let k_chunks = (k - start_ida + gate_segment - 1) / gate_segment;
            let mut cells = Vec::with_capacity(1 + (gate_segment + 1) * k_chunks);
            let mut gate_offsets = Vec::with_capacity(k_chunks);
            let mut running_sum = if start_ida == 1 {
                vec_a[0].clone()
            } else {
                Constant(F::zero())
            };
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
                cells.extend((window.len()..gate_segment).map(|_| Constant(F::from(0))));
                running_sum = Witness(
                    window
                        .into_iter()
                        .fold(running_sum.value().copied(), |sum, j| {
                            sum + Value::known(vec_b[j]) * vec_a[j].value()
                        }),
                );
                cells.push(running_sum.clone());
            }

            let assignments = self.assign_region(ctx, cells, gate_offsets, None)?;
            let mut a_assigned = Vec::with_capacity(k);
            if start_ida == 1 {
                a_assigned.push(assignments[0].clone());
            }
            for i in start_ida..k {
                let chunk = (i - start_ida) / gate_segment;
                a_assigned.push(
                    assignments[1 + chunk * (gate_segment + 1) + ((i - start_ida) % gate_segment)]
                        .clone(),
                );
            }
            return Ok((Some(a_assigned), None, assignments.last().unwrap().clone()));
        }

        if self.strategy == GateStrategy::PlonkPlus
            && vec_a.iter().all(|a| {
                if matches!(a, Constant(_)) {
                    true
                } else {
                    false
                }
            })
        {
            let (b, a, out) = self.inner_product(ctx, vec_b, vec_a)?;
            return Ok((a, b, out));
        }

        let mut cells: Vec<QuantumCell<F>> = Vec::with_capacity(3 * vec_a.len() + 1);
        let mut start_id = 0;
        let mut sum = Value::known(F::zero());
        cells.push(Constant(F::from(0)));
        if matches!(vec_b[0], Constant(c) if c == F::one()) {
            cells[0] = vec_a[0].clone();
            sum = vec_a[0].value().copied();
            start_id = 1;
        }

        for (a, b) in vec_a[start_id..].iter().zip(vec_b[start_id..].iter()) {
            sum = sum
                .zip(a.value())
                .zip(b.value())
                .map(|((sum, &a), &b)| sum + a * b);

            cells.push(a.clone());
            cells.push(b.clone());
            cells.push(Witness(sum));
        }
        let mut gate_offsets = Vec::with_capacity(vec_a.len());
        for i in 0..(vec_a.len() - start_id) {
            gate_offsets.push(3 * i);
        }
        let assignments = self.assign_region(
            ctx,
            cells,
            gate_offsets.iter().map(|i| (*i as isize, None)).collect(),
            None,
        )?;
        let mut a_assigned = Vec::with_capacity(vec_a.len());
        let mut b_assigned = Vec::with_capacity(vec_a.len());
        if start_id == 1 {
            a_assigned.push(assignments[0].clone());
        }
        for i in 0..(vec_a.len() - start_id) {
            a_assigned.push(assignments[3 * i + 1].clone());
            b_assigned.push(assignments[3 * i + 2].clone());
        }
        let b_assigned = if start_id == 1 {
            None
        } else {
            Some(b_assigned)
        };

        Ok((
            Some(a_assigned),
            b_assigned,
            assignments.last().unwrap().clone(),
        ))
    }

    fn accumulated_product(
        &self,
        ctx: &mut Context<'_, F>,
        vec_a: &Vec<QuantumCell<F>>,
        vec_b: &Vec<QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert!(vec_a.len() + 1 == vec_b.len() || (vec_a.len() == 0 && vec_b.len() == 0));
        let k = vec_b.len();
        match self.strategy {
            GateStrategy::PlonkPlus => {
                todo!();
            }
            GateStrategy::Vertical => {
                let mut ret = Vec::new();
                for idx in 0..k {
                    if idx == 0 {
                        let assigned = self.assign_region_smart(
                            ctx,
                            vec![vec_b[0].clone()],
                            vec![],
                            vec![],
                            vec![],
                        )?;
                        ret.push(assigned[0].clone());
                    } else {
                        let assigned = self.assign_region_smart(
                            ctx,
                            vec![
                                vec_b[idx].clone(),
                                Existing(&ret[ret.len() - 1]),
                                vec_a[idx - 1].clone(),
                                Witness(
                                    ret[ret.len() - 1].value().copied()
                                        * vec_a[idx - 1].value().copied()
                                        + vec_b[idx].value(),
                                ),
                            ],
                            vec![0],
                            vec![],
                            vec![],
                        )?;
                        ret.push(assigned[3].clone());
                    }
                }
                Ok(ret)
            }
        }
    }

    fn sum_products_with_coeff_and_var<'a>(
        &self,
        ctx: &mut Context<'_, F>,
        values: &[(F, QuantumCell<F>, QuantumCell<F>)],
        var: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let k = values.len();
        match self.strategy {
            GateStrategy::PlonkPlus => {
                let mut cells = Vec::with_capacity(1 + 3 * k);
                let mut gate_offsets = Vec::with_capacity(k);
                let mut acc = var.value().copied();
                cells.push(var.clone());
                for (i, (c, a, b)) in values.iter().enumerate() {
                    acc = acc + Value::known(*c) * a.value() * b.value();
                    cells.append(&mut vec![a.clone(), b.clone(), Witness(acc)]);
                    gate_offsets.push((3 * i as isize, Some([*c, F::zero(), F::zero()])));
                }
                let assignments = self.assign_region(ctx, cells, gate_offsets, None)?;

                Ok(assignments.last().unwrap().clone())
            }
            GateStrategy::Vertical => {
                let mut a = Vec::with_capacity(k + 1);
                let mut b = Vec::with_capacity(k + 1);
                let mut prod_pair = Vec::with_capacity(k);
                a.push(var.clone());
                b.push(Constant(F::one()));
                for (c, va, vb) in values.iter() {
                    if *c == F::one() {
                        a.push(va.clone());
                        b.push(vb.clone());
                    } else if *c != F::zero() {
                        let prod = self.mul(ctx, va, vb)?;
                        prod_pair.push((c, prod));
                    }
                }
                for (&c, prod) in prod_pair.iter() {
                    a.push(Existing(&prod));
                    b.push(Constant(c));
                }
                let (_, _, out) = self.inner_product(ctx, &a, &b)?;
                Ok(out)
            }
        }
    }

    // | 1 - b | 1 | b | 1 | b | a | 1 - b | out |
    fn or(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            QuantumCell::Witness(b.value().map(|x| F::from(1) - *x)),
            QuantumCell::Constant(F::from(1)),
            b.clone(),
            QuantumCell::Constant(F::from(1)),
            b.clone(),
            a.clone(),
            QuantumCell::Witness(b.value().map(|x| F::from(1) - *x)),
            QuantumCell::Witness(
                a.value()
                    .zip(b.value())
                    .map(|(av, bv)| *av + *bv - (*av) * (*bv)),
            ),
        ];
        let assigned_cells =
            self.assign_region_smart(ctx, cells, vec![0, 4], vec![(0, 6)], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
    }

    // | 0 | a | b | out |
    fn and(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            QuantumCell::Constant(F::from(0)),
            a.clone(),
            b.clone(),
            QuantumCell::Witness(a.value().zip(b.value()).map(|(av, bv)| (*av) * (*bv))),
        ];
        let assigned_cells = self.assign_region_smart(ctx, cells, vec![0], vec![], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
    }

    /// assumes sel is boolean
    /// returns
    ///   a * sel + b * (1 - sel)
    fn select(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        sel: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let diff_val = a.value().zip(b.value()).map(|(av, bv)| (*av) - (*bv));
        let out_val = a
            .value()
            .zip(b.value())
            .zip(sel.value())
            .map(|((av, bv), sv)| (*av) * (*sv) + (*bv) * (F::from(1) - *sv));
        match self.strategy {
            // | a - b | 1 | b | a |
            // | b | sel | a - b | out |
            GateStrategy::Vertical => {
                let cells = vec![
                    QuantumCell::Witness(diff_val),
                    QuantumCell::Constant(F::from(1)),
                    b.clone(),
                    a.clone(),
                    b.clone(),
                    sel.clone(),
                    QuantumCell::Witness(diff_val),
                    QuantumCell::Witness(out_val),
                ];
                let assigned_cells =
                    self.assign_region_smart(ctx, cells, vec![0, 4], vec![(0, 6)], vec![])?;
                Ok(assigned_cells.last().unwrap().clone())
            }
            // | 0 | a | a - b | b | sel | a - b | out |
            // selectors
            // | 1 | 0 | 0     | 1 | 0   | 0
            // | 0 | 1 | -1    | 1 | 0   | 0
            GateStrategy::PlonkPlus => {
                let assignments = self.assign_region(
                    ctx,
                    vec![
                        Constant(F::from(0)),
                        a.clone(),
                        Witness(diff_val),
                        b.clone(),
                        sel.clone(),
                        Witness(diff_val),
                        Witness(out_val),
                    ],
                    vec![(0, Some([F::zero(), F::one(), -F::one()])), (3, None)],
                    None,
                )?;
                ctx.region
                    .constrain_equal(assignments[2].cell(), assignments[5].cell())?;
                Ok(assignments.last().unwrap().clone())
            }
        }
    }

    /// returns: a || (b && c)
    // | 1 - b c | b | c | 1 | a - 1 | 1 - b c | out | a - 1 | 1 | 1 | a |
    fn or_and(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        c: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells: Vec<QuantumCell<F>> = vec![
            QuantumCell::Witness(
                b.value()
                    .zip(c.value())
                    .map(|(bv, cv)| F::from(1) - (*bv) * (*cv)),
            ),
            b.clone(),
            c.clone(),
            QuantumCell::Constant(F::from(1)),
            QuantumCell::Witness(a.value().map(|x| *x - F::from(1))),
            QuantumCell::Witness(
                b.value()
                    .zip(c.value())
                    .map(|(bv, cv)| F::from(1) - (*bv) * (*cv)),
            ),
            QuantumCell::Witness(
                a.value()
                    .zip(b.value())
                    .zip(c.value())
                    .map(|((av, bv), cv)| *av + (*bv) * (*cv) - (*av) * (*bv) * (*cv)),
            ),
            QuantumCell::Witness(a.value().map(|x| *x - F::from(1))),
            QuantumCell::Constant(F::from(1)),
            QuantumCell::Constant(F::from(1)),
            a.clone(),
        ];
        let assigned_cells =
            self.assign_region_smart(ctx, cells, vec![0, 3, 7], vec![(4, 7), (0, 5)], vec![])?;
        Ok(assigned_cells[6].clone())
    }

    /// assume bits has boolean values
    /// returns vec[idx] with vec[idx] = 1 if and only if bits == idx as a binary number
    fn bits_to_indicator(
        &self,
        ctx: &mut Context<'_, F>,
        bits: &Vec<QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let k = bits.len();

        let (inv_last_bit, last_bit) = {
            let assignments = self.assign_region_smart(
                ctx,
                vec![
                    Witness(bits[k - 1].value().map(|x| F::from(1) - x)),
                    bits[k - 1].clone(),
                    Constant(F::from(1)),
                    Constant(F::from(1)),
                ],
                vec![0],
                vec![],
                vec![],
            )?;
            (assignments[0].clone(), assignments[1].clone())
        };
        let mut indicator: Vec<AssignedValue<F>> = Vec::with_capacity(2 * (1 << k) - 2);
        let mut offset = 0;
        indicator.push(inv_last_bit);
        indicator.push(last_bit);
        for idx in 1..k {
            for old_idx in 0..(1 << idx) {
                let inv_prod_val = indicator[offset + old_idx]
                    .value()
                    .zip(bits[k - 1 - idx].value())
                    .map(|(&a, &x)| a - a * x);
                let assignments = self.assign_region_smart(
                    ctx,
                    vec![
                        Witness(inv_prod_val),
                        Existing(&indicator[offset + old_idx]),
                        bits[k - 1 - idx].clone(),
                        Existing(&indicator[offset + old_idx]),
                    ],
                    vec![0],
                    vec![],
                    vec![],
                )?;
                let inv_prod = assignments[0].clone();
                indicator.push(inv_prod);

                let prod = self.mul(
                    ctx,
                    &Existing(&indicator[offset + old_idx]),
                    &Existing(&assignments[2]),
                )?;
                indicator.push(prod);
            }
            offset = offset + (1 << idx);
        }
        Ok(indicator[(1 << k) - 2..].to_vec())
    }

    // returns vec with vec.len() == len such that:
    //     vec[i] == 1{i == idx}
    fn idx_to_indicator(
        &self,
        ctx: &mut Context<'_, F>,
        idx: &QuantumCell<F>,
        len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let ind = self.assign_region_smart(
            ctx,
            (0..len)
                .map(|i| {
                    Witness(idx.value().map(|x| {
                        if F::from(i as u64) == *x {
                            F::from(1)
                        } else {
                            F::from(0)
                        }
                    }))
                })
                .collect(),
            vec![],
            vec![],
            vec![],
        )?;

        // check ind[i] * (i - idx) == 0
        for i in 0..len {
            self.assign_region_smart(
                ctx,
                vec![
                    Constant(F::from(0)),
                    Existing(&ind[i]),
                    idx.clone(),
                    Witness(ind[i].value().zip(idx.value()).map(|(a, b)| (*a) * (*b))),
                    Constant(-F::from(i as u64)),
                    Existing(&ind[i]),
                    Constant(F::from(0)),
                ],
                vec![0, 3],
                vec![],
                vec![],
            )?;
        }
        Ok(ind)
    }
}
