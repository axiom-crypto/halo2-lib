use self::flex_gate::{FlexGateConfig, GateStrategy, MAX_PHASE};
use super::{
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness, WitnessFraction},
};
use crate::{
    halo2_proofs::{
        circuit::{Layouter, Region, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    },
    utils::{biguint_to_fe, bit_length, fe_to_biguint, PrimeField},
    ContextCell,
};
use core::iter;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Shl, rc::Rc};

pub mod flex_gate;
// pub mod range;

type ThreadBreakPoints = Vec<usize>;
type MultiPhaseThreadBreakPoints = Vec<ThreadBreakPoints>;

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

    pub fn unknown(self, use_unknown: bool) -> Self {
        Self { use_unknown, ..self }
    }

    pub fn main(&mut self, phase: usize) -> &mut Context<F> {
        self.threads[phase].first_mut().unwrap()
    }

    pub fn new_thread(&mut self, phase: usize) -> &mut Context<F> {
        let thread_id = self.thread_count;
        self.thread_count += 1;
        self.threads[phase].push(Context::new(self.witness_gen_only, thread_id));
        self.threads[phase].last_mut().unwrap()
    }

    /// Auto-calculate configuration parameters for the circuit
    pub fn config(&self, k: usize) -> FlexGateConfigParams {
        let max_rows = 1 << k;
        let total_advice_per_phase = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.advice.len()).sum::<usize>())
            .collect::<Vec<_>>();
        // we do a rough estimate by taking ceil(advice_cells_per_phase / 2^k )
        // if this is too small, manual configuration will be needed
        let num_advice_per_phase = total_advice_per_phase
            .iter()
            .map(|count| (count + max_rows - 1) >> k)
            .collect::<Vec<_>>();

        let total_lookup_advice_per_phase = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.cells_to_lookup.len()).sum::<usize>())
            .collect::<Vec<_>>();
        let num_lookup_advice_per_phase = total_lookup_advice_per_phase
            .iter()
            .map(|count| (count + max_rows - 1) >> k)
            .collect::<Vec<_>>();

        let total_fixed: usize = self
            .threads
            .iter()
            .map(|threads| threads.iter().map(|ctx| ctx.constants.len()).sum::<usize>())
            .sum();
        let num_fixed = (total_fixed + max_rows - 1) >> k;

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
            for ctx in threads {
                for (i, (advice, q)) in ctx.advice.iter().zip(ctx.selector.into_iter()).enumerate()
                {
                    if (q && row_offset + 4 > max_rows) || row_offset >= max_rows {
                        break_point.push(row_offset);
                        row_offset = 0;
                        gate_index += 1;
                    }
                    let basic_gate = config.basic_gates[phase]
                        .get(gate_index)
                        .unwrap_or_else(|| panic!("NOT ENOUGH ADVICE COLUMNS IN PHASE {phase}"));
                    let column = basic_gate.value;
                    let value = if use_unknown { Value::unknown() } else { Value::known(advice) };
                    #[cfg(feature = "halo2-axiom")]
                    let cell = *region
                        .assign_advice(column, row_offset, value)
                        .expect("assign_advice should not fail")
                        .cell();
                    #[cfg(not(feature = "halo2-axiom"))]
                    let cell = region
                        .assign_advice(|| "", column, row_offset, || value)
                        .expect("assign_advice should not fail")
                        .cell();
                    assigned_advices.insert((ctx.context_id, i), cell);

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

                for (left, right) in ctx.advice_equality_constraints {
                    let left = assigned_advices[&(left.context_id, left.offset)];
                    let right = assigned_advices[&(right.context_id, right.offset)];
                    #[cfg(feature = "halo2-axiom")]
                    region.constrain_equal(&left, &right);
                    #[cfg(not(feature = "halo2-axiom"))]
                    region.constrain_equal(left, right).unwrap();
                }
                for (left, right) in ctx.constant_equality_constraints {
                    let left = assigned_constants[&(left.context_id, left.offset)];
                    let right = assigned_advices[&(right.context_id, right.offset)];
                    #[cfg(feature = "halo2-axiom")]
                    region.constrain_equal(&left, &right);
                    #[cfg(not(feature = "halo2-axiom"))]
                    region.constrain_equal(left, right).unwrap();
                }

                for index in ctx.cells_to_lookup {
                    if lookup_offset >= max_rows {
                        lookup_offset = 0;
                        lookup_col += 1;
                    }
                    let value = ctx.advice[index];
                    let acell = assigned_advices[&(ctx.context_id, index)];
                    let value = if use_unknown { Value::unknown() } else { Value::known(value) };
                    let column = lookup_advice[phase][lookup_col];

                    #[cfg(feature = "halo2-axiom")]
                    {
                        let bcell = *region
                            .assign_advice(column, lookup_offset, value)
                            .expect("assign_advice should not fail")
                            .cell();
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
    assert_eq!(break_points.len(), threads.len());

    let mut break_points = break_points.into_iter();
    let mut break_point = break_points.next();
    let mut gate_index = 0;
    let mut column = config.basic_gates[phase][gate_index].value;
    let mut row_offset = 0;
    let mut lookup_offset = 0;
    let mut lookup_advice = lookup_advice.iter();
    let mut lookup_column = lookup_advice.next();
    for ctx in threads {
        for index in ctx.cells_to_lookup {
            if lookup_offset >= config.max_rows {
                lookup_offset = 0;
                lookup_column = lookup_advice.next();
            }
            let value = ctx.advice[index];
            let column = *lookup_column.unwrap();
            #[cfg(feature = "halo2-axiom")]
            region.assign_advice(column, lookup_offset, Value::known(value)).unwrap();
            #[cfg(not(feature = "halo2-axiom"))]
            region.assign_advice(|| "", column, lookup_offset, || Value::known(value)).unwrap();

            lookup_offset += 1;
        }
        for advice in ctx.advice {
            if break_point == Some(row_offset) {
                break_point = break_points.next();
                row_offset = 0;
                gate_index += 1;
                column = config.basic_gates[phase][gate_index].value;
            }
            #[cfg(feature = "halo2-axiom")]
            region.assign_advice(column, row_offset, Value::known(advice)).unwrap();
            #[cfg(not(feature = "halo2-axiom"))]
            region.assign_advice(|| "", column, row_offset, || Value::known(advice)).unwrap();

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

/*
pub trait RangeInstructions<F: ScalarField> {
    type Gate: GateInstructions<F>;

    fn gate(&self) -> &Self::Gate;
    fn strategy(&self) -> RangeStrategy;

    fn lookup_bits(&self) -> usize;

    fn range_check<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: &AssignedValue<'a, F>,
        range_bits: usize,
    );

    fn check_less_than<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: QuantumCell<'_, 'a, F>,
        b: QuantumCell<'_, 'a, F>,
        num_bits: usize,
    );

    /// Checks that `a` is in `[0, b)`.
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `bit_length(b)` bits.
    fn check_less_than_safe<'a>(&self, ctx: &mut Context<'a, F>, a: &AssignedValue<'a, F>, b: u64) {
        let range_bits =
            (bit_length(b) + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.check_less_than(
            ctx,
            Existing(a),
            Constant(self.gate().get_field_element(b)),
            range_bits,
        )
    }

    /// Checks that `a` is in `[0, b)`.
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `bit_length(b)` bits.
    fn check_big_less_than_safe<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: &AssignedValue<'a, F>,
        b: BigUint,
    ) where
        F: PrimeField,
    {
        let range_bits =
            (b.bits() as usize + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.check_less_than(ctx, Existing(a), Constant(biguint_to_fe(&b)), range_bits)
    }

    /// Returns whether `a` is in `[0, b)`.
    ///
    /// Warning: This may fail silently if `a` or `b` have more than `num_bits` bits
    fn is_less_than<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: QuantumCell<'_, 'a, F>,
        b: QuantumCell<'_, 'a, F>,
        num_bits: usize,
    ) -> AssignedValue<'a, F>;

    /// Returns whether `a` is in `[0, b)`.
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `range_bits` bits.
    fn is_less_than_safe<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: &AssignedValue<'a, F>,
        b: u64,
    ) -> AssignedValue<'a, F> {
        let range_bits =
            (bit_length(b) + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.is_less_than(ctx, Existing(a), Constant(F::from(b)), range_bits)
    }

    /// Returns whether `a` is in `[0, b)`.
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `range_bits` bits.
    fn is_big_less_than_safe<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: &AssignedValue<'a, F>,
        b: BigUint,
    ) -> AssignedValue<'a, F>
    where
        F: PrimeField,
    {
        let range_bits =
            (b.bits() as usize + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.is_less_than(ctx, Existing(a), Constant(biguint_to_fe(&b)), range_bits)
    }

    /// Returns `(c, r)` such that `a = b * c + r`.
    ///
    /// Assumes that `b != 0`.
    fn div_mod<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: QuantumCell<'_, 'a, F>,
        b: impl Into<BigUint>,
        a_num_bits: usize,
    ) -> (AssignedValue<'a, F>, AssignedValue<'a, F>)
    where
        F: PrimeField,
    {
        let b = b.into();
        let mut a_val = BigUint::zero();
        a.value().map(|v| a_val = fe_to_biguint(v));
        let (div, rem) = a_val.div_mod_floor(&b);
        let [div, rem] = [div, rem].map(|v| biguint_to_fe(&v));
        let assigned = self.gate().assign_region(
            ctx,
            vec![
                Witness(Value::known(rem)),
                Constant(biguint_to_fe(&b)),
                Witness(Value::known(div)),
                a,
            ],
            vec![(0, None)],
        );
        self.check_big_less_than_safe(
            ctx,
            &assigned[2],
            BigUint::one().shl(a_num_bits as u32) / &b + BigUint::one(),
        );
        self.check_big_less_than_safe(ctx, &assigned[0], b);
        (assigned[2].clone(), assigned[0].clone())
    }

    /// Returns `(c, r)` such that `a = b * c + r`.
    ///
    /// Assumes that `b != 0`.
    ///
    /// Let `X = 2 ** b_num_bits`.
    /// Write `a = a1 * X + a0` and `c = c1 * X + c0`.
    /// If we write `b * c0 + r = d1 * X + d0` then
    ///     `b * c + r = (b * c1 + d1) * X + d0`
    fn div_mod_var<'a>(
        &self,
        ctx: &mut Context<'a, F>,
        a: QuantumCell<'_, 'a, F>,
        b: QuantumCell<'_, 'a, F>,
        a_num_bits: usize,
        b_num_bits: usize,
    ) -> (AssignedValue<'a, F>, AssignedValue<'a, F>)
    where
        F: PrimeField,
    {
        let mut a_val = BigUint::zero();
        a.value().map(|v| a_val = fe_to_biguint(v));
        let mut b_val = BigUint::one();
        b.value().map(|v| b_val = fe_to_biguint(v));
        let (div, rem) = a_val.div_mod_floor(&b_val);
        let x = BigUint::one().shl(b_num_bits as u32);
        let (div_hi, div_lo) = div.div_mod_floor(&x);

        let x_fe = self.gate().pow_of_two()[b_num_bits];
        let [div, div_hi, div_lo, rem] = [div, div_hi, div_lo, rem].map(|v| biguint_to_fe(&v));
        let assigned = self.gate().assign_region(
            ctx,
            vec![
                Witness(Value::known(div_lo)),
                Witness(Value::known(div_hi)),
                Constant(x_fe),
                Witness(Value::known(div)),
                Witness(Value::known(rem)),
            ],
            vec![(0, None)],
        );
        self.range_check(ctx, &assigned[0], b_num_bits);
        self.range_check(ctx, &assigned[1], a_num_bits.saturating_sub(b_num_bits));

        let (bcr0_hi, bcr0_lo) = {
            let bcr0 =
                self.gate().mul_add(ctx, b.clone(), Existing(&assigned[0]), Existing(&assigned[4]));
            self.div_mod(ctx, Existing(&bcr0), x.clone(), a_num_bits)
        };
        let bcr_hi =
            self.gate().mul_add(ctx, b.clone(), Existing(&assigned[1]), Existing(&bcr0_hi));

        let (a_hi, a_lo) = self.div_mod(ctx, a, x, a_num_bits);
        ctx.constrain_equal(&bcr_hi, &a_hi);
        ctx.constrain_equal(&bcr0_lo, &a_lo);

        self.range_check(ctx, &assigned[4], b_num_bits);
        self.check_less_than(ctx, Existing(&assigned[4]), b, b_num_bits);
        (assigned[3].clone(), assigned[4].clone())
    }
}
*/

#[cfg(test)]
pub mod tests;
