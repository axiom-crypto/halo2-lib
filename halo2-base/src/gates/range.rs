use crate::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    utils::{biguint_to_fe, decompose_option, fe_to_biguint},
    AssignedValue,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, SecondPhase, Selector, TableColumn, ThirdPhase,
    },
    poly::Rotation,
};
use num_bigint::BigUint;

use super::{Context, RangeInstructions};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RangeStrategy {
    Vertical, // vanilla implementation with vertical basic gate(s)
    PlonkPlus,
}

#[derive(Clone, Debug)]
pub struct RangeConfig<F: FieldExt> {
    // `lookup_advice` are special advice columns only used for lookups
    //
    // If `strategy` is `Vertical`:
    // * If `gate` has only 1 advice column, enable lookups for that column, in which case `lookup_advice` is empty
    // * Otherwise, add some user-specified number of `lookup_advice` columns
    //   * In this case, we don't even need a selector so `q_lookup` is empty
    pub lookup_advice: Vec<Column<Advice>>,
    pub q_lookup: Vec<Option<Selector>>,
    pub lookup: TableColumn,
    pub lookup_bits: usize,

    pub gate: FlexGateConfig<F>,
    strategy: RangeStrategy,
    pub context_id: String,
}

impl<F: FieldExt> RangeConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        range_strategy: RangeStrategy,
        num_advice: &[usize],
        num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
        context_id: String,
    ) -> Self {
        assert!(lookup_bits <= 28);
        let lookup = meta.lookup_table_column();

        let gate = FlexGateConfig::configure(
            meta,
            match range_strategy {
                RangeStrategy::Vertical => GateStrategy::Vertical,
                RangeStrategy::PlonkPlus => GateStrategy::PlonkPlus,
            },
            num_advice,
            num_fixed,
            context_id.clone(),
        );

        let mut q_lookup = Vec::new();
        let mut lookup_advice = Vec::new();
        for (phase, &num_columns) in num_lookup_advice.iter().enumerate() {
            if num_advice[phase] == 1 {
                q_lookup.push(Some(meta.complex_selector()));
            } else {
                q_lookup.push(None);
                for _ in 0..num_columns {
                    let a = match phase {
                        0 => meta.advice_column(),
                        1 => meta.advice_column_in(SecondPhase),
                        2 => meta.advice_column_in(ThirdPhase),
                        _ => panic!(),
                    };
                    meta.enable_equality(a);
                    lookup_advice.push(a);
                }
            }
        }
        let config = Self {
            lookup_advice,
            q_lookup,
            lookup,
            lookup_bits,
            gate,
            strategy: range_strategy,
            context_id,
        };
        config.create_lookup(meta);

        config
    }

    fn create_lookup(&self, meta: &mut ConstraintSystem<F>) -> () {
        for (i, q_l) in self.q_lookup.iter().enumerate() {
            if let Some(q) = q_l {
                meta.lookup("lookup", |meta| {
                    let q = meta.query_selector(q.clone());
                    // find an advice column of phase i
                    let a = meta.query_advice(
                        self.gate
                            .basic_gates
                            .iter()
                            .find(|bg| bg.value.column_type().phase() == i as u8)
                            .unwrap()
                            .value,
                        Rotation::cur(),
                    );
                    vec![(q * a, self.lookup)]
                });
            }
        }
        for la in self.lookup_advice.iter() {
            meta.lookup("lookup wo selector", |meta| {
                let a = meta.query_advice(la.clone(), Rotation::cur());
                vec![(a, self.lookup)]
            });
        }
    }

    pub fn load_lookup_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || format!("{} bit lookup", self.lookup_bits),
            |mut table| {
                for idx in 0..(1u32 << self.lookup_bits) {
                    table.assign_cell(
                        || "lookup table",
                        self.lookup,
                        idx as usize,
                        || Value::known(F::from(idx as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    /// call this at the very end of synthesize!
    /// returns (total number of constants assigned, total number of lookup cells assigned)
    pub fn finalize(&self, ctx: &mut Context<'_, F>) -> Result<(usize, usize, Vec<usize>), Error> {
        let (c_rows, c_count) = self.gate.finalize(ctx)?;
        let lookup_rows = ctx.copy_and_lookup_cells(&[self.lookup_advice.clone()])?;
        Ok((c_rows, c_count, lookup_rows))
    }

    /// assuming this is called when ctx.region is not in shape mode
    /// `offset` is the offset of the cell in `ctx.region`
    /// `offset` is only used if there is a single advice column
    fn enable_lookup(
        &self,
        ctx: &mut Context<'_, F>,
        acell: AssignedValue<F>,
    ) -> Result<(), Error> {
        let phase = acell.phase() as usize;
        if let Some(q) = &self.q_lookup[phase] {
            q.enable(&mut ctx.region, acell.row())?;
        } else {
            ctx.cells_to_lookup.push(acell);
        }
        Ok(())
    }

    // returns the limbs
    fn range_check_simple(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        range_bits: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let k = (range_bits + self.lookup_bits - 1) / self.lookup_bits;
        let rem_bits = range_bits % self.lookup_bits;

        let limbs = decompose_option(&a.value().map(|x| *x), k, self.lookup_bits);
        let (limbs_assigned, _, acc) = self.gate.inner_product(
            ctx,
            &limbs.into_iter().map(|limb| Witness(limb)).collect(),
            &(0..k)
                .map(|i| {
                    Constant(biguint_to_fe(
                        &(BigUint::from(1u64) << (i * self.lookup_bits)),
                    ))
                })
                .collect(),
        )?;
        let limbs_assigned = limbs_assigned.unwrap();

        // the inner product above must equal `a`
        ctx.region.constrain_equal(a.cell(), acc.cell())?;

        // range check all the limbs
        for i in 0..k {
            self.enable_lookup(ctx, limbs_assigned[i].clone())?;
        }

        // additional constraints for the last limb if rem_bits != 0
        if rem_bits == 1 {
            // we want to check x := limbs[k-1] is boolean
            // we constrain x*(x-1) = 0 + x * x - x == 0
            // | 0 | x | x | x |
            self.gate.assign_region_smart(
                ctx,
                vec![
                    Constant(F::zero()),
                    Existing(&limbs_assigned[k - 1]),
                    Existing(&limbs_assigned[k - 1]),
                    Existing(&limbs_assigned[k - 1]),
                ],
                vec![0],
                vec![],
                vec![],
            )?;
        } else if rem_bits > 1 {
            let mult_val = biguint_to_fe(&(BigUint::from(1u64) << (self.lookup_bits - rem_bits)));
            let assignments = self.gate.assign_region(
                ctx,
                vec![
                    Constant(F::zero()),
                    Existing(&limbs_assigned[k - 1]),
                    Constant(mult_val),
                    Witness(limbs_assigned[k - 1].value().map(|limb| mult_val * limb)),
                ],
                vec![(0, None)],
                None,
            )?;
            self.enable_lookup(ctx, assignments.last().unwrap().clone())?;
        }

        Ok(limbs_assigned)
    }

    /// assume `a` has been range checked already to `limb_bits` bits
    pub fn get_last_bit(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        limb_bits: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let a_v = a.value();
        let bit_v = a_v.map(|a| {
            let a_big = fe_to_biguint(a);
            if a_big % 2u64 == BigUint::from(0u64) {
                F::zero()
            } else {
                F::one()
            }
        });
        let h_v = a
            .value()
            .zip(bit_v)
            .map(|(&a, b)| (a - b) * F::from(2).invert().unwrap());
        let assignments = self.gate.assign_region_smart(
            ctx,
            vec![
                Witness(bit_v),
                Witness(h_v),
                Constant(F::from(2)),
                Existing(a),
            ],
            vec![0],
            vec![],
            vec![],
        )?;

        self.range_check(ctx, &assignments[1], limb_bits - 1)?;
        Ok(assignments[0].clone())
    }
}

impl<F: FieldExt> RangeInstructions<F> for RangeConfig<F> {
    type Gate = FlexGateConfig<F>;

    fn gate(&self) -> &Self::Gate {
        &self.gate
    }
    fn strategy(&self) -> RangeStrategy {
        self.strategy
    }

    fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    // returns the limbs
    fn range_check(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        range_bits: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        assert_ne!(range_bits, 0);
        #[cfg(feature = "display")]
        {
            let key = format!(
                "range check length {}",
                (range_bits + self.lookup_bits - 1) / self.lookup_bits
            );
            let count = ctx.op_count.entry(key).or_insert(0);
            *count += 1;
        }
        match self.strategy {
            RangeStrategy::Vertical | RangeStrategy::PlonkPlus => {
                self.range_check_simple(ctx, a, range_bits)
            }
        }
    }

    /// Warning: This may fail silently if a or b have more than num_bits
    fn check_less_than(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        num_bits: usize,
    ) -> Result<(), Error> {
        let pow_of_two = biguint_to_fe::<F>(&(BigUint::from(1u64) << num_bits));
        let check_cell = match self.strategy {
            RangeStrategy::Vertical => {
                // | a + 2^(num_bits) - b | b | 1 | a + 2^(num_bits) | - 2^(num_bits) | 1 | a |
                let cells = vec![
                    Witness(Value::known(pow_of_two) + a.value() - b.value()),
                    b.clone(),
                    Constant(F::from(1)),
                    Witness(Value::known(pow_of_two) + a.value()),
                    Constant(-pow_of_two),
                    Constant(F::from(1)),
                    a.clone(),
                ];
                let assigned_cells =
                    self.gate
                        .assign_region_smart(ctx, cells, vec![0, 3], vec![], vec![])?;
                assigned_cells[0].clone()
            }
            RangeStrategy::PlonkPlus => {
                // | a | 1 | b | a + 2^{num_bits} - b |
                // selectors:
                // | 1 | 0 | 0 |
                // | 0 | 2^{num_bits} | -1 |
                let assigned_cells = self.gate.assign_region(
                    ctx,
                    vec![
                        a.clone(),
                        Constant(F::from(1)),
                        b.clone(),
                        Witness(Value::known(pow_of_two) + a.value() - b.value()),
                    ],
                    vec![(0, Some([F::zero(), pow_of_two, -F::one()]))],
                    None,
                )?;
                assigned_cells[3].clone()
            }
        };

        self.range_check(ctx, &check_cell, num_bits)?;
        Ok(())
    }

    fn is_less_than(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        num_bits: usize,
    ) -> Result<AssignedValue<F>, Error> {
        let k = (num_bits + self.lookup_bits - 1) / self.lookup_bits;
        let padded_bits = k * self.lookup_bits;
        let pow_padded = biguint_to_fe::<F>(&(BigUint::from(1u64) << padded_bits));

        let shifted_val = a
            .value()
            .zip(b.value())
            .map(|(&av, &bv)| av + pow_padded - bv);
        let shifted_cell = match self.strategy {
            RangeStrategy::Vertical => {
                let assignments = self.gate.assign_region_smart(
                    ctx,
                    vec![
                        Witness(shifted_val),
                        b.clone(),
                        Constant(F::one()),
                        Witness(a.value().map(|&av| av + pow_padded)),
                        Constant(-pow_padded),
                        Constant(F::one()),
                        a.clone(),
                    ],
                    vec![0, 3],
                    vec![],
                    vec![],
                )?;
                assignments[0].clone()
            }
            RangeStrategy::PlonkPlus => {
                let assignments = self.gate.assign_region(
                    ctx,
                    vec![
                        a.clone(),
                        Constant(pow_padded),
                        b.clone(),
                        Witness(shifted_val),
                    ],
                    vec![(0, Some([F::zero(), F::one(), -F::one()]))],
                    None,
                )?;
                assignments.last().unwrap().clone()
            }
        };

        // check whether a - b + 2^padded_bits < 2^padded_bits ?
        // since assuming a, b < 2^padded_bits we are guaranteed a - b + 2^padded_bits < 2^{padded_bits + 1}
        let limbs = self.range_check(ctx, &shifted_cell, padded_bits + self.lookup_bits)?;
        self.is_zero(ctx, &limbs[k])
    }

    // | out | a | inv | 1 | 0 | a | out | 0
    fn is_zero(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let is_zero = a.value().map(|x| {
            if (*x).is_zero_vartime() {
                F::from(1)
            } else {
                F::from(0)
            }
        });
        let inv = a.value().map(|x| {
            if *x == F::from(0) {
                F::from(1)
            } else {
                (*x).invert().unwrap()
            }
        });

        let cells = vec![
            Witness(is_zero),
            Existing(&a),
            Witness(inv),
            Constant(F::from(1)),
            Constant(F::from(0)),
            Existing(&a),
            Witness(is_zero),
            Constant(F::from(0)),
        ];
        let assigned_cells =
            self.gate
                .assign_region_smart(ctx, cells, vec![0, 4], vec![(0, 6)], vec![])?;
        Ok(assigned_cells[0].clone())
    }

    fn is_equal(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let cells = vec![
            Witness(a.value().zip(b.value()).map(|(av, bv)| *av - *bv)),
            Constant(F::from(1)),
            b.clone(),
            a.clone(),
        ];
        let assigned_cells = self
            .gate
            .assign_region_smart(ctx, cells, vec![0], vec![], vec![])?;

        self.is_zero(ctx, &assigned_cells[0])
    }

    // returns little-endian bit vectors
    fn num_to_bits(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        range_bits: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let bits = decompose_option(&a.value().copied(), range_bits, 1usize);
        let bit_cells = match self.strategy {
            RangeStrategy::Vertical => {
                let mut enable_gates = Vec::new();
                let mut cells = Vec::with_capacity(3 * range_bits - 2);
                let mut running_sum = bits[0];
                let mut running_pow = F::from(1u64);
                cells.push(Witness(bits[0]));
                let mut offset = 1;
                for idx in 1..range_bits {
                    running_pow = running_pow * F::from(2u64);
                    running_sum = running_sum.zip(bits[idx]).map(|(x, b)| x + b * running_pow);
                    cells.push(Constant(running_pow));
                    cells.push(Witness(bits[idx]));
                    cells.push(Witness(running_sum));

                    enable_gates.push(offset - 1);
                    offset = offset + 3;
                }
                let last_idx = cells.len() - 1;
                let assigned_cells = self.gate.assign_region_smart(
                    ctx,
                    cells,
                    enable_gates,
                    vec![],
                    vec![(a, last_idx)],
                )?;

                let mut assigned_bits = Vec::with_capacity(range_bits);
                assigned_bits.push(assigned_cells[0].clone());
                for idx in 1..range_bits {
                    assigned_bits.push(assigned_cells[3 * idx - 1].clone());
                }
                assigned_bits
            }
            RangeStrategy::PlonkPlus => {
                let (bit_cells, _, acc) = self.gate.inner_product(
                    ctx,
                    &bits.iter().map(|x| Witness(*x)).collect(),
                    &(0..range_bits)
                        .map(|i| Constant(biguint_to_fe(&(BigUint::from(1u64) << i))))
                        .collect(),
                )?;
                ctx.region.constrain_equal(a.cell(), acc.cell())?;
                bit_cells.unwrap()
            }
        };
        for bit_cell in &bit_cells {
            self.gate.assign_region_smart(
                ctx,
                vec![
                    Constant(F::from(0)),
                    Existing(&bit_cell),
                    Existing(&bit_cell),
                    Existing(&bit_cell),
                ],
                vec![0],
                vec![],
                vec![],
            )?;
        }
        Ok(bit_cells)
    }
}
