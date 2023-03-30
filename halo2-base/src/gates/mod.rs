use self::{flex_gate::GateStrategy, range::RangeStrategy};
use super::{
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, ExistingOwned, Witness, WitnessFraction},
};
use crate::{
    halo2_proofs::{circuit::Value, plonk::Assigned},
    utils::{biguint_to_fe, bit_length, fe_to_biguint, PrimeField},
};
use core::iter;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use std::ops::Shl;

pub mod flex_gate;
pub mod range;

pub trait GateInstructions<F: ScalarField> {
    fn strategy(&self) -> GateStrategy;
    fn context_id(&self) -> usize;

    fn pow_of_two(&self) -> &[F];
    fn get_field_element(&self, n: u64) -> F;

    fn assign_region<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        gate_offsets: impl IntoIterator<Item = (isize, Option<[F; 3]>)>,
    ) -> Vec<AssignedValue<'b, F>> {
        self.assign_region_in(ctx, inputs, gate_offsets, ctx.current_phase())
    }

    fn assign_region_in<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        gate_offsets: impl IntoIterator<Item = (isize, Option<[F; 3]>)>,
        phase: usize,
    ) -> Vec<AssignedValue<'b, F>>;

    /// Only returns the last assigned cell
    ///
    /// Does not collect the vec, saving heap allocation
    fn assign_region_last<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        gate_offsets: impl IntoIterator<Item = (isize, Option<[F; 3]>)>,
    ) -> AssignedValue<'b, F> {
        self.assign_region_last_in(ctx, inputs, gate_offsets, ctx.current_phase())
    }

    fn assign_region_last_in<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        gate_offsets: impl IntoIterator<Item = (isize, Option<[F; 3]>)>,
        phase: usize,
    ) -> AssignedValue<'b, F>;

    /// Only call this if ctx.region is not in shape mode, i.e., if not using simple layouter or ctx.first_pass = false
    ///
    /// All indices in `gate_offsets`, `equality_offsets`, `external_equality` are with respect to `inputs` indices
    /// - `gate_offsets` specifies indices to enable selector for the gate; assume `gate_offsets` is sorted in increasing order
    /// - `equality_offsets` specifies pairs of indices to constrain equality
    /// - `external_equality` specifies an existing cell to constrain equality with the cell at a certain index
    fn assign_region_smart<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        gate_offsets: impl IntoIterator<Item = usize>,
        equality_offsets: impl IntoIterator<Item = (usize, usize)>,
        external_equality: Vec<(&AssignedValue<F>, usize)>,
    ) -> Vec<AssignedValue<'b, F>> {
        let assignments =
            self.assign_region(ctx, inputs, gate_offsets.into_iter().map(|i| (i as isize, None)));
        for (offset1, offset2) in equality_offsets.into_iter() {
            ctx.region.constrain_equal(assignments[offset1].cell(), assignments[offset2].cell()).unwrap();
        }
        for (assigned, eq_offset) in external_equality.into_iter() {
            ctx.region.constrain_equal(assigned.cell(), assignments[eq_offset].cell()).unwrap();
        }
        assignments
    }

    fn assign_witnesses<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        witnesses: impl IntoIterator<Item = Value<F>>,
    ) -> Vec<AssignedValue<'v, F>> {
        self.assign_region(ctx, witnesses.into_iter().map(Witness), [])
    }

    fn load_witness<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        witness: Value<F>,
    ) -> AssignedValue<'v, F> {
        self.assign_region_last(ctx, [Witness(witness)], [])
    }

    fn load_constant<'a>(&self, ctx: &mut Context<'_, F>, c: F) -> AssignedValue<'a, F> {
        self.assign_region_last(ctx, [Constant(c)], [])
    }

    fn load_zero<'a>(&self, ctx: &mut Context<'a, F>) -> AssignedValue<'a, F> {
        if let Some(zcell) = &ctx.zero_cell {
            return zcell.clone();
        }
        let zero_cell = self.assign_region_last(ctx, [Constant(F::zero())], []);
        ctx.zero_cell = Some(zero_cell.clone());
        zero_cell
    }

    /// Copies a, b and constrains `a + b * 1 = out`
    // | a | b | 1 | a + b |
    fn add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let out_val = a.value().zip(b.value()).map(|(a, b)| *a + b);
        self.assign_region_last(
            ctx,
            vec![a, b, Constant(F::one()), Witness(out_val)],
            vec![(0, None)],
        )
    }

    /// Copies a, b and constrains `a + b * (-1) = out`
    // | a - b | b | 1 | a |
    fn sub<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let out_val = a.value().zip(b.value()).map(|(a, b)| *a - b);
        // slightly better to not have to compute -F::one() since F::one() is cached
        let assigned_cells = self.assign_region(
            ctx,
            vec![Witness(out_val), b, Constant(F::one()), a],
            vec![(0, None)],
        );
        assigned_cells.into_iter().next().unwrap()
    }

    // | a | -a | 1 | 0 |
    fn neg<'v>(&self, ctx: &mut Context<'_, F>, a: QuantumCell<'_, 'v, F>) -> AssignedValue<'v, F> {
        let out_val = a.value().map(|v| -*v);
        let assigned_cells = self.assign_region(
            ctx,
            vec![a, Witness(out_val), Constant(F::one()), Constant(F::zero())],
            vec![(0, None)],
        );
        assigned_cells.into_iter().nth(1).unwrap()
    }

    /// Copies a, b and constrains `0 + a * b = out`
    // | 0 | a | b | a * b |
    fn mul<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let out_val = a.value().zip(b.value()).map(|(a, b)| *a * b);
        self.assign_region_last(
            ctx,
            vec![Constant(F::zero()), a, b, Witness(out_val)],
            vec![(0, None)],
        )
    }

    /// a * b + c
    fn mul_add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
        c: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let out_val = a.value().zip(b.value()).map(|(a, b)| *a * b) + c.value();
        self.assign_region_last(ctx, vec![c, a, b, Witness(out_val)], vec![(0, None)])
    }

    /// (1 - a) * b = b - a * b
    fn mul_not<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let out_val = a.value().zip(b.value()).map(|(a, b)| (F::one() - a) * b);
        let assignments =
            self.assign_region(ctx, vec![Witness(out_val), a, b.clone(), b], vec![(0, None)]);
        ctx.region.constrain_equal(assignments[2].cell(), assignments[3].cell()).unwrap();
        assignments.into_iter().next().unwrap()
    }

    /// Constrain x is 0 or 1.
    fn assert_bit(&self, ctx: &mut Context<'_, F>, x: &AssignedValue<F>) {
        self.assign_region_last(
            ctx,
            [Constant(F::zero()), Existing(x), Existing(x), Existing(x)],
            [(0, None)],
        );
    }

    fn div_unsafe<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        // TODO: if really necessary, make `c` of type `Assigned<F>`
        // this would require the API using `Assigned<F>` instead of `F` everywhere, so leave as last resort
        let c = a.value().zip(b.value()).map(|(a, b)| b.invert().unwrap() * a);
        let assignments =
            self.assign_region(ctx, vec![Constant(F::zero()), Witness(c), b, a], vec![(0, None)]);
        assignments.into_iter().nth(1).unwrap()
    }

    fn assert_equal(&self, ctx: &mut Context<'_, F>, a: QuantumCell<F>, b: QuantumCell<F>) {
        if let (Existing(a), Existing(b)) = (&a, &b) {
            ctx.region.constrain_equal(a.cell(), b.cell()).unwrap();
        } else {
            self.assign_region_smart(
                ctx,
                vec![Constant(F::zero()), a, Constant(F::one()), b],
                vec![0],
                vec![],
                vec![],
            );
        }
    }

    fn assert_is_const(&self, ctx: &mut Context<'_, F>, a: &AssignedValue<F>, constant: F) {
        let c_cell = ctx.assign_fixed(constant);
        #[cfg(feature = "halo2-axiom")]
        ctx.region.constrain_equal(a.cell(), &c_cell);
        #[cfg(feature = "halo2-pse")]
        ctx.region.constrain_equal(a.cell(), c_cell).unwrap();
    }

    /// Returns `(assignments, output)` where `output` is the inner product of `<a, b>`
    ///
    /// `assignments` is for internal use
    fn inner_product<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
    ) -> AssignedValue<'b, F>;

    /// very specialized for optimal range check, not for general consumption
    /// - `a_assigned` is expected to have capacity a.len()
    /// - we re-use `a_assigned` to save memory allocation
    fn inner_product_left<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        a_assigned: &mut Vec<AssignedValue<'b, F>>,
    ) -> AssignedValue<'b, F>;

    /// Returns an iterator with the partial sums `sum_{j=0..=i} a[j] * b[j]`.
    fn inner_product_with_sums<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
    ) -> Box<dyn Iterator<Item = AssignedValue<'b, F>> + 'b>;

    fn sum<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'b, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
    ) -> AssignedValue<'b, F> {
        let mut a = a.into_iter().peekable();
        let start = a.next();
        if start.is_none() {
            return self.load_zero(ctx);
        }
        let start = start.unwrap();
        if a.peek().is_none() {
            return self.assign_region_last(ctx, [start], []);
        }
        let (len, hi) = a.size_hint();
        debug_assert_eq!(Some(len), hi);

        let mut sum = start.value().copied();
        let cells = iter::once(start).chain(a.flat_map(|a| {
            sum = sum + a.value();
            [a, Constant(F::one()), Witness(sum)]
        }));
        self.assign_region_last(ctx, cells, (0..len).map(|i| (3 * i as isize, None)))
    }

    /// Returns the assignment trace where `output[3 * i]` has the running sum `sum_{j=0..=i} a[j]`
    fn sum_with_assignments<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'b, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
    ) -> Vec<AssignedValue<'b, F>> {
        let mut a = a.into_iter().peekable();
        let start = a.next();
        if start.is_none() {
            return vec![self.load_zero(ctx)];
        }
        let start = start.unwrap();
        if a.peek().is_none() {
            return self.assign_region(ctx, [start], []);
        }
        let (len, hi) = a.size_hint();
        debug_assert_eq!(Some(len), hi);

        let mut sum = start.value().copied();
        let cells = iter::once(start).chain(a.flat_map(|a| {
            sum = sum + a.value();
            [a, Constant(F::one()), Witness(sum)]
        }));
        self.assign_region(ctx, cells, (0..len).map(|i| (3 * i as isize, None)))
    }

    // requires b.len() == a.len() + 1
    // returns
    // x_i = b_1 * (a_1...a_{i - 1})
    //     + b_2 * (a_2...a_{i - 1})
    //     + ...
    //     + b_i
    // Returns [x_1, ..., x_{b.len()}]
    fn accumulated_product<'a, 'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'v, F>>,
        b: impl IntoIterator<Item = QuantumCell<'a, 'v, F>>,
    ) -> Vec<AssignedValue<'v, F>> {
        let mut b = b.into_iter();
        let mut a = a.into_iter();
        let b_first = b.next();
        if let Some(b_first) = b_first {
            let b_first = self.assign_region_last(ctx, [b_first], []);
            std::iter::successors(Some(b_first), |x| {
                a.next().zip(b.next()).map(|(a, b)| self.mul_add(ctx, Existing(x), a, b))
            })
            .collect()
        } else {
            vec![]
        }
    }

    fn sum_products_with_coeff_and_var<'a, 'b: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        values: impl IntoIterator<Item = (F, QuantumCell<'a, 'b, F>, QuantumCell<'a, 'b, F>)>,
        var: QuantumCell<'a, 'b, F>,
    ) -> AssignedValue<'b, F>;

    // | 1 - b | 1 | b | 1 | b | a | 1 - b | out |
    fn or<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let not_b_val = b.value().map(|x| F::one() - x);
        let out_val = a.value().zip(b.value()).map(|(a, b)| *a + b)
            - a.value().zip(b.value()).map(|(a, b)| *a * b);
        let cells = vec![
            Witness(not_b_val),
            Constant(F::one()),
            b.clone(),
            Constant(F::one()),
            b,
            a,
            Witness(not_b_val),
            Witness(out_val),
        ];
        let mut assigned_cells =
            self.assign_region_smart(ctx, cells, vec![0, 4], vec![(0, 6), (2, 4)], vec![]);
        assigned_cells.pop().unwrap()
    }

    // | 0 | a | b | out |
    fn and<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        self.mul(ctx, a, b)
    }

    fn not<'v>(&self, ctx: &mut Context<'_, F>, a: QuantumCell<'_, 'v, F>) -> AssignedValue<'v, F> {
        self.sub(ctx, Constant(F::one()), a)
    }

    fn select<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
        sel: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F>;

    fn or_and<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
        c: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F>;

    /// assume bits has boolean values
    /// returns vec[idx] with vec[idx] = 1 if and only if bits == idx as a binary number
    fn bits_to_indicator<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        bits: &[AssignedValue<'v, F>],
    ) -> Vec<AssignedValue<'v, F>> {
        let k = bits.len();

        let (inv_last_bit, last_bit) = {
            let mut assignments = self
                .assign_region(
                    ctx,
                    vec![
                        Witness(bits[k - 1].value().map(|b| F::one() - b)),
                        Existing(&bits[k - 1]),
                        Constant(F::one()),
                        Constant(F::one()),
                    ],
                    vec![(0, None)],
                )
                .into_iter();
            (assignments.next().unwrap(), assignments.next().unwrap())
        };
        let mut indicator = Vec::with_capacity(2 * (1 << k) - 2);
        let mut offset = 0;
        indicator.push(inv_last_bit);
        indicator.push(last_bit);
        for (idx, bit) in bits.iter().rev().enumerate().skip(1) {
            for old_idx in 0..(1 << idx) {
                let inv_prod_val = indicator[offset + old_idx]
                    .value()
                    .zip(bit.value())
                    .map(|(a, b)| (F::one() - b) * a);
                let inv_prod = self
                    .assign_region_smart(
                        ctx,
                        vec![
                            Witness(inv_prod_val),
                            Existing(&indicator[offset + old_idx]),
                            Existing(bit),
                            Existing(&indicator[offset + old_idx]),
                        ],
                        vec![0],
                        vec![],
                        vec![],
                    )
                    .into_iter()
                    .next()
                    .unwrap();
                indicator.push(inv_prod);

                let prod = self.mul(ctx, Existing(&indicator[offset + old_idx]), Existing(bit));
                indicator.push(prod);
            }
            offset += 1 << idx;
        }
        indicator.split_off((1 << k) - 2)
    }

    // returns vec with vec.len() == len such that:
    //     vec[i] == 1{i == idx}
    fn idx_to_indicator<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        mut idx: QuantumCell<'_, 'v, F>,
        len: usize,
    ) -> Vec<AssignedValue<'v, F>> {
        let ind = self.assign_region(
            ctx,
            (0..len).map(|i| {
                Witness(idx.value().map(|x| {
                    if x.get_lower_32() == i as u32 {
                        F::one()
                    } else {
                        F::zero()
                    }
                }))
            }),
            vec![],
        );

        // check ind[i] * (i - idx) == 0
        for (i, ind) in ind.iter().enumerate() {
            let val = ind.value().zip(idx.value()).map(|(ind, idx)| *ind * idx);
            let assignments = self.assign_region(
                ctx,
                vec![
                    Constant(F::zero()),
                    Existing(ind),
                    idx,
                    Witness(val),
                    Constant(-F::from(i as u64)),
                    Existing(ind),
                    Constant(F::zero()),
                ],
                vec![(0, None), (3, None)],
            );
            // need to use assigned idx after i > 0 so equality constraint holds
            idx = ExistingOwned(assignments.into_iter().nth(2).unwrap());
        }
        ind
    }

    // performs inner product on a, indicator
    // `indicator` values are all boolean
    /// Assumes for witness generation that only one element of `indicator` has non-zero value and that value is `F::one()`.
    fn select_by_indicator<'a, 'i, 'b: 'a + 'i>(
        &self,
        ctx: &mut Context<'_, F>,
        a: impl IntoIterator<Item = QuantumCell<'a, 'b, F>>,
        indicator: impl IntoIterator<Item = &'i AssignedValue<'b, F>>,
    ) -> AssignedValue<'b, F> {
        let mut sum = Value::known(F::zero());
        let a = a.into_iter();
        let (len, hi) = a.size_hint();
        debug_assert_eq!(Some(len), hi);

        let cells =
            std::iter::once(Constant(F::zero())).chain(a.zip(indicator).flat_map(|(a, ind)| {
                sum = sum.zip(a.value().zip(ind.value())).map(|(sum, (a, ind))| {
                    if ind.is_zero_vartime() {
                        sum
                    } else {
                        *a
                    }
                });
                [a, Existing(ind), Witness(sum)]
            }));
        self.assign_region_last(ctx, cells, (0..len).map(|i| (3 * i as isize, None)))
    }

    fn select_from_idx<'a, 'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        cells: impl IntoIterator<Item = QuantumCell<'a, 'v, F>>,
        idx: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let cells = cells.into_iter();
        let (len, hi) = cells.size_hint();
        debug_assert_eq!(Some(len), hi);

        let ind = self.idx_to_indicator(ctx, idx, len);
        let out = self.select_by_indicator(ctx, cells, &ind);
        out
    }

    // | out | a | inv | 1 | 0 | a | out | 0
    fn is_zero<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<'v, F>,
    ) -> AssignedValue<'v, F> {
        let (is_zero, inv) = a
            .value()
            .map(|x| {
                if x.is_zero_vartime() {
                    (F::one(), Assigned::Trivial(F::one()))
                } else {
                    (F::zero(), Assigned::Rational(F::one(), *x))
                }
            })
            .unzip();

        let cells = vec![
            Witness(is_zero),
            Existing(a),
            WitnessFraction(inv),
            Constant(F::one()),
            Constant(F::zero()),
            Existing(a),
            Witness(is_zero),
            Constant(F::zero()),
        ];
        let assigned_cells = self.assign_region_smart(ctx, cells, vec![0, 4], vec![(0, 6)], vec![]);
        assigned_cells.into_iter().next().unwrap()
    }

    fn is_equal<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumCell<'_, 'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedValue<'v, F> {
        let diff = self.sub(ctx, a, b);
        self.is_zero(ctx, &diff)
    }

    // returns little-endian bit vectors
    fn num_to_bits<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<'v, F>,
        range_bits: usize,
    ) -> Vec<AssignedValue<'v, F>>;

    /// given pairs `coords[i] = (x_i, y_i)`, let `f` be the unique degree `len(coords)` polynomial such that `f(x_i) = y_i` for all `i`.
    ///
    /// input: coords, x
    ///
    /// output: (f(x), Prod_i (x - x_i))
    ///
    /// constrains all x_i and x are distinct
    fn lagrange_and_eval<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        coords: &[(AssignedValue<'v, F>, AssignedValue<'v, F>)],
        x: &AssignedValue<'v, F>,
    ) -> (AssignedValue<'v, F>, AssignedValue<'v, F>) {
        let mut z = self.sub(ctx, Existing(x), Existing(&coords[0].0));
        for coord in coords.iter().skip(1) {
            let sub = self.sub(ctx, Existing(x), Existing(&coord.0));
            z = self.mul(ctx, Existing(&z), Existing(&sub));
        }
        let mut eval = None;
        for i in 0..coords.len() {
            // compute (x - x_i) * Prod_{j != i} (x_i - x_j)
            let mut denom = self.sub(ctx, Existing(x), Existing(&coords[i].0));
            for j in 0..coords.len() {
                if i == j {
                    continue;
                }
                let sub = self.sub(ctx, Existing(&coords[i].0), Existing(&coords[j].0));
                denom = self.mul(ctx, Existing(&denom), Existing(&sub));
            }
            // TODO: batch inversion
            let is_zero = self.is_zero(ctx, &denom);
            self.assert_is_const(ctx, &is_zero, F::zero());

            // y_i / denom
            let quot = self.div_unsafe(ctx, Existing(&coords[i].1), Existing(&denom));
            eval = if let Some(eval) = eval {
                let eval = self.add(ctx, Existing(&eval), Existing(&quot));
                Some(eval)
            } else {
                Some(quot)
            };
        }
        let out = self.mul(ctx, Existing(&eval.unwrap()), Existing(&z));
        (out, z)
    }
}

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

#[cfg(test)]
pub mod tests;
