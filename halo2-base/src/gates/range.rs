use crate::{
    gates::flex_gate::{FlexGateConfig, GateInstructions, GateStrategy, MAX_PHASE},
    halo2_proofs::{
        circuit::{Layouter, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Error, SecondPhase, Selector, TableColumn, ThirdPhase,
        },
        poly::Rotation,
    },
    utils::{
        biguint_to_fe, bit_length, decompose_fe_to_u64_limbs, fe_to_biguint, BigPrimeField,
        ScalarField,
    },
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use std::{cmp::Ordering, ops::Shl};

use super::flex_gate::GateChip;

/// Specifies the gate strategy for the range chip
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RangeStrategy {
    /// # Vertical Gate Strategy:
    /// `q_0 * (a + b * c - d) = 0`
    /// where
    /// * a = value[0], b = value[1], c = value[2], d = value[3]
    /// * q = q_lookup[0]
    /// * q is either 0 or 1 so this is just a simple selector
    ///
    /// Using `a + b * c` instead of `a * b + c` allows for "chaining" of gates, i.e., the output of one gate becomes `a` in the next gate.
    Vertical, // vanilla implementation with vertical basic gate(s)
}

/// Configuration for Range Chip
#[derive(Clone, Debug)]
pub struct RangeConfig<F: ScalarField> {
    /// Underlying Gate Configuration
    pub gate: FlexGateConfig<F>,
    /// Special advice (witness) Columns used only for lookup tables.
    ///
    /// Each phase of a halo2 circuit has a distinct lookup_advice column.
    ///
    /// * If `gate` has only 1 advice column, lookups are enabled for that column, in which case `lookup_advice` is empty
    /// * If `gate` has more than 1 advice column some number of user-specified `lookup_advice` columns are added
    ///     * In this case, we don't need a selector so `q_lookup` is empty
    pub lookup_advice: [Vec<Column<Advice>>; MAX_PHASE],
    /// Selector values for the lookup table.
    pub q_lookup: Vec<Option<Selector>>,
    /// Column for lookup table values.
    pub lookup: TableColumn,
    /// Defines the number of bits represented in the lookup table [0,2^<sup>lookup_bits</sup>).
    lookup_bits: usize,
    /// Gate Strategy used for specifying advice values.
    _strategy: RangeStrategy,
}

impl<F: ScalarField> RangeConfig<F> {
    /// Generates a new [RangeConfig] with the specified parameters.
    ///
    /// If `num_columns` is 0, then we assume you do not want to perform any lookups in that phase.
    ///
    /// Panics if `lookup_bits` > 28.
    /// * `meta`: [ConstraintSystem] of the circuit
    /// * `range_strategy`: [GateStrategy] of the range chip
    /// * `num_advice`: Number of [Advice] [Column]s without lookup enabled in each phase
    /// * `num_lookup_advice`: Number of `lookup_advice` [Column]s in each phase
    /// * `num_fixed`: Number of fixed [Column]s in each phase
    /// * `lookup_bits`: Number of bits represented in the LookUp table [0,2^lookup_bits)
    /// * `circuit_degree`: Degree that expresses the size of circuit (i.e., 2^<sup>circuit_degree</sup> is the number of rows in the circuit)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        range_strategy: RangeStrategy,
        num_advice: &[usize],
        num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
        // params.k()
        circuit_degree: usize,
    ) -> Self {
        assert!(lookup_bits <= 28);
        let lookup = meta.lookup_table_column();

        let gate = FlexGateConfig::configure(
            meta,
            match range_strategy {
                RangeStrategy::Vertical => GateStrategy::Vertical,
            },
            num_advice,
            num_fixed,
            circuit_degree,
        );

        // For now, we apply the same range lookup table to each phase
        let mut q_lookup = Vec::new();
        let mut lookup_advice = [(); MAX_PHASE].map(|_| Vec::new());
        for (phase, &num_columns) in num_lookup_advice.iter().enumerate() {
            // if num_columns is set to 0, then we assume you do not want to perform any lookups in that phase
            if num_advice[phase] == 1 && num_columns != 0 {
                q_lookup.push(Some(meta.complex_selector()));
            } else {
                q_lookup.push(None);
                for _ in 0..num_columns {
                    let a = match phase {
                        0 => meta.advice_column(),
                        1 => meta.advice_column_in(SecondPhase),
                        2 => meta.advice_column_in(ThirdPhase),
                        _ => panic!("Currently RangeConfig only supports {MAX_PHASE} phases"),
                    };
                    meta.enable_equality(a);
                    lookup_advice[phase].push(a);
                }
            }
        }

        let mut config =
            Self { lookup_advice, q_lookup, lookup, lookup_bits, gate, _strategy: range_strategy };

        // sanity check: only create lookup table if there are lookup_advice columns
        if !num_lookup_advice.is_empty() {
            config.create_lookup(meta);
        }
        config.gate.max_rows = (1 << circuit_degree) - meta.minimum_rows();
        assert!(
            (1 << lookup_bits) <= config.gate.max_rows,
            "lookup table is too large for the circuit degree plus blinding factors!"
        );

        config
    }

    /// Returns the number of bits represented in the lookup table [0,2^<sup>lookup_bits</sup>).
    pub fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    /// Instantiates the lookup table of the circuit.
    /// * `meta`: [ConstraintSystem] of the circuit
    fn create_lookup(&self, meta: &mut ConstraintSystem<F>) {
        for (phase, q_l) in self.q_lookup.iter().enumerate() {
            if let Some(q) = q_l {
                meta.lookup("lookup", |meta| {
                    let q = meta.query_selector(*q);
                    // there should only be 1 advice column in phase `phase`
                    let a =
                        meta.query_advice(self.gate.basic_gates[phase][0].value, Rotation::cur());
                    vec![(q * a, self.lookup)]
                });
            }
        }
        //if multiple columns
        for la in self.lookup_advice.iter().flat_map(|advices| advices.iter()) {
            meta.lookup("lookup wo selector", |meta| {
                let a = meta.query_advice(*la, Rotation::cur());
                vec![(a, self.lookup)]
            });
        }
    }

    /// Loads the lookup table into the circuit using the provided `layouter`.
    /// * `layouter`: layouter for the circuit
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
}

/// Trait that implements methods to constrain a field element number `x` is within a range of bits.
pub trait RangeInstructions<F: ScalarField> {
    /// The type of Gate used within the instructions.
    type Gate: GateInstructions<F>;

    /// Returns the type of gate used.
    fn gate(&self) -> &Self::Gate;

    /// Returns the [GateStrategy] for this range.
    fn strategy(&self) -> RangeStrategy;

    /// Returns the number of bits the lookup table represents.
    fn lookup_bits(&self) -> usize;

    /// Checks and constrains that `a` lies in the range [0, 2<sup>range_bits</sup>).
    ///
    /// Assumes that both `a`<= `range_bits` bits.
    /// * a: [AssignedValue] value to be range checked
    /// * range_bits: number of bits to represent the range
    fn range_check(&self, ctx: &mut Context<F>, a: AssignedValue<F>, range_bits: usize);

    /// Constrains that 'a' is less than 'b'.
    ///
    /// Assumes that `a` and `b` have bit length <= num_bits bits.
    ///
    /// Note: This may fail silently if a or b have more than num_bits.
    /// * a: [QuantumCell] value to check
    /// * b: upper bound expressed as a [QuantumCell]
    /// * num_bits: number of bits used to represent the values of `a` and `b`
    fn check_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        num_bits: usize,
    );

    /// Performs a range check that `a` has at most `bit_length(b)` bits and then constrains that `a` is less than `b`.
    ///
    /// * a: [AssignedValue] value to check
    /// * b: upper bound expressed as a [u64] value
    fn check_less_than_safe(&self, ctx: &mut Context<F>, a: AssignedValue<F>, b: u64) {
        let range_bits =
            (bit_length(b) + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.check_less_than(ctx, a, Constant(self.gate().get_field_element(b)), range_bits)
    }

    /// Performs a range check that `a` has at most `bit_length(b)` bits and then constrains that `a` is less than `b`.
    ///
    /// * a: [AssignedValue] value to check
    /// * b: upper bound expressed as a [BigUint] value
    fn check_big_less_than_safe(&self, ctx: &mut Context<F>, a: AssignedValue<F>, b: BigUint)
    where
        F: BigPrimeField,
    {
        let range_bits =
            (b.bits() as usize + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.check_less_than(ctx, a, Constant(biguint_to_fe(&b)), range_bits)
    }

    /// Constrains whether `a` is in `[0, b)`, and returns 1 if `a` < `b`, otherwise 0.
    ///
    /// Assumes that`a` and `b` are known to have <= num_bits bits.
    /// * a: first [QuantumCell] to compare
    /// * b: second [QuantumCell] to compare
    /// * num_bits: number of bits to represent the values
    fn is_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        num_bits: usize,
    ) -> AssignedValue<F>;

    /// Performs a range check that `a` has at most `bit_length(b)` and then constrains that `a` is in `[0,b)`.
    ///
    /// Returns 1 if `a` < `b`, otherwise 0.
    ///
    /// * a: [AssignedValue] value to check
    /// * b: upper bound as [u64] value
    fn is_less_than_safe(
        &self,
        ctx: &mut Context<F>,
        a: AssignedValue<F>,
        b: u64,
    ) -> AssignedValue<F> {
        let range_bits =
            (bit_length(b) + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.is_less_than(ctx, a, Constant(self.gate().get_field_element(b)), range_bits)
    }

    /// Performs a range check that `a` has at most `bit_length(b)` and then constrains that `a` is in `[0,b)`.
    ///
    /// Returns 1 if `a` < `b`, otherwise 0.
    ///
    /// * a: [AssignedValue] value to check
    /// * b: upper bound as [BigUint] value
    fn is_big_less_than_safe(
        &self,
        ctx: &mut Context<F>,
        a: AssignedValue<F>,
        b: BigUint,
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let range_bits =
            (b.bits() as usize + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.is_less_than(ctx, a, Constant(biguint_to_fe(&b)), range_bits)
    }

    /// Constrains and returns `(c, r)` such that `a = b * c + r`.
    ///
    /// Assumes that `b != 0` and that `a` has <= `a_num_bits` bits.
    /// * a: [QuantumCell] value to divide
    /// * b: [BigUint] value to divide by
    /// * a_num_bits: number of bits needed to represent the value of `a`
    fn div_mod(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<BigUint>,
        a_num_bits: usize,
    ) -> (AssignedValue<F>, AssignedValue<F>)
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let b = b.into();
        let a_val = fe_to_biguint(a.value());
        let (div, rem) = a_val.div_mod_floor(&b);
        let [div, rem] = [div, rem].map(|v| biguint_to_fe(&v));
        ctx.assign_region([Witness(rem), Constant(biguint_to_fe(&b)), Witness(div), a], [0]);
        let rem = ctx.get(-4);
        let div = ctx.get(-2);
        // Constrain that a_num_bits fulfills `div < 2 ** a_num_bits / b`.
        self.check_big_less_than_safe(
            ctx,
            div,
            BigUint::one().shl(a_num_bits as u32) / &b + BigUint::one(),
        );
        // Constrain that remainder is less than divisor (i.e. `r < b`).
        self.check_big_less_than_safe(ctx, rem, b);
        (div, rem)
    }

    /// Constrains and returns `(c, r)` such that `a = b * c + r`.
    ///
    /// Assumes:
    /// that `b != 0`.
    /// that `a` has <= `a_num_bits` bits.
    /// that `b` has <= `b_num_bits` bits.
    ///
    /// Note:
    /// Let `X = 2 ** b_num_bits`
    /// Write `a = a1 * X + a0` and `c = c1 * X + c0`
    /// If we write `b * c0 + r = d1 * X + d0` then
    ///     `b * c + r = (b * c1 + d1) * X + d0`
    /// * a: [QuantumCell] value to divide
    /// * b: [QuantumCell] value to divide by
    /// * a_num_bits: number of bits needed to represent the value of `a`
    /// * b_num_bits: number of bits needed to represent the value of `b`
    ///
    fn div_mod_var(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        a_num_bits: usize,
        b_num_bits: usize,
    ) -> (AssignedValue<F>, AssignedValue<F>)
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let b = b.into();
        let a_val = fe_to_biguint(a.value());
        let b_val = fe_to_biguint(b.value());
        let (div, rem) = a_val.div_mod_floor(&b_val);
        let x = BigUint::one().shl(b_num_bits as u32);
        let (div_hi, div_lo) = div.div_mod_floor(&x);

        let x_fe = self.gate().pow_of_two()[b_num_bits];
        let [div, div_hi, div_lo, rem] = [div, div_hi, div_lo, rem].map(|v| biguint_to_fe(&v));
        ctx.assign_region(
            [Witness(div_lo), Witness(div_hi), Constant(x_fe), Witness(div), Witness(rem)],
            [0],
        );
        let [div_lo, div_hi, div, rem] = [-5, -4, -2, -1].map(|i| ctx.get(i));
        self.range_check(ctx, div_lo, b_num_bits);
        if a_num_bits <= b_num_bits {
            self.gate().assert_is_const(ctx, &div_hi, &F::zero());
        } else {
            self.range_check(ctx, div_hi, a_num_bits - b_num_bits);
        }

        let (bcr0_hi, bcr0_lo) = {
            let bcr0 = self.gate().mul_add(ctx, b, Existing(div_lo), Existing(rem));
            self.div_mod(ctx, Existing(bcr0), x.clone(), a_num_bits)
        };
        let bcr_hi = self.gate().mul_add(ctx, b, Existing(div_hi), Existing(bcr0_hi));

        let (a_hi, a_lo) = self.div_mod(ctx, a, x, a_num_bits);
        ctx.constrain_equal(&bcr_hi, &a_hi);
        ctx.constrain_equal(&bcr0_lo, &a_lo);

        self.range_check(ctx, rem, b_num_bits);
        self.check_less_than(ctx, Existing(rem), b, b_num_bits);
        (div, rem)
    }

    /// Constrains and returns the last bit of the value of `a`.
    ///
    /// Assume `a` has been range checked already to `limb_bits` bits.
    /// * a: [AssignedValue] value to get the last bit of
    /// * limb_bits: number of bits in a limb
    fn get_last_bit(
        &self,
        ctx: &mut Context<F>,
        a: AssignedValue<F>,
        limb_bits: usize,
    ) -> AssignedValue<F> {
        let a_v = a.value();
        let bit_v = {
            let a = a_v.get_lower_32();
            F::from(a ^ 1 != 0)
        };
        let two = self.gate().get_field_element(2u64);
        let h_v = (*a_v - bit_v) * two.invert().unwrap();
        ctx.assign_region([Witness(bit_v), Witness(h_v), Constant(two), Existing(a)], [0]);

        let half = ctx.get(-3);
        self.range_check(ctx, half, limb_bits - 1);
        let bit = ctx.get(-4);
        self.gate().assert_bit(ctx, bit);
        bit
    }
}

/// A chip that implements RangeInstructions which provides methods to constrain a field element `x` is within a range of bits.
#[derive(Clone, Debug)]
pub struct RangeChip<F: ScalarField> {
    /// # RangeChip
    /// Provides methods to constrain a field element `x` is within a range of  bits.
    /// Declares a lookup table of [0, 2<sup>lookup_bits</sup>) and constrains whether a field element appears in this table.

    /// [GateStrategy] for advice values in this chip.
    strategy: RangeStrategy,
    /// Underlying [GateChip] for this chip.
    pub gate: GateChip<F>,
    /// Defines the number of bits represented in the lookup table [0,2<sup>lookup_bits</sup>).
    pub lookup_bits: usize,
    /// [Vec] of 'limbs' represented as [QuantumCell] that divide the underlying scalar field element into sections smaller than lookup_bits.
    /// * This allows range checks on field elements that are larger than the maximum value of the lookup table.
    pub limb_bases: Vec<QuantumCell<F>>,
}

impl<F: ScalarField> RangeChip<F> {
    /// Creates a new [RangeChip] with the given strategy and lookup_bits.
    /// * strategy: [GateStrategy] for advice values in this chip
    /// * lookup_bits: number of bits represented in the lookup table [0,2<sup>lookup_bits</sup>)
    pub fn new(strategy: RangeStrategy, lookup_bits: usize) -> Self {
        let limb_base = F::from(1u64 << lookup_bits);
        let mut running_base = limb_base;
        let num_bases = F::NUM_BITS as usize / lookup_bits;
        let mut limb_bases = Vec::with_capacity(num_bases + 1);
        limb_bases.extend([Constant(F::one()), Constant(running_base)]);
        for _ in 2..=num_bases {
            running_base *= &limb_base;
            limb_bases.push(Constant(running_base));
        }
        let gate = GateChip::new(match strategy {
            RangeStrategy::Vertical => GateStrategy::Vertical,
        });

        Self { strategy, gate, lookup_bits, limb_bases }
    }

    /// Creates a new [RangeChip] with the default strategy and provided lookup_bits.
    /// * lookup_bits: number of bits represented in the lookup table [0,2<sup>lookup_bits</sup>)
    pub fn default(lookup_bits: usize) -> Self {
        Self::new(RangeStrategy::Vertical, lookup_bits)
    }
}

impl<F: ScalarField> RangeInstructions<F> for RangeChip<F> {
    type Gate = GateChip<F>;

    /// The type of Gate used in this chip.
    fn gate(&self) -> &Self::Gate {
        &self.gate
    }

    /// Returns the [GateStrategy] for this range.
    fn strategy(&self) -> RangeStrategy {
        self.strategy
    }

    /// Defines the number of bits represented in the lookup table [0,2<sup>lookup_bits</sup>).
    fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    /// Checks and constrains that `a` lies in the range [0, 2<sup>range_bits</sup>).
    ///
    /// This is done by decomposing `a` into `k` limbs, where `k = (range_bits + lookup_bits - 1) / lookup_bits`.
    /// Each limb is constrained to be within the range [0, 2<sup>lookup_bits</sup>).
    /// The limbs are then combined to form `a` again with the last limb having `rem_bits` number of bits.
    ///
    /// * `a`: [AssignedValue] value to be range checked
    /// * `range_bits`: number of bits in the range
    /// * `lookup_bits`: number of bits in the lookup table
    fn range_check(&self, ctx: &mut Context<F>, a: AssignedValue<F>, range_bits: usize) {
        // the number of limbs
        let k = (range_bits + self.lookup_bits - 1) / self.lookup_bits;
        // println!("range check {} bits {} len", range_bits, k);
        let rem_bits = range_bits % self.lookup_bits;

        debug_assert!(self.limb_bases.len() >= k);

        if k == 1 {
            ctx.cells_to_lookup.push(a);
        } else {
            let limbs = decompose_fe_to_u64_limbs(a.value(), k, self.lookup_bits)
                .into_iter()
                .map(|x| Witness(F::from(x)));
            let row_offset = ctx.advice.len() as isize;
            let acc = self.gate.inner_product(ctx, limbs, self.limb_bases[..k].to_vec());
            // the inner product above must equal `a`
            ctx.constrain_equal(&a, &acc);
            // we fetch the cells to lookup by getting the indices where `limbs` were assigned in `inner_product`. Because `limb_bases[0]` is 1, the progression of indices is 0,1,4,...,4+3*i
            ctx.cells_to_lookup.push(ctx.get(row_offset));
            for i in 0..k - 1 {
                ctx.cells_to_lookup.push(ctx.get(row_offset + 1 + 3 * i as isize));
            }
        };

        // additional constraints for the last limb if rem_bits != 0
        match rem_bits.cmp(&1) {
            // we want to check x := limbs[k-1] is boolean
            // we constrain x*(x-1) = 0 + x * x - x == 0
            // | 0 | x | x | x |
            Ordering::Equal => {
                self.gate.assert_bit(ctx, *ctx.cells_to_lookup.last().unwrap());
            }
            Ordering::Greater => {
                let mult_val = self.gate.pow_of_two[self.lookup_bits - rem_bits];
                let check =
                    self.gate.mul(ctx, *ctx.cells_to_lookup.last().unwrap(), Constant(mult_val));
                ctx.cells_to_lookup.push(check);
            }
            _ => {}
        }
    }

    /// Constrains that 'a' is less than 'b'.
    ///
    /// Assumes that`a` and `b` are known to have <= num_bits bits.
    ///
    /// Note: This may fail silently if a or b have more than num_bits
    /// * a: [QuantumCell] value to check
    /// * b: upper bound expressed as a [QuantumCell]
    /// * num_bits: number of bits to represent the values
    fn check_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        num_bits: usize,
    ) {
        let a = a.into();
        let b = b.into();
        let pow_of_two = self.gate.pow_of_two[num_bits];
        let check_cell = match self.strategy {
            RangeStrategy::Vertical => {
                let shift_a_val = pow_of_two + a.value();
                // | a + 2^(num_bits) - b | b | 1 | a + 2^(num_bits) | - 2^(num_bits) | 1 | a |
                let cells = [
                    Witness(shift_a_val - b.value()),
                    b,
                    Constant(F::one()),
                    Witness(shift_a_val),
                    Constant(-pow_of_two),
                    Constant(F::one()),
                    a,
                ];
                ctx.assign_region(cells, [0, 3]);
                ctx.get(-7)
            }
        };

        self.range_check(ctx, check_cell, num_bits);
    }

    /// Constrains whether `a` is in `[0, b)`, and returns 1 if `a` < `b`, otherwise 0.
    ///
    /// Assumes that`a` and `b` are known to have <= num_bits bits.
    /// * a: first [QuantumCell] to compare
    /// * b: second [QuantumCell] to compare
    /// * num_bits: number of bits to represent the values
    fn is_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        num_bits: usize,
    ) -> AssignedValue<F> {
        let a = a.into();
        let b = b.into();

        let k = (num_bits + self.lookup_bits - 1) / self.lookup_bits;
        let padded_bits = k * self.lookup_bits;
        let pow_padded = self.gate.pow_of_two[padded_bits];

        let shift_a_val = pow_padded + a.value();
        let shifted_val = shift_a_val - b.value();
        let shifted_cell = match self.strategy {
            RangeStrategy::Vertical => {
                ctx.assign_region(
                    [
                        Witness(shifted_val),
                        b,
                        Constant(F::one()),
                        Witness(shift_a_val),
                        Constant(-pow_padded),
                        Constant(F::one()),
                        a,
                    ],
                    [0, 3],
                );
                ctx.get(-7)
            }
        };

        // check whether a - b + 2^padded_bits < 2^padded_bits ?
        // since assuming a, b < 2^padded_bits we are guaranteed a - b + 2^padded_bits < 2^{padded_bits + 1}
        self.range_check(ctx, shifted_cell, padded_bits + self.lookup_bits);
        // ctx.cells_to_lookup.last() will have the (k + 1)-th limb of `a - b + 2^{k * limb_bits}`, which is zero iff `a < b`
        self.gate.is_zero(ctx, *ctx.cells_to_lookup.last().unwrap())
    }
}
