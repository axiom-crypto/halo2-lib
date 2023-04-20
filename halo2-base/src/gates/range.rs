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
    /// * q = q_enable[0]
    /// * q_i is either 0 or 1 so this is just a simple selector
    /// We chose `a + b * c` instead of `a * b + c` to allow "chaining" of gates, i.e., the output of one gate because `a` in the next gate
    Vertical, // vanilla implementation with vertical basic gate(s)
}

/// Configuration for Range Chip
#[derive(Clone, Debug)]
pub struct RangeConfig<F: ScalarField> {
    /// Underlying Gate Configuration
    pub gate: FlexGateConfig<F>,
    /// Special advice (witness) Columns used only for LookUp Table 
    /// Each phase of a halo2 circuit has a distinct lookup_advice column
    ///
    /// * If `gate` has only 1 advice column, enable lookups for that column, in which case `lookup_advice` is empty
    /// * Otherwise, add some user-specified number of `lookup_advice` columns
    /// * In this case, we don't even need a selector so `q_lookup` is empty
    pub lookup_advice: [Vec<Column<Advice>>; MAX_PHASE],
    /// Selector values for the LookUp Table
    pub q_lookup: Vec<Option<Selector>>,
    /// Column for LookUp Table values
    pub lookup: TableColumn,
    /// Defines the number of bits represented in the LookUp Table [0,2^lookup_bits)
    lookup_bits: usize,
    /// Gate Strategy used for specifying advice values
    _strategy: RangeStrategy,
}

impl<F: ScalarField> RangeConfig<F> {

    /// Generates a new RangeConfig
    /// * `meta`: ConstraintSystem
    /// * `range_strategy`: GateStrategy
    /// * `num_advice`: Number of advice columns in each phase
    /// * `num_lookup_advice`: Number of lookup_advice columns in each phase
    /// * `num_fixed`: Number of fixed columns
    /// * `lookup_bits`: Number of bits represented in the LookUp Table [0,2^lookup_bits)
    /// * `circuit_degree`: Size of circuit (i.e., number of rows in circuit)
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

        config.create_lookup(meta);
        config.gate.max_rows = (1 << circuit_degree) - meta.minimum_rows();
        assert!(
            (1 << lookup_bits) <= config.gate.max_rows,
            "lookup table is too large for the circuit degree plus blinding factors!"
        );

        config
    }

    /// Returns the number of bits represented in the LookUp Table [0,2^lookup_bits)
    pub fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    /// Instantiates the LookUp Table 
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
        for la in self.lookup_advice.iter().flat_map(|advices| advices.iter()) {
            meta.lookup("lookup wo selector", |meta| {
                let a = meta.query_advice(*la, Rotation::cur());
                vec![(a, self.lookup)]
            });
        }
    }

    /// Loads the LookUp Table into the circuit using the provided layouter
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

/// Trait that implements methods to constrain a field element number `x` is within a certain number of bits.
pub trait RangeInstructions<F: ScalarField> {

    /// The type of Gate used within the instructions
    type Gate: GateInstructions<F>;

    /// Returns the gate configuration for this range.
    fn gate(&self) -> &Self::Gate;

    /// Returns the gate strategy for this range.
    fn strategy(&self) -> RangeStrategy;

    /// Returns the number of bits the lookup table represents
    fn lookup_bits(&self) -> usize;

    /// Checks that `a` lies in the range [0, 2<sup>range_bits</sup>).
    /// * a: value to be range checked
    /// * range_bits: number of bits to represent the range
    fn range_check(&self, ctx: &mut Context<F>, a: AssignedValue<F>, range_bits: usize);

    /// Check that 'a' is less than 'b' 
    /// * a: value to check
    /// * b: upper bound
    /// * num_bits: number of bits to represent the range
    fn check_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        num_bits: usize,
    );

    /// Checks that `a` is in `[0, b)`.
    /// * a: value to check
    /// * b: upper bound
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `bit_length(b)` bits.
    fn check_less_than_safe(&self, ctx: &mut Context<F>, a: AssignedValue<F>, b: u64) {
        let range_bits =
            (bit_length(b) + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.check_less_than(ctx, a, Constant(self.gate().get_field_element(b)), range_bits)
    }

    /// Checks that `a` is in `[0, b)`.
    /// * a: value to check
    /// * b: upper bound
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `bit_length(b)` bits.
    fn check_big_less_than_safe(&self, ctx: &mut Context<F>, a: AssignedValue<F>, b: BigUint)
    where
        F: BigPrimeField,
    {
        let range_bits =
            (b.bits() as usize + self.lookup_bits() - 1) / self.lookup_bits() * self.lookup_bits();

        self.range_check(ctx, a, range_bits);
        self.check_less_than(ctx, a, Constant(biguint_to_fe(&b)), range_bits)
    }

    /// Returns whether `a` is in `[0, b)`.
    /// * a: value to check
    /// * b: upper bound
    /// * num_bits: number of bits to represent the range
    ///
    /// Warning: This may fail silently if `a` or `b` have more than `num_bits` bits
    fn is_less_than(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>,
        num_bits: usize,
    ) -> AssignedValue<F>;

    /// Returns whether `a` is in `[0, b)`.
    /// * a: value to check
    /// * b: upper bound
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `range_bits` bits.
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

    /// Returns whether `a` is in `[0, b)`.
    /// * a: value to check
    /// * b: upper bound
    ///
    /// Does not require bit assumptions on `a, b` because we range check that `a` has at most `range_bits` bits.
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

    /// Returns `(c, r)` such that `a = b * c + r`.
    /// * a: value to divide
    /// * b: value to divide by
    /// * a_num_bits: number of bits in `a`
    ///
    /// Assumes that `b != 0`.
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
        self.check_big_less_than_safe(
            ctx,
            div,
            BigUint::one().shl(a_num_bits as u32) / &b + BigUint::one(),
        );
        self.check_big_less_than_safe(ctx, rem, b);
        (div, rem)
    }

    /// Returns `(c, r)` such that `a = b * c + r`.
    /// * a: value to divide
    /// * b: value to divide by
    /// * a_num_bits: number of bits in `a`
    /// * b_num_bits: number of bits in `b`
    /// 
    /// Assumes that `b != 0`.
    ///
    /// Let `X = 2 ** b_num_bits`.
    /// Write `a = a1 * X + a0` and `c = c1 * X + c0`.
    /// If we write `b * c0 + r = d1 * X + d0` then
    ///     `b * c + r = (b * c1 + d1) * X + d0`
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
        self.range_check(ctx, div_hi, a_num_bits.saturating_sub(b_num_bits));

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

    /// Returns the last bit of the [a] of a 2^64 bit number
    /// * a: value to get the last bit of
    /// * limb_bits: number of bits in a limb
    /// 
    /// Assume `a` has been range checked already to `limb_bits` bits
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

/// Represents a chip that can be used to constrain a field element number `x` is within a certain number of bits.
#[derive(Clone, Debug)]
pub struct RangeChip<F: ScalarField> {
    /// # RangeChip
    /// Provides methods to constrain a field element number `x` is within a certain number of bits.
    /// Declares a LookUp table of [0, 2**lookup_bits) and constrains whether a field element appears in this table
    /// 
    /// # LookUp bits:
    /// The environment variable DEGREE specifies that the circuit will have 2**DEGREE rows. 
    /// LOOKUP_BITS can be any (nonzero) number less than DEGREE. 
    /// The value of LOOKUP_BITS doesn't affect the functionality of range_check. However, the choice of LOOKUP_BITS will affect circuit performance. 
    /// 
    /// # Guidelines:
    /// If you know you will only do lookups on a fixed number of bits, then set LOOKUP_BITS to that number.
    /// If you will be doing variable length range checks, generally you should set LOOKUP_BITS = DEGREE - 1.

    /// Gate Strategy for advice values in this chip
    strategy: RangeStrategy,
    /// Underlying GateChip 
    pub gate: GateChip<F>,
    /// Defines the number of bits represented in the LookUp Table [0,2^lookup_bits)
    pub lookup_bits: usize,
    /// Vector of 'Limbs' that divide the underlying scalar field element into smaller smaller than lookup_bits
    /// * This allows us to perform range checks on field elements that are larger than the lookup table
    pub limb_bases: Vec<QuantumCell<F>>,
}

impl<F: ScalarField> RangeChip<F> {

    /// Creates a new RangeChip with the given strategy and lookup_bits
    /// * strategy: GateStrategy for advice values in this chip
    /// * lookup_bits: number of bits represented in the LookUp Table [0,2^lookup_bits)
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

    /// Creates a new RangeChip with the default strategy and provided lookup_bits
    /// * lookup_bits: number of bits represented in the LookUp Table [0,2^lookup_bits)
    pub fn default(lookup_bits: usize) -> Self {
        Self::new(RangeStrategy::Vertical, lookup_bits)
    }
}

impl<F: ScalarField> RangeInstructions<F> for RangeChip<F> {
    type Gate = GateChip<F>;

    /// The type of Gate used within the instructions
    fn gate(&self) -> &Self::Gate {
        &self.gate
    }

    /// Returns the gate strategy for this range.
    fn strategy(&self) -> RangeStrategy {
        self.strategy
    }

    /// Defines the number of bits represented in the LookUp Table [0,2^lookup_bits)
    fn lookup_bits(&self) -> usize {
        self.lookup_bits
    }

    /// Checks that `a` lies in the range [0, 2<sup>range_bits</sup>).
    ///
    /// This is done by decomposing `a` into `k` limbs, where `k = (range_bits + lookup_bits - 1) / lookup_bits`.
    /// Each limb is constrained to be within the range [0, 2<sup>lookup_bits</sup>).
    /// The limbs are then combined to form `a` again with the last limb having `rem_bits` number of bits.
    /// 
    /// * `a`: value to be range checked
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

    /// Constrain that 'a' is less than 'b' 
    /// * `a`  - the first cell to compare
    /// * `b`  - the second cell to compare
    /// * `num_bits` - max number of bits to compare
    /// 
    /// Warning: This may fail silently if a or b have more than num_bits
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

    /// Returns whether `a` is in `[0, b)`.
    /// * `a`  - the first cell to compare
    /// * `b`  - the second cell to compare
    /// * `num_bits` - max number of bits to compare
    /// 
    /// Warning: This may fail silently if a or b have more than num_bits
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