use self::{flex_gate::GateStrategy, range::RangeStrategy};
use super::{
    AssignedValue, Context, QuantumCell,
    QuantumCell::{Constant, Existing},
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

pub mod flex_gate;
pub mod range;

pub trait GateInstructions<F: FieldExt> {
    fn strategy(&self) -> GateStrategy;

    fn assign_region(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        gate_offsets: Vec<(isize, Option<[F; 3]>)>,
        gate_index: Option<usize>,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn assign_region_in(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        gate_offsets: Vec<(isize, Option<[F; 3]>)>,
        gate_index: Option<usize>,
        phase: u8,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn assign_region_smart(
        &self,
        ctx: &mut Context<'_, F>,
        inputs: Vec<QuantumCell<F>>,
        gate_offsets: Vec<usize>,
        equality_offsets: Vec<(usize, usize)>,
        external_equality: Vec<(&AssignedValue<F>, usize)>,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn load_zero(&self, ctx: &mut Context<'_, F>) -> Result<AssignedValue<F>, Error>;

    fn add(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn sub(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn neg(&self, ctx: &mut Context<'_, F>, a: &QuantumCell<F>) -> Result<AssignedValue<F>, Error>;

    fn mul(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    /// a * b + c
    fn mul_add(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        c: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn div_unsafe(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let c = a.value().zip(b.value()).map(|(&a, b)| a * b.invert().unwrap());
        let assignments = self.assign_region_smart(
            ctx,
            vec![QuantumCell::Constant(F::from(0)), QuantumCell::Witness(c), b.clone(), a.clone()],
            vec![0],
            vec![],
            vec![],
        )?;
        Ok(assignments[1].clone())
    }

    fn assert_equal(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<(), Error>;

    fn assert_is_const(&self, ctx: &mut Context<'_, F>, a: &AssignedValue<F>, constant: F) {
        ctx.constants_to_assign.push((constant, Some(a.cell())));
    }

    fn inner_product(
        &self,
        ctx: &mut Context<'_, F>,
        vec_a: &Vec<QuantumCell<F>>,
        vec_b: &Vec<QuantumCell<F>>,
    ) -> Result<
        (Option<Vec<AssignedValue<F>>>, Option<Vec<AssignedValue<F>>>, AssignedValue<F>),
        Error,
    >;

    // requires vec_b.len() == vec_a.len() + 1
    // returns
    // x_i = b_1 * (a_1...a_{i - 1})
    //     + b_2 * (a_2...a_{i - 1})
    //     + ...
    //     + b_i
    // Returns [x_1, ..., x_{vec_b.len()}]
    fn accumulated_product(
        &self,
        ctx: &mut Context<'_, F>,
        vec_a: &Vec<QuantumCell<F>>,
        vec_b: &Vec<QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn sum_products_with_coeff_and_var<'a>(
        &self,
        ctx: &mut Context<'_, F>,
        values: &[(F, QuantumCell<F>, QuantumCell<F>)],
        var: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn or(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn and(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn not(&self, ctx: &mut Context<'_, F>, a: &QuantumCell<F>) -> Result<AssignedValue<F>, Error> {
        self.sub(ctx, &QuantumCell::Constant(F::from(1)), a)
    }

    fn select(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        sel: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn or_and(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        c: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn bits_to_indicator(
        &self,
        ctx: &mut Context<'_, F>,
        bits: &Vec<QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn idx_to_indicator(
        &self,
        ctx: &mut Context<'_, F>,
        idx: &QuantumCell<F>,
        len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn select_from_idx(
        &self,
        ctx: &mut Context<'_, F>,
        cells: &Vec<QuantumCell<F>>,
        idx: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let ind = self.idx_to_indicator(ctx, idx, cells.len())?;
        let (_, _, res) = self.inner_product(
            ctx,
            cells,
            &ind.iter().map(|x| QuantumCell::Existing(&x)).collect(),
        )?;
        Ok(res)
    }
}

pub trait RangeInstructions<F: FieldExt> {
    type Gate: GateInstructions<F>;

    fn gate(&self) -> &Self::Gate;
    fn strategy(&self) -> RangeStrategy;

    fn lookup_bits(&self) -> usize;

    fn range_check(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        range_bits: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;

    fn check_less_than(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        num_bits: usize,
    ) -> Result<(), Error>;

    // checks that a in [0, b), does not require bit assumptions on a, b
    fn check_less_than_safe(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        b: usize,
        range_bits: usize,
    ) -> Result<(), Error> {
        assert!(b <= 1 << range_bits);

        self.range_check(ctx, a, range_bits)?;
        self.check_less_than(ctx, &Existing(&a), &Constant(F::from(b as u64)), range_bits)
    }

    fn is_less_than(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
        num_bits: usize,
    ) -> Result<AssignedValue<F>, Error>;

    fn is_less_than_safe(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        b: usize,
        num_bits: usize,
    ) -> Result<AssignedValue<F>, Error> {
        assert!(b <= 1 << num_bits);

        self.range_check(ctx, a, num_bits)?;
        self.is_less_than(ctx, &Existing(&a), &Constant(F::from(b as u64)), num_bits)
    }

    fn is_zero(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn is_equal(
        &self,
        ctx: &mut Context<'_, F>,
        a: &QuantumCell<F>,
        b: &QuantumCell<F>,
    ) -> Result<AssignedValue<F>, Error>;

    fn num_to_bits(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedValue<F>,
        range_bits: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;
}

#[cfg(test)]
pub mod tests;
