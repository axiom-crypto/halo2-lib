pub mod builder;
pub mod flex_gate;
// pub mod range;

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
