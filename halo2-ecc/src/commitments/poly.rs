use crate::bn254::FrChip;
use crate::fields::{
    FieldChip, PrimeField
};

use std::fmt::Debug;
use halo2_base::Context;
use num_bigint::BigUint;
use num_traits::Zero;

/*
 * Polynomial Chip
 */
#[derive(Clone, Debug)]
pub struct PolyChip<'a, F: PrimeField> {
    pub fr_chip: &'a FrChip<'a, F>
}

impl<'a, F: PrimeField> PolyChip<'a, F> {
    pub fn new(fr_chip: &'a FrChip<F>) -> Self {
        Self { fr_chip }
    }

    /*
    * Evaluate a point at a polynomial that is defined by `coeffs`
    */
    pub fn evaluate(
        &self,
        ctx: &mut Context<F>,
        coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        point: &<FrChip<F> as FieldChip<F>>::FieldPoint
    ) -> <FrChip<F> as FieldChip<F>>::FieldPoint {
        let mut acc  = self.fr_chip.load_constant_uint(ctx, BigUint::zero());
        for c in coeffs.iter().rev() {
            let mul_int = self.fr_chip.mul_no_carry(ctx, acc, point);
            acc = self.fr_chip.carry_mod(ctx, mul_int);
            let add_int = self.fr_chip.add_no_carry(ctx, acc, c);
            acc = self.fr_chip.carry_mod(ctx, add_int);
        }
        acc
    }
}
