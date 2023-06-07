use std::marker::PhantomData;

/*
 * Chip for constraining common polynomial operations. 
 */
use crate::{fields::{FieldChip, PrimeField}};

use halo2_base::Context;
use num_bigint::BigUint;
use num_traits::Zero;

pub struct PolyChip<'a, F: PrimeField, FC: FieldChip<F>> where
{
    pub fr_chip: &'a FC,
    pub phantom_data: PhantomData<F>,
}

impl<'a, F: PrimeField, FC: FieldChip<F>> PolyChip<'a, F, FC> {
    pub fn new(fr_chip: &'a FC) -> Self {
        Self { fr_chip, phantom_data: PhantomData }
    }

    /*
     * Evaluate a point at a polynomial that is defined by `coeffs`.
     */
    pub fn evaluate(
        &self,
        ctx: &mut Context<F>,
        coeffs: &Vec<<FC as FieldChip<F>>::FieldPoint>,
        point: &<FC as FieldChip<F>>::FieldPoint,
    ) -> <FC as FieldChip<F>>::FieldPoint {
        let mut acc = self.fr_chip.load_constant(ctx, <FC as FieldChip<F>>::FieldType::zero());
        for c in coeffs.iter().rev() {
            let mul_int = self.fr_chip.mul_no_carry(ctx, acc, point);
            acc = self.fr_chip.carry_mod(ctx, mul_int);
            let add_int = self.fr_chip.add_no_carry(ctx, acc, c);
            acc = self.fr_chip.carry_mod(ctx, add_int);
        }
        acc
    }
}
