use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::plonk::Error,
    utils::{decompose, BigPrimeField},
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;

use crate::secp256k1::util::{bits_le_to_fe, bits_le_to_fe_assigned, fe_to_bits_le};

#[derive(Debug, Clone)]
pub struct SpreadChip<'a, F: BigPrimeField> {
    lookup_bits: usize,
    range: &'a RangeChip<F>,
}

impl<'a, F: BigPrimeField> SpreadChip<'a, F> {
    pub fn new(range: &'a RangeChip<F>, lookup_bits: usize) -> Self {
        debug_assert_eq!(16 % lookup_bits, 0);

        Self { range, lookup_bits }
    }
    pub fn spread(
        &self,
        ctx: &mut Context<F>,
        dense: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let gate = self.range.gate();
        let limb_bits = self.lookup_bits;
        let num_limbs = 16 / limb_bits;
        let limbs = decompose(dense.value(), num_limbs, limb_bits);
        let assigned_limbs = ctx.assign_witnesses(limbs);
        {
            let mut limbs_sum = ctx.load_zero();
            for (idx, limb) in assigned_limbs.iter().copied().enumerate() {
                limbs_sum = gate.mul_add(
                    ctx,
                    QuantumCell::Existing(limb),
                    QuantumCell::Constant(F::from(1 << (limb_bits * idx))),
                    QuantumCell::Existing(limbs_sum),
                );
            }
            ctx.constrain_equal(&limbs_sum, dense);
        }
        let mut assigned_spread = ctx.load_zero();
        for (idx, limb) in assigned_limbs.iter().enumerate() {
            let spread_limb = self.spread_limb(ctx, limb)?;
            assigned_spread = gate.mul_add(
                ctx,
                QuantumCell::Existing(spread_limb),
                QuantumCell::Constant(F::from(1 << (2 * limb_bits * idx))),
                QuantumCell::Existing(assigned_spread),
            );
        }
        Ok(assigned_spread)
    }

    pub fn decompose_even_and_odd_unchecked(
        &self,
        ctx: &mut Context<F>,
        spread: &AssignedValue<F>,
    ) -> Result<(AssignedValue<F>, AssignedValue<F>), Error> {
        let bits = fe_to_bits_le(spread.value(), 32);
        let even_bits = (0..bits.len() / 2).map(|idx| bits[2 * idx]).collect_vec();
        let odd_bits = (0..bits.len() / 2).map(|idx| bits[2 * idx + 1]).collect_vec();
        let (even_val, odd_val) = (bits_le_to_fe(&even_bits), bits_le_to_fe(&odd_bits));
        let even_assigned = ctx.load_witness(even_val);
        let odd_assigned = ctx.load_witness(odd_val);
        self.range.range_check(ctx, even_assigned, 16);
        self.range.range_check(ctx, odd_assigned, 16);
        Ok((even_assigned, odd_assigned))
    }

    fn spread_limb(
        &self,
        ctx: &mut Context<F>,
        limb: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let range = self.range;

        let limb_bits = fe_to_bits_le(limb.value(), 32);
        let assigned_limb_bits =
            limb_bits.iter().map(|bit| ctx.load_constant(F::from(*bit))).collect_vec();

        let limb_sum = bits_le_to_fe_assigned(ctx, range, &assigned_limb_bits)?;
        ctx.constrain_equal(&limb_sum, limb);

        let mut assigned_spread_bits = vec![ctx.load_zero(); limb_bits.len() * 2];
        for i in 0..assigned_limb_bits.len() {
            assigned_spread_bits[2 * i] = assigned_limb_bits[i];
        }

        let assigned_spread = bits_le_to_fe_assigned(ctx, range, &assigned_spread_bits)?;

        Ok(assigned_spread)
    }

    pub fn range(&self) -> &RangeChip<F> {
        self.range
    }
}
