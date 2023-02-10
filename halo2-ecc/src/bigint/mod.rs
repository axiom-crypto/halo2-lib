use crate::halo2_proofs::circuit::Cell;
use halo2_base::{
    gates::flex_gate::GateInstructions,
    utils::{biguint_to_fe, decompose_biguint, fe_to_biguint, BigPrimeField, ScalarField},
    AssignedValue, Context,
    QuantumCell::Constant,
};
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;

pub mod add_no_carry;
pub mod big_is_equal;
pub mod big_is_zero;
pub mod big_less_than;
pub mod carry_mod;
pub mod check_carry_mod_to_zero;
pub mod check_carry_to_zero;
pub mod mul_no_carry;
pub mod negative;
pub mod scalar_mul_and_add_no_carry;
pub mod scalar_mul_no_carry;
pub mod select;
pub mod select_by_indicator;
pub mod sub;
pub mod sub_no_carry;

#[derive(Clone, Debug, PartialEq)]
#[derive(Default)]
pub enum BigIntStrategy {
    // use existing gates
    #[default]
    Simple,
    // vertical custom gates of length 4 for dot product between an unknown vector and a constant vector, both of length 3
    // we restrict to gate of length 4 since this uses the same set of evaluation points Rotation(0..=3) as our simple gate
    // CustomVerticalShort,
}



#[derive(Clone, Debug)]
pub struct OverflowInteger<F: ScalarField> {
    pub limbs: Vec<AssignedValue<F>>,
    // max bits of a limb, ignoring sign
    pub max_limb_bits: usize,
    // the standard limb bit that we use for pow of two limb base - to reduce overhead we just assume this is inferred from context (e.g., the chip stores it), so we stop storing it here
    // pub limb_bits: usize,
}

impl<F: ScalarField> OverflowInteger<F> {
    pub fn construct(limbs: Vec<AssignedValue<F>>, max_limb_bits: usize) -> Self {
        Self { limbs, max_limb_bits }
    }

    // convenience function for testing
    #[cfg(test)]
    pub fn to_bigint(&self, limb_bits: usize) -> BigInt
    where
        F: BigPrimeField,
    {
        use halo2_base::utils::fe_to_bigint;

        self.limbs
            .iter()
            .rev()
            .fold(BigInt::zero(), |acc, acell| (acc << limb_bits) + fe_to_bigint(acell.value()))
    }

    pub fn evaluate(
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
        limbs: impl IntoIterator<Item = AssignedValue<F>>,
        limb_bases: impl IntoIterator<Item = F>,
    ) -> AssignedValue<F> {
        // Constrain `out_native = sum_i out_assigned[i] * 2^{n*i}` in `F`
        gate.inner_product(ctx, limbs, limb_bases.into_iter().map(|c| Constant(c)))
    }
}

#[derive(Clone, Debug)]
pub struct FixedOverflowInteger<F: ScalarField> {
    pub limbs: Vec<F>,
}

impl<F: BigPrimeField> FixedOverflowInteger<F> {
    pub fn construct(limbs: Vec<F>) -> Self {
        Self { limbs }
    }

    /// Input: a BigInteger `value`, Output: the `FixedOverflowInteger` that represents the same value
    /// Can handle signs
    /// Note the representation of the integer will be in proper (no overflow) format, if signs are interpretted correctly
    pub fn from_native(value: &BigUint, num_limbs: usize, limb_bits: usize) -> Self {
        let limbs = decompose_biguint(value, num_limbs, limb_bits);
        Self { limbs }
    }

    pub fn to_bigint(&self, limb_bits: usize) -> BigUint {
        self.limbs
            .iter()
            .rev()
            .fold(BigUint::zero(), |acc, x| (acc << limb_bits) + fe_to_biguint(x))
    }

    pub fn assign(self, ctx: &mut Context<F>, limb_bits: usize) -> OverflowInteger<F> {
        let assigned_limbs = self.limbs.into_iter().map(|limb| ctx.load_constant(limb)).collect();
        OverflowInteger::construct(assigned_limbs, limb_bits)
    }

    /// only use case is when coeffs has only a single 1, rest are 0
    pub fn select_by_indicator(
        gate: &impl GateInstructions<F>,
        ctx: &mut Context<F>,
        a: &[Self],
        coeffs: &[AssignedValue<F>],
        limb_bits: usize,
    ) -> OverflowInteger<F> {
        let k = a[0].limbs.len();

        let out_limbs = (0..k)
            .map(|idx| {
                let int_limbs = a.iter().map(|a| Constant(a.limbs[idx]));
                gate.select_by_indicator(ctx, int_limbs, coeffs.iter().copied())
            })
            .collect();

        OverflowInteger::construct(out_limbs, limb_bits)
    }
}

#[derive(Clone, Debug)]
pub struct CRTInteger<F: ScalarField> {
    // keep track of an integer `a` using CRT as `a mod 2^t` and `a mod n`
    // where `t = truncation.limbs.len() * truncation.limb_bits`
    //       `n = modulus::<Fn>`
    // `value` is the actual integer value we want to keep track of

    // we allow `value` to be a signed BigInt
    // however `value` is really an element of Z/(2^t * n), so signs are only meaningful if:
    // ASSUME `abs(value) < 2^t * n / 2`

    // the IMPLICIT ASSUMPTION: `value (mod 2^t) = truncation` && `value (mod n) = native`
    // this struct should only be used if the implicit assumption above is satisfied
    pub truncation: OverflowInteger<F>,
    pub native: AssignedValue<F>,
    pub value: BigInt,
}

impl<F: ScalarField> CRTInteger<F> {
    pub fn construct(
        truncation: OverflowInteger<F>,
        native: AssignedValue<F>,
        value: BigInt,
    ) -> Self {
        Self { truncation, native, value }
    }

    pub fn native(&self) -> &AssignedValue<F> {
        &self.native
    }

    pub fn limbs(&self) -> &[AssignedValue<F>] {
        self.truncation.limbs.as_slice()
    }
}

#[derive(Clone, Debug)]
pub struct FixedCRTInteger<F: ScalarField> {
    // keep track of an integer `a` using CRT as `a mod 2^t` and `a mod n`
    // where `t = truncation.limbs.len() * truncation.limb_bits`
    //       `n = modulus::<Fn>`
    // `value` is the actual integer value we want to keep track of

    // we allow `value` to be a signed BigInt
    // however `value` is really an element of Z/(2^t * n), so signs are only meaningful if:
    // ASSUME `abs(value) < 2^t * n / 2`

    // the IMPLICIT ASSUMPTION: `value (mod 2^t) = truncation` && `value (mod n) = native`
    // this struct should only be used if the implicit assumption above is satisfied
    pub truncation: FixedOverflowInteger<F>,
    pub value: BigUint,
}

#[derive(Clone, Debug)]
pub struct FixedAssignedCRTInteger<F: ScalarField> {
    pub truncation: FixedOverflowInteger<F>,
    pub limb_fixed_cells: Vec<Cell>,
    pub value: BigUint,
}

impl<F: BigPrimeField> FixedCRTInteger<F> {
    pub fn construct(truncation: FixedOverflowInteger<F>, value: BigUint) -> Self {
        Self { truncation, value }
    }

    /// Input: a BigInteger `value`, Output: the `FixedCRTInteger` that represents the same value
    /// Can handle signs
    pub fn from_native(value: BigUint, num_limbs: usize, limb_bits: usize) -> Self {
        let truncation = FixedOverflowInteger::from_native(&value, num_limbs, limb_bits);
        Self { truncation, value }
    }

    pub fn assign(
        self,
        ctx: &mut Context<F>,
        limb_bits: usize,
        native_modulus: &BigUint,
    ) -> CRTInteger<F> {
        let assigned_truncation = self.truncation.assign(ctx, limb_bits);
        let assigned_native = ctx.load_constant(biguint_to_fe(&(&self.value % native_modulus)));
        CRTInteger::construct(assigned_truncation, assigned_native, self.value.into())
    }
}
