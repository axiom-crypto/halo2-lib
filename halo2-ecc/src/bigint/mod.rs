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

#[derive(Clone, Debug, PartialEq, Default)]
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
    pub fn new(limbs: Vec<AssignedValue<F>>, max_limb_bits: usize) -> Self {
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

    /// Computes `sum_i limbs[i] * limb_bases[i]` in native field `F`.
    /// In practice assumes `limb_bases[i] = 2^{limb_bits * i}`.
    pub fn evaluate_native(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        limbs: impl IntoIterator<Item = AssignedValue<F>>,
        limb_bases: &[F],
    ) -> AssignedValue<F> {
        // Constrain `out_native = sum_i out_assigned[i] * 2^{n*i}` in `F`
        gate.inner_product(ctx, limbs, limb_bases.iter().map(|c| Constant(*c)))
    }
}

/// Safe wrapper around a BigUint represented as a vector of limbs in **little endian**.
/// The underlying BigUint is represented by
/// sum<sub>i</sub> limbs\[i\] * 2<sup>limb_bits * i</sup>
///
/// To save memory we do not store the `limb_bits` and it must be inferred from context.
#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct ProperUint<F: ScalarField>(pub(crate) Vec<AssignedValue<F>>);

impl<F: ScalarField> ProperUint<F> {
    pub fn limbs(&self) -> &[AssignedValue<F>] {
        self.0.as_slice()
    }

    pub fn into_overflow(self, limb_bits: usize) -> OverflowInteger<F> {
        OverflowInteger::new(self.0, limb_bits)
    }

    /// Computes `sum_i limbs[i] * limb_bases[i]` in native field `F`.
    /// In practice assumes `limb_bases[i] = 2^{limb_bits * i}`.
    ///
    /// Assumes that `value` is the underlying BigUint value represented by `self`.
    pub fn into_crt(
        self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        value: BigUint,
        limb_bases: &[F],
        limb_bits: usize,
    ) -> ProperCrtUint<F> {
        // Constrain `out_native = sum_i out_assigned[i] * 2^{n*i}` in `F`
        let native =
            OverflowInteger::evaluate_native(ctx, gate, self.0.iter().copied(), limb_bases);
        ProperCrtUint(CRTInteger::new(self.into_overflow(limb_bits), native, value.into()))
    }
}

#[repr(transparent)]
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

    pub fn assign(self, ctx: &mut Context<F>) -> ProperUint<F> {
        let assigned_limbs = self.limbs.into_iter().map(|limb| ctx.load_constant(limb)).collect();
        ProperUint(assigned_limbs)
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

        OverflowInteger::new(out_limbs, limb_bits)
    }
}

#[derive(Clone, Debug)]
pub struct CRTInteger<F: ScalarField> {
    // keep track of an integer `a` using CRT as `a mod 2^t` and `a mod n`
    // where `t = truncation.limbs.len() * truncation.limb_bits`
    //       `n = modulus::<F>`
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

impl<F: ScalarField> AsRef<CRTInteger<F>> for CRTInteger<F> {
    fn as_ref(&self) -> &CRTInteger<F> {
        self
    }
}

// Cloning all the time impacts readability so we'll just implement From<&T> for T
impl<'a, F: ScalarField> From<&'a CRTInteger<F>> for CRTInteger<F> {
    fn from(x: &'a CRTInteger<F>) -> Self {
        x.clone()
    }
}

impl<F: ScalarField> CRTInteger<F> {
    pub fn new(truncation: OverflowInteger<F>, native: AssignedValue<F>, value: BigInt) -> Self {
        Self { truncation, native, value }
    }

    pub fn native(&self) -> &AssignedValue<F> {
        &self.native
    }

    pub fn limbs(&self) -> &[AssignedValue<F>] {
        self.truncation.limbs.as_slice()
    }
}

/// Safe wrapper for representing a BigUint as a [`CRTInteger`] whose underlying BigUint value is in `[0, 2^t)`
/// where `t = truncation.limbs.len() * limb_bits`. This struct guarantees that
/// * each `truncation.limbs[i]` is ranged checked to be in `[0, 2^limb_bits)`,
/// * `native` is the evaluation of `sum_i truncation.limbs[i] * 2^{limb_bits * i} (mod modulus::<F>)` in the native field `F`
/// * `value` is equal to `sum_i truncation.limbs[i] * 2^{limb_bits * i}` as integers
///
/// Note this means `native` and `value` are completely determined by `truncation`. However, we still store them explicitly for convenience.
#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct ProperCrtUint<F: ScalarField>(pub(crate) CRTInteger<F>);

impl<F: ScalarField> AsRef<CRTInteger<F>> for ProperCrtUint<F> {
    fn as_ref(&self) -> &CRTInteger<F> {
        &self.0
    }
}

impl<'a, F: ScalarField> From<&'a ProperCrtUint<F>> for ProperCrtUint<F> {
    fn from(x: &'a ProperCrtUint<F>) -> Self {
        x.clone()
    }
}

// cannot blanket implement From<Proper<T>> for T because of Rust
impl<F: ScalarField> From<ProperCrtUint<F>> for CRTInteger<F> {
    fn from(x: ProperCrtUint<F>) -> Self {
        x.0
    }
}

impl<'a, F: ScalarField> From<&'a ProperCrtUint<F>> for CRTInteger<F> {
    fn from(x: &'a ProperCrtUint<F>) -> Self {
        x.0.clone()
    }
}

impl<F: ScalarField> From<ProperCrtUint<F>> for ProperUint<F> {
    fn from(x: ProperCrtUint<F>) -> Self {
        ProperUint(x.0.truncation.limbs)
    }
}

impl<F: ScalarField> ProperCrtUint<F> {
    pub fn limbs(&self) -> &[AssignedValue<F>] {
        self.0.limbs()
    }

    pub fn native(&self) -> &AssignedValue<F> {
        self.0.native()
    }

    pub fn value(&self) -> BigUint {
        self.0.value.to_biguint().expect("Value of proper uint should not be negative")
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

impl<F: BigPrimeField> FixedCRTInteger<F> {
    pub fn new(truncation: FixedOverflowInteger<F>, value: BigUint) -> Self {
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
    ) -> ProperCrtUint<F> {
        let assigned_truncation = self.truncation.assign(ctx).into_overflow(limb_bits);
        let assigned_native = ctx.load_constant(biguint_to_fe(&(&self.value % native_modulus)));
        ProperCrtUint(CRTInteger::new(assigned_truncation, assigned_native, self.value.into()))
    }
}
