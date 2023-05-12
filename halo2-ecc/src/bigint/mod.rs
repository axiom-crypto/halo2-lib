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

/// Tests
#[cfg(any(test, feature = "test-utils"))]
pub mod tests;

/// Specifies the Gate Strategy for the BigInt.
#[derive(Clone, Debug, PartialEq)]
#[derive(Default)]
pub enum BigIntStrategy {
    /// # Simple  Gate Strategy:
    /// - Vertical custom gate of length 4.
    /// - Performs the dot product between an unknown vector and a constant vector, both of length 3.
    /// The gates length is restricted to length 4
    #[default]
    Simple,
    // vertical custom gates of length 4 for dot product between an unknown vector and a constant vector, both of length 3
    // we restrict to gate of length 4 since this uses the same set of evaluation points Rotation(0..=3) as our simple gate
    // CustomVerticalShort,
}

/// [OverflowInteger] defines the integer value over F/(2<sup>t</sup>) represented as a [Vec] of [AssignedValue<F>] `limbs` assigned as witnesses in the circuit.
/// 
/// Individual `limbs` are allowed to overflow during Field operations, and are lazy evaluated when `carry_mod::crt` is called.
#[derive(Clone, Debug)]
pub struct OverflowInteger<F: ScalarField> {
    /// Vector of `limb` values for the integer
    pub limbs: Vec<AssignedValue<F>>,
    /// Maximum bit length of a `limb`, ignoring sign
    pub max_limb_bits: usize,
    // the standard limb bit that we use for pow of two limb base - to reduce overhead we just assume this is inferred from context (e.g., the chip stores it), so we stop storing it here
    // pub limb_bits: usize,
}

impl<F: ScalarField> OverflowInteger<F> {
    /// Constructs a new [OverflowInteger] from a [Vec] of [AssignedValue<F>] `limbs` each at most `max_limb_bits` in length ignoring sign.
    /// * `limbs`: [Vec] of [AssignedValue<F>] `limb`s that define an integer value in F/(2^t).
    /// * `max_limb_bits`: Maximum bit length of a `limb`, ignoring sign.
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

    /// Constrains and evaluates the native [ScalarField] integer value [OverflowInteger] represents in F/(2^t) as [Constant] values in the circuit.
    ///
    /// Returns native value of [OverflowInteger] by taking the inner product of <limbs, limb_bases> in `F`
    /// 
    /// Assumes `value (mod 2^t) = truncation`
    /// 
    /// * `gate`: [GateInstructions] that defines the gate strategy for the integer.
    /// * `ctx`: [Context] that defines the circuit context.
    /// * `limbs`: [Iterator] of [AssignedValue<F>] `limb`s that define an integer value in F/(2^t).
    /// * `limb_bases`: [Iterator] of `limb` bases for the integer, i.e., `limb_bases[i]` = 2<sup>(i*max_limb_bits)</sup>.
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

/// [FixedOverflowInteger] defines the integer value over F/(2<sup>t</sup>) represented as a [Vec] of [F] `limbs` assigned as Fixed values in the circuit.
/// 
/// Note: Individual `limbs` are assigned as Fixed values in the circuit and can not overflow during Field operations.
#[derive(Clone, Debug)]
pub struct FixedOverflowInteger<F: ScalarField> {
    pub limbs: Vec<F>,
}

impl<F: BigPrimeField> FixedOverflowInteger<F> {
    /// Constructs a new [FixedOverflowInteger] from a [Vec] of limbs represented as [F] each at most `max_limb_bits` in length ignoring sign
    /// * `limbs`: [Vec] of [F] `limb`s that define an integer value in F/(2^t).
    pub fn construct(limbs: Vec<F>) -> Self {
        Self { limbs }
    }

    /// Constructs a new [FixedOverflowInteger] from a [BigUint] `value` by decomposing it into `num_limbs` each at most `limb_bits` in length.
    /// Can handle signs.
    /// 
    /// Note: the representation of the integer will be in proper (no overflow) format, if signs are interpretted correctly
    /// * `value`: [BigUint] value to be represented as a [FixedOverflowInteger].
    /// * `num_limbs`: Number of `limbs` to represent the integer value.
    /// * `limb_bits`: Maximum bit length of a `limb`, ignoring sign.
    pub fn from_native(value: &BigUint, num_limbs: usize, limb_bits: usize) -> Self {
        let limbs = decompose_biguint(value, num_limbs, limb_bits);
        Self { limbs }
    }

    /// Returns the integer value [FixedOverflowInteger] represents in F/(2^t) as an [BigUint] value.
    /// * `limb_bits`: Maximum bit length of a `limb`, ignoring sign
    pub fn to_bigint(&self, limb_bits: usize) -> BigUint {
        self.limbs
            .iter()
            .rev()
            .fold(BigUint::zero(), |acc, x| (acc << limb_bits) + fe_to_biguint(x))
    }

    /// Assigns the `limbs` of [FixedOverflowInteger] to the circuit as [Constant].
    ///
    /// Returns the underlying value as an [OverflowInteger].
    /// * `limb_bits`: Maximum bit length of a `limb`, ignoring sign
    pub fn assign(self, ctx: &mut Context<F>, limb_bits: usize) -> OverflowInteger<F> {
        let assigned_limbs = self.limbs.into_iter().map(|limb| ctx.load_constant(limb)).collect();
        OverflowInteger::construct(assigned_limbs, limb_bits)
    }

    /// Constrains and selects the `limb` values of [FixedOverflowInteger] as [Constant] values in the circuit.
    /// * gate: [GateInstructions] that defines the gate strategy for the integer.
    /// * ctx: [Context] that defines the circuit context.
    /// * a: [FixedOverflowInteger] to be constrained and selected.
    /// * coeffs: [Iterator] of [AssignedValue<F>] `coeff`s that define the indicator coefficiants of the linear combination of `limbs` to be constrained and selected.
    /// * limb_bits: Maximum bit length of a `limb`, ignoring sign
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

/// Represents an integer `value` in Chinese Remainder Theorem Form.
/// 
/// To avoid expensive operations in native field F/(n), we treat `value` in CRT form as an element of F/(2^t * n) 
/// which forms a bijection with `F/(2^t) x F/(n)`, where `t = truncation.limbs.len() * truncation.limb_bits` and `n = modulus::<F>`.
/// 
/// [CRTInteger] tracks the corresponding integer value of `value` in F/(2^t) and F/(n) as `truncation` and 'native` respectively such that:
/// 
/// `value mod(2^t)` = `truncation`
/// 
/// `value mod(n)` = `native`
/// 
/// Satisfying the CRT Theorem.
/// 
/// Addition and multiplication are performed on `truncate` and `native`, and conversion to the native field is performed lazily by calling `carry_mod::crt()` operations.
/// 
/// The limb values of `truncate` are assigned as witness values to the circuit allowing for overflow in each limb 
/// when performing Field operations and is resolved by performing carry_mod::crt().
/// 
/// Assumes `value (mod 2^t) = truncation` && `value (mod n) = native`
///
/// Note: `value` is expressed as a signed [BigInt] however as this is an element of z/(2^t * n) signs are only meaningful if abs(`value`) < 2<sup>t</sup> * n / 2
/// 
/// For me information on CRT form, see the Readme.md in the `bigint` module.
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
    /// Integer value of [CRTInteger] in F/(2^t), such that `value mod 2^t = truncation`
    pub truncation: OverflowInteger<F>,
    /// Integer value of [CRTInteger] in F/(n), such that `value mod n = native`
    pub native: AssignedValue<F>,
    /// the actual integer value of CRTInteger as a signed [BigInt]
    pub value: BigInt,
}

impl<F: ScalarField> CRTInteger<F> {
    /// Constructs a new [CRTInteger].
    /// * `truncation`: [Iterator] of limbs that represents the integer value of `value` mod 2^t
    /// * `native`: [AssignedValue] witness that represents the integer value of `value` mod n
    /// * `value`: [BigInt] representing the actual integer value of [CRTInteger].
    pub fn construct(
        truncation: OverflowInteger<F>,
        native: AssignedValue<F>,
        value: BigInt,
    ) -> Self {
        Self { truncation, native, value }
    }

    /// Returns the `native` integer value of [CRTInteger] in F/(n).
    pub fn native(&self) -> &AssignedValue<F> {
        &self.native
    }

    /// Returns the `limbs` values of the integer value of [CRTInteger] in F/(2^t).
    pub fn limbs(&self) -> &[AssignedValue<F>] {
        self.truncation.limbs.as_slice()
    }
}

/// Represents an integer `value` in Chinese Remainder Theorem Form.
/// 
/// To avoid expensive operations in native field F/(n), we treat `value` in CRT form as an element of F/(2^t * n) 
/// which forms a bijection with `F/(2^t) x F/(n)`, where `t = truncation.limbs.len() * truncation.limb_bits` and `n = modulus::<F>`.
/// 
/// [FixedCRTInteger] tracks the corresponding integer value of `value` in F/(2^t) and F/(n) as `truncation` and 'native` respectively such that:
/// 
/// `value mod(2^t)` = `truncation`
/// 
/// `value mod(n)` = `native`
/// 
/// Satisfying the CRT Theorem.
/// 
/// Addition and multiplication are performed on `truncate` and `native`, and conversion to the native field is performed lazily by calling `carry_mod::crt()` operations.
/// 
/// The limb values of `truncate` are assigned as [Constant] values to the circuit not allowing for overflow in each limb 
/// when performing Field operations.
/// 
/// Assumes `value (mod 2^t) = truncation` && `value (mod n) = native`
///
/// Note: `value` is expressed as a signed [BigInt] however as this is an element of z/(2^t * n) signs are only meaningful if abs(`value`) < 2<sup>t</sup> * n / 2
/// 
/// For me information on CRT form, see the Readme.md in the `bigint` module.
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
    /// [FixedOverflowInteger] representing the integer value of [FixedCRTInteger] in F/(2^t), such that `value mod 2^t = truncation`
    pub truncation: FixedOverflowInteger<F>,
    /// [BigUint] representing the integer value of [FixedCRTInteger] in F/(n), such that `value mod n = native`
    pub value: BigUint,
}

//TODO: Can we delete this???
// isn't allowed to overflow
#[derive(Clone, Debug)]
pub struct FixedAssignedCRTInteger<F: ScalarField> {
    pub truncation: FixedOverflowInteger<F>,
    pub limb_fixed_cells: Vec<Cell>,
    pub value: BigUint,
}

impl<F: BigPrimeField> FixedCRTInteger<F> {
    /// Constructs a new [FixedCRTInteger] from a [FixedOverflowInteger] `truncation` and a [BigUint] `value`.
    /// * `truncation`: [FixedOverflowInteger] representing the integer value of `value` in Z/(2^t)
    /// * `value`: [BigUint] representing the actual integer value of [FixedCRTInteger] in Z/(2^t * n).
    pub fn construct(truncation: FixedOverflowInteger<F>, value: BigUint) -> Self {
        Self { truncation, value }
    }

    /// Constructs a new [FixedOverflowInteger] from a [BigUint] `value` by decomposing it into `num_limbs` each at most `limb_bits` in length.
    /// Can handle signs.
    /// 
    /// Note: the representation of the integer will be in proper (no overflow) format, if signs are interpretted correctly
    /// * `value`: [BigUint] value to be represented as a [FixedCRTInteger].
    /// * `num_limbs`: Number of `limbs` to represent the integer value.
    /// * `limb_bits`: Maximum bit length of a `limb`, ignoring sign.
    pub fn from_native(value: BigUint, num_limbs: usize, limb_bits: usize) -> Self {
        let truncation = FixedOverflowInteger::from_native(&value, num_limbs, limb_bits);
        Self { truncation, value }
    }

    /// Assigns the [FixedCRTInteger] to the circuit a [Constant] value and returns the assigned values as a [CRTInteger].
    /// * `ctx`: [Context] to assign the [FixedCRTInteger] to.
    /// * `limb_bits`: Number of bits in each limb.
    /// * `native_modulus`: [BigUint] representing the modulus of the native field.
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
