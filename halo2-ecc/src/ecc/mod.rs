#![allow(non_snake_case)]
use crate::ff::Field;
use crate::fields::{fp::FpChip, FieldChip, Selectable};
use crate::group::{Curve, Group};
use crate::halo2_proofs::arithmetic::CurveAffine;
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::utils::{modulus, BigPrimeField};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::CurveAffineExt,
    AssignedValue, Context,
};
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::marker::PhantomData;

pub mod ecdsa;
pub mod fixed_base;
// pub mod fixed_base_pippenger;
pub mod pippenger;

// EcPoint and EccChip take in a generic `FieldChip` to implement generic elliptic curve operations on arbitrary field extensions (provided chip exists) for short Weierstrass curves (currently further assuming a4 = 0 for optimization purposes)
#[derive(Debug)]
pub struct EcPoint<F: BigPrimeField, FieldPoint> {
    pub x: FieldPoint,
    pub y: FieldPoint,
    _marker: PhantomData<F>,
}

impl<F: BigPrimeField, FieldPoint: Clone> Clone for EcPoint<F, FieldPoint> {
    fn clone(&self) -> Self {
        Self { x: self.x.clone(), y: self.y.clone(), _marker: PhantomData }
    }
}

// Improve readability by allowing `&EcPoint` to be converted to `EcPoint` via cloning
impl<'a, F: BigPrimeField, FieldPoint: Clone> From<&'a EcPoint<F, FieldPoint>>
    for EcPoint<F, FieldPoint>
{
    fn from(value: &'a EcPoint<F, FieldPoint>) -> Self {
        value.clone()
    }
}

impl<F: BigPrimeField, FieldPoint> EcPoint<F, FieldPoint> {
    pub fn new(x: FieldPoint, y: FieldPoint) -> Self {
        Self { x, y, _marker: PhantomData }
    }

    pub fn x(&self) -> &FieldPoint {
        &self.x
    }

    pub fn y(&self) -> &FieldPoint {
        &self.y
    }
}

/// An elliptic curve point where it is easy to compare the x-coordinate of two points
#[derive(Clone, Debug)]
pub struct StrictEcPoint<F: BigPrimeField, FC: FieldChip<F>> {
    pub x: FC::ReducedFieldPoint,
    pub y: FC::FieldPoint,
    _marker: PhantomData<F>,
}

impl<F: BigPrimeField, FC: FieldChip<F>> StrictEcPoint<F, FC> {
    pub fn new(x: FC::ReducedFieldPoint, y: FC::FieldPoint) -> Self {
        Self { x, y, _marker: PhantomData }
    }
}

impl<F: BigPrimeField, FC: FieldChip<F>> From<StrictEcPoint<F, FC>> for EcPoint<F, FC::FieldPoint> {
    fn from(value: StrictEcPoint<F, FC>) -> Self {
        Self::new(value.x.into(), value.y)
    }
}

impl<'a, F: BigPrimeField, FC: FieldChip<F>> From<&'a StrictEcPoint<F, FC>>
    for EcPoint<F, FC::FieldPoint>
{
    fn from(value: &'a StrictEcPoint<F, FC>) -> Self {
        value.clone().into()
    }
}

/// An elliptic curve point where the x-coordinate has already been constrained to be reduced or not.
/// In the reduced case one can more optimally compare equality of x-coordinates.
#[derive(Clone, Debug)]
pub enum ComparableEcPoint<F: BigPrimeField, FC: FieldChip<F>> {
    Strict(StrictEcPoint<F, FC>),
    NonStrict(EcPoint<F, FC::FieldPoint>),
}

impl<F: BigPrimeField, FC: FieldChip<F>> From<StrictEcPoint<F, FC>> for ComparableEcPoint<F, FC> {
    fn from(pt: StrictEcPoint<F, FC>) -> Self {
        Self::Strict(pt)
    }
}

impl<F: BigPrimeField, FC: FieldChip<F>> From<EcPoint<F, FC::FieldPoint>>
    for ComparableEcPoint<F, FC>
{
    fn from(pt: EcPoint<F, FC::FieldPoint>) -> Self {
        Self::NonStrict(pt)
    }
}

impl<'a, F: BigPrimeField, FC: FieldChip<F>> From<&'a StrictEcPoint<F, FC>>
    for ComparableEcPoint<F, FC>
{
    fn from(pt: &'a StrictEcPoint<F, FC>) -> Self {
        Self::Strict(pt.clone())
    }
}

impl<'a, F: BigPrimeField, FC: FieldChip<F>> From<&'a EcPoint<F, FC::FieldPoint>>
    for ComparableEcPoint<F, FC>
{
    fn from(pt: &'a EcPoint<F, FC::FieldPoint>) -> Self {
        Self::NonStrict(pt.clone())
    }
}

impl<F: BigPrimeField, FC: FieldChip<F>> From<ComparableEcPoint<F, FC>>
    for EcPoint<F, FC::FieldPoint>
{
    fn from(pt: ComparableEcPoint<F, FC>) -> Self {
        match pt {
            ComparableEcPoint::Strict(pt) => Self::new(pt.x.into(), pt.y),
            ComparableEcPoint::NonStrict(pt) => pt,
        }
    }
}

// Implements:
//  Given P = (x_1, y_1) and Q = (x_2, y_2), ecc points over the field F_p
//      assume x_1 != x_2
//  Find ec addition P + Q = (x_3, y_3)
// By solving:
//  lambda = (y_2-y_1)/(x_2-x_1) using constraint
//  lambda * (x_2 - x_1) = y_2 - y_1
//  x_3 = lambda^2 - x_1 - x_2 (mod p)
//  y_3 = lambda (x_1 - x_3) - y_1 mod p
//
/// If `is_strict = true`, then this function constrains that `P.x != Q.x`.
/// If you are calling this with `is_strict = false`, you must ensure that `P.x != Q.x` by some external logic (such
/// as a mathematical theorem).
///
/// # Assumptions
/// * Neither `P` nor `Q` is the point at infinity (undefined behavior otherwise)
pub fn ec_add_unequal<F: BigPrimeField, FC: FieldChip<F>>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: impl Into<ComparableEcPoint<F, FC>>,
    Q: impl Into<ComparableEcPoint<F, FC>>,
    is_strict: bool,
) -> EcPoint<F, FC::FieldPoint> {
    let (P, Q) = check_points_are_unequal(chip, ctx, P, Q, is_strict);

    let dx = chip.sub_no_carry(ctx, &Q.x, &P.x);
    let dy = chip.sub_no_carry(ctx, Q.y, &P.y);
    let lambda = chip.divide_unsafe(ctx, dy, dx);

    //  x_3 = lambda^2 - x_1 - x_2 (mod p)
    let lambda_sq = chip.mul_no_carry(ctx, &lambda, &lambda);
    let lambda_sq_minus_px = chip.sub_no_carry(ctx, lambda_sq, &P.x);
    let x_3_no_carry = chip.sub_no_carry(ctx, lambda_sq_minus_px, Q.x);
    let x_3 = chip.carry_mod(ctx, x_3_no_carry);

    //  y_3 = lambda (x_1 - x_3) - y_1 mod p
    let dx_13 = chip.sub_no_carry(ctx, P.x, &x_3);
    let lambda_dx_13 = chip.mul_no_carry(ctx, lambda, dx_13);
    let y_3_no_carry = chip.sub_no_carry(ctx, lambda_dx_13, P.y);
    let y_3 = chip.carry_mod(ctx, y_3_no_carry);

    EcPoint::new(x_3, y_3)
}

/// If `do_check = true`, then this function constrains that `P.x != Q.x`.
/// Otherwise does nothing.
fn check_points_are_unequal<F: BigPrimeField, FC: FieldChip<F>>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: impl Into<ComparableEcPoint<F, FC>>,
    Q: impl Into<ComparableEcPoint<F, FC>>,
    do_check: bool,
) -> (EcPoint<F, FC::FieldPoint> /*P */, EcPoint<F, FC::FieldPoint> /*Q */) {
    let P = P.into();
    let Q = Q.into();
    if do_check {
        // constrains that P.x != Q.x
        let [x1, x2] = [&P, &Q].map(|pt| match pt {
            ComparableEcPoint::Strict(pt) => pt.x.clone(),
            ComparableEcPoint::NonStrict(pt) => chip.enforce_less_than(ctx, pt.x.clone()),
        });
        let x_is_equal = chip.is_equal_unenforced(ctx, x1, x2);
        chip.gate().assert_is_const(ctx, &x_is_equal, &F::ZERO);
    }
    (EcPoint::from(P), EcPoint::from(Q))
}

// Implements:
//  Given P = (x_1, y_1) and Q = (x_2, y_2), ecc points over the field F_p
//  Find ecc subtraction P - Q = (x_3, y_3)
//  -Q = (x_2, -y_2)
//  lambda = -(y_2+y_1)/(x_2-x_1) using constraint
//  x_3 = lambda^2 - x_1 - x_2 (mod p)
//  y_3 = lambda (x_1 - x_3) - y_1 mod p
//  Assumes that P !=Q and Q != (P - Q)
//
/// If `is_strict = true`, then this function constrains that `P.x != Q.x`.
/// If you are calling this with `is_strict = false`, you must ensure that `P.x != Q.x` by some external logic (such
/// as a mathematical theorem).
///
/// # Assumptions
/// * Neither `P` nor `Q` is the point at infinity (undefined behavior otherwise)
pub fn ec_sub_unequal<F: BigPrimeField, FC: FieldChip<F>>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: impl Into<ComparableEcPoint<F, FC>>,
    Q: impl Into<ComparableEcPoint<F, FC>>,
    is_strict: bool,
) -> EcPoint<F, FC::FieldPoint> {
    let (P, Q) = check_points_are_unequal(chip, ctx, P, Q, is_strict);

    let dx = chip.sub_no_carry(ctx, &Q.x, &P.x);
    let sy = chip.add_no_carry(ctx, Q.y, &P.y);

    let lambda = chip.neg_divide_unsafe(ctx, sy, dx);

    //  x_3 = lambda^2 - x_1 - x_2 (mod p)
    let lambda_sq = chip.mul_no_carry(ctx, &lambda, &lambda);
    let lambda_sq_minus_px = chip.sub_no_carry(ctx, lambda_sq, &P.x);
    let x_3_no_carry = chip.sub_no_carry(ctx, lambda_sq_minus_px, Q.x);
    let x_3 = chip.carry_mod(ctx, x_3_no_carry);

    //  y_3 = lambda (x_1 - x_3) - y_1 mod p
    let dx_13 = chip.sub_no_carry(ctx, P.x, &x_3);
    let lambda_dx_13 = chip.mul_no_carry(ctx, lambda, dx_13);
    let y_3_no_carry = chip.sub_no_carry(ctx, lambda_dx_13, P.y);
    let y_3 = chip.carry_mod(ctx, y_3_no_carry);

    EcPoint::new(x_3, y_3)
}

/// Constrains `P != -Q` but allows `P == Q`, in which case output is (0,0).
/// For Weierstrass curves only.
///
/// Assumptions
/// # Neither P or Q is the point at infinity
pub fn ec_sub_strict<F: BigPrimeField, FC: FieldChip<F>>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: impl Into<EcPoint<F, FC::FieldPoint>>,
    Q: impl Into<EcPoint<F, FC::FieldPoint>>,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: Selectable<F, FC::FieldPoint>,
{
    let mut P = P.into();
    let Q = Q.into();
    // Compute curr_point - start_point, allowing for output to be identity point
    let x_is_eq = chip.is_equal(ctx, P.x(), Q.x());
    let y_is_eq = chip.is_equal(ctx, P.y(), Q.y());
    let is_identity = chip.gate().and(ctx, x_is_eq, y_is_eq);
    // we ONLY allow x_is_eq = true if y_is_eq is also true; this constrains P != -Q
    ctx.constrain_equal(&x_is_eq, &is_identity);

    // P.x = Q.x and P.y = Q.y
    // in ec_sub_unequal it will try to do -(P.y + Q.y) / (P.x - Q.x) = -2P.y / 0
    // this will cause divide_unsafe to panic when P.y != 0
    // to avoid this, we load a random pair of points and replace P with it *only if* `is_identity == true`
    // we don't even check (rand_x, rand_y) is on the curve, since we don't care about the output
    let mut rng = ChaCha20Rng::from_entropy();
    let [rand_x, rand_y] = [(); 2].map(|_| FC::FieldType::random(&mut rng));
    let [rand_x, rand_y] = [rand_x, rand_y].map(|x| chip.load_private(ctx, x));
    let rand_pt = EcPoint::new(rand_x, rand_y);
    P = ec_select(chip, ctx, rand_pt, P, is_identity);

    let out = ec_sub_unequal(chip, ctx, P, Q, false);
    let zero = chip.load_constant(ctx, FC::FieldType::ZERO);
    ec_select(chip, ctx, EcPoint::new(zero.clone(), zero), out, is_identity)
}

// Implements:
// computing 2P on elliptic curve E for P = (x, y)
// formula from https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html
// assume y != 0 (otherwise 2P = O)

// lamb =  3x^2 / (2 y) % p
// x_3 = out[0] = lambda^2 - 2 x % p
// y_3 = out[1] = lambda (x - x_3) - y % p

// we precompute lambda and constrain (2y) * lambda = 3 x^2 (mod p)
// then we compute x_3 = lambda^2 - 2 x (mod p)
//                 y_3 = lambda (x - x_3) - y (mod p)
/// # Assumptions
/// * `P.y != 0`
/// * `P` is not the point at infinity (undefined behavior otherwise)
pub fn ec_double<F: BigPrimeField, FC: FieldChip<F>>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: impl Into<EcPoint<F, FC::FieldPoint>>,
) -> EcPoint<F, FC::FieldPoint> {
    let P = P.into();
    // removed optimization that computes `2 * lambda` while assigning witness to `lambda` simultaneously, in favor of readability. The difference is just copying `lambda` once
    let two_y = chip.scalar_mul_no_carry(ctx, &P.y, 2);
    let three_x = chip.scalar_mul_no_carry(ctx, &P.x, 3);
    let three_x_sq = chip.mul_no_carry(ctx, three_x, &P.x);
    let lambda = chip.divide_unsafe(ctx, three_x_sq, two_y);

    // x_3 = lambda^2 - 2 x % p
    let lambda_sq = chip.mul_no_carry(ctx, &lambda, &lambda);
    let two_x = chip.scalar_mul_no_carry(ctx, &P.x, 2);
    let x_3_no_carry = chip.sub_no_carry(ctx, lambda_sq, two_x);
    let x_3 = chip.carry_mod(ctx, x_3_no_carry);

    // y_3 = lambda (x - x_3) - y % p
    let dx = chip.sub_no_carry(ctx, P.x, &x_3);
    let lambda_dx = chip.mul_no_carry(ctx, lambda, dx);
    let y_3_no_carry = chip.sub_no_carry(ctx, lambda_dx, P.y);
    let y_3 = chip.carry_mod(ctx, y_3_no_carry);

    EcPoint::new(x_3, y_3)
}

/// Implements:
/// computing 2P + Q = P + Q + P for P = (x0, y0), Q = (x1, y1)
// using Montgomery ladder(?) to skip intermediate y computation
// from halo2wrong: https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg?view
// lambda_0 = (y_1 - y_0) / (x_1 - x_0)
// x_2 = lambda_0^2 - x_0 - x_1
// lambda_1 = lambda_0 + 2 * y_0 / (x_2 - x_0)
// x_res = lambda_1^2 - x_0 - x_2
// y_res = lambda_1 * (x_res - x_0) - y_0
///
/// # Assumptions
/// * Neither `P` nor `Q` is the point at infinity (undefined behavior otherwise)
pub fn ec_double_and_add_unequal<F: BigPrimeField, FC: FieldChip<F>>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: impl Into<ComparableEcPoint<F, FC>>,
    Q: impl Into<ComparableEcPoint<F, FC>>,
    is_strict: bool,
) -> EcPoint<F, FC::FieldPoint> {
    let P = P.into();
    let Q = Q.into();
    let mut x_0 = None;
    if is_strict {
        // constrains that P.x != Q.x
        let [x0, x1] = [&P, &Q].map(|pt| match pt {
            ComparableEcPoint::Strict(pt) => pt.x.clone(),
            ComparableEcPoint::NonStrict(pt) => chip.enforce_less_than(ctx, pt.x.clone()),
        });
        let x_is_equal = chip.is_equal_unenforced(ctx, x0.clone(), x1);
        chip.gate().assert_is_const(ctx, &x_is_equal, &F::ZERO);
        x_0 = Some(x0);
    }
    let P = EcPoint::from(P);
    let Q = EcPoint::from(Q);

    let dx = chip.sub_no_carry(ctx, &Q.x, &P.x);
    let dy = chip.sub_no_carry(ctx, Q.y, &P.y);
    let lambda_0 = chip.divide_unsafe(ctx, dy, dx);

    //  x_2 = lambda_0^2 - x_0 - x_1 (mod p)
    let lambda_0_sq = chip.mul_no_carry(ctx, &lambda_0, &lambda_0);
    let lambda_0_sq_minus_x_0 = chip.sub_no_carry(ctx, lambda_0_sq, &P.x);
    let x_2_no_carry = chip.sub_no_carry(ctx, lambda_0_sq_minus_x_0, Q.x);
    let x_2 = chip.carry_mod(ctx, x_2_no_carry);

    if is_strict {
        let x_2 = chip.enforce_less_than(ctx, x_2.clone());
        // TODO: when can we remove this check?
        // constrains that x_2 != x_0
        let x_is_equal = chip.is_equal_unenforced(ctx, x_0.unwrap(), x_2);
        chip.range().gate().assert_is_const(ctx, &x_is_equal, &F::ZERO);
    }
    // lambda_1 = lambda_0 + 2 * y_0 / (x_2 - x_0)
    let two_y_0 = chip.scalar_mul_no_carry(ctx, &P.y, 2);
    let x_2_minus_x_0 = chip.sub_no_carry(ctx, &x_2, &P.x);
    let lambda_1_minus_lambda_0 = chip.divide_unsafe(ctx, two_y_0, x_2_minus_x_0);
    let lambda_1_no_carry = chip.add_no_carry(ctx, lambda_0, lambda_1_minus_lambda_0);

    // x_res = lambda_1^2 - x_0 - x_2
    let lambda_1_sq_nc = chip.mul_no_carry(ctx, &lambda_1_no_carry, &lambda_1_no_carry);
    let lambda_1_sq_minus_x_0 = chip.sub_no_carry(ctx, lambda_1_sq_nc, &P.x);
    let x_res_no_carry = chip.sub_no_carry(ctx, lambda_1_sq_minus_x_0, x_2);
    let x_res = chip.carry_mod(ctx, x_res_no_carry);

    // y_res = lambda_1 * (x_res - x_0) - y_0
    let x_res_minus_x_0 = chip.sub_no_carry(ctx, &x_res, P.x);
    let lambda_1_x_res_minus_x_0 = chip.mul_no_carry(ctx, lambda_1_no_carry, x_res_minus_x_0);
    let y_res_no_carry = chip.sub_no_carry(ctx, lambda_1_x_res_minus_x_0, P.y);
    let y_res = chip.carry_mod(ctx, y_res_no_carry);

    EcPoint::new(x_res, y_res)
}

pub fn ec_select<F: BigPrimeField, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: EcPoint<F, FC::FieldPoint>,
    Q: EcPoint<F, FC::FieldPoint>,
    sel: AssignedValue<F>,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint>,
{
    let Rx = chip.select(ctx, P.x, Q.x, sel);
    let Ry = chip.select(ctx, P.y, Q.y, sel);
    EcPoint::new(Rx, Ry)
}

// takes the dot product of points with sel, where each is intepreted as
// a _vector_
pub fn ec_select_by_indicator<F: BigPrimeField, FC, Pt>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[Pt],
    coeffs: &[AssignedValue<F>],
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint>,
    Pt: Into<EcPoint<F, FC::FieldPoint>> + Clone,
{
    let (x, y): (Vec<_>, Vec<_>) = points
        .iter()
        .map(|P| {
            let P: EcPoint<_, _> = P.clone().into();
            (P.x, P.y)
        })
        .unzip();
    let Rx = chip.select_by_indicator(ctx, &x, coeffs);
    let Ry = chip.select_by_indicator(ctx, &y, coeffs);
    EcPoint::new(Rx, Ry)
}

// `sel` is little-endian binary
pub fn ec_select_from_bits<F: BigPrimeField, FC, Pt>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[Pt],
    sel: &[AssignedValue<F>],
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint>,
    Pt: Into<EcPoint<F, FC::FieldPoint>> + Clone,
{
    let w = sel.len();
    assert_eq!(1 << w, points.len());
    let coeffs = chip.range().gate().bits_to_indicator(ctx, sel);
    ec_select_by_indicator(chip, ctx, points, &coeffs)
}

// `sel` is little-endian binary
pub fn strict_ec_select_from_bits<F: BigPrimeField, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    points: &[StrictEcPoint<F, FC>],
    sel: &[AssignedValue<F>],
) -> StrictEcPoint<F, FC>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint> + Selectable<F, FC::ReducedFieldPoint>,
{
    let w = sel.len();
    assert_eq!(1 << w, points.len());
    let coeffs = chip.range().gate().bits_to_indicator(ctx, sel);
    let (x, y): (Vec<_>, Vec<_>) = points.iter().map(|pt| (pt.x.clone(), pt.y.clone())).unzip();
    let x = chip.select_by_indicator(ctx, &x, &coeffs);
    let y = chip.select_by_indicator(ctx, &y, &coeffs);
    StrictEcPoint::new(x, y)
}

/// Computes `[scalar] * P` on short Weierstrass curve `y^2 = x^3 + b`
/// - `scalar` is represented as a reference array of `AssignedValue`s
/// - `scalar = sum_i scalar_i * 2^{max_bits * i}`
/// - an array of length > 1 is needed when `scalar` exceeds the modulus of scalar field `F`
///
/// # Assumptions
/// - `window_bits != 0`
/// - The order of `P` is at least `2^{window_bits}` (in particular, `P` is not the point at infinity)
/// - The curve has no points of order 2.
/// - `scalar_i < 2^{max_bits} for all i`
/// - `max_bits <= modulus::<F>.bits()`, and equality only allowed when the order of `P` equals the modulus of `F`
pub fn scalar_multiply<F: BigPrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: EcPoint<F, FC::FieldPoint>,
    scalar: Vec<AssignedValue<F>>,
    max_bits: usize,
    window_bits: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    assert!(!scalar.is_empty());
    assert!((max_bits as u64) <= modulus::<F>().bits());
    assert!(window_bits != 0);
    multi_scalar_multiply::<F, FC, C>(chip, ctx, &[P], vec![scalar], max_bits, window_bits)
    /*
    let total_bits = max_bits * scalar.len();
    let num_windows = (total_bits + window_bits - 1) / window_bits;
    let rounded_bitlen = num_windows * window_bits;

    let mut bits = Vec::with_capacity(rounded_bitlen);
    for x in scalar {
        let mut new_bits = chip.gate().num_to_bits(ctx, x, max_bits);
        bits.append(&mut new_bits);
    }
    let mut rounded_bits = bits;
    let zero_cell = ctx.load_zero();
    rounded_bits.resize(rounded_bitlen, zero_cell);

    // is_started[idx] holds whether there is a 1 in bits with index at least (rounded_bitlen - idx)
    let mut is_started = Vec::with_capacity(rounded_bitlen);
    is_started.resize(rounded_bitlen - total_bits + 1, zero_cell);
    for idx in 1..=total_bits {
        let or = chip.gate().or(ctx, *is_started.last().unwrap(), rounded_bits[total_bits - idx]);
        is_started.push(or);
    }

    // is_zero_window[idx] is 0/1 depending on whether bits [rounded_bitlen - window_bits * (idx + 1), rounded_bitlen - window_bits * idx) are all 0
    let mut is_zero_window = Vec::with_capacity(num_windows);
    for idx in 0..num_windows {
        let temp_bits = rounded_bits
            [rounded_bitlen - window_bits * (idx + 1)..rounded_bitlen - window_bits * idx]
            .iter()
            .copied();
        let bit_sum = chip.gate().sum(ctx, temp_bits);
        let is_zero = chip.gate().is_zero(ctx, bit_sum);
        is_zero_window.push(is_zero);
    }

    let any_point = load_random_point::<F, FC, C>(chip, ctx);
    // cached_points[idx] stores idx * P, with cached_points[0] = any_point
    let cache_size = 1usize << window_bits;
    let mut cached_points = Vec::with_capacity(cache_size);
    cached_points.push(any_point);
    cached_points.push(P.clone());
    for idx in 2..cache_size {
        if idx == 2 {
            let double = ec_double(chip, ctx, &P);
            cached_points.push(double);
        } else {
            let new_point = ec_add_unequal(chip, ctx, &cached_points[idx - 1], &P, false);
            cached_points.push(new_point);
        }
    }

    // if all the starting window bits are 0, get start_point = any_point
    let mut curr_point = ec_select_from_bits(
        chip,
        ctx,
        &cached_points,
        &rounded_bits[rounded_bitlen - window_bits..rounded_bitlen],
    );

    for idx in 1..num_windows {
        let mut mult_point = curr_point.clone();
        for _ in 0..window_bits {
            mult_point = ec_double(chip, ctx, mult_point);
        }
        let add_point = ec_select_from_bits(
            chip,
            ctx,
            &cached_points,
            &rounded_bits
                [rounded_bitlen - window_bits * (idx + 1)..rounded_bitlen - window_bits * idx],
        );
        // if is_zero_window[idx] = true, add_point = any_point. We only need any_point to avoid divide by zero in add_unequal
        // if is_zero_window = true and is_started = false, then mult_point = 2^window_bits * any_point. Since window_bits != 0, we have mult_point != +- any_point
        let mult_and_add = ec_add_unequal(chip, ctx, &mult_point, &add_point, true);
        let is_started_point = ec_select(chip, ctx, mult_point, mult_and_add, is_zero_window[idx]);

        curr_point =
            ec_select(chip, ctx, is_started_point, add_point, is_started[window_bits * idx]);
    }
    // if at the end, return identity point (0,0) if still not started
    let zero = chip.load_constant(ctx, FC::FieldType::zero());
    ec_select(chip, ctx, curr_point, EcPoint::new(zero.clone(), zero), *is_started.last().unwrap())
    */
}

/// Checks that `P` is indeed a point on the elliptic curve `C`.
pub fn check_is_on_curve<F, FC, C>(chip: &FC, ctx: &mut Context<F>, P: &EcPoint<F, FC::FieldPoint>)
where
    F: BigPrimeField,
    FC: FieldChip<F>,
    C: CurveAffine<Base = FC::FieldType>,
{
    let lhs = chip.mul_no_carry(ctx, &P.y, &P.y);
    let mut rhs = chip.mul(ctx, &P.x, &P.x).into();
    rhs = chip.mul_no_carry(ctx, rhs, &P.x);

    rhs = chip.add_constant_no_carry(ctx, rhs, C::b());
    let diff = chip.sub_no_carry(ctx, lhs, rhs);
    chip.check_carry_mod_to_zero(ctx, diff)
}

pub fn load_random_point<F, FC, C>(chip: &FC, ctx: &mut Context<F>) -> EcPoint<F, FC::FieldPoint>
where
    F: BigPrimeField,
    FC: FieldChip<F>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    let base_point: C = C::CurveExt::random(ChaCha20Rng::from_entropy()).to_affine();
    let (x, y) = base_point.into_coordinates();
    let base = {
        let x_overflow = chip.load_private(ctx, x);
        let y_overflow = chip.load_private(ctx, y);
        EcPoint::new(x_overflow, y_overflow)
    };
    // for above reason we still need to constrain that the witness is on the curve
    check_is_on_curve::<F, FC, C>(chip, ctx, &base);
    base
}

pub fn into_strict_point<F, FC>(
    chip: &FC,
    ctx: &mut Context<F>,
    pt: EcPoint<F, FC::FieldPoint>,
) -> StrictEcPoint<F, FC>
where
    F: BigPrimeField,
    FC: FieldChip<F>,
{
    let x = chip.enforce_less_than(ctx, pt.x);
    StrictEcPoint::new(x, pt.y)
}

// need to supply an extra generic `C` implementing `CurveAffine` trait in order to generate random witness points on the curve in question
// Using Simultaneous 2^w-Ary Method, see https://www.bmoeller.de/pdf/multiexp-sac2001.pdf
// Random Accumlation point trick learned from halo2wrong: https://hackmd.io/ncuKqRXzR-Cw-Au2fGzsMg?view
// Input:
// - `scalars` is vector of same length as `P`
// - each `scalar` in `scalars` satisfies same assumptions as in `scalar_multiply` above

/// # Assumptions
/// * `points.len() == scalars.len()`
/// * `scalars[i].len() == scalars[j].len()` for all `i, j`
/// * `scalars[i]` is less than the order of `P`
/// * `scalars[i][j] < 2^{max_bits} for all j`
/// * `max_bits <= modulus::<F>.bits()`, and equality only allowed when the order of `P` equals the modulus of `F`
/// * `points` are all on the curve or the point at infinity
/// * `points[i]` is allowed to be (0, 0) to represent the point at infinity (identity point)
/// * Currently implementation assumes that the only point on curve with y-coordinate equal to `0` is identity point
pub fn multi_scalar_multiply<F: BigPrimeField, FC, C>(
    chip: &FC,
    ctx: &mut Context<F>,
    P: &[EcPoint<F, FC::FieldPoint>],
    scalars: Vec<Vec<AssignedValue<F>>>,
    max_bits: usize,
    window_bits: usize,
) -> EcPoint<F, FC::FieldPoint>
where
    FC: FieldChip<F> + Selectable<F, FC::FieldPoint>,
    C: CurveAffineExt<Base = FC::FieldType>,
{
    let k = P.len();
    assert_eq!(k, scalars.len());
    assert_ne!(k, 0);
    assert!(!scalars[0].is_empty());
    assert!((max_bits as u32) <= F::NUM_BITS);

    let scalar_len = scalars[0].len();
    let total_bits = max_bits * scalar_len;
    let num_windows = (total_bits + window_bits - 1) / window_bits;
    let rounded_bitlen = num_windows * window_bits;

    let zero_cell = ctx.load_zero();
    let rounded_bits = scalars
        .into_iter()
        .flat_map(|scalar| {
            debug_assert_eq!(scalar.len(), scalar_len);
            scalar
                .into_iter()
                .flat_map(|scalar_chunk| chip.gate().num_to_bits(ctx, scalar_chunk, max_bits))
                .chain(std::iter::repeat(zero_cell).take(rounded_bitlen - total_bits))
                .collect_vec()
        })
        .collect_vec();

    // load any sufficiently generic C point as witness
    // note that while we load a random point, an adversary would load a specifically chosen point, so we must carefully handle edge cases with constraints
    let base = load_random_point::<F, FC, C>(chip, ctx);
    // contains random base points [A, ..., 2^{w + k - 1} * A]
    let mut rand_start_vec = Vec::with_capacity(k + window_bits);
    rand_start_vec.push(base);
    for idx in 1..(k + window_bits) {
        let base_mult = ec_double(chip, ctx, &rand_start_vec[idx - 1]);
        rand_start_vec.push(base_mult);
    }
    assert!(rand_start_vec.len() >= k + window_bits);

    let cache_size = 1usize << window_bits;
    // this is really a 2d array that we store as 1d vec for memory optimization
    let mut cached_points = Vec::with_capacity(k * cache_size);
    for (idx, point) in P.iter().enumerate() {
        // add selector for whether P_i is the point at infinity (aka 0 in elliptic curve group)
        // this can be checked by P_i.y == 0 iff P_i == O
        let is_infinity = chip.is_zero(ctx, &point.y);
        // (1 - 2^w) * [A, ..., 2^(k - 1) * A]
        let neg_mult_rand_start = ec_sub_unequal(
            chip,
            ctx,
            &rand_start_vec[idx],
            &rand_start_vec[idx + window_bits],
            true, // not necessary if we assume (2^w - 1) * A != +- A, but put in for safety
        );
        let point = into_strict_point(chip, ctx, point.clone());
        let neg_mult_rand_start = into_strict_point(chip, ctx, neg_mult_rand_start);
        // cached_points[i][0..cache_size] stores (1 - 2^w) * 2^i * A + [0..cache_size] * P_i
        cached_points.push(neg_mult_rand_start);
        for _ in 0..(cache_size - 1) {
            let prev = cached_points.last().unwrap().clone();
            // adversary could pick `A` so add equal case occurs, so we must use strict add_unequal
            let mut new_point = ec_add_unequal(chip, ctx, &prev, &point, true);
            // special case for when P[idx] = O
            new_point = ec_select(chip, ctx, prev.into(), new_point, is_infinity);
            let new_point = into_strict_point(chip, ctx, new_point);
            cached_points.push(new_point);
        }
    }

    // initialize at (2^{k + 1} - 1) * A
    // note k can be large (e.g., 800) so 2^{k+1} may be larger than the order of A
    // random fact: 2^{k + 1} - 1 can be prime: see Mersenne primes
    // TODO: I don't see a way to rule out 2^{k+1} A = +-A case in general, so will use strict sub_unequal
    let start_point = ec_sub_unequal(
        chip,
        ctx,
        &rand_start_vec[k],
        &rand_start_vec[0],
        true, // k >= F::CAPACITY as usize, // this assumed random points on `C` were of prime order equal to modulus of `F`. Since this is easily missed, we turn on strict mode always
    );
    let mut curr_point = start_point.clone();

    // compute \sum_i x_i P_i + (2^{k + 1} - 1) * A
    for idx in 0..num_windows {
        for _ in 0..window_bits {
            curr_point = ec_double(chip, ctx, curr_point);
        }
        for (cached_points, rounded_bits) in
            cached_points.chunks(cache_size).zip(rounded_bits.chunks(rounded_bitlen))
        {
            let add_point = ec_select_from_bits(
                chip,
                ctx,
                cached_points,
                &rounded_bits
                    [rounded_bitlen - window_bits * (idx + 1)..rounded_bitlen - window_bits * idx],
            );
            // this all needs strict add_unequal since A can be non-randomly chosen by adversary
            curr_point = ec_add_unequal(chip, ctx, curr_point, add_point, true);
        }
    }
    ec_sub_strict(chip, ctx, curr_point, start_point)
}

pub fn get_naf(mut exp: Vec<u64>) -> Vec<i8> {
    // https://en.wikipedia.org/wiki/Non-adjacent_form
    // NAF for exp:
    let mut naf: Vec<i8> = Vec::with_capacity(64 * exp.len());
    let len = exp.len();

    // generate the NAF for exp
    for idx in 0..len {
        let mut e: u64 = exp[idx];
        for _ in 0..64 {
            if e & 1 == 1 {
                let z = 2i8 - (e % 4) as i8;
                e /= 2;
                if z == -1 {
                    e += 1;
                }
                naf.push(z);
            } else {
                naf.push(0);
                e /= 2;
            }
        }
        if e != 0 {
            assert_eq!(e, 1);
            let mut j = idx + 1;
            while j < exp.len() && exp[j] == u64::MAX {
                exp[j] = 0;
                j += 1;
            }
            if j < exp.len() {
                exp[j] += 1;
            } else {
                exp.push(1);
            }
        }
    }
    if exp.len() != len {
        assert_eq!(len, exp.len() + 1);
        assert!(exp[len] == 1);
        naf.push(1);
    }
    naf
}

pub type BaseFieldEccChip<'chip, C> = EccChip<
    'chip,
    <C as CurveAffine>::ScalarExt,
    FpChip<'chip, <C as CurveAffine>::ScalarExt, <C as CurveAffine>::Base>,
>;

#[derive(Clone, Debug)]
pub struct EccChip<'chip, F: BigPrimeField, FC: FieldChip<F>> {
    pub field_chip: &'chip FC,
    _marker: PhantomData<F>,
}

impl<'chip, F: BigPrimeField, FC: FieldChip<F>> EccChip<'chip, F, FC> {
    pub fn new(field_chip: &'chip FC) -> Self {
        Self { field_chip, _marker: PhantomData }
    }

    pub fn field_chip(&self) -> &FC {
        self.field_chip
    }

    /// Load affine point as private witness. Constrains witness to lie on curve. Does not allow (0, 0) point,
    pub fn load_private<C>(
        &self,
        ctx: &mut Context<F>,
        (x, y): (FC::FieldType, FC::FieldType),
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        let pt = self.load_private_unchecked(ctx, (x, y));
        self.assert_is_on_curve::<C>(ctx, &pt);
        pt
    }

    /// Does not constrain witness to lie on curve
    pub fn load_private_unchecked(
        &self,
        ctx: &mut Context<F>,
        (x, y): (FC::FieldType, FC::FieldType),
    ) -> EcPoint<F, FC::FieldPoint> {
        let x_assigned = self.field_chip.load_private(ctx, x);
        let y_assigned = self.field_chip.load_private(ctx, y);

        EcPoint::new(x_assigned, y_assigned)
    }

    /// Load affine point as private witness. Constrains witness to either lie on curve or be the point at infinity,
    /// represented in affine coordinates as (0, 0).
    pub fn assign_point<C>(&self, ctx: &mut Context<F>, g: C) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
        C::Base: crate::ff::PrimeField,
    {
        let pt = self.assign_point_unchecked(ctx, g);
        let is_on_curve = self.is_on_curve_or_infinity::<C>(ctx, &pt);
        self.field_chip.gate().assert_is_const(ctx, &is_on_curve, &F::ONE);
        pt
    }

    /// Does not constrain witness to lie on curve
    pub fn assign_point_unchecked<C>(
        &self,
        ctx: &mut Context<F>,
        g: C,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        let (x, y) = g.into_coordinates();
        self.load_private_unchecked(ctx, (x, y))
    }

    pub fn assign_constant_point<C>(&self, ctx: &mut Context<F>, g: C) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        let (x, y) = g.into_coordinates();
        let x = self.field_chip.load_constant(ctx, x);
        let y = self.field_chip.load_constant(ctx, y);

        EcPoint::new(x, y)
    }

    pub fn load_random_point<C>(&self, ctx: &mut Context<F>) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        load_random_point::<F, FC, C>(self.field_chip(), ctx)
    }

    pub fn assert_is_on_curve<C>(&self, ctx: &mut Context<F>, P: &EcPoint<F, FC::FieldPoint>)
    where
        C: CurveAffine<Base = FC::FieldType>,
    {
        check_is_on_curve::<F, FC, C>(self.field_chip, ctx, P)
    }

    pub fn is_on_curve_or_infinity<C>(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FC::FieldPoint>,
    ) -> AssignedValue<F>
    where
        C: CurveAffine<Base = FC::FieldType>,
    {
        let lhs = self.field_chip.mul_no_carry(ctx, &P.y, &P.y);
        let mut rhs = self.field_chip.mul(ctx, &P.x, &P.x).into();
        rhs = self.field_chip.mul_no_carry(ctx, rhs, &P.x);

        rhs = self.field_chip.add_constant_no_carry(ctx, rhs, C::b());
        let diff = self.field_chip.sub_no_carry(ctx, lhs, rhs);
        let diff = self.field_chip.carry_mod(ctx, diff);

        let is_on_curve = self.field_chip.is_zero(ctx, diff);

        let x_is_zero = self.field_chip.is_zero(ctx, &P.x);
        let y_is_zero = self.field_chip.is_zero(ctx, &P.y);

        self.field_chip.range().gate().or_and(ctx, is_on_curve, x_is_zero, y_is_zero)
    }

    pub fn negate(
        &self,
        ctx: &mut Context<F>,
        P: impl Into<EcPoint<F, FC::FieldPoint>>,
    ) -> EcPoint<F, FC::FieldPoint> {
        let P = P.into();
        EcPoint::new(P.x, self.field_chip.negate(ctx, P.y))
    }

    pub fn negate_strict(
        &self,
        ctx: &mut Context<F>,
        P: impl Into<StrictEcPoint<F, FC>>,
    ) -> StrictEcPoint<F, FC> {
        let P = P.into();
        StrictEcPoint::new(P.x, self.field_chip.negate(ctx, P.y))
    }

    /// Assumes that P.x != Q.x
    /// If `is_strict == true`, then actually constrains that `P.x != Q.x`
    /// Neither are points at infinity (otherwise, undefined behavior)
    pub fn add_unequal(
        &self,
        ctx: &mut Context<F>,
        P: impl Into<ComparableEcPoint<F, FC>>,
        Q: impl Into<ComparableEcPoint<F, FC>>,
        is_strict: bool,
    ) -> EcPoint<F, FC::FieldPoint> {
        ec_add_unequal(self.field_chip, ctx, P, Q, is_strict)
    }

    /// Assumes that P.x != Q.x
    /// Otherwise will panic
    pub fn sub_unequal(
        &self,
        ctx: &mut Context<F>,
        P: impl Into<ComparableEcPoint<F, FC>>,
        Q: impl Into<ComparableEcPoint<F, FC>>,
        is_strict: bool,
    ) -> EcPoint<F, FC::FieldPoint> {
        ec_sub_unequal(self.field_chip, ctx, P, Q, is_strict)
    }

    pub fn double(
        &self,
        ctx: &mut Context<F>,
        P: impl Into<EcPoint<F, FC::FieldPoint>>,
    ) -> EcPoint<F, FC::FieldPoint> {
        ec_double(self.field_chip, ctx, P)
    }

    pub fn is_equal(
        &self,
        ctx: &mut Context<F>,
        P: EcPoint<F, FC::FieldPoint>,
        Q: EcPoint<F, FC::FieldPoint>,
    ) -> AssignedValue<F> {
        // TODO: optimize
        let x_is_equal = self.field_chip.is_equal(ctx, P.x, Q.x);
        let y_is_equal = self.field_chip.is_equal(ctx, P.y, Q.y);
        self.field_chip.range().gate().and(ctx, x_is_equal, y_is_equal)
    }

    /// Checks if a point is the point at infinity (represented by (0, 0))
    /// Assumes points at infinity are always serialized as (0, 0) as bigints
    pub fn is_infinity(
        &self,
        ctx: &mut Context<F>,
        P: EcPoint<F, FC::FieldPoint>,
    ) -> AssignedValue<F> {
        // TODO: optimize
        let x_is_zero = self.field_chip.is_soft_zero(ctx, P.x);
        let y_is_zero = self.field_chip.is_soft_zero(ctx, P.y);
        self.field_chip.range().gate().and(ctx, x_is_zero, y_is_zero)
    }

    pub fn assert_equal(
        &self,
        ctx: &mut Context<F>,
        P: EcPoint<F, FC::FieldPoint>,
        Q: EcPoint<F, FC::FieldPoint>,
    ) {
        self.field_chip.assert_equal(ctx, P.x, Q.x);
        self.field_chip.assert_equal(ctx, P.y, Q.y);
    }

    /// None of elements in `points` can be point at infinity. Sum cannot be point at infinity either.
    pub fn sum_unsafe<C>(
        &self,
        ctx: &mut Context<F>,
        points: impl IntoIterator<Item = EcPoint<F, FC::FieldPoint>>,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        let rand_point = self.load_random_point::<C>(ctx);
        let rand_point = into_strict_point(self.field_chip, ctx, rand_point);
        let mut acc = rand_point.clone();
        for point in points {
            let _acc = self.add_unequal(ctx, acc, point, true);
            acc = into_strict_point(self.field_chip, ctx, _acc);
        }
        self.sub_unequal(ctx, acc, rand_point, true)
    }
}

impl<'chip, F: BigPrimeField, FC: FieldChip<F>> EccChip<'chip, F, FC>
where
    FC: Selectable<F, FC::FieldPoint>,
{
    /// Expensive version of `sum_unsafe`, but works generally meaning that
    /// * sum can be the point at infinity
    /// * addends can be points at infinity
    pub fn sum<C>(
        &self,
        ctx: &mut Context<F>,
        points: impl IntoIterator<Item = EcPoint<F, FC::FieldPoint>>,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        let rand_point = self.load_random_point::<C>(ctx);
        let rand_point2 = self.load_random_point::<C>(ctx);
        let zero = ctx.load_constant(F::ZERO);
        let neg_rand_point = self.negate(ctx, rand_point.clone());
        let mut acc = ComparableEcPoint::from(neg_rand_point.clone());
        for point in points {
            let point_is_inf = self.is_infinity(ctx, point.clone());
            let addend = self.select(ctx, rand_point2.clone(), point.clone(), point_is_inf);
            let _acc = self.add_unequal(ctx, acc.clone(), addend.clone(), true);
            let _acc = self.select(ctx, acc.clone().into(), _acc, point_is_inf);
            acc = _acc.into();
        }
        let acc_is_neg_rand = self.is_equal(ctx, acc.clone().into(), neg_rand_point);
        let addend = self.select(ctx, rand_point2.clone(), acc.clone().into(), acc_is_neg_rand);
        let sum = self.add_unequal(ctx, addend, rand_point, true);
        let inf = self.load_private_unchecked(ctx, (FC::FieldType::ZERO, FC::FieldType::ZERO));
        self.select(ctx, inf, sum, acc_is_neg_rand)
    }

    pub fn select(
        &self,
        ctx: &mut Context<F>,
        P: EcPoint<F, FC::FieldPoint>,
        Q: EcPoint<F, FC::FieldPoint>,
        condition: AssignedValue<F>,
    ) -> EcPoint<F, FC::FieldPoint> {
        ec_select(self.field_chip, ctx, P, Q, condition)
    }

    /// See [`scalar_multiply`] for more details.
    pub fn scalar_mult<C>(
        &self,
        ctx: &mut Context<F>,
        P: EcPoint<F, FC::FieldPoint>,
        scalar: Vec<AssignedValue<F>>,
        max_bits: usize,
        window_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
    {
        scalar_multiply::<F, FC, C>(self.field_chip, ctx, P, scalar, max_bits, window_bits)
    }

    // default for most purposes
    /// See [`pippenger::multi_exp_par`] for more details.
    pub fn variable_base_msm<C>(
        &self,
        thread_pool: &mut SinglePhaseCoreManager<F>,
        P: &[EcPoint<F, FC::FieldPoint>],
        scalars: Vec<Vec<AssignedValue<F>>>,
        max_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
        FC: Selectable<F, FC::ReducedFieldPoint>,
    {
        // window_bits = 4 is optimal from empirical observations
        self.variable_base_msm_custom::<C>(thread_pool, P, scalars, max_bits, 4)
    }

    // TODO: add asserts to validate input assumptions described in docs
    pub fn variable_base_msm_custom<C>(
        &self,
        builder: &mut SinglePhaseCoreManager<F>,
        P: &[EcPoint<F, FC::FieldPoint>],
        scalars: Vec<Vec<AssignedValue<F>>>,
        max_bits: usize,
        window_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt<Base = FC::FieldType>,
        FC: Selectable<F, FC::ReducedFieldPoint>,
    {
        #[cfg(feature = "display")]
        println!("computing length {} MSM", P.len());

        if P.len() <= 25 {
            multi_scalar_multiply::<F, FC, C>(
                self.field_chip,
                builder.main(),
                P,
                scalars,
                max_bits,
                window_bits,
            )
        } else {
            /*let mut radix = (f64::from((max_bits * scalars[0].len()) as u32)
                / f64::from(P.len() as u32))
            .sqrt()
            .floor() as usize;
            if radix == 0 {
                radix = 1;
            }*/
            // guessing that is is always better to use parallelism for >25 points
            pippenger::multi_exp_par::<F, FC, C>(
                self.field_chip,
                builder,
                P,
                scalars,
                max_bits,
                window_bits, // clump_factor := window_bits
            )
        }
    }
}

impl<'chip, F: BigPrimeField, FC: FieldChip<F>> EccChip<'chip, F, FC> {
    /// See [`fixed_base::scalar_multiply`] for more details.
    // TODO: put a check in place that scalar is < modulus of C::Scalar
    pub fn fixed_base_scalar_mult<C>(
        &self,
        ctx: &mut Context<F>,
        point: &C,
        scalar: Vec<AssignedValue<F>>,
        max_bits: usize,
        window_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt,
        FC: FieldChip<F, FieldType = C::Base> + Selectable<F, FC::FieldPoint>,
    {
        fixed_base::scalar_multiply::<F, _, _>(
            self.field_chip,
            ctx,
            point,
            scalar,
            max_bits,
            window_bits,
        )
    }

    // default for most purposes
    pub fn fixed_base_msm<C>(
        &self,
        builder: &mut SinglePhaseCoreManager<F>,
        points: &[C],
        scalars: Vec<Vec<AssignedValue<F>>>,
        max_scalar_bits_per_cell: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt,
        FC: FieldChip<F, FieldType = C::Base> + Selectable<F, FC::FieldPoint>,
    {
        self.fixed_base_msm_custom::<C>(builder, points, scalars, max_scalar_bits_per_cell, 4)
    }

    // `radix = 0` means auto-calculate
    //
    /// `clump_factor = 0` means auto-calculate
    ///
    /// The user should filter out base points that are identity beforehand; we do not separately do this here
    pub fn fixed_base_msm_custom<C>(
        &self,
        builder: &mut SinglePhaseCoreManager<F>,
        points: &[C],
        scalars: Vec<Vec<AssignedValue<F>>>,
        max_scalar_bits_per_cell: usize,
        clump_factor: usize,
    ) -> EcPoint<F, FC::FieldPoint>
    where
        C: CurveAffineExt,
        FC: FieldChip<F, FieldType = C::Base> + Selectable<F, FC::FieldPoint>,
    {
        assert_eq!(points.len(), scalars.len());
        #[cfg(feature = "display")]
        println!("computing length {} fixed base msm", points.len());

        fixed_base::msm_par(self, builder, points, scalars, max_scalar_bits_per_cell, clump_factor)

        // Empirically does not seem like pippenger is any better for fixed base msm right now, because of the cost of `select_by_indicator`
        // Cell usage becomes around comparable when `points.len() > 100`, and `clump_factor` should always be 4
        /*
        let radix = if radix == 0 {
            // auto calculate
            (f64::from(FC::FieldType::NUM_BITS) / f64::from(points.len() as u32)).sqrt().ceil()
                as usize
        } else {
            radix
        };
        assert!(radix > 0);

        fixed_base_pippenger::multi_exp::<F, FC, C>(
            self.field_chip,
            ctx,
            points,
            scalars,
            max_scalar_bits_per_cell,
            radix,
            clump_factor,
        )
        */
    }
}

#[cfg(test)]
pub(crate) mod tests;
