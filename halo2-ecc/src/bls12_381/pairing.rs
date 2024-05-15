#![allow(non_snake_case)]
use super::{Fp12Chip, Fp2Chip, FpChip, FpPoint, Fq, FqPoint, XI_0};
use super::{Fq12, G1Affine, G2Affine, BLS_X, BLS_X_IS_NEGATIVE};
use crate::fields::vector::FieldVector;
use crate::{
    ecc::{EcPoint, EccChip},
    fields::fp12::mul_no_carry_w6,
    fields::FieldChip,
};

use halo2_base::utils::BigPrimeField;
use halo2_base::Context;

// Assuming curve is of form Y^2 = X^3 + b (a = 0) to save operations
// Inputs:
//  Q = (Q.x, Q.y) is a point in E(Fp)
//  P = (x, y) in E(Fp2)
// Output:
//  line_{Psi(P), Psi(P)}(Q) where Psi(x,y) = (1/w^2 x, 1/w^3 y)
//  - equals (3x^3 - 2y^2) + w^2 (-3 x^2 * Q.x) + w^3 (2 y * Q.y) =: out0 + out2 * w^2 + out3 * w^3 where out0, out2, out3 are Fp2 points
// Output is [None, out1, None, out3, out4, None] as vector of `Option<FqPoint>`s
pub fn sparse_line_function_unequal<F: BigPrimeField>(
    fp2_chip: &Fp2Chip<F>,
    ctx: &mut Context<F>,
    Q: (&EcPoint<F, FqPoint<F>>, &EcPoint<F, FqPoint<F>>),
    P: &EcPoint<F, FpPoint<F>>,
) -> Vec<Option<FqPoint<F>>> {
    let (x_1, y_1) = (&Q.0.x, &Q.0.y);
    let (x_2, y_2) = (&Q.1.x, &Q.1.y);
    let (X, Y) = (&P.x, &P.y);
    assert_eq!(x_1.0.len(), 2);
    assert_eq!(y_1.0.len(), 2);
    assert_eq!(x_2.0.len(), 2);
    assert_eq!(y_2.0.len(), 2);

    let y1_minus_y2 = fp2_chip.sub_no_carry(ctx, y_1, y_2);
    let x2_minus_x1 = fp2_chip.sub_no_carry(ctx, x_2, x_1);
    let x1y2 = fp2_chip.mul_no_carry(ctx, x_1, y_2);
    let x2y1 = fp2_chip.mul_no_carry(ctx, x_2, y_1);

    let out3 = fp2_chip.0.fp_mul_no_carry(ctx, y1_minus_y2, X);
    let out4 = fp2_chip.0.fp_mul_no_carry(ctx, x2_minus_x1, Y);
    let out1 = fp2_chip.sub_no_carry(ctx, &x1y2, &x2y1);

    // so far we have not "carried mod p" for any of the outputs
    // we do this below
    [None, Some(out1), None, Some(out3), Some(out4), None]
        .into_iter()
        .map(|option_nc| option_nc.map(|nocarry| fp2_chip.carry_mod(ctx, nocarry)))
        .collect()
}

// Assuming curve is of form Y^2 = X^3 + b (a = 0) to save operations
// Inputs:
//  Q0 = (x_1, y_1) and Q1 = (x_2, y_2) are points in E(Fp2)
//  P is point (X, Y) in E(Fp)
// Assuming Q0 != Q1
// Output:
//  line_{Psi(Q0), Psi(Q1)}(P) where Psi(x,y) = (1/w^2 x, 1/w^3 y)
//  - equals w^3 (y_1 - y_2) X + w^4 (x_2 - x_1) Y + w (x_1 y_2 - x_2 y_1) =: out3 * w^3 + out4 * w^4 + out2 * w where out2, out3, out4 are Fp2 points
// Output is [out0, None, out2, out3, None, None] as vector of `Option<FqPoint>`s
pub fn sparse_line_function_equal<F: BigPrimeField>(
    fp2_chip: &Fp2Chip<F>,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FpPoint<F>>,
    Q: &EcPoint<F, FqPoint<F>>,
) -> Vec<Option<FqPoint<F>>> {
    let (x, y) = (&Q.x, &Q.y);
    assert_eq!(x.0.len(), 2);
    assert_eq!(y.0.len(), 2);

    let x_sq = fp2_chip.mul(ctx, x, x);

    let x_cube = fp2_chip.mul_no_carry(ctx, &x_sq, x);
    let three_x_cu = fp2_chip.scalar_mul_no_carry(ctx, &x_cube, 3);
    let y_sq = fp2_chip.mul_no_carry(ctx, y, y);
    let two_y_sq = fp2_chip.scalar_mul_no_carry(ctx, &y_sq, 2);
    let out0 = fp2_chip.sub_no_carry(ctx, &three_x_cu, &two_y_sq);

    let x_sq_Px = fp2_chip.0.fp_mul_no_carry(ctx, x_sq, &P.x);
    let out2 = fp2_chip.scalar_mul_no_carry(ctx, x_sq_Px, -3);

    let y_Py = fp2_chip.0.fp_mul_no_carry(ctx, y.clone(), &P.y);
    let out3 = fp2_chip.scalar_mul_no_carry(ctx, &y_Py, 2);

    // so far we have not "carried mod p" for any of the outputs
    // we do this below
    [Some(out0), None, Some(out2), Some(out3), None, None]
        .into_iter()
        .map(|option_nc| option_nc.map(|nocarry| fp2_chip.carry_mod(ctx, nocarry)))
        .collect()
}

// multiply Fp12 point `a` with Fp12 point `b` where `b` is len 6 vector of Fp2 points, where some are `None` to represent zero.
// Assumes `b` is not vector of all `None`s
pub fn sparse_fp12_multiply<F: BigPrimeField>(
    fp2_chip: &Fp2Chip<F>,
    ctx: &mut Context<F>,
    a: &FqPoint<F>,
    b_fp2_coeffs: &[Option<FqPoint<F>>],
) -> FqPoint<F> {
    assert_eq!(a.0.len(), 12);
    assert_eq!(b_fp2_coeffs.len(), 6);
    let mut a_fp2_coeffs = Vec::with_capacity(6);
    for i in 0..6 {
        a_fp2_coeffs.push(FieldVector(vec![a[i].clone(), a[i + 6].clone()]));
    }
    // a * b as element of Fp2[w] without evaluating w^6 = (XI_0 + u)
    let mut prod_2d = vec![None; 11];
    for i in 0..6 {
        for j in 0..6 {
            prod_2d[i + j] =
                match (prod_2d[i + j].clone(), &a_fp2_coeffs[i], b_fp2_coeffs[j].as_ref()) {
                    (a, _, None) => a,
                    (None, a, Some(b)) => {
                        let ab = fp2_chip.mul_no_carry(ctx, a, b);
                        Some(ab)
                    }
                    (Some(a), b, Some(c)) => {
                        let bc = fp2_chip.mul_no_carry(ctx, b, c);
                        let out = fp2_chip.add_no_carry(ctx, &a, &bc);
                        Some(out)
                    }
                };
        }
    }

    let mut out_fp2 = Vec::with_capacity(6);
    for i in 0..6 {
        // prod_2d[i] + prod_2d[i+6] * w^6
        let prod_nocarry = if i != 5 {
            let eval_w6 = prod_2d[i + 6]
                .as_ref()
                .map(|a| mul_no_carry_w6::<_, _, XI_0>(fp2_chip.fp_chip(), ctx, a.clone()));
            match (prod_2d[i].as_ref(), eval_w6) {
                (None, b) => b.unwrap(), // Our current use cases of 235 and 034 sparse multiplication always result in non-None value
                (Some(a), None) => a.clone(),
                (Some(a), Some(b)) => fp2_chip.add_no_carry(ctx, a, &b),
            }
        } else {
            prod_2d[i].clone().unwrap()
        };
        let prod = fp2_chip.carry_mod(ctx, prod_nocarry);
        out_fp2.push(prod);
    }

    let mut out_coeffs = Vec::with_capacity(12);
    for fp2_coeff in &out_fp2 {
        out_coeffs.push(fp2_coeff[0].clone());
    }
    for fp2_coeff in &out_fp2 {
        out_coeffs.push(fp2_coeff[1].clone());
    }
    FieldVector(out_coeffs)
}

// Input:
// - g is Fp12 point
// - P = (P0, P1) with Q0, Q1 points in E(Fp2)
// - Q is point in E(Fp)
// Output:
// - out = g * l_{Psi(Q0), Psi(Q1)}(P) as Fp12 point
pub fn fp12_multiply_with_line_unequal<F: BigPrimeField>(
    fp2_chip: &Fp2Chip<F>,
    ctx: &mut Context<F>,
    g: &FqPoint<F>,
    P: &EcPoint<F, FpPoint<F>>,
    Q: (&EcPoint<F, FqPoint<F>>, &EcPoint<F, FqPoint<F>>),
) -> FqPoint<F> {
    let line = sparse_line_function_unequal::<F>(fp2_chip, ctx, Q, P);
    sparse_fp12_multiply::<F>(fp2_chip, ctx, g, &line)
}

// Input:
// - g is Fp12 point
// - P is point in E(Fp2)
// - Q is point in E(Fp)
// Output:
// - out = g * l_{Psi(Q), Psi(Q)}(P) as Fp12 point
pub fn fp12_multiply_with_line_equal<F: BigPrimeField>(
    fp2_chip: &Fp2Chip<F>,
    ctx: &mut Context<F>,
    g: &FqPoint<F>,
    P: &EcPoint<F, FpPoint<F>>,
    Q: &EcPoint<F, FqPoint<F>>,
) -> FqPoint<F> {
    let line = sparse_line_function_equal::<F>(fp2_chip, ctx, P, Q);
    sparse_fp12_multiply::<F>(fp2_chip, ctx, g, &line)
}

// Assuming curve is of form `y^2 = x^3 + b` for now (a = 0) for less operations
// Value of `b` is never used
// Inputs:
// - Q = (x, y) is a point in E(Fp2)
// - P is a point in E(Fp)
// Output:
//  - f_{loop_count}(Q,P) * l_{[loop_count] Q', Frob_p(Q')}(P) * l_{[loop_count] Q' + Frob_p(Q'), -Frob_p^2(Q')}(P)
//  - where we start with `f_1(Q,P) = 1` and use Miller's algorithm f_{i+j} = f_i * f_j * l_{i,j}(Q,P)
//  - Q' = Psi(Q) in E(Fp12)
//  - Frob_p(x,y) = (x^p, y^p)
pub fn miller_loop<F: BigPrimeField>(
    ecc_chip: &EccChip<F, Fp2Chip<F>>,
    ctx: &mut Context<F>,
    P: &EcPoint<F, FpPoint<F>>,
    Q: &EcPoint<F, FqPoint<F>>,
) -> FqPoint<F> {
    let sparse_f = sparse_line_function_equal::<F>(ecc_chip.field_chip(), ctx, P, Q);
    assert_eq!(sparse_f.len(), 6);

    let fp_chip = ecc_chip.field_chip.fp_chip();
    let zero_fp = fp_chip.load_constant(ctx, Fq::zero());
    let mut f_coeffs = Vec::with_capacity(12);
    for coeff in &sparse_f {
        if let Some(fp2_point) = coeff {
            f_coeffs.push(fp2_point[0].clone());
        } else {
            f_coeffs.push(zero_fp.clone());
        }
    }
    for coeff in &sparse_f {
        if let Some(fp2_point) = coeff {
            f_coeffs.push(fp2_point[1].clone());
        } else {
            f_coeffs.push(zero_fp.clone());
        }
    }

    let mut f = FieldVector(f_coeffs);
    let fp12_chip = Fp12Chip::<F>::new(fp_chip);

    let mut r = Q.clone();

    let mut found_one = true;
    let mut prev_bit = true;

    // double Q as in the first part of Miller loop
    r = ecc_chip.double(ctx, r.clone());

    // skip two bits after init (first beacuse f = 1, second because 1-ft found_one = false)
    // resequence the loop to perfrom additiona step for the previous iteration first and then doubling step
    for bit in (0..62).rev().map(|i| ((BLS_X >> i) & 1) == 1) {
        if prev_bit {
            f = fp12_multiply_with_line_unequal::<F>(ecc_chip.field_chip(), ctx, &f, P, (&r, Q));
            r = ecc_chip.add_unequal(ctx, r.clone(), Q.clone(), false);
        }

        prev_bit = bit;

        if !found_one {
            found_one = bit;
            continue;
        }

        f = fp12_chip.mul(ctx, &f, &f);

        f = fp12_multiply_with_line_equal::<F>(ecc_chip.field_chip(), ctx, &f, P, &r);
        r = ecc_chip.double(ctx, r.clone());
    }

    if BLS_X_IS_NEGATIVE {
        f = fp12_chip.conjugate(ctx, f)
    }

    f
}

// let pairs = [(a_i, b_i)], a_i in G_1, b_i in G_2
// output is Prod_i e'(a_i, b_i), where e'(a_i, b_i) is the output of `miller_loop_BN(b_i, a_i)`
pub fn multi_miller_loop<F: BigPrimeField>(
    ecc_chip: &EccChip<F, Fp2Chip<F>>,
    ctx: &mut Context<F>,
    pairs: Vec<(&EcPoint<F, FpPoint<F>>, &EcPoint<F, FqPoint<F>>)>,
) -> FqPoint<F> {
    let fp_chip = ecc_chip.field_chip.fp_chip();

    // initialize the first line function into Fq12 point with first (Q,P) pair
    // this is to skip first iteration by leveraging the fact that f = 1
    let mut f = {
        let sparse_f =
            sparse_line_function_equal::<F>(ecc_chip.field_chip(), ctx, pairs[0].0, pairs[0].1);
        assert_eq!(sparse_f.len(), 6);

        let zero_fp = fp_chip.load_constant(ctx, Fq::zero());
        let mut f_coeffs = Vec::with_capacity(12);
        for coeff in &sparse_f {
            if let Some(fp2_point) = coeff {
                f_coeffs.push(fp2_point[0].clone());
            } else {
                f_coeffs.push(zero_fp.clone());
            }
        }
        for coeff in &sparse_f {
            if let Some(fp2_point) = coeff {
                f_coeffs.push(fp2_point[1].clone());
            } else {
                f_coeffs.push(zero_fp.clone());
            }
        }
        FieldVector(f_coeffs)
    };

    // process second (Q,P) pair
    for &(p, q) in pairs.iter().skip(1) {
        f = fp12_multiply_with_line_equal::<F>(ecc_chip.field_chip(), ctx, &f, p, q);
    }

    let fp12_chip = Fp12Chip::<F>::new(fp_chip);

    let mut r = pairs.iter().map(|pair| pair.1.clone()).collect::<Vec<_>>();
    let mut found_one = true;
    let mut prev_bit = true;

    // double Q as in the first part of Miller loop
    for r in r.iter_mut() {
        *r = ecc_chip.double(ctx, r.clone());
    }

    // skip two bits after init (first beacuse f = 1, second because 1-ft found_one = false)
    // resequence the loop to perfrom additiona step for the previous iteration first and then doubling step
    for bit in (0..62).rev().map(|i| ((BLS_X >> i) & 1) == 1) {
        if prev_bit {
            for (r, &(p, q)) in r.iter_mut().zip(pairs.iter()) {
                f = fp12_multiply_with_line_unequal::<F>(ecc_chip.field_chip(), ctx, &f, p, (r, q));
                *r = ecc_chip.add_unequal(ctx, r.clone(), q.clone(), false);
            }
        }

        prev_bit = bit;

        if !found_one {
            found_one = bit;
            continue;
        }

        f = fp12_chip.mul(ctx, &f, &f);

        for (r, &(p, _q)) in r.iter_mut().zip(pairs.iter()) {
            f = fp12_multiply_with_line_equal::<F>(ecc_chip.field_chip(), ctx, &f, p, r);
            *r = ecc_chip.double(ctx, r.clone());
        }
    }

    // Apperently Gt conjugation can be skipped for multi miller loop. However, cannot find evidence for this.
    // if BLS_X_IS_NEGATIVE {
    //     f = fp12_chip.conjugate(ctx, f)
    // }

    f
}

/// Pairing chip for BLS12-381.
/// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store `fp_chip` and construct `g2_chip` in scope when needed for temporary mutable borrows
pub struct PairingChip<'chip, F: BigPrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
}

impl<'chip, F: BigPrimeField> PairingChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>) -> Self {
        Self { fp_chip }
    }

    /// Assigns a constant G1 point without checking if it's on the curve.
    pub fn load_private_g1_unchecked(
        &self,
        ctx: &mut Context<F>,
        point: G1Affine,
    ) -> EcPoint<F, FpPoint<F>> {
        let g1_chip = EccChip::new(self.fp_chip);
        g1_chip.load_private_unchecked(ctx, (point.x, point.y))
    }

    /// Assigns a constant G2 point without checking if it's on the curve.
    pub fn load_private_g2_unchecked(
        &self,
        ctx: &mut Context<F>,
        point: G2Affine,
    ) -> EcPoint<F, FqPoint<F>> {
        let fp2_chip = Fp2Chip::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        g2_chip.load_private_unchecked(ctx, (point.x, point.y))
    }

    /// Miller loop for a single pair of (G1, G2).
    pub fn miller_loop(
        &self,
        ctx: &mut Context<F>,
        P: &EcPoint<F, FpPoint<F>>,
        Q: &EcPoint<F, FqPoint<F>>,
    ) -> FqPoint<F> {
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        miller_loop::<F>(&g2_chip, ctx, P, Q)
    }

    /// Multi-pairing Miller loop.
    pub fn multi_miller_loop(
        &self,
        ctx: &mut Context<F>,
        pairs: Vec<(&EcPoint<F, FpPoint<F>>, &EcPoint<F, FqPoint<F>>)>,
    ) -> FqPoint<F> {
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        multi_miller_loop::<F>(&g2_chip, ctx, pairs)
    }

    /// Final exponentiation to complete the pairing.
    pub fn final_exp(&self, ctx: &mut Context<F>, f: FqPoint<F>) -> FqPoint<F> {
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        fp12_chip.final_exp(ctx, f)
    }

    // optimal Ate pairing
    pub fn pairing(
        &self,
        ctx: &mut Context<F>,
        Q: &EcPoint<F, FqPoint<F>>,
        P: &EcPoint<F, FpPoint<F>>,
    ) -> FqPoint<F> {
        let f0 = self.miller_loop(ctx, P, Q);
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        // final_exp implemented in final_exp module
        fp12_chip.final_exp(ctx, f0)
    }

    /// Multi-pairing Miller loop + final exponentiation.
    pub fn batched_pairing(
        &self,
        ctx: &mut Context<F>,
        pairs: &[(&EcPoint<F, FpPoint<F>>, &EcPoint<F, FqPoint<F>>)],
    ) -> FqPoint<F> {
        let mml = self.multi_miller_loop(ctx, pairs.to_vec());
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fe = fp12_chip.final_exp(ctx, mml.clone());
        fe
    }

    /*
     * Conducts an efficient pairing check e(P, Q) = e(S, T) using only one
     * final exponentiation. In particular, this constraints
     * (e'(-P, Q)e'(S, T))^x = 1, where e' is the optimal ate pairing without
     * the final exponentiation. Reduces number of necessary advice cells by
     * ~30%.
     */
    pub fn pairing_check(
        &self,
        ctx: &mut Context<F>,
        Q: &EcPoint<F, FqPoint<F>>,
        P: &EcPoint<F, FpPoint<F>>,
        T: &EcPoint<F, FqPoint<F>>,
        S: &EcPoint<F, FpPoint<F>>,
    ) {
        let ecc_chip_fp = EccChip::new(self.fp_chip);
        let negated_P = ecc_chip_fp.negate(ctx, P);
        let gt = self.batched_pairing(ctx, &[(&negated_P, Q), (S, T)]);
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fp12_one = fp12_chip.load_constant(ctx, Fq12::one());
        fp12_chip.assert_equal(ctx, gt, fp12_one);
    }
}
