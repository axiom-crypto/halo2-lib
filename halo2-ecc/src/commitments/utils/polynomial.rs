/*
 * For doing core operations of polynomials defined over finite fields. Used
 * custom implementation here because we needed Euclidean division.
 * Inspired by https://applied-math-coding.medium.com/implementing-polynomial-division-rust-ca2a59370003
 */
use halo2_base::halo2_proofs::{
    arithmetic::{best_fft, lagrange_interpolate, CurveExt},
    halo2curves::FieldExt,
};
use std::ops::{Add, AddAssign, Mul, Neg, Sub};

#[derive(Clone, Debug)]
pub struct Polynomial<F: FieldExt>(Vec<F>);

impl<F: FieldExt> Neg for Polynomial<F> {
    type Output = Self;

    /*
     * Negating the polynomial.
     */
    fn neg(self) -> Self::Output {
        Polynomial(self.0.iter().map(|a| a.neg()).collect())
    }
}

impl<F: FieldExt> Add for Polynomial<F> {
    type Output = Self;

    /*
     * Adding a polynomial on the right.
     */
    fn add(self, rhs: Self) -> Self::Output {
        let mut a = vec![];
        for i in 0..usize::max(self.deg(), rhs.deg()) + 1 {
            a.push(*self.0.get(i).unwrap_or(&F::zero()) + rhs.0.get(i).unwrap_or(&F::zero()));
        }
        Polynomial(a)
    }
}

impl<F: FieldExt> Sub for Polynomial<F> {
    type Output = Self;

    /*
     * Subtracting a polynomial on the right.
     */
    fn sub(self, rhs: Self) -> Self::Output {
        let mut a = vec![];
        for i in 0..usize::max(self.deg(), rhs.deg()) + 1 {
            a.push(*self.0.get(i).unwrap_or(&F::zero()) - rhs.0.get(i).unwrap_or(&F::zero()));
        }
        Polynomial(a)
    }
}

impl<F: FieldExt> Mul for Polynomial<F> {
    type Output = Self;

    /*
     * Multiplying a polynomial on the right.
     */
    fn mul(self, rhs: Self) -> Self::Output {
        let [n, m] = [self.deg(), rhs.deg()];
        let mut a = vec![F::zero(); n + m + 1];
        for i in 0..n + 1 {
            for j in 0..m + 1 {
                a[i + j] = a[i + j] + self.0[i] * rhs.0[j];
            }
        }
        Polynomial(a)
    }
}

impl<F: FieldExt> Polynomial<F> {
    /*
     * Instantiates a new polynomial coefficients stored in the monomial
     * basis w/ increasing degree. Eg Coefficients of f(x) = 2 + x + 3x^2 are
     * stored as [2, 1, 3].
     */
    pub fn new(coeffs: Vec<F>) -> Self {
        return Self(coeffs);
    }

    /*
     * Uses inverse FFT to find the lowest degree polynomial that passes through
     * (w_i, eval_i) for all i in [0, n). Assumes that evals is of length 
     * 2^k and w is a 2^k-th root of unity in F. 
     */
    pub fn from_points_ifft(evals: Vec<F>, w: F, k: u32) -> Self {
        let mut coeffs = evals.clone();
        best_fft(&mut coeffs, w.invert().unwrap(), k);
        coeffs = coeffs
            .into_iter()
            .map(|x| x * F::from(evals.len() as u64).invert().unwrap())
            .collect::<Vec<F>>();
        Self::new(coeffs)
    }

    /*
     * Uses lagrange interpolation to find the lowest degree polynomial that
     * passes through (points, evals).
     */
    pub fn from_points_lagrange(points: &[F], evals: &[F]) -> Self {
        Self::new(lagrange_interpolate(points, evals))
    }

    /*
     * Computes the vanishing polynomial z(X) = Σ X - z_i for a vector of
     * indices.
     */
    pub fn vanishing(openings: &[F]) -> Self {
        if openings.is_empty() {
            panic!("Cannot compute a vanishing polynomial for 0 openings.");
        }
        let mut z: Polynomial<F> = Self::new(vec![F::one()]);
        for open_idx in openings {
            z = z * Self::new(vec![open_idx.neg(), F::one()]);
        }
        z
    }

    /*
     * Evaluates this polynomial at f(τ) using powers tau [G * τ^0, G * τ^1,
     * ..., G * τ^i].
     */
    pub fn eval_ptau<G: CurveExt + Mul<F, Output = G> + AddAssign>(&self, ptau: &[G]) -> G {
        if self.0.is_empty() {
            panic!("Cannot evaluate polynomial with no coefficients.");
        }
        if self.0.len() > ptau.len() {
            panic!("Aren't enough powers of tau to capture all coefficients.");
        }
        let mut acc = G::identity();
        for (i, coeff) in self.0.iter().enumerate() {
            acc += ptau[i] * coeff.clone();
        }
        acc
    }

    /*
     * Accessor function to get the coefficients of this polynomial.
     */
    pub fn get_coeffs(&self) -> Vec<F> {
        self.0.clone()
    }

    /*
     * Get the degree of this polynomial.
     */
    fn deg(&self) -> usize {
        self.0
            .iter()
            .enumerate()
            .rev()
            .find(|(_, a)| !bool::from(a.is_zero()))
            .map(|(idx, _)| idx)
            .unwrap_or(0)
    }

    /*
     * Checks whether this is a zero polynomial.
     */
    pub fn is_zero(&self) -> bool {
        for coeff in &self.0 {
            if !bool::from(coeff.is_zero()) {
                return false;
            }
        }
        true
    }

    /*
     * Returns the polynomial f(X) = 0.
     */
    fn zero() -> Self {
        Polynomial(vec![F::zero()])
    }

    /*
     * Euclidean division for two polynomials, with f(X) as the dividend and
     * g(X) as the divisor. Returns (quotient, remainder).
     */
    pub fn div_euclid(f: &Self, g: &Self) -> (Self, Self) {
        let [n, m] = [f.deg(), g.deg()];
        if n < m {
            (Self::zero(), f.clone())
        } else if n == 0 {
            if *g.0.get(0).unwrap_or(&F::zero()) == F::zero() {
                panic!("Cannot divide by 0!");
            }
            (Polynomial(vec![f.0[0] * g.0[0].invert().unwrap()]), Self::zero())
        } else {
            let [a_n, b_m] = [f.0[n], g.0[m]];
            let mut q_1 = Polynomial(vec![F::zero(); n - m + 1]);
            q_1.0[n - m] = a_n * b_m.invert().unwrap();
            let h_2 = f.clone() - q_1.clone() * g.clone();
            let (q_2, r) = Self::div_euclid(&h_2, g);
            (q_1 + q_2, r)
        }
    }
}
