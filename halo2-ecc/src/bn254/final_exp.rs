use super::{Fp12Chip, Fp2Chip, FpChip, FqPoint};
use crate::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Fq, Fq2, BN_X, FROBENIUS_COEFF_FQ12_C1},
};
use crate::{
    ecc::get_naf,
    fields::{fp12::mul_no_carry_w6, vector::FieldVector, FieldChip},
};
use halo2_base::{
    gates::GateInstructions,
    utils::{modulus, BigPrimeField},
    Context,
    QuantumCell::Constant,
};
use num_bigint::BigUint;

const XI_0: i64 = 9;

impl<'chip, F: BigPrimeField> Fp12Chip<'chip, F> {
    // computes a ** (p ** power)
    // only works for p = 3 (mod 4) and p = 1 (mod 6)
    pub fn frobenius_map(
        &self,
        ctx: &mut Context<F>,
        a: &<Self as FieldChip<F>>::FieldPoint,
        power: usize,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        assert_eq!(modulus::<Fq>() % 4u64, BigUint::from(3u64));
        assert_eq!(modulus::<Fq>() % 6u64, BigUint::from(1u64));
        assert_eq!(a.0.len(), 12);
        let pow = power % 12;
        let mut out_fp2 = Vec::with_capacity(6);

        let fp_chip = self.fp_chip();
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);
        for i in 0..6 {
            let frob_coeff = FROBENIUS_COEFF_FQ12_C1[pow].pow_vartime([i as u64]);
            // possible optimization (not implemented): load `frob_coeff` as we multiply instead of loading first
            // frobenius map is used infrequently so this is a small optimization

            let mut a_fp2 = FieldVector(vec![a[i].clone(), a[i + 6].clone()]);
            if pow % 2 != 0 {
                a_fp2 = fp2_chip.conjugate(ctx, a_fp2);
            }
            // if `frob_coeff` is in `Fp` and not just `Fp2`, then we can be more efficient in multiplication
            if frob_coeff == Fq2::one() {
                out_fp2.push(a_fp2);
            } else if frob_coeff.c1 == Fq::zero() {
                let frob_fixed = fp_chip.load_constant(ctx, frob_coeff.c0);
                {
                    let out_nocarry = fp2_chip.0.fp_mul_no_carry(ctx, a_fp2, frob_fixed);
                    out_fp2.push(fp2_chip.carry_mod(ctx, out_nocarry));
                }
            } else {
                let frob_fixed = fp2_chip.load_constant(ctx, frob_coeff);
                out_fp2.push(fp2_chip.mul(ctx, a_fp2, frob_fixed));
            }
        }

        let out_coeffs = out_fp2
            .iter()
            .map(|x| x[0].clone())
            .chain(out_fp2.iter().map(|x| x[1].clone()))
            .collect();

        FieldVector(out_coeffs)
    }

    // exp is in little-endian
    /// # Assumptions
    /// * `a` is nonzero field point
    pub fn pow(
        &self,
        ctx: &mut Context<F>,
        a: &<Self as FieldChip<F>>::FieldPoint,
        exp: Vec<u64>,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        let mut res = a.clone();
        let mut is_started = false;
        let naf = get_naf(exp);

        for &z in naf.iter().rev() {
            if is_started {
                res = self.mul(ctx, &res, &res);
            }

            if z != 0 {
                assert!(z == 1 || z == -1);
                if is_started {
                    res = if z == 1 {
                        self.mul(ctx, &res, a)
                    } else {
                        self.divide_unsafe(ctx, &res, a)
                    };
                } else {
                    assert_eq!(z, 1);
                    is_started = true;
                }
            }
        }
        res
    }

    // assume input is an element of Fp12 in the cyclotomic subgroup GΦ₁₂
    // A cyclotomic group is a subgroup of Fp^n defined by
    //   GΦₙ(p) = {α ∈ Fpⁿ : α^{Φₙ(p)} = 1}

    // below we implement compression and decompression for an element  GΦ₁₂ following Theorem 3.1 of https://eprint.iacr.org/2010/542.pdf
    // Fp4 = Fp2(w^3) where (w^3)^2 = XI_0 +u
    // Fp12 = Fp4(w) where w^3 = w^3

    /// in = g0 + g2 w + g4 w^2 + g1 w^3 + g3 w^4 + g5 w^5 where g_i = g_i0 + g_i1 * u are elements of Fp2
    /// out = Compress(in) = [ g2, g3, g4, g5 ]
    pub fn cyclotomic_compress(&self, a: &FqPoint<F>) -> Vec<FqPoint<F>> {
        let a = &a.0;
        let g2 = FieldVector(vec![a[1].clone(), a[1 + 6].clone()]);
        let g3 = FieldVector(vec![a[4].clone(), a[4 + 6].clone()]);
        let g4 = FieldVector(vec![a[2].clone(), a[2 + 6].clone()]);
        let g5 = FieldVector(vec![a[5].clone(), a[5 + 6].clone()]);
        vec![g2, g3, g4, g5]
    }

    /// Input:
    /// * `compression = [g2, g3, g4, g5]` where g_i are proper elements of Fp2
    ///
    /// Output:
    /// * `Decompress(compression) = g0 + g2 w + g4 w^2 + g1 w^3 + g3 w^4 + g5 w^5` where
    /// * All elements of output are proper elements of Fp2 and:
    ///     c = XI0 + u
    ///     if g2 != 0:
    ///         g1 = (g5^2 * c + 3 g4^2 - 2 g3)/(4g2)
    ///         g0 = (2 g1^2 + g2 * g5 - 3 g3*g4) * c + 1
    ///     if g2 = 0:
    ///         g1 = (2 g4 * g5)/g3
    ///         g0 = (2 g1^2 - 3 g3 * g4) * c + 1
    pub fn cyclotomic_decompress(
        &self,
        ctx: &mut Context<F>,
        compression: Vec<FqPoint<F>>,
    ) -> FqPoint<F> {
        let [g2, g3, g4, g5]: [_; 4] = compression.try_into().unwrap();

        let fp_chip = self.fp_chip();
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);
        let g5_sq = fp2_chip.mul_no_carry(ctx, &g5, &g5);
        let g5_sq_c = mul_no_carry_w6::<_, _, XI_0>(fp_chip, ctx, g5_sq);

        let g4_sq = fp2_chip.mul_no_carry(ctx, &g4, &g4);
        let g4_sq_3 = fp2_chip.scalar_mul_no_carry(ctx, &g4_sq, 3);
        let g3_2 = fp2_chip.scalar_mul_no_carry(ctx, &g3, 2);

        let mut g1_num = fp2_chip.add_no_carry(ctx, &g5_sq_c, &g4_sq_3);
        g1_num = fp2_chip.sub_no_carry(ctx, &g1_num, &g3_2);
        // can divide without carrying g1_num or g1_denom (I think)
        let g2_4 = fp2_chip.scalar_mul_no_carry(ctx, &g2, 4);
        let g1_1 = fp2_chip.divide_unsafe(ctx, &g1_num, &g2_4);

        let g4_g5 = fp2_chip.mul_no_carry(ctx, &g4, &g5);
        let g1_num = fp2_chip.scalar_mul_no_carry(ctx, &g4_g5, 2);
        let g1_0 = fp2_chip.divide_unsafe(ctx, &g1_num, &g3);

        let g2_is_zero = fp2_chip.is_zero(ctx, &g2);
        // resulting `g1` is already in "carried" format (witness is in `[0, p)`)
        let g1 = fp2_chip.0.select(ctx, g1_0, g1_1, g2_is_zero);

        // share the computation of 2 g1^2 between the two cases
        let g1_sq = fp2_chip.mul_no_carry(ctx, &g1, &g1);
        let g1_sq_2 = fp2_chip.scalar_mul_no_carry(ctx, &g1_sq, 2);

        let g2_g5 = fp2_chip.mul_no_carry(ctx, &g2, &g5);
        let g3_g4 = fp2_chip.mul_no_carry(ctx, &g3, &g4);
        let g3_g4_3 = fp2_chip.scalar_mul_no_carry(ctx, &g3_g4, 3);
        let temp = fp2_chip.add_no_carry(ctx, &g1_sq_2, &g2_g5);
        let temp = fp2_chip.0.select(ctx, g1_sq_2, temp, g2_is_zero);
        let temp = fp2_chip.sub_no_carry(ctx, &temp, &g3_g4_3);
        let mut g0 = mul_no_carry_w6::<_, _, XI_0>(fp_chip, ctx, temp);

        // compute `g0 + 1`
        g0[0].truncation.limbs[0] =
            fp2_chip.gate().add(ctx, g0[0].truncation.limbs[0], Constant(F::ONE));
        g0[0].native = fp2_chip.gate().add(ctx, g0[0].native, Constant(F::ONE));
        g0[0].truncation.max_limb_bits += 1;
        g0[0].value += 1usize;

        // finally, carry g0
        let g0 = fp2_chip.carry_mod(ctx, g0);

        let mut g0 = g0.into_iter();
        let mut g1 = g1.into_iter();
        let mut g2 = g2.into_iter();
        let mut g3 = g3.into_iter();
        let mut g4 = g4.into_iter();
        let mut g5 = g5.into_iter();

        let mut out_coeffs = Vec::with_capacity(12);
        for _ in 0..2 {
            out_coeffs.append(&mut vec![
                g0.next().unwrap(),
                g2.next().unwrap(),
                g4.next().unwrap(),
                g1.next().unwrap(),
                g3.next().unwrap(),
                g5.next().unwrap(),
            ]);
        }
        FieldVector(out_coeffs)
    }

    // input is [g2, g3, g4, g5] = C(g) in compressed format of `cyclotomic_compress`
    // assume all inputs are proper Fp2 elements
    // output is C(g^2) = [h2, h3, h4, h5] computed using Theorem 3.2 of https://eprint.iacr.org/2010/542.pdf
    // all output elements are proper Fp2 elements (with carry)
    //  c = XI_0 + u
    //  h2 = 2(g2 + 3*c*B_45)
    //  h3 = 3(A_45 - (c+1)B_45) - 2g3
    //  h4 = 3(A_23 - (c+1)B_23) - 2g4
    //  h5 = 2(g5 + 3B_23)
    //  A_ij = (g_i + g_j)(g_i + c g_j)
    //  B_ij = g_i g_j

    pub fn cyclotomic_square(
        &self,
        ctx: &mut Context<F>,
        compression: &[FqPoint<F>],
    ) -> Vec<FqPoint<F>> {
        assert_eq!(compression.len(), 4);
        let g2 = &compression[0];
        let g3 = &compression[1];
        let g4 = &compression[2];
        let g5 = &compression[3];

        let fp_chip = self.fp_chip();
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);

        let g2_plus_g3 = fp2_chip.add_no_carry(ctx, g2, g3);
        let cg3 = mul_no_carry_w6::<F, FpChip<F>, XI_0>(fp_chip, ctx, g3.into());
        let g2_plus_cg3 = fp2_chip.add_no_carry(ctx, g2, &cg3);
        let a23 = fp2_chip.mul_no_carry(ctx, &g2_plus_g3, &g2_plus_cg3);

        let g4_plus_g5 = fp2_chip.add_no_carry(ctx, g4, g5);
        let cg5 = mul_no_carry_w6::<_, _, XI_0>(fp_chip, ctx, g5.into());
        let g4_plus_cg5 = fp2_chip.add_no_carry(ctx, g4, &cg5);
        let a45 = fp2_chip.mul_no_carry(ctx, &g4_plus_g5, &g4_plus_cg5);

        let b23 = fp2_chip.mul_no_carry(ctx, g2, g3);
        let b45 = fp2_chip.mul_no_carry(ctx, g4, g5);
        let b45_c = mul_no_carry_w6::<_, _, XI_0>(fp_chip, ctx, b45.clone());

        let mut temp = fp2_chip.scalar_mul_and_add_no_carry(ctx, &b45_c, g2, 3);
        let h2 = fp2_chip.scalar_mul_no_carry(ctx, &temp, 2);

        temp = fp2_chip.add_no_carry(ctx, b45_c, b45);
        temp = fp2_chip.sub_no_carry(ctx, &a45, temp);
        temp = fp2_chip.scalar_mul_no_carry(ctx, temp, 3);
        let h3 = fp2_chip.scalar_mul_and_add_no_carry(ctx, g3, temp, -2);

        const XI0_PLUS_1: i64 = XI_0 + 1;
        // (c + 1) = (XI_0 + 1) + u
        temp = mul_no_carry_w6::<F, FpChip<F>, XI0_PLUS_1>(fp_chip, ctx, b23.clone());
        temp = fp2_chip.sub_no_carry(ctx, &a23, temp);
        temp = fp2_chip.scalar_mul_no_carry(ctx, temp, 3);
        let h4 = fp2_chip.scalar_mul_and_add_no_carry(ctx, g4, temp, -2);

        temp = fp2_chip.scalar_mul_and_add_no_carry(ctx, b23, g5, 3);
        let h5 = fp2_chip.scalar_mul_no_carry(ctx, temp, 2);

        [h2, h3, h4, h5].into_iter().map(|h| fp2_chip.carry_mod(ctx, h)).collect()
    }

    // exp is in little-endian
    /// # Assumptions
    /// * `a` is a nonzero element in the cyclotomic subgroup
    pub fn cyclotomic_pow(&self, ctx: &mut Context<F>, a: FqPoint<F>, exp: Vec<u64>) -> FqPoint<F> {
        let mut compression = self.cyclotomic_compress(&a);
        let mut out = None;
        let mut is_started = false;
        let naf = get_naf(exp);

        for &z in naf.iter().rev() {
            if is_started {
                compression = self.cyclotomic_square(ctx, &compression);
            }
            if z != 0 {
                assert!(z == 1 || z == -1);
                if is_started {
                    let mut res = self.cyclotomic_decompress(ctx, compression);
                    res = if z == 1 {
                        self.mul(ctx, &res, &a)
                    } else {
                        self.divide_unsafe(ctx, &res, &a)
                    };
                    // compression is free, so it doesn't hurt (except possibly witness generation runtime) to do it
                    // TODO: alternatively we go from small bits to large to avoid this compression
                    compression = self.cyclotomic_compress(&res);
                    out = Some(res);
                } else {
                    assert_eq!(z, 1);
                    is_started = true;
                }
            }
        }
        if naf[0] == 0 {
            out = Some(self.cyclotomic_decompress(ctx, compression));
        }
        out.unwrap_or(a)
    }

    #[allow(non_snake_case)]
    // use equation for (p^4 - p^2 + 1)/r in Section 5 of https://eprint.iacr.org/2008/490.pdf for BN curves
    pub fn hard_part_BN(
        &self,
        ctx: &mut Context<F>,
        m: <Self as FieldChip<F>>::FieldPoint,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        // x = BN_X

        // m^p
        let mp = self.frobenius_map(ctx, &m, 1);
        // m^{p^2}
        let mp2 = self.frobenius_map(ctx, &m, 2);
        // m^{p^3}
        let mp3 = self.frobenius_map(ctx, &m, 3);

        // y0 = m^p * m^{p^2} * m^{p^3}
        let mp2_mp3 = self.mul(ctx, &mp2, &mp3);
        let y0 = self.mul(ctx, &mp, &mp2_mp3);
        // y1 = 1/m,  inverse = frob(6) = conjugation in cyclotomic subgroup
        let y1 = self.conjugate(ctx, m.clone());

        // m^x
        let mx = self.cyclotomic_pow(ctx, m, vec![BN_X]);
        // (m^x)^p
        let mxp = self.frobenius_map(ctx, &mx, 1);
        // m^{x^2}

        let mx2 = self.cyclotomic_pow(ctx, mx.clone(), vec![BN_X]);
        // (m^{x^2})^p
        let mx2p = self.frobenius_map(ctx, &mx2, 1);
        // y2 = (m^{x^2})^{p^2}
        let y2 = self.frobenius_map(ctx, &mx2, 2);
        // m^{x^3}
        // y5 = 1/mx2
        let y5 = self.conjugate(ctx, mx2.clone());

        let mx3 = self.cyclotomic_pow(ctx, mx2, vec![BN_X]);
        // (m^{x^3})^p
        let mx3p = self.frobenius_map(ctx, &mx3, 1);

        // y3 = 1/mxp
        let y3 = self.conjugate(ctx, mxp);
        // y4 = 1/(mx * mx2p)
        let mx_mx2p = self.mul(ctx, &mx, &mx2p);
        let y4 = self.conjugate(ctx, mx_mx2p);
        // y6 = 1/(mx3 * mx3p)
        let mx3_mx3p = self.mul(ctx, &mx3, &mx3p);
        let y6 = self.conjugate(ctx, mx3_mx3p);

        // out = y0 * y1^2 * y2^6 * y3^12 * y4^18 * y5^30 * y6^36
        // we compute this using the vectorial addition chain from p. 6 of https://eprint.iacr.org/2008/490.pdf
        let mut T0 = self.mul(ctx, &y6, &y6);
        T0 = self.mul(ctx, &T0, &y4);
        T0 = self.mul(ctx, &T0, &y5);
        let mut T1 = self.mul(ctx, &y3, &y5);
        T1 = self.mul(ctx, &T1, &T0);
        T0 = self.mul(ctx, &T0, &y2);
        T1 = self.mul(ctx, &T1, &T1);
        T1 = self.mul(ctx, &T1, &T0);
        T1 = self.mul(ctx, &T1, &T1);
        T0 = self.mul(ctx, &T1, &y1);
        T1 = self.mul(ctx, &T1, &y0);
        T0 = self.mul(ctx, &T0, &T0);
        T0 = self.mul(ctx, &T0, &T1);

        T0
    }

    // out = in^{ (q^6 - 1)*(q^2 + 1) }
    /// # Assumptions
    /// * `a` is nonzero field point
    pub fn easy_part(
        &self,
        ctx: &mut Context<F>,
        a: <Self as FieldChip<F>>::FieldPoint,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        // a^{q^6} = conjugate of a
        let f1 = self.conjugate(ctx, a.clone());
        let f2 = self.divide_unsafe(ctx, &f1, a);
        let f3 = self.frobenius_map(ctx, &f2, 2);
        self.mul(ctx, &f3, &f2)
    }

    // out = in^{(q^12 - 1)/r}
    pub fn final_exp(
        &self,
        ctx: &mut Context<F>,
        a: <Self as FieldChip<F>>::FieldPoint,
    ) -> <Self as FieldChip<F>>::FieldPoint {
        let f0 = self.easy_part(ctx, a);
        let f = self.hard_part_BN(ctx, f0);
        f
    }
}
