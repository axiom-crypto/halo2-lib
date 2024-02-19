/*
 * Chip for constraining a KZG multi-open verifier.
 */
use super::FrChip;
use crate::bigint::CRTInteger;
use crate::bn254::{Fp2Chip, FpChip};
use crate::commitments::utils::polynomial::Polynomial as Poly;
use crate::ecc::EcPoint;
use crate::fields::poly::PolyChip;
use crate::fields::{FieldChip, PrimeField};
use crate::{bn254::pairing::PairingChip, ecc::EccChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};

pub struct KZGChip<'a, F: PrimeField> {
    poly_chip: &'a PolyChip<'a, F, FrChip<'a, F>>,
    pairing_chip: &'a PairingChip<'a, F>,
    g1_chip: &'a EccChip<'a, F, FpChip<'a, F>>,
    g2_chip: &'a EccChip<'a, F, Fp2Chip<'a, F>>,
}

impl<'a, F: PrimeField> KZGChip<'a, F> {
    pub fn new(
        poly_chip: &'a PolyChip<'a, F, FrChip<F>>,
        pairing_chip: &'a PairingChip<'a, F>,
        g1_chip: &'a EccChip<'a, F, FpChip<'a, F>>,
        g2_chip: &'a EccChip<'a, F, Fp2Chip<'a, F>>,
    ) -> Self {
        Self { poly_chip, pairing_chip, g1_chip, g2_chip }
    }

    /*
     * Given the pre-computed coefficients of r(X) and z(X),
     * polynomial commitment, and opening proof, verify the opening.
     *
     * IMPORTANT: that r(X) and z(X) are not guaranteed to be validly computed
     * and must either be manually checked by the verifier, or computed
     * in-circuit by calling self::check_kzg_polynomials.
     */
    pub fn opening_assert_unsafe(
        &self,
        builder: &mut GateThreadBuilder<F>,
        commitment: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        r_coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        quotient: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        z_coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        ptau_g1_loaded: &[EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>],
        ptau_g2_loaded: &[EcPoint<F, <Fp2Chip<'a, F> as FieldChip<F>>::FieldPoint>],
    ) {
        let r_curve = self.g1_chip.variable_base_msm::<G1Affine>(
            builder,
            &ptau_g1_loaded,
            r_coeffs.iter().map(|x| vec![*x.native()]).collect::<Vec<_>>(),
            254,
        );
        let z_curve = self.g2_chip.variable_base_msm::<G2Affine>(
            builder,
            &ptau_g2_loaded,
            z_coeffs.iter().map(|x| vec![*x.native()]).collect::<Vec<_>>(),
            254,
        );

        let ctx = builder.main(0);
        let p_bar_r_diff = self.g1_chip.sub_unequal(ctx, commitment, r_curve, true);
        let g2_generator = self.g2_chip.assign_constant_point(ctx, G2Affine::generator());
        self.pairing_chip.pairing_check(ctx, &z_curve, &quotient, &g2_generator, &p_bar_r_diff);
    }

    /*
     * Checks that r(X) and Z(X) are properly constructed.
     */
    pub fn check_kzg_polynomials(
        &self,
        builder: &mut GateThreadBuilder<F>,
        open_idxs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        open_vals: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        z_coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
    ) {
        let ctx = builder.main(0);

        // r(X) must open to all (open_idxs, open_vals)
        for (root, opening) in open_idxs.iter().zip(open_vals.iter()) {
            let eval = self.poly_chip.evaluate(ctx, r_coeffs, root);
            self.poly_chip.fr_chip.assert_equal(ctx, eval, opening);
        }

        // Z(X) must open to 0 for all open_idxs
        for root in open_idxs.iter() {
            let eval = self.poly_chip.evaluate(ctx, z_coeffs, root);
            let zero = self.poly_chip.fr_chip.load_constant(ctx, Fr::zero());
            self.poly_chip.fr_chip.assert_equal(ctx, eval, zero);
        }

        // Need to constrain an extra point on Z(X) since it is an m degree
        // polynomial, where m is the number of openings. Need m + 1 points to
        // uniquely determine it. Our extra point is Z(0), which must be equal
        // to the product of all negated open_vals.
        let mut acc = self.poly_chip.fr_chip.load_constant(ctx, Fr::one());
        let eval_zero = &z_coeffs[0];
        for root in open_idxs.iter() {
            let root_neg = self.poly_chip.fr_chip.negate(ctx, root.clone());
            acc = self.poly_chip.fr_chip.mul(ctx, acc, root_neg);
        }
        self.poly_chip.fr_chip.assert_equal(ctx, acc, eval_zero);
    }

    /*
     * Given a set of points, and their evaluations for r(X), compute z(X)
     * and r(X). Then it properly constrains the computed coefficients.
     */
    pub fn generate_coeffs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        open_idxs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        open_vals: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
    ) -> (Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>, Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>)
    {
        let free_open_idxs = open_idxs
            .iter()
            .map(|x| self.poly_chip.fr_chip.get_assigned_value(&CRTInteger::from(x)))
            .collect::<Vec<_>>();
        let free_open_vals = open_vals
            .iter()
            .map(|x| self.poly_chip.fr_chip.get_assigned_value(&CRTInteger::from(x)))
            .collect::<Vec<_>>();

        let r_coeffs = Poly::from_points_lagrange(&free_open_idxs, &free_open_vals).get_coeffs();
        let z_coeffs = Poly::vanishing(&free_open_idxs).get_coeffs();

        let mut load_fr = |x: Vec<Fr>| {
            x.into_iter()
                .map(|c| self.poly_chip.fr_chip.load_private(builder.main(0), c))
                .collect::<Vec<_>>()
        };
        let loaded_r_coeffs = load_fr(r_coeffs);
        let loaded_z_coeffs = load_fr(z_coeffs);

        self.check_kzg_polynomials(
            builder,
            open_idxs,
            open_vals,
            &loaded_r_coeffs,
            &loaded_z_coeffs,
        );
        (loaded_r_coeffs, loaded_z_coeffs)
    }

    /*
     * Given the pre-computed coefficients of r(X) and z(X), commitment, and
     * opening proof, verify the opening.
     */
    pub fn opening_assert(
        &self,
        builder: &mut GateThreadBuilder<F>,
        p_bar: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        open_idxs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        open_vals: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        q_bar: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        ptau_g1_loaded: &[EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>],
        ptau_g2_loaded: &[EcPoint<F, <Fp2Chip<'a, F> as FieldChip<F>>::FieldPoint>],
    ) {
        let (r_coeffs, z_coeffs) = self.generate_coeffs(builder, open_idxs, open_vals);
        self.opening_assert_unsafe(
            builder,
            p_bar,
            &r_coeffs,
            q_bar,
            &z_coeffs,
            ptau_g1_loaded,
            ptau_g2_loaded,
        );
    }
}
