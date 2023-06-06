use std::fmt::Debug;
use crate::bigint::CRTInteger;
use crate::bn254::{Fp2Chip, FpChip, FrChip};
use crate::ecc::EcPoint;
use crate::{bn254::pairing::PairingChip, ecc::EccChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine, Fr};
use crate::commitments::utils::polynomial::{Polynomial as Poly};

use crate::fields::{FieldChip, PrimeField};

use super::poly::PolyChip;

/*
 * KZG Chip
 */
#[derive(Clone, Debug)]
pub struct KZGChip<'a, F: PrimeField> {
    poly_chip: &'a PolyChip<'a, F>,
    pairing_chip: &'a PairingChip<'a, F>,
    g1_chip: &'a EccChip<'a, F, FpChip<'a, F>>,
    g2_chip: &'a EccChip<'a, F, Fp2Chip<'a, F>>,
}

impl<'a, F: PrimeField> KZGChip<'a, F> {
    pub fn new(
        poly_chip: &'a PolyChip<'a, F>,
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
     * in-circuit through calling Self::check_kzg_polynomials.
     */
    pub fn opening_assert_unsafe(
        &self,
        builder: &mut GateThreadBuilder<F>,
        ptau_g1_loaded: &[EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>],
        ptau_g2_loaded: &[EcPoint<F, <Fp2Chip<'a, F> as FieldChip<F>>::FieldPoint>],
        r_coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        z_coeffs: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        commitment: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        quotient: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
    ) {
        // Consider later how to dea
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
    * Performs a check to verify that r(X) open to a set of openings for a given set of points,
    * and z(X) is the vanishing polynomial over a set of point 
    */
    pub fn check_kzg_polynomials(
        &self,
        builder: &mut GateThreadBuilder<F>,
        eval_points: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_openings: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_coeffs_fr: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        z_coeffs_fr: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>
    ) {
        let ctx = builder.main(0);

        for (root, opening) in eval_points.iter().zip(r_openings.iter()) {
            let eval = self.poly_chip.evaluate(ctx, r_coeffs_fr, root);
            self.poly_chip.fr_chip.assert_equal(ctx, eval, opening);
        }
        for root in eval_points.iter() {
            let eval = self.poly_chip.evaluate(ctx, z_coeffs_fr, root);
            let zero = self.poly_chip.fr_chip.load_constant(ctx, Fr::zero());
            self.poly_chip.fr_chip.assert_equal(ctx, eval, zero);
        }
    }

    /*
     * Given a bunch of points, and their evaluations for r(X),
     * compute z(X) and r(X)
     */
    pub fn generate_coeffs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        eval_points: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_openings: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
    ) ->  (Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>, Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>) {
        let free_eval_points = eval_points.iter().map(|x| self.poly_chip.fr_chip.get_assigned_value(&CRTInteger::from(x))).collect::<Vec<_>>();
        let free_r_openings = r_openings.iter().map(|x| self.poly_chip.fr_chip.get_assigned_value(&CRTInteger::from(x))).collect::<Vec<_>>();
        let r_coeffs_fr = Poly::from_points(&free_eval_points, &free_r_openings).get_coeffs();
        let z_coeffs_fr = Poly::vanishing(&free_eval_points).get_coeffs();
        let mut load_fr = |x: Vec<Fr>| x.into_iter().map(|c| self.poly_chip.fr_chip.load_private(builder.main(0), c)).collect::<Vec<_>>();
        let loaded_r_coeffs = load_fr(r_coeffs_fr);
        let loaded_z_coeffs = load_fr(z_coeffs_fr);
        self.check_kzg_polynomials(
            builder,
            eval_points,
            r_openings,
            &loaded_r_coeffs,
            &loaded_z_coeffs,
        );
        (loaded_r_coeffs, loaded_z_coeffs)
    }

    /*
     * Given the pre-computed coefficients of r(X) and z(X),
     * polynomial commitment, and opening proof, verify the opening.
     */
    pub fn opening_assert(
        &self,
        builder: &mut GateThreadBuilder<F>,
        ptau_g1_loaded: &[EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>],
        ptau_g2_loaded: &[EcPoint<F, <Fp2Chip<'a, F> as FieldChip<F>>::FieldPoint>],
        eval_roots: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_openings: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        p_bar: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        q_bar: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
    ) {
        let (r_coeffs, z_coeffs) = self.generate_coeffs(builder, eval_roots, r_openings);
        self.opening_assert_unsafe(builder, ptau_g1_loaded, ptau_g2_loaded, &r_coeffs, &z_coeffs, p_bar, q_bar);
    }
}
