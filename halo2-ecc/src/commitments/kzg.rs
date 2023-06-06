use std::fmt::Debug;

use crate::bigint::{CRTInteger, ProperCrtUint};
use crate::bn254::{Fp2Chip, FpChip, FrChip};
use crate::ecc::EcPoint;
use crate::{bn254::pairing::PairingChip, ecc::EccChip};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::plonk::Assigned;
use halo2_base::AssignedValue;

use crate::fields::{FieldChip, PrimeField};

use super::poly::PolyChip;

/// Represent Fp2 point as `FieldVector` with degree = 2
/// `Fp2 = Fp[u] / (u^2 + 1)`
/// This implementation assumes p = 3 (mod 4) in order for the polynomial u^2 + 1 to be irreducible over Fp; i.e., in order for -1 to not be a square (quadratic residue) in Fp
/// This means we store an Fp2 point as `a_0 + a_1 * u` where `a_0, a_1 in Fp`
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

    // Assert an opening
    pub fn opening_assert(
        &self,
        builder: &mut GateThreadBuilder<F>,
        ptau_g1_loaded: &[EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>],
        ptau_g2_loaded: &[EcPoint<F, <Fp2Chip<'a, F> as FieldChip<F>>::FieldPoint>],
        eval_roots: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_openings: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        r_coeffs: Vec<Vec<AssignedValue<F>>>,
        r_coeffs_fr: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        z_coeffs: Vec<Vec<AssignedValue<F>>>,
        z_coeffs_fr: &Vec<<FrChip<F> as FieldChip<F>>::FieldPoint>,
        p_bar: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
        q_bar: EcPoint<F, <FpChip<'a, F> as FieldChip<F>>::FieldPoint>,
    ) {
        let r_curve =
            self.g1_chip.variable_base_msm::<G1Affine>(builder, &ptau_g1_loaded, r_coeffs, 254);

        let z_curve =
            self.g2_chip.variable_base_msm::<G2Affine>(builder, &ptau_g2_loaded, z_coeffs, 254);

        let ctx = builder.main(0);
        for (root, opening) in eval_roots.iter().zip(r_openings.iter()) {
            let eval = self.poly_chip.evaluate(ctx, r_coeffs_fr, root);
            self.poly_chip.fr_chip.assert_equal(ctx, eval, opening)
        }

        let p_bar_r_diff = self.g1_chip.sub_unequal(ctx, p_bar, r_curve, true);
        let g2_generator = self.g2_chip.assign_constant_point(ctx, G2Affine::generator());

        self.pairing_chip.pairing_check(ctx, &z_curve, &q_bar, &g2_generator, &p_bar_r_diff);
    }
}
