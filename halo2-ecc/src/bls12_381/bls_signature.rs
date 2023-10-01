use std::ops::Neg;

use super::pairing::PairingChip;
use super::{Fp12Chip, FpChip};
use crate::bigint::ProperCrtUint;
use crate::ecc::{EcPoint, EccChip};
use crate::fields::vector::FieldVector;
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bls12_381::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::bls12_381::Fq12;
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};

pub struct BlsSignatureChip<'chip, F: BigPrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: BigPrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip }
    }

    // Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1
    // where e(,) is optimal Ate pairing
    // G1: {g1, pubkey}, G2: {signature, message}
    pub fn bls_signature_verify(
        &self,
        ctx: &mut Context<F>,
        signature: G2Affine,
        pubkey: G1Affine,
        msghash: G2Affine,
    ) {
        let signature_assigned = self.pairing_chip.load_private_g2_unchecked(ctx, signature);
        let pubkey_assigned = self.pairing_chip.load_private_g1_unchecked(ctx, pubkey);
        let hash_m_assigned = self.pairing_chip.load_private_g2_unchecked(ctx, msghash);

        self.assert_valid_signature(ctx, signature_assigned, hash_m_assigned, pubkey_assigned);
    }

    pub fn is_valid_signature(
        &self,
        ctx: &mut Context<F>,
        signature: EcPoint<F, FieldVector<ProperCrtUint<F>>>,
        msghash: EcPoint<F, FieldVector<ProperCrtUint<F>>>,
        pubkey: EcPoint<F, ProperCrtUint<F>>,
    ) -> AssignedValue<F> {
        let g1_chip = EccChip::new(self.fp_chip);

        let g1_neg = g1_chip.assign_constant_point(ctx, G1Affine::generator().neg());

        let gt = self.compute_pairing(ctx, signature, msghash, pubkey, g1_neg);

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fp12_one = fp12_chip.load_constant(ctx, Fq12::one());

        fp12_chip.is_equal(ctx, gt, fp12_one)
    }

    pub fn assert_valid_signature(
        &self,
        ctx: &mut Context<F>,
        signature: EcPoint<F, FieldVector<ProperCrtUint<F>>>,
        msghash: EcPoint<F, FieldVector<ProperCrtUint<F>>>,
        pubkey: EcPoint<F, ProperCrtUint<F>>,
    ) {
        let g1_chip = EccChip::new(self.fp_chip);
        let g1_neg = g1_chip.assign_constant_point(ctx, G1Affine::generator().neg());

        let gt = self.compute_pairing(ctx, signature, msghash, pubkey, g1_neg);

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fp12_one = fp12_chip.load_constant(ctx, Fq12::one());

        fp12_chip.assert_equal(ctx, gt, fp12_one);
    }

    fn compute_pairing(
        &self,
        ctx: &mut Context<F>,
        signature: EcPoint<F, FieldVector<ProperCrtUint<F>>>,
        msghash: EcPoint<F, FieldVector<ProperCrtUint<F>>>,
        pubkey: EcPoint<F, ProperCrtUint<F>>,
        g1_neg: EcPoint<F, ProperCrtUint<F>>,
    ) -> FieldVector<ProperCrtUint<F>> {
        let mml = self
            .pairing_chip
            .multi_miller_loop(ctx, vec![(&g1_neg, &signature), (&pubkey, &msghash)]);

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fe = fp12_chip.final_exp(ctx, mml);

        assert_eq!(fe.0.len(), 12);

        fe
    }
}
