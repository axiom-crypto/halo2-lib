#![allow(non_snake_case)]

use super::pairing::PairingChip;
use super::{Fp12Chip, Fp2Chip, FpChip, FqPoint};
use crate::ecc::EccChip;
use crate::fields::PrimeField;
use crate::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::Context;

// To avoid issues with mutably borrowing twice (not allowed in Rust), we only store fp_chip and construct g2_chip and fp12_chip in scope when needed for temporary mutable borrows
pub struct BlsSignatureChip<'chip, F: PrimeField> {
    pub fp_chip: &'chip FpChip<'chip, F>,
    pub pairing_chip: &'chip PairingChip<'chip, F>,
}

impl<'chip, F: PrimeField> BlsSignatureChip<'chip, F> {
    pub fn new(fp_chip: &'chip FpChip<F>, pairing_chip: &'chip PairingChip<F>) -> Self {
        Self { fp_chip, pairing_chip }
    }

    // Verifies that e(g1, signature) = e(pubkey, H(m)) by checking e(g1, signature)*e(pubkey, -H(m)) === 1
    // where e(,) is optimal Ate pairing
    // G1: {g1, pubkey}, G2: {signature, message}
    // TODO add support for aggregating signatures over different messages
    pub fn bls_signature_verify(
        &self,
        ctx: &mut Context<F>,
        g1: G1Affine,
        signatures: &[G2Affine],
        pubkeys: &[G1Affine],
        msghash: G2Affine,
    ) -> FqPoint<F> {
        assert!(
            signatures.len() == pubkeys.len(),
            "signatures and pubkeys must be the same length"
        );
        assert!(!signatures.is_empty(), "signatures must not be empty");
        assert!(!pubkeys.is_empty(), "pubkeys must not be empty");

        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::<F>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        let g1_assigned = self.pairing_chip.load_private_g1(ctx, g1);

        let hash_m_assigned = self.pairing_chip.load_private_g2(ctx, msghash);

        let signature_points =
            signatures.iter().map(|pt| g2_chip.assign_point(ctx, *pt)).collect::<Vec<_>>();
        let signature_agg_assigned = g2_chip.sum::<G2Affine>(ctx, signature_points);

        let pubkey_points =
            pubkeys.iter().map(|pt| g1_chip.assign_point(ctx, *pt)).collect::<Vec<_>>();
        let pubkey_agg_assigned = g1_chip.sum::<G1Affine>(ctx, pubkey_points);

        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let g12_chip = EccChip::new(&fp12_chip);
        let neg_signature_assigned_g12 = g12_chip.negate(ctx, &signature_agg_assigned);

        let multi_paired = self.pairing_chip.multi_miller_loop(
            ctx,
            vec![
                (&g1_assigned, &neg_signature_assigned_g12),
                (&pubkey_agg_assigned, &hash_m_assigned),
            ],
        );
        let result = fp12_chip.final_exp(ctx, multi_paired);
        result
    }
}
