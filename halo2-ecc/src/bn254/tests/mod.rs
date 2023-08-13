#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::*;
use crate::ecc::EccChip;
use crate::group::Curve;
use crate::{
    fields::FpStrategy,
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{pairing, Bn256, Fr, G1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
        transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    },
};
use ark_std::{end_timer, start_timer};
use halo2_base::utils::fe_to_biguint;
use serde::{Deserialize, Serialize};
use std::io::Write;

pub mod ec_add;
pub mod fixed_base_msm;
pub mod msm;
pub mod msm_sum_infinity;
pub mod msm_sum_infinity_fixed_base;
pub mod pairing;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct MSMCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    batch_size: usize,
    window_bits: usize,
}
