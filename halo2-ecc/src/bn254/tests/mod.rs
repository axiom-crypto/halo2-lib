#![allow(non_snake_case)]
use super::pairing::PairingChip;
use super::*;
use crate::halo2_proofs::{
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
};
use crate::{ecc::EccChip, fields::PrimeField};
use ark_std::{end_timer, start_timer};
use group::Curve;
use halo2_base::utils::fe_to_biguint;
use serde::{Deserialize, Serialize};
use std::io::Write;

pub mod ec_add;
pub mod fixed_base_msm;
pub mod msm;
pub mod pairing;
