#![allow(clippy::type_complexity)]
use crate::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::commitment::ParamsProver,
    poly::kzg::{
        commitment::KZGCommitmentScheme, commitment::ParamsKZG, multiopen::ProverSHPLONK,
        multiopen::VerifierSHPLONK, strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;

#[cfg(test)]
mod flex_gate_tests;
#[cfg(test)]
mod general;
#[cfg(test)]
mod idx_to_indicator;
#[cfg(test)]
mod neg_prop_tests;
#[cfg(test)]
mod pos_prop_tests;
#[cfg(test)]
mod range_gate_tests;
#[cfg(test)]
mod test_ground_truths;

/// helper function to generate a proof with real prover
pub fn gen_proof(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
) -> Vec<u8> {
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<_>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, _>,
        _,
    >(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("prover should not fail");
    transcript.finalize()
}

/// helper function to verify a proof
pub fn check_proof(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    expect_satisfied: bool,
) {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    let res = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, &[&[]], &mut transcript);

    if expect_satisfied {
        assert!(res.is_ok());
    } else {
        assert!(res.is_err());
    }
}
