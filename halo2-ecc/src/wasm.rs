use crate::halo2_proofs::{
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use crate::secp256k1::ecdsa::{CircuitParams, ECDSACircuit};
use crate::{
    halo2_proofs::{
        arithmetic::CurveAffine,
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        halo2curves::secp256k1::{Fq, Secp256k1Affine},
        plonk::*,
        poly::commitment::ParamsProver,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
        SerdeFormat,
    },
    secp256k1::ecdsa::generate_ecdsa_input,
};
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
use halo2_base::{halo2_proofs::poly::commitment::Params, utils::PrimeField};

use js_sys::Uint8Array;
use rand_core::OsRng;
use std::io::BufReader;
use std::marker::PhantomData;
use std::{env::set_var, fs, io::BufRead};
use std::{env::var, io::Write};
use wasm_bindgen::prelude::*;
use web_sys;

// wasm_bindgen_rayon requires the rustflags defined in .cargo/config
// to be set in order to compile. When we enable rustflags,
// rust-analyzer (the vscode extension) stops working, so by default,
// we don't compile wasm_bindgen_rayon which requires rustflags,
#[cfg(target_family = "wasm")]
pub use wasm_bindgen_rayon::init_thread_pool;

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn prove(params_ser: JsValue) -> JsValue {
    // parse params
    web_sys::console::time_with_label("Loading params");
    let params_vec = Uint8Array::new(&params_ser).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params_vec[..])).unwrap();
    web_sys::console::time_end_with_label("Loading params");

    // generate proving key and verification key
    let circuit = ECDSACircuit::<Fr>::default();

    web_sys::console::time_with_label("Generating verifying key");
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    web_sys::console::time_end_with_label("Generating verifying key");

    web_sys::console::time_with_label("Generating proving key");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    web_sys::console::time_end_with_label("Generating proving key");

    // inputs
    let (r, s, msg_hash, pubkey, G) = generate_ecdsa_input();
    let circuit = ECDSACircuit::<Fr> {
        r: Some(r),
        s: Some(s),
        msghash: Some(msg_hash),
        pk: Some(pubkey),
        G,
        _marker: PhantomData,
    };

    // generating a proof
    web_sys::console::time_with_label("Generating proof");
    let rng = rand::thread_rng();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        ECDSACircuit<Fr>,
    >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)
    .unwrap();
    let proof = transcript.finalize();
    web_sys::console::time_end_with_label("Generating proof");

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn prove_vk(params_ser: JsValue, vk_ser: JsValue) -> JsValue {
    // parse params
    web_sys::console::time_with_label("Loading params");
    let params_vec = Uint8Array::new(&params_ser).to_vec();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params_vec[..])).unwrap();
    web_sys::console::time_end_with_label("Loading params");

    // generate proving key from loaded verification key
    let circuit = ECDSACircuit::<Fr>::default();

    web_sys::console::time_with_label("Loading verifying key");
    let vk_vec = Uint8Array::new(&vk_ser).to_vec();
    let vk = VerifyingKey::<G1Affine>::read::<_, ECDSACircuit<Fr>>(
        &mut BufReader::new(&vk_vec[..]),
        SerdeFormat::RawBytes,
    )
    .unwrap();
    web_sys::console::time_end_with_label("Loading verifying key");

    web_sys::console::time_with_label("Generating proving key");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    web_sys::console::time_end_with_label("Generating proving key");

    // inputs
    let (r, s, msg_hash, pubkey, G) = generate_ecdsa_input();
    let circuit = ECDSACircuit::<Fr> {
        r: Some(r),
        s: Some(s),
        msghash: Some(msg_hash),
        pk: Some(pubkey),
        G,
        _marker: PhantomData,
    };

    // generating a proof
    let rng = rand::thread_rng();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        ECDSACircuit<Fr>,
    >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)
    .unwrap();
    let proof = transcript.finalize();

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

// #[wasm_bindgen]
// pub fn verify(params_ser: JsValue, proof: JsValue) {
//   // parse params
//   let params_vec = Uint8Array::new(&params_ser).to_vec();
//   let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(&params_vec[..])).unwrap();

//   // parse proof
//   let proof = proof_js.into_serde::<Vec<u8>>().unwrap();

//   // generate vk
//   let circuit = ECDSACircuit::<Fr>::default();
//   let vk = keygen_vk(&params, &circuit)?;

//   // verify the entire proof
//   let strategy = SingleStrategy::new(&params);
//   let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
// }
