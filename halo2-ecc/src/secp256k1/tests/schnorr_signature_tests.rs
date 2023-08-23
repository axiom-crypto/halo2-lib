#![allow(non_snake_case)]
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::*,
    poly::commitment::ParamsProver,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use crate::halo2_proofs::{
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use crate::secp256k1::{FpChip, FqChip};
use crate::{
    ecc::{schnorr_signature::schnorr_verify_no_pubkey_check, EccChip},
    fields::{FieldChip, PrimeField},
};
use ark_std::{end_timer, start_timer};
use halo2_base::utils::fs::gen_srs;
use halo2_base::{
    gates::builder::{
        CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
    },
    utils::fe_to_biguint,
};
use num_bigint::BigUint;

use halo2_base::gates::RangeChip;
use halo2_base::Context;
use num_integer::Integer;
use rand::random;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{fs, io::BufRead};
use test_case::test_case;

use super::CircuitParams;

fn schnorr_signature_test<F: PrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    r: Fp,
    s: Fq,
    msghash: Fq,
    pk: Secp256k1Affine,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, s] = [msghash, s].map(|x| fq_chip.load_private(ctx, x));
    let r = fp_chip.load_private(ctx, r);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.assign_point(ctx, pk);
    // test schnorr signature
    let res = schnorr_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    assert_eq!(res.value(), &F::one());
}

fn random_parameters_schnorr_signature() -> (Fp, Fq, Fq, Secp256k1Affine) {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));
    let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash =
        <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));

    let mut k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));

    let mut r_point =
        Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let mut x: &Fp = r_point.x();
    let mut y: &Fp = r_point.y();
    // make sure R.y is even
    while fe_to_biguint(y).mod_floor(&BigUint::from(2u64)) != BigUint::from(0u64) {
        k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(StdRng::from_seed([0u8; 32]));
        r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
        x = r_point.x();
        y = r_point.y();
    }

    let r = *x;
    let s = k + sk * msg_hash;

    (r, s, msg_hash, pubkey)
}

fn custom_parameters_schnorr_signature(
    sk: u64,
    msg_hash: u64,
    k: u64,
) -> (Fp, Fq, Fq, Secp256k1Affine) {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
    let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::from(msg_hash);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::from(k);

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();

    let r = *x;
    let s = k + sk * msg_hash;

    (r, s, msg_hash, pubkey)
}

fn schnorr_signature_circuit(
    r: Fp,
    s: Fq,
    msg_hash: Fq,
    pubkey: Secp256k1Affine,
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };
    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    schnorr_signature_test(builder.main(0), params, r, s, msg_hash, pubkey);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_schnorr_signature_msg_hash_zero() {
    let path = "configs/secp256k1/schnorr_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) =
        custom_parameters_schnorr_signature(random::<u64>(), 0, random::<u64>());

    let circuit =
        schnorr_signature_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_schnorr_signature_private_key_zero() {
    let path = "configs/secp256k1/schnorr_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) =
        custom_parameters_schnorr_signature(0, random::<u64>(), random::<u64>());

    let circuit =
        schnorr_signature_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test_case(1, 1, 0; "")]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_schnorr_signature_k_zero(sk: u64, msg_hash: u64, k: u64) {
    let path = "configs/secp256k1/schnorr_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = custom_parameters_schnorr_signature(sk, msg_hash, k);

    let circuit =
        schnorr_signature_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_schnorr_signature_random_valid_inputs() {
    let path = "configs/secp256k1/schnorr_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    for _ in 0..10 {
        let (r, s, msg_hash, pubkey) = random_parameters_schnorr_signature();

        let circuit = schnorr_signature_circuit(
            r,
            s,
            msg_hash,
            pubkey,
            params,
            CircuitBuilderStage::Mock,
            None,
        );
        MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
    }
}

#[test_case(1, 1, 1; "")]
fn test_schnorr_signature_custom_valid_inputs(sk: u64, msg_hash: u64, k: u64) {
    let path = "configs/secp256k1/schnorr_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = custom_parameters_schnorr_signature(sk, msg_hash, k);

    let circuit =
        schnorr_signature_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_secp256k1_schnorr() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let config_path = "configs/secp256k1/bench_schnorr.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/secp256k1").unwrap();
    fs::create_dir_all("data").unwrap();
    let results_path = "results/secp256k1/schnorr_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        let (r, s, msg_hash, pubkey) = random_parameters_schnorr_signature();
        println!("---------------------- degree = {k} ------------------------------",);

        let params = gen_srs(k);
        println!("{bench_params:?}");
        let circuit = schnorr_signature_circuit(
            r,
            s,
            msg_hash,
            pubkey,
            bench_params,
            CircuitBuilderStage::Keygen,
            None,
        );
        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let break_points = circuit.0.break_points.take();
        drop(circuit);
        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let circuit = schnorr_signature_circuit(
            r,
            s,
            msg_hash,
            pubkey,
            bench_params,
            CircuitBuilderStage::Prover,
            Some(break_points),
        );

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], &mut rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            let path = format!(
                "data/schnorr_circuit_proof_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs
            );
            let mut fd = File::create(&path)?;
            fd.write_all(&proof)?;
            let size = fd.metadata().unwrap().len();
            fs::remove_file(path)?;
            size
        };

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
