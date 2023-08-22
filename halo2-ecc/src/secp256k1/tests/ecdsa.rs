#![allow(non_snake_case)]
use crate::ff::Field as _;
use crate::fields::FpStrategy;
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::*,
};
use crate::secp256k1::{FpChip, FqChip};
use crate::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
};
use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::{
    BaseConfigParams, CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
    RangeCircuitBuilder,
};
use halo2_base::gates::RangeChip;
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof, gen_proof};
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus, BigPrimeField};
use halo2_base::Context;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{fs, io::BufRead};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn ecdsa_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    r: Fq,
    s: Fq,
    msghash: Fq,
    pk: Secp256k1Affine,
) {
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, r, s] = [msghash, r, s].map(|x| fq_chip.load_private(ctx, x));

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.load_private_unchecked(ctx, (pk.x, pk.y));
    // test ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    assert_eq!(res.value(), &F::ONE);
}

fn random_ecdsa_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    config_params: Option<BaseConfigParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msg_hash + (r * sk));

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    ecdsa_test(builder.main(0), params, r, s, msg_hash, pubkey);

    let mut config_params =
        config_params.unwrap_or_else(|| builder.config(params.degree as usize, Some(20)));
    config_params.lookup_bits = Some(params.lookup_bits);
    let circuit = match stage {
        CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder, config_params),
        CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder, config_params),
        CircuitBuilderStage::Prover => {
            RangeCircuitBuilder::prover(builder, config_params, break_points.unwrap())
        }
    };
    end_timer!(start0);
    circuit
}

#[test]
fn test_secp256k1_ecdsa() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_ecdsa_circuit(params, CircuitBuilderStage::Mock, None, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_secp256k1_ecdsa() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/secp256k1/bench_ecdsa.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/secp256k1").unwrap();
    fs::create_dir_all("data").unwrap();
    let results_path = "results/secp256k1/ecdsa_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let params = gen_srs(k);
        println!("{bench_params:?}");

        let circuit = random_ecdsa_circuit(bench_params, CircuitBuilderStage::Keygen, None, None);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let break_points = circuit.0.break_points.take();
        let config_params = circuit.0.config_params.clone();
        drop(circuit);
        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let circuit = random_ecdsa_circuit(
            bench_params,
            CircuitBuilderStage::Prover,
            Some(config_params),
            Some(break_points),
        );
        let proof = gen_proof(&params, &pk, circuit);
        end_timer!(proof_time);

        let proof_size = proof.len();

        let verify_time = start_timer!(|| "Verify time");
        check_proof(&params, pk.get_vk(), &proof, true);
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
