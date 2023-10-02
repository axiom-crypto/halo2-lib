use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    ops::Neg,
};

use super::*;
use crate::{
    bls12_381::bls_signature::BlsSignatureChip, fields::FpStrategy,
    halo2_proofs::halo2curves::bls12_381::G2Affine,
};
use halo2_base::{
    gates::RangeChip,
    halo2_proofs::halo2curves::bls12_381::{multi_miller_loop, Gt},
    utils::BigPrimeField,
    Context,
};
extern crate pairing;
use pairing::group::ff::Field;
use rand_core::OsRng;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct BlsSignatureCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    num_aggregation: u32,
}

/// Verify e(g1, signature_agg) = e(pubkey_agg, H(m))
fn bls_signature_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: BlsSignatureCircuitParams,
    signature: G2Affine,
    pubkey: G1Affine,
    msghash: G2Affine,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip, &pairing_chip);

    let assigned_signature = pairing_chip.load_private_g2_unchecked(ctx, signature);
    let assigned_pubkey = pairing_chip.load_private_g1_unchecked(ctx, pubkey);
    let assigned_msghash = pairing_chip.load_private_g2_unchecked(ctx, msghash);

    let result = bls_signature_chip.is_valid_signature(
        ctx,
        assigned_signature,
        assigned_msghash,
        assigned_pubkey,
    );

    // Verify off-circuit
    let g1_neg = G1Affine::generator().neg();
    let actual_result =
        multi_miller_loop(&[(&g1_neg, &signature.into()), (&pubkey, &msghash.into())])
            .final_exponentiation();

    // Compare the 2 results
    assert_eq!(*result.value(), F::from(actual_result == Gt::identity()))
}

#[test]
fn test_bls_signature() {
    let run_path = "configs/bls12_381/bls_signature_circuit.config";
    let path = run_path;
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!("num_advice: {num_advice}", num_advice = params.num_advice);

    let msghash = G2Affine::random(OsRng);
    let sk = Scalar::random(OsRng);
    let pubkey = G1Affine::from(G1Affine::generator() * sk);
    let signature = G2Affine::from(msghash * sk);

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        bls_signature_test(ctx, range, params, signature, pubkey, msghash);
    })
}

#[test]
fn test_bls_signature_fail() {
    let run_path = "configs/bls12_381/bls_signature_circuit.config";
    let path = run_path;
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!("num_advice: {num_advice}", num_advice = params.num_advice);

    let msghash = G2Affine::random(OsRng);
    let sk = Scalar::random(OsRng);
    let pubkey = G1Affine::from(G1Affine::generator() * sk);
    let signature = G2Affine::random(OsRng);

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        bls_signature_test(ctx, range, params, signature, pubkey, msghash);
    })
}

#[test]
fn bench_bls_signature() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bls12_381/bench_bls_signature.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bls12_381").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bls12_381/bls_signature_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: BlsSignatureCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let msghash = G2Affine::random(OsRng);
        let sk = Scalar::random(OsRng);
        let pubkey = G1Affine::from(G1Affine::generator() * sk);
        let signature = G2Affine::from(msghash * sk);

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (signature, pubkey, msghash),
            (signature, pubkey, msghash),
            |pool, range, (signature, pubkey, msghash)| {
                bls_signature_test(pool.main(), range, bench_params, signature, pubkey, msghash);
            },
        );

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.num_aggregation,
            stats.proof_time.time.elapsed(),
            stats.proof_size,
            stats.verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
