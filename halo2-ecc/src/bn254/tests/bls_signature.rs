use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use super::*;
use crate::{
    bn254::bls_signature::BlsSignatureChip, fields::FpStrategy,
    halo2_proofs::halo2curves::bn256::G2Affine,
};
use halo2_base::{
    gates::RangeChip,
    halo2_proofs::halo2curves::bn256::{multi_miller_loop, G2Prepared, Gt},
    utils::BigPrimeField,
    Context,
};
extern crate pairing;
use crate::group::ff::Field;
#[cfg(feature = "halo2-pse")]
use halo2_base::halo2_proofs::halo2curves::pairing::MillerLoopResult;
#[cfg(feature = "halo2-axiom")]
use pairing::MillerLoopResult;
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
    g1: G1Affine,
    signatures: &[G2Affine],
    pubkeys: &[G1Affine],
    msghash: G2Affine,
) {
    // Calculate halo2 pairing by multipairing
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let result = bls_signature_chip.bls_signature_verify(ctx, g1, signatures, pubkeys, msghash);

    // Calculate non-halo2 pairing by multipairing
    let mut signatures_g2: G2Affine = signatures[0];
    for sig in signatures.iter().skip(1) {
        signatures_g2 = (signatures_g2 + sig).into();
    }
    let signature_g2_prepared = G2Prepared::from(signatures_g2);

    let mut pubkeys_g1: G1Affine = pubkeys[0];
    for pubkey in pubkeys.iter().skip(1) {
        pubkeys_g1 = (pubkeys_g1 + pubkey).into();
    }
    let pubkey_aggregated = pubkeys_g1;

    let hash_m_prepared = G2Prepared::from(-msghash);
    let actual_result =
        multi_miller_loop(&[(&g1, &signature_g2_prepared), (&pubkey_aggregated, &hash_m_prepared)])
            .final_exponentiation();

    // Compare the 2 results
    assert_eq!(*result.value(), F::from(actual_result == Gt::identity()))
}

#[test]
fn test_bls_signature() {
    let run_path = "configs/bn254/bls_signature_circuit.config";
    let path = run_path;
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!("num_advice: {num_advice}", num_advice = params.num_advice);

    let msg_hash = G2Affine::random(OsRng);
    let g1 = G1Affine::generator();
    let mut signatures: Vec<G2Affine> = Vec::new();
    let mut pubkeys: Vec<G1Affine> = Vec::new();
    for _ in 0..params.num_aggregation {
        let sk = Fr::random(OsRng);
        let signature = G2Affine::from(msg_hash * sk);
        let pubkey = G1Affine::from(G1Affine::generator() * sk);

        signatures.push(signature);
        pubkeys.push(pubkey);
    }

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        // signatures: &[G2Affine], pubkeys: &[G1Affine], msghash: G2Affine)
        bls_signature_test(ctx, range, params, g1, &signatures, &pubkeys, msg_hash);
    })
}

#[test]
fn bench_bls_signature() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_bls_signature.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/bls_signature_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: BlsSignatureCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let msg_hash = G2Affine::random(OsRng);
        let g1 = G1Affine::generator();
        let mut signatures: Vec<G2Affine> = Vec::new();
        let mut pubkeys: Vec<G1Affine> = Vec::new();
        for _ in 0..bench_params.num_aggregation {
            let sk = Fr::random(OsRng);
            let signature = G2Affine::from(msg_hash * sk);
            let pubkey = G1Affine::from(G1Affine::generator() * sk);

            signatures.push(signature);
            pubkeys.push(pubkey);
        }

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (g1, signatures.clone(), pubkeys.clone(), msg_hash),
            (g1, signatures, pubkeys, msg_hash),
            |pool, range, (g1, signatures, pubkeys, msg_hash)| {
                bls_signature_test(
                    pool.main(),
                    range,
                    bench_params,
                    g1,
                    &signatures,
                    &pubkeys,
                    msg_hash,
                );
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
