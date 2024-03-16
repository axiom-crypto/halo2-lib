#![allow(non_snake_case)]
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{fs, io::BufRead};

use super::*;
use crate::fields::FpStrategy;
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::bn256::Fr,
    halo2curves::secp256r1::{Fp, Fq, Secp256r1Affine},
};
use crate::secp256r1::{FpChip, FqChip};
use crate::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
};
use halo2_base::gates::RangeChip;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus, BigPrimeField};
use halo2_base::Context;
use serde::{Deserialize, Serialize};
use test_log::test;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct ECDSAInput {
    pub r: Fq,
    pub s: Fq,
    pub msghash: Fq,
    pub pk: Secp256r1Affine,
}

pub fn ecdsa_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CircuitParams,
    input: ECDSAInput,
) -> F {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(range, params.limb_bits, params.num_limbs);

    let [m, r, s] = [input.msghash, input.r, input.s].map(|x| fq_chip.load_private(ctx, x));

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.load_private_unchecked(ctx, (input.pk.x, input.pk.y));
    // test ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256r1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    *res.value()
}

pub fn random_ecdsa_input(rng: &mut StdRng) -> ECDSAInput {
    let sk = <Secp256r1Affine as CurveAffine>::ScalarExt::random(rng.clone());
    let pk = Secp256r1Affine::from(Secp256r1Affine::generator() * sk);
    let msghash = <Secp256r1Affine as CurveAffine>::ScalarExt::random(rng.clone());

    let k = <Secp256r1Affine as CurveAffine>::ScalarExt::random(rng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256r1Affine::from(Secp256r1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msghash + (r * sk));

    ECDSAInput { r, s, msghash, pk }
}

pub fn run_test(input: ECDSAInput) {
    let path = "configs/secp256r1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let res = base_test()
        .k(params.degree)
        .lookup_bits(params.lookup_bits)
        .run(|ctx, range| ecdsa_test(ctx, range, params, input));
    assert_eq!(res, Fr::ONE);
}

#[test]
fn test_secp256r1_ecdsa() {
    let mut rng = StdRng::seed_from_u64(0);
    let input = random_ecdsa_input(&mut rng);
    run_test(input);
}

#[test]
fn bench_secp256r1_ecdsa() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/secp256r1/bench_ecdsa.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/secp256r1").unwrap();
    fs::create_dir_all("data").unwrap();
    let results_path = "results/secp256r1/ecdsa_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let mut rng = StdRng::seed_from_u64(0);
    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let stats =
            base_test().k(k).lookup_bits(bench_params.lookup_bits).unusable_rows(20).bench_builder(
                random_ecdsa_input(&mut rng),
                random_ecdsa_input(&mut rng),
                |pool, range, input| {
                    ecdsa_test(pool.main(), range, bench_params, input);
                },
            );

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
            stats.proof_time.time.elapsed(),
            stats.proof_size,
            stats.verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
