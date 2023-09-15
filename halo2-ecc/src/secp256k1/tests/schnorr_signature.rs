#![allow(non_snake_case)]
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::bn256::Fr,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
};
use crate::secp256k1::{FpChip, FqChip};
use crate::{
    ecc::{schnorr_signature::schnorr_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
};
use halo2_base::gates::RangeChip;
use halo2_base::utils::fe_to_biguint;
use halo2_base::utils::BigPrimeField;
use halo2_base::Context;
use halo2_base::{halo2_proofs::arithmetic::Field, utils::testing::base_test};
use num_bigint::BigUint;
use num_integer::Integer;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::fs::File;
use std::io::BufReader;
use std::io::Write;
use std::{fs, io::BufRead};

use super::CircuitParams;

#[derive(Clone, Copy, Debug)]
pub struct SchnorrInput {
    pub r: Fp,
    pub s: Fq,
    pub msg_hash: Fq,
    pub pk: Secp256k1Affine,
}

pub fn schnorr_signature_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CircuitParams,
    input: SchnorrInput,
) -> F {
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, s] = [input.msg_hash, input.s].map(|x| fq_chip.load_private(ctx, x));
    let r = fp_chip.load_private(ctx, input.r);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.assign_point(ctx, input.pk);
    // test schnorr signature
    let res = schnorr_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    *res.value()
}

pub fn random_schnorr_signature_input(rng: &mut StdRng) -> SchnorrInput {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(rng.clone());
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(rng.clone());

    let mut k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(rng.clone());

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

    SchnorrInput { r, s, msg_hash, pk }
}

pub fn run_test(input: SchnorrInput) {
    let path = "configs/secp256k1/schnorr_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let res = base_test()
        .k(params.degree)
        .lookup_bits(params.lookup_bits)
        .run(|ctx, range| schnorr_signature_test(ctx, range, params, input));
    assert_eq!(res, Fr::ONE);
}

#[test]
fn test_secp256k1_schnorr() {
    let mut rng = StdRng::seed_from_u64(0);
    let input = random_schnorr_signature_input(&mut rng);
    run_test(input);
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
        println!("---------------------- degree = {k} ------------------------------",);

        let stats =
            base_test().k(k).lookup_bits(bench_params.lookup_bits).unusable_rows(20).bench_builder(
                random_schnorr_signature_input(&mut rng),
                random_schnorr_signature_input(&mut rng),
                |pool, range, input| {
                    schnorr_signature_test(pool.main(), range, bench_params, input);
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
