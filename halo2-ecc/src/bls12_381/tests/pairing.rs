use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use crate::fields::FieldChip;

use super::*;
use halo2_base::{
    gates::RangeChip, halo2_proofs::arithmetic::Field, utils::BigPrimeField, Context,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PairingCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn pairing_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: PairingCircuitParams,
    P: G1Affine,
    Q: G2Affine,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let chip = PairingChip::new(&fp_chip);
    let P_assigned = chip.load_private_g1_unchecked(ctx, P);
    let Q_assigned = chip.load_private_g2_unchecked(ctx, Q);
    // test optimal ate pairing
    let f = chip.pairing(ctx, &Q_assigned, &P_assigned);
    let actual_f = pairing(&P, &Q);
    let fp12_chip = Fp12Chip::new(&fp_chip);
    // cannot directly compare f and actual_f because `Gt` has private field `Fq12`
    assert_eq!(
        format!("Gt({:?})", fp12_chip.get_assigned_value(&f.into())),
        format!("{actual_f:?}")
    );
}

#[test]
fn test_pairing() {
    let path = "configs/bls12_381/pairing_circuit.config";
    let params: PairingCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let P = G1Affine::random(&mut rng);
    let Q = G2Affine::random(&mut rng);
    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        pairing_test(ctx, range, params, P, Q);
    });
}

fn pairing_check_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: PairingCircuitParams,
    P: G1Affine,
    Q: G2Affine,
    S: G1Affine,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let chip = PairingChip::new(&fp_chip);
    let P_assigned = chip.load_private_g1_unchecked(ctx, P);
    let Q_assigned = chip.load_private_g2_unchecked(ctx, Q);
    let S_assigned = chip.load_private_g1_unchecked(ctx, S);
    let T_assigned = chip.load_private_g2_unchecked(ctx, G2Affine::generator());
    chip.pairing_check(ctx, &Q_assigned, &P_assigned, &T_assigned, &S_assigned);
}

/*
 * Samples a random α,β in Fr and does the pairing check
 * e(H_1^α, H_2^β) = e(H_1^(α*β), H_2), where H_1 is the generator for G1 and
 * H_2 for G2.
 */
#[test]
fn test_pairing_check() {
    let path = "configs/bls12_381/pairing_circuit.config";
    let params: PairingCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let P = G1Affine::from(G1Affine::generator() * alpha);
    let Q = G2Affine::from(G2Affine::generator() * beta);
    let S = G1Affine::from(G1Affine::generator() * alpha * beta);
    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        pairing_check_test(ctx, range, params, P, Q, S);
    })
}

/*
 * Samples a random α,β in Fr and does an incorrect pairing check
 * e(H_1^α, H_2^β) = e(H_1^α, H_2), where H_1 is the generator for G1 and
 * H_2 for G2.
 */
#[test]
fn test_pairing_check_fail() {
    let path = "configs/bls12_381/pairing_circuit.config";
    let params: PairingCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0);
    let alpha = Scalar::random(&mut rng);
    let beta = Scalar::random(&mut rng);
    let P = G1Affine::from(G1Affine::generator() * alpha);
    let Q = G2Affine::from(G2Affine::generator() * beta);
    base_test().k(params.degree).lookup_bits(params.lookup_bits).expect_satisfied(false).run(
        |ctx, range| {
            pairing_check_test(ctx, range, params, P, Q, P);
        },
    )
}

#[test]
fn bench_pairing() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bls12_381/bench_pairing.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bls12_381").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bls12_381/pairing_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let mut rng = StdRng::seed_from_u64(0);
    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: PairingCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let P = G1Affine::random(&mut rng);
        let Q = G2Affine::random(&mut rng);
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (P, Q),
            (P, Q),
            |pool, range, (P, Q)| {
                pairing_test(pool.main(), range, bench_params, P, Q);
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
