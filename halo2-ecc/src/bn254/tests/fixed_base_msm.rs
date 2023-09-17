use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use crate::ff::{Field, PrimeField};

use super::*;
use itertools::Itertools;

pub fn fixed_base_msm_test(
    pool: &mut SinglePhaseCoreManager<Fr>,
    range: &RangeChip<Fr>,
    params: FixedMSMCircuitParams,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
) {
    let fp_chip = FpChip::<Fr>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let scalars_assigned =
        scalars.iter().map(|scalar| vec![pool.main().load_witness(*scalar)]).collect::<Vec<_>>();

    let msm = ecc_chip.fixed_base_msm(pool, &bases, scalars_assigned, Fr::NUM_BITS as usize);

    let mut elts: Vec<G1> = Vec::new();
    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        elts.push(base * scalar);
    }
    let msm_answer = elts.into_iter().reduce(|a, b| a + b).unwrap().to_affine();

    let msm_x = msm.x.value();
    let msm_y = msm.y.value();
    assert_eq!(msm_x, fe_to_biguint(&msm_answer.x));
    assert_eq!(msm_y, fe_to_biguint(&msm_answer.y));
}

#[test]
fn test_fixed_base_msm() {
    let path = "configs/bn254/fixed_msm_circuit.config";
    let params: FixedMSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let mut rng = StdRng::seed_from_u64(0);
    let bases = (0..params.batch_size).map(|_| G1Affine::random(&mut rng)).collect_vec();
    let scalars = (0..params.batch_size).map(|_| Fr::random(&mut rng)).collect_vec();
    base_test().k(params.degree).lookup_bits(params.lookup_bits).run_builder(|pool, range| {
        fixed_base_msm_test(pool, range, params, bases, scalars);
    });
}

#[test]
fn test_fixed_msm_minus_1() {
    let path = "configs/bn254/fixed_msm_circuit.config";
    let params: FixedMSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let rng = StdRng::seed_from_u64(0);
    let base = G1Affine::random(rng);
    base_test().k(params.degree).lookup_bits(params.lookup_bits).run_builder(|pool, range| {
        fixed_base_msm_test(pool, range, params, vec![base], vec![-Fr::one()]);
    });
}

#[test]
fn bench_fixed_base_msm() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_fixed_msm.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/fixed_msm_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,batch_size,proof_time,proof_size,verify_time")?;

    let mut rng = StdRng::seed_from_u64(0);
    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: FixedMSMCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        let batch_size = bench_params.batch_size;
        println!("---------------------- degree = {k} ------------------------------",);

        let bases = (0..batch_size).map(|_| G1Affine::random(&mut rng)).collect_vec();
        let scalars = (0..batch_size).map(|_| Fr::random(&mut rng)).collect_vec();
        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            (bases.clone(), scalars.clone()),
            (bases, scalars),
            |pool, range, (bases, scalars)| {
                fixed_base_msm_test(pool, range, bench_params, bases, scalars);
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
            bench_params.batch_size,
            stats.proof_time.time.elapsed(),
            stats.proof_size,
            stats.verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
