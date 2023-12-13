use crate::ff::{Field, PrimeField};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use super::*;

pub fn msm_test(
    pool: &mut SinglePhaseCoreManager<Fr>,
    range: &RangeChip<Fr>,
    params: MSMCircuitParams,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
) {
    let fp_chip = FpChip::<Fr>::new(range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let ctx = pool.main();
    let scalars_assigned =
        scalars.iter().map(|scalar| vec![ctx.load_witness(*scalar)]).collect::<Vec<_>>();
    let bases_assigned = bases
        .iter()
        .map(|base| ecc_chip.load_private_unchecked(ctx, (base.x, base.y)))
        .collect::<Vec<_>>();

    let msm = ecc_chip.variable_base_msm_custom::<G1Affine>(
        pool,
        &bases_assigned,
        scalars_assigned,
        Fr::NUM_BITS as usize,
        params.window_bits,
    );

    let msm_answer = bases
        .iter()
        .zip(scalars.iter())
        .map(|(base, scalar)| base * scalar)
        .reduce(|a, b| a + b)
        .unwrap()
        .to_affine();

    let msm_x = msm.x.value();
    let msm_y = msm.y.value();
    assert_eq!(msm_x, fe_to_biguint(&msm_answer.x));
    assert_eq!(msm_y, fe_to_biguint(&msm_answer.y));
}

fn random_pairs(batch_size: usize, rng: &StdRng) -> (Vec<G1Affine>, Vec<Fr>) {
    (0..batch_size).map(|_| (G1Affine::random(rng.clone()), Fr::random(rng.clone()))).unzip()
}

#[test]
fn test_msm() {
    let path = "configs/bn254/msm_circuit.config";
    let params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let (bases, scalars) = random_pairs(params.batch_size, &StdRng::seed_from_u64(0));
    base_test().k(params.degree).lookup_bits(params.lookup_bits).run_builder(|pool, range| {
        msm_test(pool, range, params, bases, scalars);
    });
}

#[test]
fn bench_msm() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_msm.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/msm_bench.csv";
    let mut fs_results = match File::options().append(true).open(results_path) {
        Ok(file) => file,
        Err(_) => {
            let mut file = File::create(results_path).unwrap();
            writeln!(file, "halo2_feature,degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,batch_size,window_bits,proof_time,proof_size,verify_time")?;
            file
        }
    };

    #[cfg(feature = "halo2-icicle")]
    let halo2_feature = "pse-icicle";
    #[cfg(feature = "halo2-axiom-icicle")]
    let halo2_feature = "axiom-icicle";
    #[cfg(feature = "halo2-axiom")]
    let halo2_feature = "axiom";
    #[cfg(feature = "halo2-pse")]
    let halo2_feature = "pse";

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: MSMCircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let (bases, scalars) = random_pairs(bench_params.batch_size, &StdRng::seed_from_u64(0));
        let stats =
            base_test().k(bench_params.degree).lookup_bits(bench_params.lookup_bits).bench_builder(
                (bases.clone(), scalars.clone()),
                (bases, scalars),
                |pool, range, (bases, scalars)| {
                    msm_test(pool, range, bench_params, bases, scalars);
                },
            );

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{},{:?},{},{:?}",
            halo2_feature,
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.batch_size,
            bench_params.window_bits,
            stats.proof_time.time.elapsed(),
            stats.proof_size,
            stats.verify_time.time.elapsed(),
        )?;
    }
    Ok(())
}
