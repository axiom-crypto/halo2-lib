use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};

use super::*;
use crate::fields::{FieldChip, FpStrategy};
use halo2_base::gates::RangeChip;
use halo2_base::utils::testing::base_test;
use halo2_base::utils::BigPrimeField;
use halo2_base::Context;
use itertools::Itertools;
use rand_core::OsRng;

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
    batch_size: usize,
}

fn g2_add_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: CircuitParams,
    _points: Vec<G2Affine>,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);

    let points =
        _points.iter().map(|pt| g2_chip.assign_point_unchecked(ctx, *pt)).collect::<Vec<_>>();

    let acc = g2_chip.sum::<G2Affine>(ctx, points);

    let answer = _points.iter().fold(G2Affine::identity(), |a, &b| (a + b).to_affine());
    let x = fp2_chip.get_assigned_value(&acc.x.into());
    let y = fp2_chip.get_assigned_value(&acc.y.into());
    assert_eq!(answer.x, x);
    assert_eq!(answer.y, y);
}

#[test]
fn test_ec_add() {
    let path = "configs/bls12_381/ec_add_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let k = params.degree;
    let points = (0..params.batch_size).map(|_| G2Affine::random(OsRng)).collect_vec();

    base_test()
        .k(k)
        .lookup_bits(params.lookup_bits)
        .run(|ctx, range| g2_add_test(ctx, range, params, points));
}

#[test]
fn bench_ec_add() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bls12_381/bench_ec_add.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bls12_381").unwrap();

    let results_path = "results/bls12_381/ec_add_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,batch_size,proof_time,proof_size,verify_time")?;
    fs::create_dir_all("data").unwrap();

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);
        let mut rng = OsRng;

        let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
            vec![G2Affine::generator(); bench_params.batch_size],
            (0..bench_params.batch_size).map(|_| G2Affine::random(&mut rng)).collect_vec(),
            |pool, range, points| {
                g2_add_test(pool.main(), range, bench_params, points);
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
