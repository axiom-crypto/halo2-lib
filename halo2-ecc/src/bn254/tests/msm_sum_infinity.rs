use std::fs::File;

use super::{msm::msm_test, *};

fn run_test(scalars: Vec<Fr>, bases: Vec<G1Affine>) {
    let path = "configs/bn254/msm_circuit.config";
    let params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    base_test().k(params.degree).lookup_bits(params.lookup_bits).run_builder(|pool, range| {
        msm_test(pool, range, params, bases, scalars);
    });
}

#[test]
fn test_msm1() {
    let rng = StdRng::seed_from_u64(0);
    let random_point = G1Affine::random(rng);
    let bases = vec![random_point, random_point, random_point];
    let scalars = vec![Fr::one(), Fr::one(), -Fr::one() - Fr::one()];
    run_test(scalars, bases);
}

#[test]
fn test_msm2() {
    let rng = StdRng::seed_from_u64(0);
    let random_point = G1Affine::random(rng);
    let bases = vec![random_point, random_point, (random_point + random_point).to_affine()];
    let scalars = vec![Fr::one(), Fr::one(), -Fr::one()];
    run_test(scalars, bases);
}

#[test]
fn test_msm3() {
    let rng = StdRng::seed_from_u64(0);
    let random_point = G1Affine::random(rng);
    let bases = vec![
        random_point,
        random_point,
        random_point,
        (random_point + random_point + random_point).to_affine(),
    ];
    let scalars = vec![Fr::one(), Fr::one(), Fr::one(), -Fr::one()];
    run_test(scalars, bases);
}

#[test]
fn test_msm4() {
    let generator_point = G1Affine::generator();
    let bases = vec![
        generator_point,
        generator_point,
        generator_point,
        (generator_point + generator_point + generator_point).to_affine(),
    ];
    let scalars = vec![Fr::one(), Fr::one(), Fr::one(), -Fr::one()];
    run_test(scalars, bases);
}

#[test]
fn test_msm5() {
    let rng = StdRng::seed_from_u64(0);
    let random_point = G1Affine::random(rng);
    let bases =
        vec![random_point, random_point, random_point, (random_point + random_point).to_affine()];
    let scalars = vec![-Fr::one(), -Fr::one(), Fr::one(), Fr::one()];
    run_test(scalars, bases);
}
