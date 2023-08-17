use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField as _;
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::commitment::ParamsKZG,
};
use halo2_base::{
    gates::{
        builder::{
            BaseConfigParams, CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    utils::testing::gen_proof,
};
use halo2_ecc::{bn254::FpChip, ecc::EccChip};
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

#[derive(Clone, Copy, Debug)]
struct MSMCircuitParams {
    degree: u32,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    batch_size: usize,
}

const BEST_100_CONFIG: MSMCircuitParams =
    MSMCircuitParams { degree: 20, lookup_bits: 19, limb_bits: 88, num_limbs: 3, batch_size: 100 };

const TEST_CONFIG: MSMCircuitParams = BEST_100_CONFIG;

fn fixed_base_msm_bench(
    builder: &mut GateThreadBuilder<Fr>,
    params: MSMCircuitParams,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
) {
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let scalars_assigned = scalars
        .iter()
        .map(|scalar| vec![builder.main(0).load_witness(*scalar)])
        .collect::<Vec<_>>();

    ecc_chip.fixed_base_msm(builder, &bases, scalars_assigned, Fr::NUM_BITS as usize);
}

fn fixed_base_msm_circuit(
    params: MSMCircuitParams,
    stage: CircuitBuilderStage,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
    config_params: Option<BaseConfigParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = GateThreadBuilder::new(stage == CircuitBuilderStage::Prover);

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    fixed_base_msm_bench(&mut builder, params, bases, scalars);

    let mut config_params = config_params.unwrap_or_else(|| builder.config(k, Some(20)));
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

fn bench(c: &mut Criterion) {
    let config = TEST_CONFIG;

    let k = config.degree;
    let mut rng = OsRng;
    let circuit = fixed_base_msm_circuit(
        config,
        CircuitBuilderStage::Keygen,
        vec![G1Affine::generator(); config.batch_size],
        vec![Fr::zero(); config.batch_size],
        None,
        None,
    );
    let config_params = circuit.0.config_params.clone();

    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.0.break_points.take();
    drop(circuit);

    let (bases, scalars): (Vec<_>, Vec<_>) =
        (0..config.batch_size).map(|_| (G1Affine::random(&mut rng), Fr::random(&mut rng))).unzip();
    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("fixed base msm", k),
        &(&params, &pk, &bases, &scalars),
        |b, &(params, pk, bases, scalars)| {
            b.iter(|| {
                let circuit = fixed_base_msm_circuit(
                    config,
                    CircuitBuilderStage::Prover,
                    bases.clone(),
                    scalars.clone(),
                    Some(config_params.clone()),
                    Some(break_points.clone()),
                );

                gen_proof(params, pk, circuit);
            })
        },
    );
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
