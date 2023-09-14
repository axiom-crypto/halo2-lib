use ark_std::{end_timer, start_timer};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::flex_gate::threads::SinglePhaseCoreManager;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::gates::{
    circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
    RangeChip,
};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField as _;
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::commitment::ParamsKZG,
};
use halo2_base::utils::testing::gen_proof;
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
    clump_factor: usize,
}

const BEST_100_CONFIG: MSMCircuitParams = MSMCircuitParams {
    degree: 19,
    lookup_bits: 18,
    limb_bits: 90,
    num_limbs: 3,
    batch_size: 100,
    clump_factor: 4,
};
const TEST_CONFIG: MSMCircuitParams = BEST_100_CONFIG;

fn msm_bench(
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

    ecc_chip.variable_base_msm_custom::<G1Affine>(
        pool,
        &bases_assigned,
        scalars_assigned,
        Fr::NUM_BITS as usize,
        params.clump_factor,
    );
}

fn msm_circuit(
    params: MSMCircuitParams,
    stage: CircuitBuilderStage,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
    config_params: Option<BaseCircuitParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Prover => {
            RangeCircuitBuilder::prover(config_params.unwrap(), break_points.unwrap())
        }
        _ => RangeCircuitBuilder::from_stage(stage).use_k(k).use_lookup_bits(params.lookup_bits),
    };
    let range = builder.range_chip();
    msm_bench(builder.pool(0), &range, params, bases, scalars);
    end_timer!(start0);
    if !stage.witness_gen_only() {
        builder.calculate_params(Some(20));
    }
    builder
}

fn bench(c: &mut Criterion) {
    let config = TEST_CONFIG;

    let k = config.degree;
    let mut rng = OsRng;
    let circuit = msm_circuit(
        config,
        CircuitBuilderStage::Keygen,
        vec![G1Affine::generator(); config.batch_size],
        vec![Fr::one(); config.batch_size],
        None,
        None,
    );
    let config_params = circuit.params();

    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.break_points();
    drop(circuit);

    let (bases, scalars): (Vec<_>, Vec<_>) =
        (0..config.batch_size).map(|_| (G1Affine::random(&mut rng), Fr::random(&mut rng))).unzip();
    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("msm", k),
        &(&params, &pk, &bases, &scalars),
        |b, &(params, pk, bases, scalars)| {
            b.iter(|| {
                let circuit = msm_circuit(
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
