use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        builder::{
            BaseConfigParams, CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::{
        arithmetic::Field,
        halo2curves::bn256::{Bn256, Fq, Fr},
        plonk::*,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::{testing::gen_proof, BigPrimeField},
    Context,
};
use halo2_ecc::fields::fp::FpChip;
use halo2_ecc::fields::FieldChip;
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

const K: u32 = 19;

fn fp_mul_bench<F: BigPrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    _a: Fq,
    _b: Fq,
) {
    let range = RangeChip::<F>::default(lookup_bits);
    let chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);

    let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, x));
    for _ in 0..2857 {
        chip.mul(ctx, &a, &b);
    }
}

fn fp_mul_circuit(
    stage: CircuitBuilderStage,
    a: Fq,
    b: Fq,
    config_params: Option<BaseConfigParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = K as usize;
    let lookup_bits = k - 1;
    let mut builder = GateThreadBuilder::from_stage(stage);

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    fp_mul_bench(builder.main(0), lookup_bits, 88, 3, a, b);

    let mut config_params = config_params.unwrap_or_else(|| builder.config(k, Some(20)));
    config_params.lookup_bits = Some(lookup_bits);
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
    let circuit = fp_mul_circuit(CircuitBuilderStage::Keygen, Fq::zero(), Fq::zero(), None, None);
    let config_params = circuit.0.config_params.clone();

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.0.break_points.take();

    let a = Fq::random(OsRng);
    let b = Fq::random(OsRng);
    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("fp mul", K),
        &(&params, &pk, a, b),
        |bencher, &(params, pk, a, b)| {
            bencher.iter(|| {
                let circuit = fp_mul_circuit(
                    CircuitBuilderStage::Prover,
                    a,
                    b,
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
