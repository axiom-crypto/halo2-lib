use ark_std::{end_timer, start_timer};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::gates::{
    circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
    RangeChip,
};
use halo2_base::{
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
    range: &RangeChip<F>,
    limb_bits: usize,
    num_limbs: usize,
    _a: Fq,
    _b: Fq,
) {
    let chip = FpChip::<F, Fq>::new(range, limb_bits, num_limbs);

    let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, x));
    for _ in 0..2857 {
        chip.mul(ctx, &a, &b);
    }
}

fn fp_mul_circuit(
    stage: CircuitBuilderStage,
    a: Fq,
    b: Fq,
    config_params: Option<BaseCircuitParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = K as usize;
    let lookup_bits = k - 1;
    let mut builder = match stage {
        CircuitBuilderStage::Prover => {
            RangeCircuitBuilder::prover(config_params.unwrap(), break_points.unwrap())
        }
        _ => RangeCircuitBuilder::from_stage(stage).use_k(k).use_lookup_bits(lookup_bits),
    };

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    let range = builder.range_chip();
    fp_mul_bench(builder.main(0), &range, 88, 3, a, b);
    end_timer!(start0);
    if !stage.witness_gen_only() {
        builder.calculate_params(Some(20));
    }
    builder
}

fn bench(c: &mut Criterion) {
    let circuit = fp_mul_circuit(CircuitBuilderStage::Keygen, Fq::zero(), Fq::zero(), None, None);
    let config_params = circuit.params();

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    let break_points = circuit.break_points();

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
