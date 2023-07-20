use ff::Field;
use halo2_base::gates::builder::{GateThreadBuilder, RangeCircuitBuilder};
use halo2_base::gates::flex_gate::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverGWC,
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use halo2_base::utils::ScalarField;
use halo2_base::Context;
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

const K: u32 = 9;

fn mul_bench<F: ScalarField>(ctx: &mut Context<F>, inputs: [F; 2]) {
    let [a, b]: [_; 2] = ctx.assign_witnesses(inputs).try_into().unwrap();
    let chip = GateChip::default();

    for _ in 0..120 {
        chip.mul(ctx, a, b);
    }
}

fn bench(c: &mut Criterion) {
    // create circuit for keygen
    let mut builder = GateThreadBuilder::new(false);
    mul_bench(builder.main(0), [Fr::zero(); 2]);
    builder.config(K as usize, Some(9));
    let circuit = RangeCircuitBuilder::keygen(builder);

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let break_points = circuit.0.break_points.take();

    let a = Fr::random(OsRng);
    let b = Fr::random(OsRng);
    // native multiplication 120 times
    c.bench_with_input(
        BenchmarkId::new("native mul", K),
        &(&params, &pk, [a, b]),
        |bencher, &(params, pk, inputs)| {
            bencher.iter(|| {
                let mut builder = GateThreadBuilder::new(true);
                // do the computation
                mul_bench(builder.main(0), inputs);
                let circuit = RangeCircuitBuilder::prover(builder, break_points.clone());

                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverGWC<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
                .unwrap();
            })
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
