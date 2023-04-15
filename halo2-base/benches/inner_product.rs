#![allow(unused_imports)]
#![allow(unused_variables)]
use halo2_base::gates::builder::{GateCircuitBuilder, GateThreadBuilder};
use halo2_base::gates::flex_gate::{FlexGateConfig, GateChip, GateInstructions, GateStrategy};
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverSHPLONK,
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use halo2_base::utils::ScalarField;
use halo2_base::{
    Context,
    QuantumCell::{Existing, Witness},
    SKIP_FIRST_PASS,
};
use itertools::Itertools;
use rand::rngs::OsRng;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

const K: u32 = 19;

fn inner_prod_bench<F: ScalarField>(ctx: &mut Context<F>, a: Vec<F>, b: Vec<F>) {
    assert_eq!(a.len(), b.len());
    let a = ctx.assign_witnesses(a);
    let b = ctx.assign_witnesses(b);

    let chip = GateChip::default();
    for _ in 0..(1 << K) / 16 - 10 {
        chip.inner_product(ctx, a.clone(), b.clone().into_iter().map(Existing));
    }
}

fn bench(c: &mut Criterion) {
    let k = 19u32;
    // create circuit for keygen
    let mut builder = GateThreadBuilder::new(false);
    inner_prod_bench(builder.main(0), vec![Fr::zero(); 5], vec![Fr::zero(); 5]);
    builder.config(k as usize, Some(20));
    let circuit = GateCircuitBuilder::mock(builder);

    // check the circuit is correct just in case
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let break_points = circuit.break_points.take();
    drop(circuit);

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("inner_product", k),
        &(&params, &pk),
        |bencher, &(params, pk)| {
            bencher.iter(|| {
                let mut builder = GateThreadBuilder::new(true);
                let a = (0..5).map(|_| Fr::random(OsRng)).collect_vec();
                let b = (0..5).map(|_| Fr::random(OsRng)).collect_vec();
                inner_prod_bench(builder.main(0), a, b);
                let circuit = GateCircuitBuilder::prover(builder, break_points.clone());

                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
                .expect("prover should not fail");
            })
        },
    );
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
