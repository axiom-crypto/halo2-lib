#![allow(unused_imports)]
#![allow(unused_variables)]
use halo2_base::gates::{
    flex_gate::{FlexGateConfig, GateStrategy},
    GateInstructions,
};
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
use halo2_base::{Context, ContextParams, QuantumCell::Witness, SKIP_FIRST_PASS};
use itertools::Itertools;
use rand::rngs::OsRng;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

#[derive(Clone, Default)]
struct MyCircuit<F> {
    _marker: PhantomData<F>,
}

const NUM_ADVICE: usize = 1;
const K: u32 = 19;

impl Circuit<Fr> for MyCircuit<Fr> {
    type Config = FlexGateConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        FlexGateConfig::configure(meta, GateStrategy::Vertical, &[NUM_ADVICE], 1, 0, K as usize)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "gate",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.constants.clone(),
                    },
                );
                let ctx = &mut aux;

                let a = (0..5).map(|_| Witness(Value::known(Fr::random(OsRng)))).collect_vec();
                let b = (0..5).map(|_| Witness(Value::known(Fr::random(OsRng)))).collect_vec();

                for _ in 0..(1 << K) / 16 - 10 {
                    config.inner_product(ctx, a.clone(), b.clone());
                }

                Ok(())
            },
        )
    }
}

fn bench(c: &mut Criterion) {
    let circuit = MyCircuit::<Fr> { _marker: PhantomData };

    MockProver::run(K, &circuit, vec![]).unwrap().assert_satisfied();

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("inner_product", K),
        &(&params, &pk),
        |b, &(params, pk)| {
            b.iter(|| {
                let circuit = MyCircuit::<Fr> { _marker: PhantomData };
                let rng = OsRng;
                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit], &[&[]], rng, &mut transcript)
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
