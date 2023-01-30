use halo2_base::gates::{
    flex_gate::{FlexGateConfig, GateStrategy},
    GateInstructions,
};
use halo2_base::halo2_proofs::{
    circuit::*,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverGWC,
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use halo2_base::{
    Context, ContextParams,
    QuantumCell::{Existing, Witness},
    SKIP_FIRST_PASS,
};
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

#[derive(Clone, Default)]
struct MyCircuit<F> {
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
}

const NUM_ADVICE: usize = 1;
const K: u32 = 9;

impl Circuit<Fr> for MyCircuit<Fr> {
    type Config = FlexGateConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        FlexGateConfig::configure(meta, GateStrategy::PlonkPlus, &[NUM_ADVICE], 1, 0, K as usize)
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

                let (_a_cell, b_cell, c_cell) = {
                    let cells = config.assign_region_smart(
                        ctx,
                        vec![Witness(self.a), Witness(self.b), Witness(self.c)],
                        vec![],
                        vec![],
                        vec![],
                    );
                    (cells[0].clone(), cells[1].clone(), cells[2].clone())
                };

                for _ in 0..120 {
                    config.mul(ctx, Existing(&c_cell), Existing(&b_cell));
                }

                Ok(())
            },
        )
    }
}

fn bench(c: &mut Criterion) {
    let circuit = MyCircuit::<Fr> {
        a: Value::known(Fr::from(10u64)),
        b: Value::known(Fr::from(12u64)),
        c: Value::known(Fr::from(120u64)),
    };

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    // native multiplication 120 times
    c.bench_with_input(
        BenchmarkId::new("native mul", K),
        &(&params, &pk, &circuit),
        |b, &(params, pk, circuit)| {
            b.iter(|| {
                let rng = OsRng;
                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverGWC<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit.clone()], &[&[]], rng, &mut transcript)
                .expect("prover should not fail");
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
