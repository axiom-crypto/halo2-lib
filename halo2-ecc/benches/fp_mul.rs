use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverSHPLONK,
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
};
use rand::rngs::OsRng;

use halo2_base::{
    utils::{fe_to_bigint, modulus, PrimeField},
    SKIP_FIRST_PASS,
};
use halo2_ecc::fields::fp::{FpConfig, FpStrategy};
use halo2_ecc::fields::FieldChip;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

const K: u32 = 19;

#[derive(Default)]
struct MyCircuit<F> {
    a: Value<Fq>,
    b: Value<Fq>,
    _marker: PhantomData<F>,
}

const NUM_ADVICE: usize = 2;
const NUM_FIXED: usize = 1;

impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
    type Config = FpConfig<F, Fq>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        FpConfig::<F, _>::configure(
            meta,
            FpStrategy::Simple,
            &[NUM_ADVICE],
            &[1],
            NUM_FIXED,
            K as usize - 1,
            88,
            3,
            modulus::<Fq>(),
            0,
            K as usize,
        )
    }

    fn synthesize(&self, chip: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        chip.load_lookup_table(&mut layouter)?;

        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "fp",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = chip.new_context(region);
                let ctx = &mut aux;

                let a_assigned = chip.load_private(ctx, self.a.as_ref().map(fe_to_bigint));
                let b_assigned = chip.load_private(ctx, self.b.as_ref().map(fe_to_bigint));

                for _ in 0..2857 {
                    chip.mul(ctx, &a_assigned, &b_assigned);
                }

                // IMPORTANT: this copies advice cells to enable lookup
                // This is not optional.
                chip.finalize(ctx);

                Ok(())
            },
        )
    }
}

fn bench(c: &mut Criterion) {
    let a = Fq::random(OsRng);
    let b = Fq::random(OsRng);

    let circuit = MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(BenchmarkId::new("fp mul", K), &(&params, &pk), |b, &(params, pk)| {
        b.iter(|| {
            let rng = OsRng;
            let a = Fq::random(OsRng);
            let b = Fq::random(OsRng);

            let circuit =
                MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

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
    });
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
