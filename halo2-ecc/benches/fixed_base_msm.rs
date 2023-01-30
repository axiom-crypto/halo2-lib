use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

#[allow(unused_imports)]
use ff::PrimeField as _;
use halo2_base::utils::modulus;
use pprof::criterion::{Output, PProfProfiler};

use ark_std::{end_timer, start_timer};
use halo2_base::SKIP_FIRST_PASS;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::*,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverSHPLONK,
    },
    transcript::TranscriptWriterBuffer,
    transcript::{Blake2bWrite, Challenge255},
};
use halo2_base::{gates::GateInstructions, utils::PrimeField};
use halo2_ecc::{
    ecc::EccChip,
    fields::fp::{FpConfig, FpStrategy},
};

type FpChip<F> = FpConfig<F, Fq>;

#[derive(Serialize, Deserialize, Debug)]
struct MSMCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    batch_size: usize,
    radix: usize,
    clump_factor: usize,
}

const BEST_100_CONFIG: MSMCircuitParams = MSMCircuitParams {
    strategy: FpStrategy::Simple,
    degree: 20,
    num_advice: 10,
    num_lookup_advice: 1,
    num_fixed: 1,
    lookup_bits: 19,
    limb_bits: 88,
    num_limbs: 3,
    batch_size: 100,
    radix: 0,
    clump_factor: 4,
};

const TEST_CONFIG: MSMCircuitParams = BEST_100_CONFIG;

#[derive(Clone, Debug)]
struct MSMConfig<F: PrimeField> {
    fp_chip: FpChip<F>,
    clump_factor: usize,
}

impl<F: PrimeField> MSMConfig<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(meta: &mut ConstraintSystem<F>, params: MSMCircuitParams) -> Self {
        let fp_chip = FpChip::<F>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            modulus::<Fq>(),
            0,
            params.degree as usize,
        );
        MSMConfig { fp_chip, clump_factor: params.clump_factor }
    }
}

struct MSMCircuit<F: PrimeField> {
    bases: Vec<G1Affine>,
    scalars: Vec<Option<Fr>>,
    _marker: PhantomData<F>,
}

impl Circuit<Fr> for MSMCircuit<Fr> {
    type Config = MSMConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            bases: self.bases.clone(),
            scalars: vec![None; self.scalars.len()],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params = TEST_CONFIG;

        MSMConfig::<Fr>::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.fp_chip.load_lookup_table(&mut layouter)?;

        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "fixed base msm",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = config.fp_chip.new_context(region);
                let ctx = &mut aux;

                let witness_time = start_timer!(|| "Witness generation");
                let mut scalars_assigned = Vec::new();
                for scalar in &self.scalars {
                    let assignment = config
                        .fp_chip
                        .range
                        .gate
                        .assign_witnesses(ctx, vec![scalar.map_or(Value::unknown(), Value::known)]);
                    scalars_assigned.push(assignment);
                }

                let ecc_chip = EccChip::construct(config.fp_chip.clone());

                let _msm = ecc_chip.fixed_base_msm::<G1Affine>(
                    ctx,
                    &self.bases,
                    &scalars_assigned,
                    Fr::NUM_BITS as usize,
                    0,
                    config.clump_factor,
                );

                config.fp_chip.finalize(ctx);
                end_timer!(witness_time);

                Ok(())
            },
        )
    }
}

fn bench(c: &mut Criterion) {
    let config = TEST_CONFIG;

    let k = config.degree;
    let mut rng = OsRng;
    let mut bases = Vec::new();
    let mut scalars = Vec::new();
    for _ in 0..config.batch_size {
        let new_pt = G1Affine::random(&mut rng);
        bases.push(new_pt);

        let new_scalar = Some(Fr::random(&mut rng));
        scalars.push(new_scalar);
    }
    let circuit = MSMCircuit::<Fr> { bases, scalars, _marker: PhantomData };

    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(
        BenchmarkId::new("fixed base msm", k),
        &(&params, &pk),
        |b, &(params, pk)| {
            b.iter(|| {
                let mut bases = Vec::new();
                let mut scalars = Vec::new();
                for _ in 0..config.batch_size {
                    let new_pt = G1Affine::random(&mut rng);
                    bases.push(new_pt);

                    let new_scalar = Some(Fr::random(&mut rng));
                    scalars.push(new_scalar);
                }

                let circuit = MSMCircuit::<Fr> { bases, scalars, _marker: PhantomData };

                let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
                create_proof::<
                    KZGCommitmentScheme<Bn256>,
                    ProverSHPLONK<'_, Bn256>,
                    Challenge255<G1Affine>,
                    _,
                    Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
                    _,
                >(params, pk, &[circuit], &[&[]], &mut rng, &mut transcript)
                .expect("prover should not fail");
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
