use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

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
use halo2_base::{
    gates::GateInstructions,
    utils::{biguint_to_fe, fe_to_biguint},
    QuantumCell::Witness,
};
use halo2_ecc::fields::PrimeField;
use halo2_ecc::{
    ecc::EccChip,
    fields::fp::{FpConfig, FpStrategy},
};
use num_bigint::BigUint;

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
    window_bits: usize,
}

const BEST_100_CONFIG: MSMCircuitParams = MSMCircuitParams {
    strategy: FpStrategy::Simple,
    degree: 19,
    num_advice: 20,
    num_lookup_advice: 3,
    num_fixed: 1,
    lookup_bits: 18,
    limb_bits: 90,
    num_limbs: 3,
    batch_size: 100,
    window_bits: 4,
};

const TEST_CONFIG: MSMCircuitParams = BEST_100_CONFIG;

#[derive(Clone, Debug)]
struct MSMConfig<F: PrimeField> {
    fp_chip: FpChip<F>,
    batch_size: usize,
    window_bits: usize,
}

impl<F: PrimeField> MSMConfig<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        strategy: FpStrategy,
        num_advice: &[usize],
        num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
        p: BigUint,
        batch_size: usize,
        window_bits: usize,
        context_id: usize,
        k: usize,
    ) -> Self {
        let fp_chip = FpChip::<F>::configure(
            meta,
            strategy,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
            limb_bits,
            num_limbs,
            p,
            context_id,
            k,
        );
        MSMConfig { fp_chip, batch_size, window_bits }
    }
}

struct MSMCircuit<F: PrimeField> {
    bases: Vec<Option<G1Affine>>,
    scalars: Vec<Option<Fr>>,
    batch_size: usize,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for MSMCircuit<F> {
    fn default() -> Self {
        Self {
            bases: vec![None; 10],
            scalars: vec![None; 10],
            batch_size: 10,
            _marker: PhantomData,
        }
    }
}

impl Circuit<Fr> for MSMCircuit<Fr> {
    type Config = MSMConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            bases: vec![None; self.batch_size],
            scalars: vec![None; self.batch_size],
            batch_size: self.batch_size,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let params: MSMCircuitParams = TEST_CONFIG;

        MSMConfig::<Fr>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            modulus::<Fq>(),
            params.batch_size,
            params.window_bits,
            0,
            params.degree as usize,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        assert_eq!(config.batch_size, self.scalars.len());
        assert_eq!(config.batch_size, self.bases.len());

        config.fp_chip.load_lookup_table(&mut layouter)?;

        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "MSM",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let witness_time = start_timer!(|| "Witness Generation");
                let mut aux = config.fp_chip.new_context(region);
                let ctx = &mut aux;

                let mut scalars_assigned = Vec::new();
                for scalar in &self.scalars {
                    let assignment = config.fp_chip.range.gate.assign_region_last(
                        ctx,
                        vec![Witness(scalar.map_or(Value::unknown(), Value::known))],
                        vec![],
                    );
                    scalars_assigned.push(vec![assignment]);
                }

                let ecc_chip = EccChip::construct(config.fp_chip.clone());
                let mut bases_assigned = Vec::new();
                for base in &self.bases {
                    let base_assigned = ecc_chip.load_private(
                        ctx,
                        (
                            base.map(|pt| Value::known(biguint_to_fe(&fe_to_biguint(&pt.x))))
                                .unwrap_or(Value::unknown()),
                            base.map(|pt| Value::known(biguint_to_fe(&fe_to_biguint(&pt.y))))
                                .unwrap_or(Value::unknown()),
                        ),
                    );
                    bases_assigned.push(base_assigned);
                }

                let _msm = ecc_chip.variable_base_msm::<G1Affine>(
                    ctx,
                    &bases_assigned,
                    &scalars_assigned,
                    254,
                    config.window_bits,
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
        let new_pt = Some(G1Affine::random(&mut rng));
        bases.push(new_pt);

        let new_scalar = Some(Fr::random(&mut rng));
        scalars.push(new_scalar);
    }
    let circuit =
        MSMCircuit::<Fr> { bases, scalars, batch_size: config.batch_size, _marker: PhantomData };

    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let mut group = c.benchmark_group("plonk-prover");
    group.sample_size(10);
    group.bench_with_input(BenchmarkId::new("msm", k), &(&params, &pk), |b, &(params, pk)| {
        b.iter(|| {
            let mut bases = Vec::new();
            let mut scalars = Vec::new();
            for _ in 0..config.batch_size {
                let new_pt = Some(G1Affine::random(&mut rng));
                bases.push(new_pt);

                let new_scalar = Some(Fr::random(&mut rng));
                scalars.push(new_scalar);
            }

            let circuit = MSMCircuit::<Fr> {
                bases,
                scalars,
                batch_size: config.batch_size,
                _marker: PhantomData,
            };

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
    });
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
