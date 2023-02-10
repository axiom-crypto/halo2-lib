use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::{
        arithmetic::Field,
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        plonk::*,
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    Context,
};
use halo2_ecc::fields::fp::FpChip;
use halo2_ecc::fields::{FieldChip, PrimeField};
use rand::rngs::OsRng;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};
// Thanks to the example provided by @jebbow in his article
// https://www.jibbow.com/posts/criterion-flamegraphs/

const K: u32 = 19;

fn fp_mul_bench<F: PrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    _a: Fq,
    _b: Fq,
) {
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<F>::default(lookup_bits);
    let chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);

    let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, FpChip::<F, Fq>::fe_to_witness(&x)));
    for _ in 0..2857 {
        chip.mul(ctx, &a, &b);
    }
}

fn fp_mul_circuit(
    stage: CircuitBuilderStage,
    a: Fq,
    b: Fq,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = K as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    fp_mul_bench(builder.main(0), k - 1, 88, 3, a, b);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

fn bench(c: &mut Criterion) {
    let circuit = fp_mul_circuit(CircuitBuilderStage::Keygen, Fq::zero(), Fq::zero(), None);

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
                let circuit =
                    fp_mul_circuit(CircuitBuilderStage::Prover, a, b, Some(break_points.clone()));

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
    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
