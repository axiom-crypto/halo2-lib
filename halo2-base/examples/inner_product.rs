#![allow(unused_imports)]
#![allow(unused_variables)]
use halo2_base::gates::builder::{GateThreadBuilder, RangeCircuitBuilder};
use halo2_base::gates::flex_gate::{FlexGateConfig, GateChip, GateInstructions, GateStrategy};
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    circuit::*,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::*,
    poly::kzg::multiopen::VerifierSHPLONK,
    poly::kzg::strategy::SingleStrategy,
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverSHPLONK,
    },
    transcript::{Blake2bRead, TranscriptReadBuffer},
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

fn main() {
    let k = 10u32;
    // create circuit for keygen
    let mut builder = GateThreadBuilder::new(false);
    inner_prod_bench(builder.main(0), vec![Fr::zero(); 5], vec![Fr::zero(); 5]);
    builder.config(k as usize, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    // check the circuit is correct just in case
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let break_points = circuit.0.break_points.take();

    let mut builder = GateThreadBuilder::new(true);
    let a = (0..5).map(|_| Fr::random(OsRng)).collect_vec();
    let b = (0..5).map(|_| Fr::random(OsRng)).collect_vec();
    inner_prod_bench(builder.main(0), a, b);
    let circuit = RangeCircuitBuilder::prover(builder, break_points);

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("prover should not fail");

    let strategy = SingleStrategy::new(&params);
    let proof = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, pk.get_vk(), strategy, &[&[]], &mut transcript)
    .unwrap();
}
