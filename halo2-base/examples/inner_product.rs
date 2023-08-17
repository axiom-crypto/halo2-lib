use halo2_base::gates::builder::{GateThreadBuilder, RangeCircuitBuilder};
use halo2_base::gates::flex_gate::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr},
    plonk::*,
    poly::kzg::commitment::ParamsKZG,
};
use halo2_base::utils::testing::{check_proof, gen_proof};
use halo2_base::utils::ScalarField;
use halo2_base::{Context, QuantumCell::Existing};
use itertools::Itertools;
use rand::rngs::OsRng;

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
    let config_params = builder.config(k as usize, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder, config_params.clone());

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
    let circuit = RangeCircuitBuilder::prover(builder, config_params, break_points);

    let proof = gen_proof(&params, &pk, circuit);
    check_proof(&params, pk.get_vk(), &proof, true);
}
