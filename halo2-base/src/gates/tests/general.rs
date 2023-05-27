use crate::gates::{
    builder::{GateCircuitBuilder, GateThreadBuilder, RangeCircuitBuilder},
    flex_gate::{GateChip, GateInstructions},
    range::{RangeChip, RangeInstructions},
};
use crate::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use crate::utils::{BigPrimeField, ScalarField};
use crate::{Context, QuantumCell::Constant};
use ff::Field;
use rand::rngs::OsRng;
use rayon::prelude::*;

fn gate_tests<F: ScalarField>(ctx: &mut Context<F>, inputs: [F; 3]) {
    let [a, b, c]: [_; 3] = ctx.assign_witnesses(inputs).try_into().unwrap();
    let chip = GateChip::default();

    // test add
    chip.add(ctx, a, b);

    // test sub
    chip.sub(ctx, a, b);

    // test multiply
    chip.mul(ctx, c, b);

    // test idx_to_indicator
    chip.idx_to_indicator(ctx, Constant(F::from(3u64)), 4);

    let bits = ctx.assign_witnesses([F::zero(), F::one()]);
    chip.bits_to_indicator(ctx, &bits);

    chip.is_equal(ctx, b, a);

    chip.is_zero(ctx, a);
}

#[test]
fn test_gates() {
    let k = 6;
    let inputs = [10u64, 12u64, 120u64].map(Fr::from);
    let mut builder = GateThreadBuilder::mock();
    gate_tests(builder.main(0), inputs);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = GateCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_multithread_gates() {
    let k = 6;
    let inputs = [10u64, 12u64, 120u64].map(Fr::from);
    let mut builder = GateThreadBuilder::mock();
    gate_tests(builder.main(0), inputs);

    let thread_ids = (0..4usize).map(|_| builder.get_new_thread_id()).collect::<Vec<_>>();
    let new_threads = thread_ids
        .into_par_iter()
        .map(|id| {
            let mut ctx = Context::new(builder.witness_gen_only(), id);
            gate_tests(&mut ctx, [(); 3].map(|_| Fr::random(OsRng)));
            ctx
        })
        .collect::<Vec<_>>();
    builder.threads[0].extend(new_threads);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = GateCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_gates() {
    let k = 5;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Gates Layout", ("sans-serif", 60)).unwrap();

    let inputs = [Fr::zero(); 3];
    let builder = GateThreadBuilder::new(false);
    gate_tests(builder.main(0), inputs);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = GateCircuitBuilder::keygen(builder);
    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}

fn range_tests<F: BigPrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    inputs: [F; 2],
    range_bits: usize,
    lt_bits: usize,
) {
    let [a, b]: [_; 2] = ctx.assign_witnesses(inputs).try_into().unwrap();
    let chip = RangeChip::default(lookup_bits);
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());

    chip.range_check(ctx, a, range_bits);

    chip.check_less_than(ctx, a, b, lt_bits);

    chip.is_less_than(ctx, a, b, lt_bits);

    chip.is_less_than(ctx, b, a, lt_bits);

    chip.div_mod(ctx, a, 7u64, lt_bits);
}

#[test]
fn test_range_single() {
    let k = 11;
    let inputs = [100, 101].map(Fr::from);
    let mut builder = GateThreadBuilder::mock();
    range_tests(builder.main(0), 3, inputs, 8, 8);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_range_multicolumn() {
    let k = 5;
    let inputs = [100, 101].map(Fr::from);
    let mut builder = GateThreadBuilder::mock();
    range_tests(builder.main(0), 3, inputs, 8, 8);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_range() {
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Range Layout", ("sans-serif", 60)).unwrap();

    let k = 11;
    let inputs = [0, 0].map(Fr::from);
    let mut builder = GateThreadBuilder::new(false);
    range_tests(builder.main(0), 3, inputs, 8, 8);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::keygen(builder);
    halo2_proofs::dev::CircuitLayout::default().render(7, &circuit, &root).unwrap();
}
