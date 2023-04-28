use super::*;
use crate::{gates::{
    builder::{GateCircuitBuilder,GateThreadBuilder},
    flex_gate::{GateChip, GateInstructions},
}, QuantumCell};
use crate::halo2_proofs::dev::MockProver;
use crate::utils::ScalarField;
use crate::QuantumCell::Witness;
use test_case::test_case;

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(2) ; "add(): 1 + 1 == 2")]
fn test_add<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.add(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(0) ; "sub(): 1 - 1 == 0")]
fn test_sub<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.sub(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case(Witness(Fr::from(1)) => -Fr::from(1) ; "neg(): 1 -> -1")]
fn test_neg<F: ScalarField>(a: QuantumCell<F>) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.neg(ctx, a);
    *a.value()
}

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(1) ; "mul(): 1 * 1 == 1")]
fn test_mul<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.mul(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case([1, 1, 1].map(Fr::from).map(Witness) => Fr::from(2) ; "mul_add(): 1 * 1 + 1 == 2")]
fn test_mul_add<F: ScalarField>(inputs: [QuantumCell<F>; 3]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.mul_add(ctx, inputs[0], inputs[1], inputs[2]);
    *a.value()
}

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(0) ; "mul_not(): 1 * 1 == 0")]
fn test_mul_not<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.mul_not(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case(Fr::from(1); "assert_bit(): 1 == bit")]
fn test_assert_bit<F: ScalarField>(input: F) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = ctx.assign_witnesses([input])[0]; 
    chip.assert_bit(ctx, a);
    // auto-tune circuit
    builder.config(6, Some(9));
    // create circuit
    let circuit = GateCircuitBuilder::mock(builder);
    MockProver::run(6, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(1) ; "div_unsafe(): 1 / 1 == 1")]
fn test_div_unsafe<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.div_unsafe(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case([1, 1].map(Fr::from); "assert_is_const()")]
fn test_assert_is_const<F: ScalarField>(inputs: [F; 2]) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = ctx.assign_witnesses([inputs[0]])[0]; 
    chip.assert_is_const(ctx, &a, &inputs[1]);
    // auto-tune circuit
    builder.config(6, Some(9));
    // create circuit
    let circuit = GateCircuitBuilder::mock(builder);
    MockProver::run(6, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case((vec![Witness(Fr::one()); 5], vec![Witness(Fr::one()); 5]) => Fr::from(5) ; "inner_product(): 1 * 1 + ... + 1 * 1 == 5")]
fn test_inner_product<F: ScalarField>(input: (Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.inner_product(ctx, input.0, input.1);
    *a.value()
}

#[test_case((vec![Witness(Fr::one()); 5], vec![Witness(Fr::one()); 5]) => (Fr::from(5), Fr::from(1)); "inner_product_left_last(): 1 * 1 + ... + 1 * 1 == (5, 1)")]
fn test_inner_product_left_last<F: ScalarField>(input: (Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> (F, F) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.inner_product_left_last(ctx, input.0, input.1);
    (*a.0.value(), *a.1.value())
}