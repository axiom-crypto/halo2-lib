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