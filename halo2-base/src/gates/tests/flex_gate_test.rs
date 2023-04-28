use super::*;
use crate::{gates::{
    builder::{GateCircuitBuilder,GateThreadBuilder},
    flex_gate::{GateChip, GateInstructions},
}, QuantumCell};
use crate::halo2_proofs::dev::MockProver;
use crate::utils::ScalarField;
use crate::QuantumCell::Witness;
use test_case::test_case;

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(2) ; "add(): 1 + 1 = 2")]
fn test_add<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.add(ctx, inputs[0], inputs[1]);
    *a.value()
}
