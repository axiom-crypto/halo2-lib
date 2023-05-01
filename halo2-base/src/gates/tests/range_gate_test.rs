use super::*;
use crate::{gates::{
    builder::{RangeCircuitBuilder,GateThreadBuilder},
    range::{RangeChip, RangeInstructions},
}, QuantumCell, utils::BigPrimeField};
use crate::halo2_proofs::dev::MockProver;
use crate::utils::ScalarField;
use crate::QuantumCell::Witness;
use num_bigint::BigUint;
use test_case::test_case;

#[test_case((Fr::from(100), 8); "range_check() pos")]
fn test_range_check<F: ScalarField>(inputs: (F, usize)) {
    std::env::set_var("LOOKUP_BITS", "3".to_string());
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    chip.range_check(ctx, a, inputs.1);
    // auto-tune circuit
    builder.config(11, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(11 as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case(([0, 1].map(Fr::from).map(Witness), 64) ; "check_less_than() pos")]
fn test_check_less_than<F: ScalarField>(inputs: ([QuantumCell<F>; 2], usize)) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    chip.check_less_than(ctx, inputs.0[0], inputs.0[1], inputs.1);
    // auto-tune circuit
    builder.config(11, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(11 as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case((Fr::zero(), 1); "check_less_than_safe() pos")]
fn test_check_less_than_safe<F: ScalarField>(inputs: (F, u64)) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    chip.check_less_than_safe(ctx, a, inputs.1);
    // auto-tune circuit
    builder.config(11, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(11 as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case((Fr::zero(), 1); "check_big_less_than_safe() pos")]
fn test_check_big_less_than_safe<F: ScalarField + BigPrimeField>(inputs: (F, u64)) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    chip.check_big_less_than_safe(ctx, a, BigUint::from(inputs.1));
    // auto-tune circuit
    builder.config(11, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(11 as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case(([0, 1].map(Fr::from).map(Witness), 3) => Fr::from(1) ; "is_less_than() pos")]
fn test_is_less_than<F: ScalarField>(inputs: ([QuantumCell<F>; 2], usize)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = chip.is_less_than(ctx, inputs.0[0], inputs.0[1], inputs.1);
    *a.value()
}