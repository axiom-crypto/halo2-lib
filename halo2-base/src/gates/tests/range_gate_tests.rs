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
pub fn test_range_check<F: ScalarField>(inputs: (F, usize)) {
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
pub fn test_check_less_than<F: ScalarField>(inputs: ([QuantumCell<F>; 2], usize)) {
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
pub fn test_check_less_than_safe<F: ScalarField>(inputs: (F, u64)) {
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
pub fn test_check_big_less_than_safe<F: ScalarField + BigPrimeField>(inputs: (F, u64)) {
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
// Failing case
#[test_case(([5102093178976689982, 5102015491250118463].map(Fr::from).map(Witness), 1) => Fr::from(1) ; "failing_case_1_bit() pos")]
#[test_case(([5102093178976689982, 5102015491250118463].map(Fr::from).map(Witness), 16) => Fr::from(0) ; "failing_case_16_bit() pos")]
#[test_case(([5102093178976689982, 5102015491250118463].map(Fr::from).map(Witness), 61) => Fr::from(0) ; "failing_case_61_bits() pos")]
#[test_case(([5102093178976689982, 5102015491250118463].map(Fr::from).map(Witness), 50) => Fr::from(0) ; "failing_case_50_bits() pos")]
// Failing case
#[test_case(([1300436882932358974, 1311097767942152000].map(Fr::from).map(Witness),25) => Fr::from(0) ; "failing_case_25_bits() pos")]
#[test_case(([1300436882932358974, 1311097767942152000].map(Fr::from).map(Witness),32) => Fr::from(1) ; "failing_case_32_bits() pos")]
#[test_case(([1300436882932358974, 1311097767942152000].map(Fr::from).map(Witness), 62) => Fr::from(1) ; "failing_case_62_bits() pos")]
pub fn test_is_less_than<F: ScalarField>(inputs: ([QuantumCell<F>; 2], usize)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = chip.is_less_than(ctx, inputs.0[0], inputs.0[1], inputs.1);
    *a.value()
}

#[test_case((Fr::zero(), 3) => Fr::from(1) ; "is_less_than_safe() pos")]
pub fn test_is_less_than_safe<F: ScalarField>(inputs: (F, u64)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    let b = chip.is_less_than_safe(ctx, a, inputs.1);
    *b.value()
}

#[test_case((Fr::zero(), 3) => Fr::from(1) ; "is_big_less_than_safe() pos")]
pub fn test_is_big_less_than_safe<F: ScalarField + BigPrimeField>(inputs: (F, u64)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip= RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    let b = chip.is_big_less_than_safe(ctx, a, BigUint::from(inputs.1));
    *b.value()
}

#[test_case((Witness(Fr::one()), 1, 2) => (Fr::one(), Fr::zero()) ; "div_mod() pos")]
pub fn test_div_mod<F: ScalarField + BigPrimeField>(inputs: (QuantumCell<F>, u64, usize)) -> (F, F) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = chip.div_mod(ctx, inputs.0, BigUint::from(inputs.1), inputs.2);
    (*a.0.value(), *a.1.value())
}

#[test_case((Fr::from(6), 4) => Fr::one() ; "get_last_bit() pos")]
pub fn test_get_last_bit<F: ScalarField>(inputs: (F, usize)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    let b = chip.get_last_bit(ctx, a, inputs.1);
    *b.value()
}

// TODO: fix test currently fails during final range check due to `attempt to subtract with oveflow` w/ k = 0;
#[test_case((Witness(Fr::one()), Witness(Fr::from(2)), 3, 3) => (Fr::zero(), Fr::one()) ; "div_mod_var() pos")]
pub fn test_div_mod_var<F: ScalarField + BigPrimeField>(inputs: (QuantumCell<F>, QuantumCell<F>, usize, usize)) -> (F, F) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = chip.div_mod_var(ctx, inputs.0, inputs.1, inputs.2, inputs.3);
    (*a.0.value(), *a.1.value())
}