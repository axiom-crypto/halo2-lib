use std::env::set_var;

use super::*;
use crate::halo2_proofs::dev::MockProver;
use crate::utils::{biguint_to_fe, ScalarField};
use crate::QuantumCell::Witness;
use crate::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        range::{RangeChip, RangeInstructions},
    },
    utils::BigPrimeField,
    QuantumCell,
};
use num_bigint::BigUint;
use test_case::test_case;

#[test_case(16, 10, Fr::from(100), 8; "range_check() pos")]
pub fn test_range_check<F: ScalarField>(k: usize, lookup_bits: usize, a_val: F, range_bits: usize) {
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(lookup_bits);
    let a = ctx.assign_witnesses([a_val])[0];
    chip.range_check(ctx, a, range_bits);
    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case(12, 10, Witness(Fr::zero()), Witness(Fr::one()), 64; "check_less_than() pos")]
pub fn test_check_less_than<F: ScalarField>(
    k: usize,
    lookup_bits: usize,
    a: QuantumCell<F>,
    b: QuantumCell<F>,
    num_bits: usize,
) {
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(lookup_bits);
    chip.check_less_than(ctx, a, b, num_bits);
    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case(10, 8, Fr::zero(), 1; "check_less_than_safe() pos")]
pub fn test_check_less_than_safe<F: ScalarField>(k: usize, lookup_bits: usize, a_val: F, b: u64) {
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(lookup_bits);
    let a = ctx.assign_witnesses([a_val])[0];
    chip.check_less_than_safe(ctx, a, b);
    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case(10, 8, Fr::zero(), 1; "check_big_less_than_safe() pos")]
pub fn test_check_big_less_than_safe<F: ScalarField + BigPrimeField>(
    k: usize,
    lookup_bits: usize,
    a_val: F,
    b: u64,
) {
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(lookup_bits);
    let a = ctx.assign_witnesses([a_val])[0];
    chip.check_big_less_than_safe(ctx, a, BigUint::from(b));
    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied()
}

#[test_case(([0, 1].map(Fr::from).map(Witness), 3, 12) => Fr::from(1) ; "is_less_than() pos")]
pub fn test_is_less_than<F: ScalarField>(inputs: ([QuantumCell<F>; 2], usize, usize)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(inputs.2);
    let a = chip.is_less_than(ctx, inputs.0[0], inputs.0[1], inputs.1);
    *a.value()
}

#[test_case((Fr::zero(), 3, 3) => Fr::from(1) ; "is_less_than_safe() pos")]
pub fn test_is_less_than_safe<F: ScalarField>(inputs: (F, u64, usize)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(inputs.2);
    let a = ctx.assign_witnesses([inputs.0])[0];
    let b = chip.is_less_than_safe(ctx, a, inputs.1);
    *b.value()
}

#[test_case((biguint_to_fe(&BigUint::from(2u64).pow(252)), BigUint::from(2u64).pow(253) - 1usize, 8) => Fr::from(1) ; "is_big_less_than_safe() pos")]
pub fn test_is_big_less_than_safe<F: ScalarField + BigPrimeField>(
    (a, b, lookup_bits): (F, BigUint, usize),
) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(lookup_bits);
    let a = ctx.load_witness(a);
    let b = chip.is_big_less_than_safe(ctx, a, b);
    *b.value()
}

#[test_case((Witness(Fr::one()), 1, 2) => (Fr::one(), Fr::zero()) ; "div_mod() pos")]
pub fn test_div_mod<F: ScalarField + BigPrimeField>(
    inputs: (QuantumCell<F>, u64, usize),
) -> (F, F) {
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

#[test_case((Witness(Fr::from(3)), Witness(Fr::from(2)), 3, 3) => (Fr::one(), Fr::one()) ; "div_mod_var() pos")]
pub fn test_div_mod_var<F: ScalarField + BigPrimeField>(
    inputs: (QuantumCell<F>, QuantumCell<F>, usize, usize),
) -> (F, F) {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = chip.div_mod_var(ctx, inputs.0, inputs.1, inputs.2, inputs.3);
    (*a.0.value(), *a.1.value())
}
