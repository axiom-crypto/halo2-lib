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

#[test_case((vec![Witness(Fr::one()); 5], vec![Witness(Fr::one()); 5]) => vec![Fr::one(), Fr::from(2), Fr::from(3), Fr::from(4), Fr::from(5)]; "inner_product_with_sums(): 1 * 1 + ... + 1 * 1 == [1, 2, 3, 4, 5]")]
fn test_inner_product_with_sums<F: ScalarField>(input: (Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> Vec<F> {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.inner_product_with_sums(ctx, input.0, input.1);
    a.into_iter().map(|x| *x.value()).collect()
}

#[test_case((vec![(Fr::from(1), Witness(Fr::from(1)), Witness(Fr::from(1)))], Witness(Fr::from(1))) => Fr::from(2) ; "sum_product_with_coeff_and_var(): 1 * 1 + 1 == 2")]
fn test_sum_products_with_coeff_and_var<F: ScalarField>(input: (Vec<(F, QuantumCell<F>, QuantumCell<F>)>, QuantumCell<F>)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.sum_products_with_coeff_and_var(ctx, input.0, input.1);
    *a.value()
}

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::from(1) ; "and(): 1 && 1 == 1")]
fn test_and<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.and(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case(Witness(Fr::from(1)) => Fr::zero() ; "not(): !1 == 0")]
fn test_not<F: ScalarField>(a: QuantumCell<F>) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.not(ctx, a);
    *a.value()
}

//todo: add neg test
#[test_case([2, 3, 1].map(Fr::from).map(Witness) => Fr::from(2) ; "select(): 2 ? 3 : 1 == 2")]
fn test_select<F: ScalarField>(inputs: [QuantumCell<F>; 3]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.select(ctx, inputs[0], inputs[1], inputs[2]);
    *a.value()
}

#[test_case([1, 1, 1].map(Fr::from).map(Witness) => Fr::from(1) ; "or_and(): 1 || 1 && 1 == 1")]
fn test_or_and<F: ScalarField>(inputs: [QuantumCell<F>; 3]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.or_and(ctx, inputs[0], inputs[1], inputs[2]);
    *a.value()
}

#[test_case(Fr::zero() => vec![Fr::one(), Fr::zero()]; "bits_to_indicator(): 0 -> [1, 0]")]
fn test_bits_to_indicator<F: ScalarField>(bits: F) -> Vec<F> {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = ctx.assign_witnesses([bits])[0]; 
    let a = chip.bits_to_indicator(ctx, &[a]);
    a.iter().map(|x| *x.value()).collect()
}

#[test_case((Witness(Fr::zero()), 3) => vec![Fr::one(), Fr::zero(), Fr::zero()] ; "idx_to_indicator(): 0 -> [1, 0, 0]")]
fn test_idx_to_indicator<F: ScalarField>(input: (QuantumCell<F>, usize)) -> Vec<F> {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.idx_to_indicator(ctx, input.0, input.1);
    a.iter().map(|x| *x.value()).collect()
}

#[test_case((vec![Witness(Fr::zero()), Witness(Fr::one()), Witness(Fr::from(2))], Witness(Fr::one())) => Fr::from(1) ; "select_by_indicator(): [0, 1, 2] -> 1")]
fn test_select_by_indicator<F: ScalarField>(input: (Vec<QuantumCell<F>>, QuantumCell<F>)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.idx_to_indicator(ctx, input.1, input.0.len());
    let a = chip.select_by_indicator(ctx, input.0, a);
    *a.value()
}

#[test_case((vec![Witness(Fr::zero()), Witness(Fr::one()), Witness(Fr::from(2))], Witness(Fr::one())) => Fr::from(1) ; "select_from_idx(): [0, 1, 2] -> 1")]
fn test_select_from_idx<F: ScalarField>(input: (Vec<QuantumCell<F>>, QuantumCell<F>)) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.idx_to_indicator(ctx, input.1, input.0.len());
    let a = chip.select_by_indicator(ctx, input.0, a);
    *a.value()
}

#[test_case(Fr::zero() => Fr::from(1) ; "is_zero(): 0 -> 1")]
fn test_is_zero<F: ScalarField>(x: F) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = ctx.assign_witnesses([x])[0]; 
    let a = chip.is_zero(ctx, a);
    *a.value()
}

#[test_case([1, 1].map(Fr::from).map(Witness) => Fr::one() ; "is_equal(): 1 == 1")]
fn test_is_equal<F: ScalarField>(inputs: [QuantumCell<F>; 2]) -> F {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = chip.is_equal(ctx, inputs[0], inputs[1]);
    *a.value()
}

#[test_case((Fr::one(), 2) => vec![Fr::one(), Fr::zero()] ; "num_to_bits(): 1 -> [1, 0]")]
fn test_num_to_bits<F: ScalarField>(input: (F, usize)) -> Vec<F> {
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = GateChip::default();
    let a = ctx.assign_witnesses([input.0])[0]; 
    let a = chip.num_to_bits(ctx, a, input.1);
    a.iter().map(|x| *x.value()).collect()
}