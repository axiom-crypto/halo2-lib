use proptest::{prelude::*, collection::vec};
use crate::{gates::tests::{Fr, flex_gate_test, range_gate_test}, utils::ScalarField};
use crate::{QuantumCell, QuantumCell::Witness};

prop_compose! {
    fn rand_fr()(val in any::<u64>()) -> Fr {
        Fr::from(val)
    }
}
prop_compose! {
    fn rand_witness()(val in any::<u64>()) -> QuantumCell<Fr> {
        Witness(Fr::from(val))
    }
}
prop_compose! {
    fn sum_products_with_coeff_and_var_strat(max_length: usize)(val in vec((rand_fr(), rand_witness(), rand_witness()), 1..=max_length), witness in rand_witness()) -> (Vec<(Fr, QuantumCell<Fr>, QuantumCell<Fr>)>, QuantumCell<Fr>) {
        (val, witness)
    }
}

// Ground truth functions

//  Flex Gate Ground Truths

fn add_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() + *inputs[1].value()
}

fn sub_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() - *inputs[1].value()
}

fn neg_ground_truth<F: ScalarField>(input: QuantumCell<F>) -> F {
    -(*input.value())
}

fn mul_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * *inputs[1].value()
}

fn mul_add_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * *inputs[1].value() + *inputs[2].value()
}

fn mul_not_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * (F::one() - *inputs[1].value())
}

fn div_unsafe_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    inputs[0].value().invert().unwrap() * *inputs[1].value()
}

fn inner_product_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> F {
    inputs.0.iter().zip(inputs.1.iter()).fold(F::zero(),|acc, (a, b)| acc + (*a.value() * *b.value()))    
}

fn inner_product_left_last_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> (F, F) {
    let product = inner_product_ground_truth(inputs);
    let last = *inputs.0.last().unwrap().value();
    (product, last)
}

fn inner_product_with_sums_ground_truth<F: ScalarField>(input: &(Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> Vec<F> {
    let (a, b) = &input;
    let mut result = Vec::new();
    let mut sum = F::zero();
    // TODO: convert to fold
    for (ai, bi) in a.iter().zip(b) {
        let product = *ai.value() * *bi.value();
        sum += product;
        result.push(sum);
    }
    result
}

fn sum_products_with_coeff_and_var_ground_truth<F: ScalarField>(input: &(Vec<(F, QuantumCell<F>, QuantumCell<F>)>, QuantumCell<F>)) -> F {
    let expected = input.0.iter().fold(F::zero(), |acc, (coeff, cell1, cell2)| {
        acc + *coeff * *cell1.value() * *cell2.value()
    }) + *input.1.value();
    expected
}

fn and_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * *inputs[1].value()
}

fn not_ground_truth<F: ScalarField>(a: &QuantumCell<F>) -> F {
    F::one() - *a.value()
}

fn select_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    (*inputs[0].value() *  *inputs[2].value()) +  (*inputs[1].value() *( *inputs[2].value() - F::one()))
}

fn or_and_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    let bc_val = *inputs[1].value() * inputs[2].value();
    bc_val + inputs[0].value() - bc_val * inputs[0].value()
}

fn idx_to_indicator_ground_truth<F: ScalarField>(inputs: (QuantumCell<F>, usize)) -> Vec<F> {
    let (idx, size) = inputs;
    let mut indicator = vec![F::zero(); size];
    let mut idx_value = size + 1;
    for i in 0..size as u64 {
        if F::from(i) == *idx.value() {
            idx_value = i as usize;
            break;
        }
    }
    if idx_value < size {
        indicator[idx_value] = F::one();
    }
    indicator
}

fn select_by_indicator_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, QuantumCell<F>)) -> F {
    let mut idx_value = inputs.0.len() + 1;
    let mut indicator = vec![F::zero(); inputs.0.len()];
    for i in 0..inputs.0.len() as u64{
        if F::from(i) == *inputs.1.value() {
            idx_value = i as usize;
            break;
        }
    }
    if idx_value < inputs.0.len() {
        indicator[idx_value] = F::one();
    }
    // take cross product of indicator and inputs.0
    inputs.0.iter().zip(indicator.iter()).fold(F::zero(),|acc, (a, b)| acc + (*a.value() * *b))
}

fn select_from_idx_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, QuantumCell<F>)) -> F {
    let idx = inputs.1.value();
    // Since F does not implement From<u64>, we have to iterate and find the matching index
    for i in 0..inputs.0.len() as u64 {
        if F::from(i) == *idx {
            return *inputs.0[i as usize].value();
        }
    }
    F::zero()
}

fn is_zero_ground_truth<F: ScalarField>(x: F) -> F {
    if x.is_zero().into() { F::one() } else { F::zero() }
}

fn is_equal_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    if inputs[0].value() == inputs[1].value() {
        F::one()
    } else {
        F::zero()
    }
}

fn lagrange_eval_ground_truth<F: ScalarField>(inputs: &[F]) -> (F, F) {
    let x1 = inputs[0];
    let x2 = inputs[1];
    let y1 = inputs[2];
    let quotient = (y1 - x1).invert().unwrap() * (x2 - x1);
    let y2 = quotient * (x2 - x1) + x1;
    (quotient, y2)
}

fn get_field_element_ground_truth<F: ScalarField>(n: u64) -> F {
    F::from(n)
}

// Range Chip Ground Truths

fn is_less_than_ground_truth<F: ScalarField>(inputs: (F, F)) -> F {
    if inputs.0 < inputs.1 {
        F::one()
    } else {
        F::zero()
    }
}

fn is_less_than_safe_ground_truth<F: ScalarField>(inputs: (F, u64)) -> F {
    if inputs.0 < F::from(inputs.1) {
        F::one()
    } else {
        F::zero()
    }
}

fn div_mod_ground_truth<F: ScalarField>(inputs: (F, u64)) -> (F, F) {
    let dividend = inputs.0;
    let divisor = F::from(inputs.1);
    let quotient = dividend.invert().unwrap() * divisor;
    let remainder = dividend - (quotient * divisor);
    (quotient, remainder)
}

fn get_last_bit_ground_truth<F: ScalarField>(inputs: (F, usize)) -> F {
    let bits = inputs.0.to_repr().as_ref()[0] >> (inputs.1 - 1);
    F::from(u64::from(bits & 1))
}

proptest! {

    // Positive tests
    #[test]
    fn prop_test_add(input in vec(rand_witness(), 2)) {
        let ground_truth = add_ground_truth(input.as_slice());
        let result = flex_gate_test::test_add(input.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_sub(input in vec(rand_witness(), 2)) {
        let ground_truth = sub_ground_truth(input.as_slice());
        let result = flex_gate_test::test_sub(input.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_neg(input in rand_witness()) {
        let ground_truth = neg_ground_truth(input);
        let result = flex_gate_test::test_neg(input);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul(inputs in vec(rand_witness(), 2)) {
        let ground_truth = mul_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_mul(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul_add(inputs in vec(rand_witness(), 3)) {
        let ground_truth = mul_add_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_mul_add(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul_not(inputs in vec(rand_witness(), 2)) {
        let ground_truth = mul_not_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_mul_not(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_assert_bit(input in rand_fr()) {
        flex_gate_test::test_assert_bit(input);
    }

    // Note: due to unwrap after inversion this test will fail if the denominator is zero so we want to test for that. Therefore we do not filter for zero values.
    #[test]
    fn prop_test_div_unsafe(inputs in vec(rand_witness(), 2)) {
        let ground_truth = div_unsafe_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_div_unsafe(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_assert_is_const(inputs in vec(rand_fr(), 2)) {
        flex_gate_test::test_assert_is_const(inputs.as_slice());
    }

    #[test]
    fn prop_test_inner_product(inputs in (vec(rand_witness(), 0..=100), vec(rand_witness(), 0..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_ground_truth(&inputs);
        let result = flex_gate_test::test_inner_product(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_inner_product_left_last(inputs in (vec(rand_witness(), 0..=100), vec(rand_witness(), 0..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_left_last_ground_truth(&inputs);
        let result = flex_gate_test::test_inner_product_left_last(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_inner_product_with_sums(inputs in (vec(rand_witness(), 0..=10), vec(rand_witness(), 1..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_with_sums_ground_truth(&inputs);
        let result = flex_gate_test::test_inner_product_with_sums(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_sum_products_with_coeff_and_var(input in sum_products_with_coeff_and_var_strat(100)) {
        let expected = sum_products_with_coeff_and_var_ground_truth(&input);
        let output = flex_gate_test::test_sum_products_with_coeff_and_var(input);
        prop_assert_eq!(expected, output);
    }

    #[test]
    fn prop_test_and(inputs in vec(rand_witness(), 2)) {
        let ground_truth = and_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_and(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_not(input in rand_witness()) {
        let ground_truth = not_ground_truth(&input);
        let result = flex_gate_test::test_not(input);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select(inputs in vec(rand_witness(), 3)) {
        let ground_truth = select_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_select(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_or_and(inputs in vec(rand_witness(), 3)) {
        let ground_truth = or_and_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_or_and(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_idx_to_indicator(input in (rand_witness(), 1..=16_usize)) {
        let ground_truth = idx_to_indicator_ground_truth(input);
        let result = flex_gate_test::test_idx_to_indicator((input.0, input.1));
        prop_assert_eq!(result, ground_truth);
    }
    
    #[test]
    fn prop_test_select_by_indicator(inputs in (vec(rand_witness(), 1..=10), rand_witness())) {
        let ground_truth = select_by_indicator_ground_truth(&inputs);
        let result = flex_gate_test::test_select_by_indicator(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select_from_idx(inputs in (vec(rand_witness(), 1..=10), rand_witness())) {
        let ground_truth = select_from_idx_ground_truth(&inputs);
        let result = flex_gate_test::test_select_from_idx(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_zero(x in rand_fr()) {
        let ground_truth = is_zero_ground_truth(x);
        let result = flex_gate_test::test_is_zero(x);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_equal(inputs in vec(rand_witness(), 2)) {
        let ground_truth = is_equal_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_is_equal(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_lagrange_eval(inputs in vec(rand_fr(), 3)) {
        let ground_truth = lagrange_eval_ground_truth(inputs.as_slice());
        let result = flex_gate_test::test_lagrange_eval(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_get_field_element(n in any::<u64>()) {
        let ground_truth = get_field_element_ground_truth(n);
        let result = flex_gate_test::test_get_field_element::<Fr>(n);
        prop_assert_eq!(result, ground_truth);
    }

    // Range Check Property Tests
    #[test]
    fn prop_test_is_less_than(inputs in (rand_witness(), rand_witness(), 1..=16_usize)) {
        let ground_truth = is_less_than_ground_truth((*inputs.0.value(), *inputs.1.value()));
        let result = range_gate_test::test_is_less_than(([inputs.0, inputs.1], inputs.2));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_less_than_safe(input in (rand_fr(), 0u64..(1 << 16))) {
        let ground_truth = is_less_than_safe_ground_truth((input.0, input.1));
        let result = range_gate_test::test_is_less_than_safe((input.0, input.1));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_div_mod(inputs in (rand_witness(), any::<u64>().prop_filter("Non-zero divisor", |x| *x != 0u64), 1..=16_usize)) {
        let ground_truth = div_mod_ground_truth((*inputs.0.value(), inputs.1));
        let result = range_gate_test::test_div_mod((inputs.0, inputs.1, inputs.2));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_get_last_bit(inputs in (rand_fr(), 1..=16_usize)) {
        let ground_truth = get_last_bit_ground_truth((inputs.0, inputs.1));
        let result = range_gate_test::test_get_last_bit((inputs.0, inputs.1));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_div_mod_var(inputs in (rand_witness(), any::<u64>(), 1..=16_usize, 1..=16_usize)) {
        let ground_truth = div_mod_ground_truth((*inputs.0.value(), inputs.1));
        let result = range_gate_test::test_div_mod_var((inputs.0, Witness(Fr::from(inputs.1)), inputs.2, inputs.3));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_range_check(inputs in (rand_fr(), 1..=16_usize)) {
        range_gate_test::test_range_check((inputs.0, inputs.1));
    }

    #[test]
    fn prop_test_check_less_than(inputs in (rand_witness(), rand_witness(), 1..=16_usize)) {
        range_gate_test::test_check_less_than(([inputs.0, inputs.1], inputs.2));
    }

    #[test]
    fn prop_test_check_less_than_safe(inputs in (rand_fr(), any::<u64>().prop_filter("Non-zero upper bound", |x| *x != 0u64))) {
        range_gate_test::test_check_less_than_safe((inputs.0, inputs.1));
    }

    #[test]
    fn prop_test_check_big_less_than_safe(inputs in (rand_fr(), any::<u64>().prop_filter("Non-zero upper bound", |x| *x != 0u64))) {
        range_gate_test::test_check_big_less_than_safe((inputs.0, inputs.1));
    }
}