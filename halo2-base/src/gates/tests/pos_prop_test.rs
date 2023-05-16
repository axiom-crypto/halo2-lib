use proptest::{prelude::*, collection::vec};
use crate::gates::tests::{Fr, flex_gate_tests, range_gate_tests, test_ground_truths::*};
use crate::{QuantumCell, QuantumCell::Witness};

//TODO: implement Copy for rand witness and rand fr to allow for array creation
//  create vec and convert to array???
//TODO: implement arbitrary for fr using looks like you'd probably need to implement your own TestFr struct to implement Arbitrary: https://docs.rs/quickcheck/latest/quickcheck/trait.Arbitrary.html , can probably just hack it from Fr = [u64; 4]
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

prop_compose! {
    fn rand_bin_witness()(val in prop::sample::select(vec![Fr::zero(), Fr::one()])) -> QuantumCell<Fr> {
        Witness(val)
    }
}

proptest! {

    // Flex Gate Positive Tests
    #[test]
    fn prop_test_add(input in vec(rand_witness(), 2)) {
        let ground_truth = add_ground_truth(input.as_slice());
        let result = flex_gate_tests::test_add(input.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_sub(input in vec(rand_witness(), 2)) {
        let ground_truth = sub_ground_truth(input.as_slice());
        let result = flex_gate_tests::test_sub(input.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_neg(input in rand_witness()) {
        let ground_truth = neg_ground_truth(input);
        let result = flex_gate_tests::test_neg(input);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul(inputs in vec(rand_witness(), 2)) {
        let ground_truth = mul_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_mul(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul_add(inputs in vec(rand_witness(), 3)) {
        let ground_truth = mul_add_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_mul_add(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul_not(inputs in vec(rand_witness(), 2)) {
        let ground_truth = mul_not_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_mul_not(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    // TODO: Notes could be a better way of doing this
    #[test]
    fn prop_test_assert_bit(input in rand_fr()) {
        let ground_truth = if input == Fr::one() || input == Fr::zero() { true } else { false };
        let result = match flex_gate_tests::test_assert_bit(input) {
            Ok(_) => true,
            Err(_) => false
        };
        prop_assert_eq!(result, ground_truth);
    }

    // Note: due to unwrap after inversion this test will fail if the denominator is zero so we want to test for that. Therefore we do not filter for zero values.
    #[test]
    fn prop_test_div_unsafe(inputs in vec(rand_witness().prop_filter("Input cannot be 0",|x| *x.value() != Fr::zero()), 2)) {
        let ground_truth = div_unsafe_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_div_unsafe(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_assert_is_const(input in rand_fr()) {
        flex_gate_tests::test_assert_is_const(&[input; 2]);
    }

    #[test]
    fn prop_test_inner_product(inputs in (vec(rand_witness(), 0..=100), vec(rand_witness(), 0..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_ground_truth(&inputs);
        let result = flex_gate_tests::test_inner_product(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_inner_product_left_last(inputs in (vec(rand_witness(), 0..=100), vec(rand_witness(), 0..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_left_last_ground_truth(&inputs);
        let result = flex_gate_tests::test_inner_product_left_last(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_inner_product_with_sums(inputs in (vec(rand_witness(), 0..=10), vec(rand_witness(), 1..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_with_sums_ground_truth(&inputs);
        let result = flex_gate_tests::test_inner_product_with_sums(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_sum_products_with_coeff_and_var(input in sum_products_with_coeff_and_var_strat(100)) {
        let expected = sum_products_with_coeff_and_var_ground_truth(&input);
        let output = flex_gate_tests::test_sum_products_with_coeff_and_var(input);
        prop_assert_eq!(expected, output);
    }

    #[test]
    fn prop_test_and(inputs in vec(rand_witness(), 2)) {
        let ground_truth = and_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_and(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_not(input in rand_witness()) {
        let ground_truth = not_ground_truth(&input);
        let result = flex_gate_tests::test_not(input);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select(vals in vec(rand_witness(), 2), sel in rand_bin_witness()) {
        let inputs = vec![vals[0], vals[1], sel];
        let ground_truth = select_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_select(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_or_and(inputs in vec(rand_witness(), 3)) {
        let ground_truth = or_and_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_or_and(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_idx_to_indicator(input in (rand_witness(), 1..=16_usize)) {
        let ground_truth = idx_to_indicator_ground_truth(input);
        let result = flex_gate_tests::test_idx_to_indicator((input.0, input.1));
        prop_assert_eq!(result, ground_truth);
    }
    
    #[test]
    fn prop_test_select_by_indicator(inputs in (vec(rand_witness(), 1..=10), rand_witness())) {
        let ground_truth = select_by_indicator_ground_truth(&inputs);
        let result = flex_gate_tests::test_select_by_indicator(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select_from_idx(inputs in (vec(rand_witness(), 1..=10), rand_witness())) {
        let ground_truth = select_from_idx_ground_truth(&inputs);
        let result = flex_gate_tests::test_select_from_idx(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_zero(x in rand_fr()) {
        let ground_truth = is_zero_ground_truth(x);
        let result = flex_gate_tests::test_is_zero(x);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_equal(inputs in vec(rand_witness(), 2)) {
        let ground_truth = is_equal_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_is_equal(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_lagrange_eval(inputs in vec(rand_fr(), 3)) {
        let ground_truth = lagrange_eval_ground_truth(inputs.as_slice());
        let result = flex_gate_tests::test_lagrange_eval(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_get_field_element(n in any::<u64>()) {
        let ground_truth = get_field_element_ground_truth(n);
        let result = flex_gate_tests::test_get_field_element::<Fr>(n);
        prop_assert_eq!(result, ground_truth);
    }

    // Range Check Property Tests
    #[test]
    fn prop_test_is_less_than(inputs in (rand_witness(), rand_witness(), 16..=32_usize)) {
        println!("a: {:?}, b: {:?}", inputs.0.value(), inputs.1.value());
        let ground_truth = is_less_than_ground_truth((*inputs.0.value(), *inputs.1.value()));
        let result = range_gate_tests::test_is_less_than(([inputs.0, inputs.1], inputs.2));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_less_than_safe(input in (rand_fr(), 0u64..(1 << 16))) {
        let ground_truth = is_less_than_ground_truth((input.0, Fr::from(input.1)));
        let result = range_gate_tests::test_is_less_than_safe((input.0, input.1));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_div_mod(inputs in (rand_witness().prop_filter("Non-zero num", |x| *x.value() != Fr::zero()), any::<u64>().prop_filter("Non-zero divisor", |x| *x != 0u64), 1..=16_usize)) {
        let ground_truth = div_mod_ground_truth((*inputs.0.value(), inputs.1));
        let result = range_gate_tests::test_div_mod((inputs.0, inputs.1, inputs.2));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_get_last_bit(inputs in (rand_fr().prop_filter("can't be 0", |x| *x != Fr::zero()), 1..=32_usize)) {
        let ground_truth = get_last_bit_ground_truth(inputs.0);
        let result = range_gate_tests::test_get_last_bit((inputs.0, inputs.1));
        println!("result: {:?}, ground_truth: {:?}", result, ground_truth);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_div_mod_var(inputs in (rand_witness(), any::<u64>(), 1..=16_usize, 1..=16_usize)) {
        let ground_truth = div_mod_ground_truth((*inputs.0.value(), inputs.1));
        let result = range_gate_tests::test_div_mod_var((inputs.0, Witness(Fr::from(inputs.1)), inputs.2, inputs.3));
        prop_assert_eq!(result, ground_truth);
    }

    // TODO change to ground truth
    #[test]
    fn prop_test_range_check(inputs in (rand_fr(), any::<usize>().prop_filter("Non-zero upper bound", |x| *x != 0usize))) {
        prop_assert_eq!(range_gate_tests::test_range_check((inputs.0, inputs.1)), ());
    }

    #[test]
    fn prop_test_check_less_than(inputs in (rand_witness(), rand_witness(), any::<usize>().prop_filter("Non-zero upper bound", |x| *x != 0usize))) {
        prop_assert_eq!(range_gate_tests::test_check_less_than(([inputs.0, inputs.1], inputs.2)), ());
    }

    #[test]
    fn prop_test_check_less_than_safe(inputs in (rand_fr(), any::<u64>().prop_filter("Non-zero upper bound", |x| *x != 0u64))) {
        prop_assert_eq!(range_gate_tests::test_check_less_than_safe((inputs.0, inputs.1)), ());
    }

    #[test]
    fn prop_test_check_big_less_than_safe(inputs in (rand_fr(), any::<u64>().prop_filter("Non-zero upper bound", |x| *x != 0u64))) {
        prop_assert_eq!(range_gate_tests::test_check_big_less_than_safe((inputs.0, inputs.1)), ());
    }
}