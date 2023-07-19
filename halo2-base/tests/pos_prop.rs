use halo2_base::utils::{bit_length, fe_to_biguint};
use halo2_base::{QuantumCell, QuantumCell::Witness};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use proptest::{collection::vec, prelude::*};

mod flex_gate;
mod range_gate;
mod common;

use common::utils::*;

//TODO: implement Copy for rand witness and rand fr to allow for array creation
//  create vec and convert to array???
//TODO: implement arbitrary for fr using looks like you'd probably need to implement your own TestFr struct to implement Arbitrary: https://docs.rs/quickcheck/latest/quickcheck/trait.Arbitrary.html , can probably just hack it from Fr = [u64; 4]
prop_compose! {
    pub fn rand_fr()(val in any::<u64>()) -> Fr {
        Fr::from(val)
    }
}

prop_compose! {
    pub fn rand_witness()(val in any::<u64>()) -> QuantumCell<Fr> {
        Witness(Fr::from(val))
    }
}

prop_compose! {
    pub fn sum_products_with_coeff_and_var_strat(max_length: usize)(val in vec((rand_fr(), rand_witness(), rand_witness()), 1..=max_length), witness in rand_witness()) -> (Vec<(Fr, QuantumCell<Fr>, QuantumCell<Fr>)>, QuantumCell<Fr>) {
        (val, witness)
    }
}

prop_compose! {
    pub fn rand_bin_witness()(val in prop::sample::select(vec![Fr::zero(), Fr::one()])) -> QuantumCell<Fr> {
        Witness(val)
    }
}

prop_compose! {
    pub fn rand_fr_range(lo: u32, hi: u32)(val in any::<u64>().prop_map(move |x| x % 2u64.pow(hi - lo))) -> Fr {
        Fr::from(val)
    }
}

prop_compose! {
    pub fn rand_witness_range(lo: u32, hi: u32)(val in any::<u64>().prop_map(move |x| x % 2u64.pow(hi - lo))) -> QuantumCell<Fr> {
        Witness(Fr::from(val))
    }
}

// LEsson here 0..2^range_bits fails with 'Uniform::new called with `low >= high`
// therfore to still have a range of 0..2^range_bits we need on a mod it by 2^range_bits
// note k > lookup_bits
prop_compose! {
    fn range_check_strat((k_lo, k_hi): (usize, usize), min_lookup_bits: usize, max_range_bits: u32)
    (range_bits in 2..=max_range_bits, k in k_lo..=k_hi)
    (k in Just(k), lookup_bits in min_lookup_bits..(k-3), a in rand_fr_range(0, range_bits),
    range_bits in Just(range_bits))
    -> (usize, usize, Fr, usize) {
        (k, lookup_bits, a, range_bits as usize)
    }
}

prop_compose! {
    fn check_less_than_strat((k_lo, k_hi): (usize, usize), min_lookup_bits: usize, max_num_bits: usize)
    (num_bits in 2..max_num_bits, k in k_lo..=k_hi)
    (k in Just(k), a in rand_witness_range(0, num_bits as u32), b in rand_witness_range(0, num_bits as u32),
    num_bits in Just(num_bits), lookup_bits in min_lookup_bits..k)
    -> (usize, usize, QuantumCell<Fr>, QuantumCell<Fr>, usize) {
        (k, lookup_bits, a, b, num_bits)
    }
}

prop_compose! {
    fn check_less_than_safe_strat((k_lo, k_hi): (usize, usize), min_lookup_bits: usize)
    (k in k_lo..=k_hi)
    (k in Just(k), b in any::<u64>(), a in rand_fr(), lookup_bits in min_lookup_bits..k)
    -> (usize, usize, Fr, u64) {
        (k, lookup_bits, a, b)
    }
}

proptest! {

    // Flex Gate Positive Tests
    #[test]
    fn prop_test_add(input in vec(rand_witness(), 2)) {
        let ground_truth = add_ground_truth(input.as_slice());
        let result = flex_gate::test_add(input.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_sub(input in vec(rand_witness(), 2)) {
        let ground_truth = sub_ground_truth(input.as_slice());
        let result = flex_gate::test_sub(input.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_neg(input in rand_witness()) {
        let ground_truth = neg_ground_truth(input);
        let result = flex_gate::test_neg(input);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul(inputs in vec(rand_witness(), 2)) {
        let ground_truth = mul_ground_truth(inputs.as_slice());
        let result = flex_gate::test_mul(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul_add(inputs in vec(rand_witness(), 3)) {
        let ground_truth = mul_add_ground_truth(inputs.as_slice());
        let result = flex_gate::test_mul_add(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_mul_not(inputs in vec(rand_witness(), 2)) {
        let ground_truth = mul_not_ground_truth(inputs.as_slice());
        let result = flex_gate::test_mul_not(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_assert_bit(input in rand_fr()) {
        let ground_truth = input == Fr::one() || input == Fr::zero();
        let result = flex_gate::test_assert_bit(input).is_ok();
        prop_assert_eq!(result, ground_truth);
    }

    // Note: due to unwrap after inversion this test will fail if the denominator is zero so we want to test for that. Therefore we do not filter for zero values.
    #[test]
    fn prop_test_div_unsafe(inputs in vec(rand_witness().prop_filter("Input cannot be 0",|x| *x.value() != Fr::zero()), 2)) {
        let ground_truth = div_unsafe_ground_truth(inputs.as_slice());
        let result = flex_gate::test_div_unsafe(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_assert_is_const(input in rand_fr()) {
        flex_gate::test_assert_is_const(&[input; 2]);
    }

    #[test]
    fn prop_test_inner_product(inputs in (vec(rand_witness(), 0..=100), vec(rand_witness(), 0..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_ground_truth(&inputs);
        let result = flex_gate::test_inner_product(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_inner_product_left_last(inputs in (vec(rand_witness(), 1..=100), vec(rand_witness(), 1..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_left_last_ground_truth(&inputs);
        let result = flex_gate::test_inner_product_left_last(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_inner_product_with_sums(inputs in (vec(rand_witness(), 0..=10), vec(rand_witness(), 1..=100)).prop_filter("Input vectors must have equal length", |(a, b)| a.len() == b.len())) {
        let ground_truth = inner_product_with_sums_ground_truth(&inputs);
        let result = flex_gate::test_inner_product_with_sums(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_sum_products_with_coeff_and_var(input in sum_products_with_coeff_and_var_strat(100)) {
        let expected = sum_products_with_coeff_and_var_ground_truth(&input);
        let output = flex_gate::test_sum_products_with_coeff_and_var(input);
        prop_assert_eq!(expected, output);
    }

    #[test]
    fn prop_test_and(inputs in vec(rand_witness(), 2)) {
        let ground_truth = and_ground_truth(inputs.as_slice());
        let result = flex_gate::test_and(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_not(input in rand_witness()) {
        let ground_truth = not_ground_truth(&input);
        let result = flex_gate::test_not(input);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select(vals in vec(rand_witness(), 2), sel in rand_bin_witness()) {
        let inputs = vec![vals[0], vals[1], sel];
        let ground_truth = select_ground_truth(inputs.as_slice());
        let result = flex_gate::test_select(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_or_and(inputs in vec(rand_witness(), 3)) {
        let ground_truth = or_and_ground_truth(inputs.as_slice());
        let result = flex_gate::test_or_and(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_idx_to_indicator(input in (rand_witness(), 1..=16_usize)) {
        let ground_truth = idx_to_indicator_ground_truth(input);
        let result = flex_gate::test_idx_to_indicator((input.0, input.1));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select_by_indicator(inputs in (vec(rand_witness(), 1..=10), rand_witness())) {
        let ground_truth = select_by_indicator_ground_truth(&inputs);
        let result = flex_gate::test_select_by_indicator(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_select_from_idx(inputs in (vec(rand_witness(), 1..=10), rand_witness())) {
        let ground_truth = select_from_idx_ground_truth(&inputs);
        let result = flex_gate::test_select_from_idx(inputs);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_zero(x in rand_fr()) {
        let ground_truth = is_zero_ground_truth(x);
        let result = flex_gate::test_is_zero(x);
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_equal(inputs in vec(rand_witness(), 2)) {
        let ground_truth = is_equal_ground_truth(inputs.as_slice());
        let result = flex_gate::test_is_equal(inputs.as_slice());
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_num_to_bits(num in any::<u64>()) {
        let mut tmp = num;
        let mut bits = vec![];
        if num == 0 {
            bits.push(0);
        }
        while tmp > 0 {
            bits.push(tmp & 1);
            tmp /= 2;
        }
        let result = flex_gate::test_num_to_bits((Fr::from(num), bits.len()));
        prop_assert_eq!(bits.into_iter().map(Fr::from).collect::<Vec<_>>(), result);
    }

    /*
    #[test]
    fn prop_test_lagrange_eval(inputs in vec(rand_fr(), 3)) {
    }
    */

    #[test]
    fn prop_test_get_field_element(n in any::<u64>()) {
        let ground_truth = get_field_element_ground_truth(n);
        let result = flex_gate::test_get_field_element::<Fr>(n);
        prop_assert_eq!(result, ground_truth);
    }

    // Range Check Property Tests

    #[test]
    fn prop_test_is_less_than(a in rand_witness(), b in any::<u64>().prop_filter("not zero", |&x| x != 0),
    lookup_bits in 4..=16_usize) {
        let bits = std::cmp::max(fe_to_biguint(a.value()).bits() as usize, bit_length(b));
        let ground_truth = is_less_than_ground_truth((*a.value(), Fr::from(b)));
        let result = range_gate::test_is_less_than(([a, Witness(Fr::from(b))], bits, lookup_bits));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_is_less_than_safe(a in rand_fr().prop_filter("not zero", |&x| x != Fr::zero()),
    b in any::<u64>().prop_filter("not zero", |&x| x != 0),
    lookup_bits in 4..=16_usize) {
        prop_assume!(fe_to_biguint(&a).bits() as usize <= bit_length(b));
        let ground_truth = is_less_than_ground_truth((a, Fr::from(b)));
        let result = range_gate::test_is_less_than_safe((a, b, lookup_bits));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_div_mod(inputs in (rand_witness().prop_filter("Non-zero num", |x| *x.value() != Fr::zero()), any::<u64>().prop_filter("Non-zero divisor", |x| *x != 0u64), 1..=16_usize)) {
        let ground_truth = div_mod_ground_truth((*inputs.0.value(), inputs.1));
        let result = range_gate::test_div_mod((inputs.0, inputs.1, inputs.2));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_get_last_bit(input in rand_fr(), pad_bits in 0..10usize) {
        let ground_truth = get_last_bit_ground_truth(input);
        let bits = fe_to_biguint(&input).bits() as usize + pad_bits;
        let result = range_gate::test_get_last_bit((input, bits));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_div_mod_var(inputs in (rand_witness(), any::<u64>(), 1..=16_usize, 1..=16_usize)) {
        let ground_truth = div_mod_ground_truth((*inputs.0.value(), inputs.1));
        let result = range_gate::test_div_mod_var((inputs.0, Witness(Fr::from(inputs.1)), inputs.2, inputs.3));
        prop_assert_eq!(result, ground_truth);
    }

    #[test]
    fn prop_test_range_check((k, lookup_bits, a, range_bits) in range_check_strat((14,24), 3, 63)) {
        prop_assert_eq!(range_gate::test_range_check(k, lookup_bits, a, range_bits), ());
    }

    #[test]
    fn prop_test_check_less_than((k, lookup_bits, a, b, num_bits) in check_less_than_strat((14,24), 3, 10)) {
        prop_assume!(a.value() < b.value());
        prop_assert_eq!(range_gate::test_check_less_than(k, lookup_bits, a, b, num_bits), ());
    }

    #[test]
    fn prop_test_check_less_than_safe((k, lookup_bits, a, b) in check_less_than_safe_strat((12,24),3)) {
        prop_assume!(a < Fr::from(b));
        prop_assert_eq!(range_gate::test_check_less_than_safe(k, lookup_bits, a, b), ());
    }

    #[test]
    fn prop_test_check_big_less_than_safe((k, lookup_bits, a, b) in check_less_than_safe_strat((12,24),3)) {
        prop_assume!(a < Fr::from(b));
        prop_assert_eq!(range_gate::test_check_big_less_than_safe(k, lookup_bits, a, b), ());
    }
}
