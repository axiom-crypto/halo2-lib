use std::env::set_var;

use ff::Field;
use itertools::Itertools;
use num_bigint::BigUint;
use proptest::{collection::vec, prelude::*};
use rand::rngs::OsRng;

use halo2_base::halo2_proofs::{
    dev::MockProver,
    halo2curves::{bn256::Fr, FieldExt},
    plonk::Assigned,
};
use halo2_base::{
    gates::{
        builder::{GateCircuitBuilder, GateThreadBuilder, RangeCircuitBuilder},
        range::{RangeChip, RangeInstructions},
        GateChip, GateInstructions,
    },
    utils::{biguint_to_fe, bit_length, fe_to_biguint, ScalarField},
    QuantumCell,
    QuantumCell::Witness,
};

mod common;
use common::rand::{rand_bin_witness, rand_fr, rand_witness};
use common::utils;

// Strategies for generating random witnesses
prop_compose! {
    // length == 1 is just selecting [0] which should be covered in unit test
    fn idx_to_indicator_strat(k_bounds: (usize, usize), max_size: usize)
        (k in k_bounds.0..=k_bounds.1, idx_val in prop::sample::select(vec![Fr::zero(), Fr::one(), Fr::random(OsRng)]), len in 2usize..=max_size)
        (k in Just(k), idx in 0..len, idx_val in Just(idx_val), len in Just(len), mut witness_vals in arb_indicator::<Fr>(len))
        -> (usize, usize, usize, Vec<Fr>) {
        witness_vals[idx] = idx_val;
        (k, len, idx, witness_vals)
    }
}

prop_compose! {
    fn select_strat(k_bounds: (usize, usize))
    (k in k_bounds.0..=k_bounds.1,  a in rand_witness(), b in rand_witness(), sel in rand_bin_witness(), rand_output in rand_fr())
    -> (usize, QuantumCell<Fr>, QuantumCell<Fr>, QuantumCell<Fr>, Fr) {
        (k, a, b, sel, rand_output)
    }
}

prop_compose! {
    fn select_by_indicator_strat(k_bounds: (usize, usize), max_size: usize)
    (k in k_bounds.0..=k_bounds.1, len in 2usize..=max_size)
    (k in Just(k), a in vec(rand_witness(), len), idx in 0..len, rand_output in rand_fr())
    -> (usize, Vec<QuantumCell<Fr>>, usize, Fr) {
        (k, a, idx, rand_output)
    }
}

prop_compose! {
    fn select_from_idx_strat(k_bounds: (usize, usize), max_size: usize)
    (k in k_bounds.0..=k_bounds.1, len in 2usize..=max_size)
    (k in Just(k), cells in vec(rand_witness(), len), idx in 0..len, rand_output in rand_fr())
    -> (usize, Vec<QuantumCell<Fr>>, usize, Fr) {
        (k, cells, idx, rand_output)
    }
}

prop_compose! {
    fn inner_product_strat(k_bounds: (usize, usize), max_size: usize)
    (k in k_bounds.0..=k_bounds.1, len in 2usize..=max_size)
    (k in Just(k), a in vec(rand_witness(), len), b in vec(rand_witness(), len), rand_output in rand_fr())
    -> (usize, Vec<QuantumCell<Fr>>, Vec<QuantumCell<Fr>>, Fr) {
        (k, a, b, rand_output)
    }
}

prop_compose! {
    fn inner_product_left_last_strat(k_bounds: (usize, usize), max_size: usize)
    (k in k_bounds.0..=k_bounds.1, len in 2usize..=max_size)
    (k in Just(k), a in vec(rand_witness(), len), b in vec(rand_witness(), len), rand_output in (rand_fr(), rand_fr()))
    -> (usize, Vec<QuantumCell<Fr>>, Vec<QuantumCell<Fr>>, (Fr, Fr)) {
        (k, a, b, rand_output)
    }
}

prop_compose! {
    pub fn range_check_strat(k_bounds: (usize, usize), max_range_bits: usize)
    (k in k_bounds.0..=k_bounds.1, range_bits in 1usize..=max_range_bits) // lookup_bits must be less than k
    (k in Just(k), range_bits in Just(range_bits), lookup_bits in 8..k,
    rand_a in prop::sample::select(vec![
        biguint_to_fe(&(BigUint::from(2u64).pow(range_bits as u32) - 1usize)),
        biguint_to_fe(&BigUint::from(2u64).pow(range_bits as u32)),
        biguint_to_fe(&(BigUint::from(2u64).pow(range_bits as u32) + 1usize)),
        Fr::random(OsRng)
    ]))
    -> (usize, usize, usize, Fr) {
        (k, range_bits, lookup_bits, rand_a)
    }
}

prop_compose! {
    fn is_less_than_safe_strat(k_bounds: (usize, usize))
    // compose strat to generate random rand fr in range
    (b in any::<u64>().prop_filter("not zero", |&i| i != 0), k in k_bounds.0..=k_bounds.1)
    (k in Just(k), b in Just(b), lookup_bits in k_bounds.0 - 1..k, rand_a in rand_fr(), out in any::<bool>())
    -> (usize, u64, usize, Fr, bool) {
        (k, b, lookup_bits, rand_a, out)
    }
}

fn arb_indicator<F: ScalarField>(max_size: usize) -> impl Strategy<Value = Vec<F>> {
    vec(Just(0), max_size).prop_map(|val| val.iter().map(|&x| F::from(x)).collect::<Vec<_>>())
}

fn check_idx_to_indicator(idx: Fr, len: usize, ind_witnesses: &[Fr]) -> bool {
    // check that:
    // the length of the witnes array is correct
    // the sum of the witnesses is 1, indicting that there is only one index that is 1
    if ind_witnesses.len() != len
        || ind_witnesses.iter().fold(Fr::zero(), |acc, val| acc + *val) != Fr::one()
    {
        return false;
    }

    let idx_val = idx.get_lower_128() as usize;

    // Check that all indexes are zero except for the one at idx
    for (i, v) in ind_witnesses.iter().enumerate() {
        if i != idx_val && *v != Fr::zero() {
            return false;
        }
    }
    true
}

// verify rand_output == a if sel == 1, rand_output == b if sel == 0
fn check_select(a: Fr, b: Fr, sel: Fr, rand_output: Fr) -> bool {
    if (sel == Fr::zero() && rand_output != b) || (sel == Fr::one() && rand_output != a) {
        return false;
    }
    true
}

fn neg_test_idx_to_indicator(k: usize, len: usize, idx: usize, ind_witnesses: &[Fr]) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = GateChip::default();
    // assign value to advice column before by assigning `idx` via ctx.load() -> use same method as ind_offsets to get offset
    let dummy_idx = Witness(Fr::from(idx as u64));
    let indicator = gate.idx_to_indicator(builder.main(0), dummy_idx, len);
    // get the offsets of the indicator cells for later 'pranking'
    builder.config(k, Some(9));
    let ind_offsets = indicator.iter().map(|ind| ind.cell.unwrap().offset).collect::<Vec<_>>();
    // prank the indicator cells
    // TODO: prank the entire advice column with random values
    for (offset, witness) in ind_offsets.iter().zip_eq(ind_witnesses) {
        builder.main(0).advice[*offset] = Assigned::Trivial(*witness);
    }
    // Get idx and indicator from advice column
    // Apply check instance function to `idx` and `ind_witnesses`
    let circuit = GateCircuitBuilder::mock(builder); // no break points
                                                     // Check soundness of witness values
    let is_valid_witness = check_idx_to_indicator(Fr::from(idx as u64), len, ind_witnesses);
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
        // if the proof is valid, then the instance should be valid -> return true
        Ok(_) => is_valid_witness,
        // if the proof is invalid, ignore
        Err(_) => !is_valid_witness,
    }
}

fn neg_test_select(
    k: usize,
    a: QuantumCell<Fr>,
    b: QuantumCell<Fr>,
    sel: QuantumCell<Fr>,
    rand_output: Fr,
) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = GateChip::default();
    // add select gate
    let select = gate.select(builder.main(0), a, b, sel);

    // Get the offset of `select`s output for later 'pranking'
    builder.config(k, Some(9));
    let select_offset = select.cell.unwrap().offset;
    // Prank the output
    builder.main(0).advice[select_offset] = Assigned::Trivial(rand_output);

    let circuit = GateCircuitBuilder::mock(builder); // no break points
                                                     // Check soundness of output
    let is_valid_instance = check_select(*a.value(), *b.value(), *sel.value(), rand_output);
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
        // if the proof is valid, then the instance should be valid -> return true
        Ok(_) => is_valid_instance,
        // if the proof is invalid, ignore
        Err(_) => !is_valid_instance,
    }
}

fn neg_test_select_by_indicator(
    k: usize,
    a: Vec<QuantumCell<Fr>>,
    idx: usize,
    rand_output: Fr,
) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = GateChip::default();

    let indicator = gate.idx_to_indicator(builder.main(0), Witness(Fr::from(idx as u64)), a.len());
    let a_idx = gate.select_by_indicator(builder.main(0), a.clone(), indicator);
    builder.config(k, Some(9));

    let a_idx_offset = a_idx.cell.unwrap().offset;
    builder.main(0).advice[a_idx_offset] = Assigned::Trivial(rand_output);
    let circuit = GateCircuitBuilder::mock(builder); // no break points
                                                     // Check soundness of witness values
                                                     // retrieve the value of a[idx] and check that it is equal to rand_output
    let is_valid_witness = rand_output == *a[idx].value();
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
        // if the proof is valid, then the instance should be valid -> return true
        Ok(_) => is_valid_witness,
        // if the proof is invalid, ignore
        Err(_) => !is_valid_witness,
    }
}

fn neg_test_select_from_idx(
    k: usize,
    cells: Vec<QuantumCell<Fr>>,
    idx: usize,
    rand_output: Fr,
) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = GateChip::default();

    let idx_val =
        gate.select_from_idx(builder.main(0), cells.clone(), Witness(Fr::from(idx as u64)));
    builder.config(k, Some(9));

    let idx_offset = idx_val.cell.unwrap().offset;
    builder.main(0).advice[idx_offset] = Assigned::Trivial(rand_output);
    let circuit = GateCircuitBuilder::mock(builder); // no break points
                                                     // Check soundness of witness values
    let is_valid_witness = rand_output == *cells[idx].value();
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
        // if the proof is valid, then the instance should be valid -> return true
        Ok(_) => is_valid_witness,
        // if the proof is invalid, ignore
        Err(_) => !is_valid_witness,
    }
}

fn neg_test_inner_product(
    k: usize,
    a: Vec<QuantumCell<Fr>>,
    b: Vec<QuantumCell<Fr>>,
    rand_output: Fr,
) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = GateChip::default();

    let inner_product = gate.inner_product(builder.main(0), a.clone(), b.clone());
    builder.config(k, Some(9));

    let inner_product_offset = inner_product.cell.unwrap().offset;
    builder.main(0).advice[inner_product_offset] = Assigned::Trivial(rand_output);
    let circuit = GateCircuitBuilder::mock(builder); // no break points
                                                     // Check soundness of witness values
    let is_valid_witness = rand_output == utils::inner_product_ground_truth(&(a, b));
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
        // if the proof is valid, then the instance should be valid -> return true
        Ok(_) => is_valid_witness,
        // if the proof is invalid, ignore
        Err(_) => !is_valid_witness,
    }
}

fn neg_test_inner_product_left_last(
    k: usize,
    a: Vec<QuantumCell<Fr>>,
    b: Vec<QuantumCell<Fr>>,
    rand_output: (Fr, Fr),
) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = GateChip::default();

    let inner_product = gate.inner_product_left_last(builder.main(0), a.clone(), b.clone());
    builder.config(k, Some(9));

    let inner_product_offset =
        (inner_product.0.cell.unwrap().offset, inner_product.1.cell.unwrap().offset);
    // prank the output cells
    builder.main(0).advice[inner_product_offset.0] = Assigned::Trivial(rand_output.0);
    builder.main(0).advice[inner_product_offset.1] = Assigned::Trivial(rand_output.1);
    let circuit = GateCircuitBuilder::mock(builder); // no break points
                                                     // Check soundness of witness values
                                                     // (inner_product_ground_truth, a[a.len()-1])
    let inner_product_ground_truth = utils::inner_product_ground_truth(&(a.clone(), b));
    let is_valid_witness =
        rand_output.0 == inner_product_ground_truth && rand_output.1 == *a[a.len() - 1].value();
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
        // if the proof is valid, then the instance should be valid -> return true
        Ok(_) => is_valid_witness,
        // if the proof is invalid, ignore
        Err(_) => !is_valid_witness,
    }
}

// Range Check

fn neg_test_range_check(k: usize, range_bits: usize, lookup_bits: usize, rand_a: Fr) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = RangeChip::default(lookup_bits);

    let a_witness = builder.main(0).load_witness(rand_a);
    gate.range_check(builder.main(0), a_witness, range_bits);

    builder.config(k, Some(9));
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let circuit = RangeCircuitBuilder::mock(builder); // no break points
                                                      // Check soundness of witness values
    let correct = fe_to_biguint(&rand_a).bits() <= range_bits as u64;

    MockProver::run(k as u32, &circuit, vec![]).unwrap().verify().is_ok() == correct
}

// TODO: expand to prank output of is_less_than_safe()
fn neg_test_is_less_than_safe(
    k: usize,
    b: u64,
    lookup_bits: usize,
    rand_a: Fr,
    prank_out: bool,
) -> bool {
    let mut builder = GateThreadBuilder::mock();
    let gate = RangeChip::default(lookup_bits);
    let ctx = builder.main(0);

    let a_witness = ctx.load_witness(rand_a); // cannot prank this later because this witness will be copy-constrained
    let out = gate.is_less_than_safe(ctx, a_witness, b);

    let out_idx = out.cell.unwrap().offset;
    ctx.advice[out_idx] = Assigned::Trivial(Fr::from(prank_out));

    builder.config(k, Some(9));
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let circuit = RangeCircuitBuilder::mock(builder); // no break points
                                                      // Check soundness of witness values
                                                      // println!("rand_a: {rand_a:?}, b: {b:?}");
    let a_big = fe_to_biguint(&rand_a);
    let is_lt = a_big < BigUint::from(b);
    let correct = (is_lt == prank_out)
        && (a_big.bits() as usize <= (bit_length(b) + lookup_bits - 1) / lookup_bits * lookup_bits); // circuit should always fail if `a` doesn't pass range check
    MockProver::run(k as u32, &circuit, vec![]).unwrap().verify().is_ok() == correct
}

proptest! {
    // Note setting the minimum value of k to 8 is intentional as it is the smallest value that will not cause an `out of columns` error. Should be noted that filtering by len * (number cells per iteration) < 2^k leads to the filtering of to many cases and the failure of the tests w/o any runs.
    #[test]
    fn prop_test_neg_idx_to_indicator((k, len, idx, witness_vals) in idx_to_indicator_strat((10,20),100)) {
        prop_assert!(neg_test_idx_to_indicator(k, len, idx, witness_vals.as_slice()));
    }

    #[test]
    fn prop_test_neg_select((k, a, b, sel, rand_output) in select_strat((10,20))) {
        prop_assert!(neg_test_select(k, a, b, sel, rand_output));
    }

    #[test]
    fn prop_test_neg_select_by_indicator((k, a, idx, rand_output) in select_by_indicator_strat((12,20),100)) {
        prop_assert!(neg_test_select_by_indicator(k, a, idx, rand_output));
    }

    #[test]
    fn prop_test_neg_select_from_idx((k, cells, idx, rand_output) in select_from_idx_strat((10,20),100)) {
        prop_assert!(neg_test_select_from_idx(k, cells, idx, rand_output));
    }

    #[test]
    fn prop_test_neg_inner_product((k, a, b, rand_output) in inner_product_strat((10,20),100)) {
        prop_assert!(neg_test_inner_product(k, a, b, rand_output));
    }

    #[test]
    fn prop_test_neg_inner_product_left_last((k, a, b, rand_output) in inner_product_left_last_strat((10,20),100)) {
        prop_assert!(neg_test_inner_product_left_last(k, a, b, rand_output));
    }

    #[test]
    fn prop_test_neg_range_check((k, range_bits, lookup_bits, rand_a) in range_check_strat((10,23),90)) {
        prop_assert!(neg_test_range_check(k, range_bits, lookup_bits, rand_a));
    }

    #[test]
    fn prop_test_neg_is_less_than_safe((k, b, lookup_bits, rand_a, out) in is_less_than_safe_strat((10,20))) {
        prop_assert!(neg_test_is_less_than_safe(k, b, lookup_bits, rand_a, out));
    }
}
