use proptest::{prelude::*, collection::vec};
use crate::{gates::{GateChip, GateInstructions, builder::{GateCircuitBuilder, GateThreadBuilder}, tests::{Fr, flex_gate_tests, range_gate_tests}}, utils::ScalarField};
use crate::halo2_proofs::plonk::Assigned;
use crate::QuantumCell::Witness;
use itertools::Itertools;
use halo2_proofs_axiom::dev::MockProver;
use rand::rngs::OsRng;
use ff::Field;
    
prop_compose! {
    // length == 1 is just selecting [0] which should be covered in unit test
    fn idx_to_indicator_strat(max_size: usize)
        (k in 8..=20usize, idx_val in prop::sample::select(vec![Fr::zero(), Fr::one(), Fr::random(OsRng)]), len in 2usize..=max_size)
        (k in Just(k), idx in 0..len, idx_val in Just(idx_val), len in Just(len), mut witness_vals in arb_indicator::<Fr>(len)) -> (usize, usize, usize, Vec<Fr>) {
        witness_vals[idx] = idx_val;
        (k, len, idx, witness_vals)
    }
}

fn arb_indicator<F: ScalarField>(max_size: usize) -> impl Strategy<Value = Vec<F>> {
    vec(Just(0), max_size).prop_map(|val| {
        val.iter().map(|&x| F::from(x)).collect::<Vec<_>>()
    })
}

fn check_instance(idx: Fr, len: usize, ind_witnesses: &[Fr]) -> bool {   
    // check that:
    // the length of the witnes array is correct
    // the sum of the witnesses is 1, indicting that there is only one index that is 1
    if ind_witnesses.len() != len || 
    ind_witnesses.iter().fold(Fr::zero(), |acc, val| { acc + *val }) != Fr::one() {
        return false;
    }

    // TODO: Clean this up
    let mut idx_val = usize::MAX;
    for i in 0..len  {
        if Fr::from(i as u64) == idx {
            idx_val = i;
        }
    }
    if idx_val > len {
        return false;
    }

    // Check that all indexes are zero except for the one at idx
   for (i, v) in ind_witnesses.iter().enumerate() {
        if i != idx_val && *v != Fr::zero() {
            return false;
        }
   }
   true 
}

// add filter to distinguish between valid and invalid output at end
fn prop_neg_test_idx_to_indicator(k: usize, len: usize, idx: usize, ind_witnesses: &[Fr]) -> bool {
    // first create proving and verifying key
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
    let is_valid_witness = check_instance(Fr::from(idx as u64), len, ind_witnesses);
    match MockProver::run(k as u32, &circuit, vec![]).unwrap().verify() {
            // if the proof is valid, then the instance should be valid -> return true
            Ok(_) => is_valid_witness == true,
            // if the proof is invalid, ignore
            Err(_) =>  is_valid_witness == false,
    }

}


proptest! {
    #[test]
    fn test_neg_idx_to_indicator_gen((k, len, idx, witness_vals) in idx_to_indicator_strat(100)) {
        prop_assert!(prop_neg_test_idx_to_indicator(k, len, idx, witness_vals.as_slice()));
    }
}