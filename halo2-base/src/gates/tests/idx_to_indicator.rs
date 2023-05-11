use crate::{
    gates::{
        builder::{GateCircuitBuilder, GateThreadBuilder},
        GateChip, GateInstructions,
    },
    halo2_proofs::{
        plonk::keygen_pk,
        plonk::{keygen_vk, Assigned},
        poly::kzg::commitment::ParamsKZG,
    },
};

use ff::Field;
use itertools::Itertools;
use rand::{thread_rng, Rng};

use super::*;
use crate::QuantumCell::Witness;

// soundness checks for `idx_to_indicator` function
fn test_idx_to_indicator_gen(k: u32, len: usize) {
    // first create proving and verifying key
    let mut builder = GateThreadBuilder::keygen();
    let gate = GateChip::default();
    let dummy_idx = Witness(Fr::zero());
    let indicator = gate.idx_to_indicator(builder.main(0), dummy_idx, len);
    // get the offsets of the indicator cells for later 'pranking'
    let ind_offsets = indicator.iter().map(|ind| ind.cell.unwrap().offset).collect::<Vec<_>>();
    // set env vars
    builder.config(k as usize, Some(9));
    let circuit = GateCircuitBuilder::keygen(builder);

    let params = ParamsKZG::setup(k, OsRng);
    // generate proving key
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let vk = pk.get_vk(); // pk consumed vk

    // now create different proofs to test the soundness of the circuit

    let gen_pf = |idx: usize, ind_witnesses: &[Fr]| {
        let mut builder = GateThreadBuilder::prover();
        let gate = GateChip::default();
        let idx = Witness(Fr::from(idx as u64));
        gate.idx_to_indicator(builder.main(0), idx, len);
        // prank the indicator cells
        for (offset, witness) in ind_offsets.iter().zip_eq(ind_witnesses) {
            builder.main(0).advice[*offset] = Assigned::Trivial(*witness);
        }
        let circuit = GateCircuitBuilder::prover(builder, vec![vec![]]); // no break points
        gen_proof(&params, &pk, circuit)
    };

    // expected answer
    for idx in 0..len {
        let mut ind_witnesses = vec![Fr::zero(); len];
        ind_witnesses[idx] = Fr::one();
        let pf = gen_pf(idx, &ind_witnesses);
        check_proof(&params, vk, &pf, true);
    }

    let mut rng = thread_rng();
    // bad cases
    for idx in 0..len {
        let mut ind_witnesses = vec![Fr::zero(); len];
        // all zeros is bad!
        let pf = gen_pf(idx, &ind_witnesses);
        check_proof(&params, vk, &pf, false);

        // ind[idx] != 1 is bad!
        for _ in 0..100usize {
            ind_witnesses.fill(Fr::zero());
            ind_witnesses[idx] = Fr::random(OsRng);
            if ind_witnesses[idx] == Fr::one() {
                continue;
            }
            let pf = gen_pf(idx, &ind_witnesses);
            check_proof(&params, vk, &pf, false);
        }

        if len < 2 {
            continue;
        }
        // nonzeros where there should be zeros is bad!
        for _ in 0..100usize {
            ind_witnesses.fill(Fr::zero());
            ind_witnesses[idx] = Fr::one();
            let num_nonzeros = rng.gen_range(1..len);
            let mut count = 0usize;
            for _ in 0..num_nonzeros {
                let index = rng.gen_range(0..len);
                if index == idx {
                    continue;
                }
                ind_witnesses[index] = Fr::random(&mut rng);
                count += 1;
            }
            if count == 0usize {
                continue;
            }
            let pf = gen_pf(idx, &ind_witnesses);
            check_proof(&params, vk, &pf, false);
        }
    }
}

#[test]
fn test_idx_to_indicator() {
    test_idx_to_indicator_gen(8, 1);
    test_idx_to_indicator_gen(8, 4);
    test_idx_to_indicator_gen(8, 10);
    test_idx_to_indicator_gen(8, 20);
    test_idx_to_indicator_gen(11, 100);
}
