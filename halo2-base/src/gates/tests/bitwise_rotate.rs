use crate::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        plonk::keygen_pk,
        plonk::{keygen_vk, Assigned},
        poly::kzg::commitment::ParamsKZG,
    },
    utils::testing::{check_proof, gen_proof},
};

use halo2_proofs_axiom::halo2curves::FieldExt;
use rand::rngs::OsRng;
use std::env;

use super::*;

// soundness checks for bitwise rotation functions
fn test_bitwise_rotate_gen<const BIT: usize, const NUM_BITS: usize>(
    k: u32,
    is_left: bool,
    a: u128,
    result_val: u128,
    expect_satisfied: bool,
) {
    // first create proving and verifying key
    let lookup_bits = 3;
    env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let mut builder = GateThreadBuilder::keygen();
    let gate = RangeChip::<Fr>::default(lookup_bits);
    let dummy_a = builder.main(0).load_witness(Fr::zero());
    let result = if is_left {
        gate.const_left_rotate::<BIT, NUM_BITS>(builder.main(0), dummy_a)
    } else {
        gate.const_right_rotate::<BIT, NUM_BITS>(builder.main(0), dummy_a)
    };
    // get the offsets of the indicator cells for later 'pranking'
    let result_offsets = result.cell.unwrap().offset;
    // set env vars
    builder.config(k as usize, Some(9));
    let circuit = RangeCircuitBuilder::keygen(builder);

    let params = ParamsKZG::setup(k, OsRng);
    // generate proving key
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let vk = pk.get_vk(); // pk consumed vk

    // now create different proofs to test the soundness of the circuit

    let gen_pf = || {
        let mut builder = GateThreadBuilder::prover();
        let gate = RangeChip::<Fr>::default(lookup_bits);
        let a_witness = builder.main(0).load_witness(Fr::from_u128(a));
        if is_left {
            gate.const_left_rotate::<BIT, NUM_BITS>(builder.main(0), a_witness);
        } else {
            gate.const_right_rotate::<BIT, NUM_BITS>(builder.main(0), a_witness);
        };
        builder.main(0).advice[result_offsets] = Assigned::Trivial(Fr::from_u128(result_val));
        builder.config(k as usize, Some(9));
        let circuit = RangeCircuitBuilder::prover(builder, vec![vec![]]); // no break points
        gen_proof(&params, &pk, circuit)
    };

    let pf = gen_pf();
    check_proof(&params, vk, &pf, expect_satisfied);
}

#[test]
fn test_bitwise_rotate() {
    // "<<" is leftroate. ">>" is rightrotate.
    // 1 << 8 == 256
    test_bitwise_rotate_gen::<8, 10>(8, true, 1, 256, true);
    // 1 << 8 != 255
    test_bitwise_rotate_gen::<8, 10>(8, true, 1, 255, false);
    // 1 << 8 != 1
    test_bitwise_rotate_gen::<8, 10>(8, true, 1, 1, false);
    // 1 >> 1 == 512
    test_bitwise_rotate_gen::<1, 10>(8, false, 1, 512, true);
    // 1 >> 1 != 10
    test_bitwise_rotate_gen::<1, 10>(8, false, 1, 10, false);
    // 5 >> 2 == 257
    test_bitwise_rotate_gen::<2, 10>(8, false, 5, 257, true);
    // 5 >> 1 != 513
    test_bitwise_rotate_gen::<1, 10>(8, false, 5, 513, false);
    // 1023u10 << 5 == 1023
    test_bitwise_rotate_gen::<5, 10>(8, true, 1023, 1023, true);
    // 1u128 >> 5 == 1u128 << 123
    test_bitwise_rotate_gen::<5, 128>(8, false, 1, 1 << 123, true);
    // 1u128 >> 5 != 2047
    test_bitwise_rotate_gen::<5, 128>(8, false, 1, 2047, false);
}

#[test]
#[should_panic]
fn test_bitwise_rotate_zero_num_bits() {
    let lookup_bits = 3;
    let mut builder = GateThreadBuilder::keygen();
    let gate = RangeChip::<Fr>::default(lookup_bits);
    let dummy_a = builder.main(0).load_witness(Fr::zero());
    gate.const_left_rotate::<1, 0>(builder.main(0), dummy_a);
}

#[test]
#[should_panic]
fn test_bitwise_rotate_too_large_num_bits() {
    let lookup_bits = 3;
    let mut builder = GateThreadBuilder::keygen();
    let gate = RangeChip::<Fr>::default(lookup_bits);
    let dummy_a = builder.main(0).load_witness(Fr::zero());
    gate.const_left_rotate::<1, 200>(builder.main(0), dummy_a);
}

#[test]
#[should_panic]
fn test_bitwise_rotate_value_overflow() {
    let lookup_bits = 3;
    let mut builder = GateThreadBuilder::keygen();
    let gate = RangeChip::<Fr>::default(lookup_bits);
    // 1 << 128
    let dummy_a = builder.main(0).load_witness(Fr::from_raw([0, 0, 1, 0]));
    gate.const_left_rotate::<1, 128>(builder.main(0), dummy_a);
}