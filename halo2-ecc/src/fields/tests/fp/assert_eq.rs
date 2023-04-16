use std::env::set_var;

use ff::Field;
use halo2_base::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        tests::{check_proof, gen_proof},
        RangeChip,
    },
    halo2_proofs::{
        halo2curves::bn256::{Fq, Fr},
        plonk::keygen_pk,
        plonk::keygen_vk,
        poly::kzg::commitment::ParamsKZG,
    },
};
use num_bigint::BigInt;

use crate::{bn254::FpChip, fields::FieldChip};
use rand::thread_rng;

// soundness checks for `` function
fn test_fp_assert_eq_gen(k: u32, lookup_bits: usize, num_tries: usize) {
    let mut rng = thread_rng();
    set_var("LOOKUP_BITS", lookup_bits.to_string());

    // first create proving and verifying key
    let mut builder = GateThreadBuilder::keygen();
    let range = RangeChip::default(lookup_bits);
    let chip = FpChip::new(&range, 88, 3);

    let ctx = builder.main(0);
    let a = chip.load_private(ctx, BigInt::from(0));
    let b = chip.load_private(ctx, BigInt::from(0));
    chip.assert_equal(ctx, &a, &b);
    // set env vars
    builder.config(k as usize, Some(9));
    let circuit = RangeCircuitBuilder::keygen(builder);

    let params = ParamsKZG::setup(k, &mut rng);
    // generate proving key
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let vk = pk.get_vk(); // pk consumed vk

    // now create different proofs to test the soundness of the circuit

    let gen_pf = |a: Fq, b: Fq| {
        let mut builder = GateThreadBuilder::prover();
        let range = RangeChip::default(lookup_bits);
        let chip = FpChip::new(&range, 88, 3);

        let ctx = builder.main(0);
        let [a, b] = [a, b].map(|x| chip.load_private(ctx, FpChip::<Fr>::fe_to_witness(&x)));
        chip.assert_equal(ctx, &a, &b);
        let circuit = RangeCircuitBuilder::prover(builder, vec![vec![]]); // no break points
        gen_proof(&params, &pk, circuit)
    };

    // expected answer
    for _ in 0..num_tries {
        let a = Fq::random(&mut rng);
        let pf = gen_pf(a, a);
        check_proof(&params, vk, &pf, true);
    }

    // unequal
    for _ in 0..num_tries {
        let a = Fq::random(&mut rng);
        let b = Fq::random(&mut rng);
        if a == b {
            continue;
        }
        let pf = gen_pf(a, b);
        check_proof(&params, vk, &pf, false);
    }
}

#[test]
fn test_fp_assert_eq() {
    test_fp_assert_eq_gen(10, 4, 100);
    test_fp_assert_eq_gen(10, 8, 100);
    test_fp_assert_eq_gen(10, 9, 100);
    test_fp_assert_eq_gen(18, 17, 10);
}
