use crate::ff::Field;
use crate::{bn254::FpChip, fields::FieldChip};

use halo2_base::gates::circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage};
use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::Fq, plonk::keygen_pk, plonk::keygen_vk,
        poly::kzg::commitment::ParamsKZG,
    },
    utils::testing::{check_proof, gen_proof},
};
use rand::thread_rng;

// soundness checks for `` function
fn test_fp_assert_eq_gen(k: u32, lookup_bits: usize, num_tries: usize) {
    let mut rng = thread_rng();

    // first create proving and verifying key
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen)
        .use_k(k as usize)
        .use_lookup_bits(lookup_bits);
    let range = builder.range_chip();
    let chip = FpChip::new(&range, 88, 3);

    let ctx = builder.main(0);
    let a = chip.load_private(ctx, Fq::zero());
    let b = chip.load_private(ctx, Fq::zero());
    chip.assert_equal(ctx, &a, &b);
    let config_params = builder.calculate_params(Some(9));

    let params = ParamsKZG::setup(k, &mut rng);
    // generate proving key
    let vk = keygen_vk(&params, &builder).unwrap();
    let pk = keygen_pk(&params, vk, &builder).unwrap();
    let vk = pk.get_vk(); // pk consumed vk
    let break_points = builder.break_points();
    drop(builder);

    // now create different proofs to test the soundness of the circuit

    let gen_pf = |a: Fq, b: Fq| {
        let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points.clone());
        let range = builder.range_chip();
        let chip = FpChip::new(&range, 88, 3);

        let ctx = builder.main(0);
        let [a, b] = [a, b].map(|x| chip.load_private(ctx, x));
        chip.assert_equal(ctx, &a, &b);
        gen_proof(&params, &pk, builder)
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
