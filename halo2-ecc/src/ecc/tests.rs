#![allow(unused_assignments, unused_imports, unused_variables)]
use super::*;
use crate::fields::fp2::Fp2Chip;
use crate::halo2_proofs::{
    circuit::*,
    dev::MockProver,
    halo2curves::bn256::{Fq, Fr, G1Affine, G2Affine, G1, G2},
    plonk::*,
};
use group::Group;
use halo2_base::gates::builder::RangeCircuitBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::utils::bigint_to_fe;
use halo2_base::SKIP_FIRST_PASS;
use halo2_base::{gates::range::RangeStrategy, utils::value_to_option};
use num_bigint::{BigInt, RandBigInt};
use rand_core::OsRng;
use std::marker::PhantomData;
use std::ops::Neg;

fn basic_g1_tests<F: PrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    P: G1Affine,
    Q: G1Affine,
) {
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<F>::default(lookup_bits);
    let fp_chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);
    let chip = EccChip::new(&fp_chip);

    let P_assigned = chip.load_private(ctx, (P.x, P.y));
    let Q_assigned = chip.load_private(ctx, (Q.x, Q.y));

    // test add_unequal
    chip.field_chip.enforce_less_than(ctx, P_assigned.x());
    chip.field_chip.enforce_less_than(ctx, Q_assigned.x());
    let sum = chip.add_unequal(ctx, &P_assigned, &Q_assigned, false);
    assert_eq!(sum.x.truncation.to_bigint(limb_bits), sum.x.value);
    assert_eq!(sum.y.truncation.to_bigint(limb_bits), sum.y.value);
    {
        let actual_sum = G1Affine::from(P + Q);
        assert_eq!(bigint_to_fe::<Fq>(&sum.x.value), actual_sum.x);
        assert_eq!(bigint_to_fe::<Fq>(&sum.y.value), actual_sum.y);
    }
    println!("add unequal witness OK");

    // test double
    let doub = chip.double(ctx, &P_assigned);
    assert_eq!(doub.x.truncation.to_bigint(limb_bits), doub.x.value);
    assert_eq!(doub.y.truncation.to_bigint(limb_bits), doub.y.value);
    {
        let actual_doub = G1Affine::from(P * Fr::from(2u64));
        assert_eq!(bigint_to_fe::<Fq>(&doub.x.value), actual_doub.x);
        assert_eq!(bigint_to_fe::<Fq>(&doub.y.value), actual_doub.y);
    }
    println!("double witness OK");
}

#[test]
fn test_ecc() {
    let k = 23;
    let P = G1Affine::random(OsRng);
    let Q = G1Affine::random(OsRng);

    let mut builder = GateThreadBuilder::<Fr>::mock();
    basic_g1_tests(builder.main(0), k - 1, 88, 3, P, Q);

    builder.config(k, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_ecc() {
    let k = 10;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (512, 16384)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Ecc Layout", ("sans-serif", 60)).unwrap();

    let P = G1Affine::random(OsRng);
    let Q = G1Affine::random(OsRng);

    let mut builder = GateThreadBuilder::<Fr>::keygen();
    basic_g1_tests(builder.main(0), 22, 88, 3, P, Q);

    builder.config(k, Some(10));
    let circuit = RangeCircuitBuilder::mock(builder);

    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}

