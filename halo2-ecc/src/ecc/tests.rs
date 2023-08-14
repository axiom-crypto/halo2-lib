#![allow(unused_assignments, unused_imports, unused_variables)]
use super::*;
use crate::fields::fp2::Fp2Chip;
use crate::group::Group;
use crate::halo2_proofs::{
    circuit::*,
    dev::MockProver,
    halo2curves::bn256::{Fq, Fr, G1Affine, G2Affine, G1, G2},
    plonk::*,
};
use halo2_base::gates::builder::RangeCircuitBuilder;
use halo2_base::gates::RangeChip;
use halo2_base::utils::bigint_to_fe;
use halo2_base::SKIP_FIRST_PASS;
use halo2_base::{gates::range::RangeStrategy, utils::value_to_option};
use num_bigint::{BigInt, RandBigInt};
use rand_core::OsRng;
use std::marker::PhantomData;
use std::ops::Neg;

fn basic_g1_tests<F: BigPrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    P: G1Affine,
    Q: G1Affine,
) {
    let range = RangeChip::<F>::default(lookup_bits);
    let fp_chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);
    let chip = EccChip::new(&fp_chip);

    let P_assigned = chip.load_private_unchecked(ctx, (P.x, P.y));
    let Q_assigned = chip.load_private_unchecked(ctx, (Q.x, Q.y));

    // test add_unequal
    chip.field_chip.enforce_less_than(ctx, P_assigned.x().clone());
    chip.field_chip.enforce_less_than(ctx, Q_assigned.x().clone());
    let sum = chip.add_unequal(ctx, &P_assigned, &Q_assigned, false);
    assert_eq!(sum.x.0.truncation.to_bigint(limb_bits), sum.x.0.value);
    assert_eq!(sum.y.0.truncation.to_bigint(limb_bits), sum.y.0.value);
    {
        let actual_sum = G1Affine::from(P + Q);
        assert_eq!(bigint_to_fe::<Fq>(&sum.x.0.value), actual_sum.x);
        assert_eq!(bigint_to_fe::<Fq>(&sum.y.0.value), actual_sum.y);
    }
    println!("add unequal witness OK");

    // test double
    let doub = chip.double(ctx, &P_assigned);
    assert_eq!(doub.x.0.truncation.to_bigint(limb_bits), doub.x.0.value);
    assert_eq!(doub.y.0.truncation.to_bigint(limb_bits), doub.y.0.value);
    {
        let actual_doub = G1Affine::from(P * Fr::from(2u64));
        assert_eq!(bigint_to_fe::<Fq>(&doub.x.0.value), actual_doub.x);
        assert_eq!(bigint_to_fe::<Fq>(&doub.y.0.value), actual_doub.y);
    }
    println!("double witness OK");
}

#[test]
fn test_ecc() {
    let k = 23;
    let P = G1Affine::random(OsRng);
    let Q = G1Affine::random(OsRng);

    let mut builder = GateThreadBuilder::<Fr>::mock();
    let lookup_bits = k - 1;
    basic_g1_tests(builder.main(0), lookup_bits, 88, 3, P, Q);

    let mut config_params = builder.config(k, Some(20));
    config_params.lookup_bits = Some(lookup_bits);
    let circuit = RangeCircuitBuilder::mock(builder, config_params);

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

    let mut config_params = builder.config(k, Some(10));
    config_params.lookup_bits = Some(22);
    let circuit = RangeCircuitBuilder::mock(builder, config_params);

    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}
