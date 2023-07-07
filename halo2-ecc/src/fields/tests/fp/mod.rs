use std::env::set_var;

use crate::fields::fp::FpChip;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fq, Fr},
};

use halo2_base::gates::builder::{GateThreadBuilder, RangeCircuitBuilder};
use halo2_base::gates::RangeChip;
use halo2_base::utils::biguint_to_fe;
use halo2_base::utils::{fe_to_biguint, modulus};
use halo2_base::Context;
use rand::rngs::OsRng;

pub mod assert_eq;

const K: usize = 10;

fn fp_chip_test(
    k: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    f: impl Fn(&mut Context<Fr>, &FpChip<Fr, Fq>),
) {
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<Fr>::default(lookup_bits);
    let chip = FpChip::<Fr, Fq>::new(&range, limb_bits, num_limbs);

    let mut builder = GateThreadBuilder::mock();
    f(builder.main(0), &chip);

    builder.config(k, Some(10));
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_fp() {
    let limb_bits = 88;
    let num_limbs = 3;
    fp_chip_test(K, K - 1, limb_bits, num_limbs, |ctx, chip| {
        let _a = Fq::random(OsRng);
        let _b = Fq::random(OsRng);

        let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, x));
        let c = chip.mul(ctx, a, b);

        assert_eq!(c.0.truncation.to_bigint(limb_bits), c.0.value);
        assert_eq!(c.native().value(), &biguint_to_fe(&(c.value() % modulus::<Fr>())));
        assert_eq!(c.0.value, fe_to_biguint(&(_a * _b)).into());
    });
}

#[test]
fn test_range_check() {
    fp_chip_test(K, K - 1, 88, 3, |ctx, chip| {
        let mut range_test = |x, bits| {
            let x = chip.load_private(ctx, x);
            chip.range_check(ctx, x, bits);
        };
        let a = -Fq::one();
        range_test(a, Fq::NUM_BITS as usize);
        range_test(Fq::one(), 1);
        range_test(Fq::from(u64::MAX), 64);
        range_test(Fq::zero(), 1);
        range_test(Fq::zero(), 0);
    });
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_fp() {
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

    let k = K;
    let a = Fq::zero();
    let b = Fq::zero();

    let mut builder = GateThreadBuilder::keygen();
    fp_mul_test(builder.main(0), k - 1, 88, 3, a, b);

    builder.config(k, Some(10));
    let circuit = RangeCircuitBuilder::keygen(builder);
    halo2_proofs::dev::CircuitLayout::default().render(k as u32, &circuit, &root).unwrap();
}
