use crate::ff::{Field as _, PrimeField as _};
use crate::fields::fp::FpChip;
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bn256::{Fq, Fr};

use halo2_base::utils::biguint_to_fe;
use halo2_base::utils::testing::base_test;
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
    base_test().k(k as u32).lookup_bits(lookup_bits).run(|ctx, range| {
        let chip = FpChip::<Fr, Fq>::new(range, limb_bits, num_limbs);
        f(ctx, &chip);
    });
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
    use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
    use halo2_base::halo2_proofs;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

    let k = K;
    let a = Fq::zero();
    let b = Fq::zero();

    let mut builder = BaseCircuitBuilder::new(false).use_k(k).use_lookup_bits(k - 1);
    let range = builder.range_chip();
    let chip = FpChip::<Fr, Fq>::new(&range, 88, 3);
    let ctx = builder.main(0);
    let [a, b] = [a, b].map(|x| chip.load_private(ctx, x));
    let c = chip.mul(ctx, a, b);

    let cp = builder.calculate_params(Some(10));
    log::info!("cp: {:?}", cp);
    halo2_proofs::dev::CircuitLayout::default().render(k as u32, &builder, &root).unwrap();
}
