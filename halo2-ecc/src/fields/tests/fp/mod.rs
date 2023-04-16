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

fn fp_mul_test<F: PrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    _a: Fq,
    _b: Fq,
) {
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<F>::default(lookup_bits);
    let chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);

    let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, FpChip::<F, Fq>::fe_to_witness(&x)));
    let c = chip.mul(ctx, &a, &b);

    assert_eq!(c.truncation.to_bigint(limb_bits), c.value);
    assert_eq!(
        c.native.value(),
        &biguint_to_fe(&(&c.value.to_biguint().unwrap() % modulus::<F>()))
    );
    assert_eq!(c.value, fe_to_biguint(&(_a * _b)).into())
}

#[test]
fn test_fp() {
    let k = K;
    let a = Fq::random(OsRng);
    let b = Fq::random(OsRng);

    let mut builder = GateThreadBuilder::<Fr>::mock();
    fp_mul_test(builder.main(0), k - 1, 88, 3, a, b);

    builder.config(k, Some(10));
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
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
