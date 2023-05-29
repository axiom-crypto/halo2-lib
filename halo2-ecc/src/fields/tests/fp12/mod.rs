use crate::fields::fp::FpChip;
use crate::fields::fp12::Fp12Chip;
use crate::fields::{FieldChip, PrimeField};
use crate::halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Fq, Fq12, Fr},
};
use halo2_base::gates::builder::{GateThreadBuilder, RangeCircuitBuilder};
use halo2_base::gates::RangeChip;
use halo2_base::Context;
use rand_core::OsRng;

const XI_0: i64 = 9;

fn fp12_mul_test<F: PrimeField>(
    ctx: &mut Context<F>,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    _a: Fq12,
    _b: Fq12,
) {
    std::env::set_var("LOOKUP_BITS", lookup_bits.to_string());
    let range = RangeChip::<F>::default(lookup_bits);
    let fp_chip = FpChip::<F, Fq>::new(&range, limb_bits, num_limbs);
    let chip = Fp12Chip::<F, _, Fq12, XI_0>::new(&fp_chip);

    let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, x));
    let c = chip.mul(ctx, a, b).into();

    assert_eq!(chip.get_assigned_value(&c), _a * _b);
    for c in c.into_iter() {
        assert_eq!(c.truncation.to_bigint(limb_bits), c.value);
    }
}

#[test]
fn test_fp12() {
    let k = 12;
    let a = Fq12::random(OsRng);
    let b = Fq12::random(OsRng);

    let mut builder = GateThreadBuilder::<Fr>::mock();
    fp12_mul_test(builder.main(0), k - 1, 88, 3, a, b);

    builder.config(k, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_fp12() {
    use ff::Field;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

    let k = 23;
    let a = Fq12::zero();
    let b = Fq12::zero();

    let mut builder = GateThreadBuilder::<Fr>::mock();
    fp12_mul_test(builder.main(0), k - 1, 88, 3, a, b);

    builder.config(k, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);

    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}
