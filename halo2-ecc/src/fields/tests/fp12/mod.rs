use crate::ff::Field as _;
use crate::fields::fp::FpChip;
use crate::fields::fp12::Fp12Chip;
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::bn256::{Fq, Fq12};
use halo2_base::utils::testing::base_test;
use rand_core::OsRng;

const XI_0: i64 = 9;

fn fp12_mul_test(
    k: u32,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    _a: Fq12,
    _b: Fq12,
) {
    base_test().k(k).lookup_bits(lookup_bits).run(|ctx, range| {
        let fp_chip = FpChip::<_, Fq>::new(range, limb_bits, num_limbs);
        let chip = Fp12Chip::<_, _, Fq12, XI_0>::new(&fp_chip);

        let [a, b] = [_a, _b].map(|x| chip.load_private(ctx, x));
        let c = chip.mul(ctx, a, b).into();

        assert_eq!(chip.get_assigned_value(&c), _a * _b);
        for c in c.into_iter() {
            assert_eq!(c.truncation.to_bigint(limb_bits), c.value);
        }
    });
}

#[test]
fn test_fp12() {
    let k = 12;
    let a = Fq12::random(OsRng);
    let b = Fq12::random(OsRng);

    fp12_mul_test(k, k as usize - 1, 88, 3, a, b);
}
