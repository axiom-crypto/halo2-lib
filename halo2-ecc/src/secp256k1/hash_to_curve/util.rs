use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;

use crate::{
    bigint::{ProperCrtUint, ProperUint},
    fields::FieldChip,
    secp256k1::{
        util::{bits_le_to_fe_assigned, fe_to_bits_le},
        FpChip,
    },
};

pub(crate) fn byte_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte: &AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    let bits = fe_to_bits_le(byte.value(), 8);
    let assigned_bits =
        bits.iter().map(|bit| ctx.load_constant(F::from(*bit as u64))).collect_vec();

    let _byte = bits_le_to_fe_assigned(ctx, range, &assigned_bits).unwrap();
    ctx.constrain_equal(byte, &_byte);

    assigned_bits
}

pub(crate) fn bytes_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bytes.iter().flat_map(|byte| byte_to_bits_le_assigned(ctx, range, byte)).collect_vec()
}

pub(crate) fn bits_le_to_byte_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> AssignedValue<F> {
    assert_eq!(bits.len(), 8);
    let gate = range.gate();
    let mut sum = ctx.load_zero();
    for (idx, bit) in bits.iter().enumerate() {
        sum = gate.mul_add(ctx, *bit, QuantumCell::Constant(F::from(1 << idx)), sum);
    }
    sum
}

pub(crate) fn bits_le_to_bytes_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bits.chunks(8).map(|chunk| bits_le_to_byte_assigned(ctx, range, chunk)).collect_vec()
}

pub(crate) fn limbs_le_to_bigint<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    limbs: &[AssignedValue<F>],
    max_limb_bits: usize,
) -> ProperCrtUint<F> {
    let native_limbs = limbs.iter().map(|limb| *limb.value()).collect_vec();

    let mut value = BigUint::from(0u64);
    let mut limb_bases = Vec::<F>::with_capacity(native_limbs.len());
    for (idx, limb) in native_limbs.iter().enumerate() {
        let limb = BigUint::from_bytes_le(limb.to_bytes_le().as_slice());
        let limb_base = BigUint::from(2u64).pow(BigUint::from(idx) * BigUint::from(max_limb_bits));
        limb_bases.push(F::from_bytes_le(limb_base.to_bytes_le().as_slice()));
        let shifted_limb = limb * limb_base;
        value += shifted_limb;
    }

    let int = ProperUint(limbs.to_vec()).into_crt(
        ctx,
        range.gate(),
        value,
        limb_bases.as_slice(),
        max_limb_bits,
    );

    int
}

pub(crate) fn mod_inverse<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    num: ProperCrtUint<F>,
) -> ProperCrtUint<F> {
    let one = ctx.load_constant(F::ONE);
    let one_int = fp_chip.load_constant_uint(ctx, BigUint::from(1u64));

    let p = fp_chip.p.to_biguint().unwrap();
    let p_minus_two = p.clone() - 2u64;

    let num_native = num.value();
    let inverse_native = num_native.clone().pow(p_minus_two);
    let mod_inverse_native = inverse_native % p;
    assert_eq!(num_native * mod_inverse_native.clone(), BigUint::from(1u64));

    let mod_inverse = fp_chip.load_constant_uint(ctx, mod_inverse_native);
    let is_one = fp_chip.mul(ctx, num, mod_inverse.clone());
    let is_equal = fp_chip.is_equal(ctx, is_one, one_int);
    ctx.constrain_equal(&is_equal, &one);

    mod_inverse
}
