use std::ops::{ Mul, Rem };

use halo2_base::{
    gates::{ GateInstructions, RangeChip, RangeInstructions },
    utils::{ fe_to_biguint, BigPrimeField },
    AssignedValue,
    Context,
    QuantumCell,
};
use itertools::Itertools;
use num_bigint::{ BigInt, BigUint, ToBigInt };
use num_integer::Integer;
use num_traits::{ One, Pow, Zero };

use crate::{
    bigint::{ CRTInteger, OverflowInteger, ProperCrtUint },
    fields::FieldChip,
    secp256k1::{ util::{ bits_le_to_fe_assigned, fe_to_bits_le }, FpChip },
};

// Assumes that input is a byte
pub(crate) fn byte_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte: &AssignedValue<F>
) -> Vec<AssignedValue<F>> {
    let bits = fe_to_bits_le(byte.value(), 8);
    let assigned_bits = bits
        .iter()
        .map(|bit| ctx.load_constant(F::from(*bit as u64)))
        .collect_vec();

    let _byte = bits_le_to_fe_assigned(ctx, range, &assigned_bits).unwrap();
    ctx.constrain_equal(byte, &_byte);

    assigned_bits
}

pub(crate) fn bytes_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>]
) -> Vec<AssignedValue<F>> {
    bytes
        .iter()
        .flat_map(|byte| byte_to_bits_le_assigned(ctx, range, byte))
        .collect_vec()
}

pub(crate) fn bits_le_to_byte_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>]
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
    bits: &[AssignedValue<F>]
) -> Vec<AssignedValue<F>> {
    bits.chunks(8)
        .map(|chunk| bits_le_to_byte_assigned(ctx, range, chunk))
        .collect_vec()
}

pub(crate) fn limbs_le_to_bigint<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>,
    limbs: &[AssignedValue<F>]
) -> ProperCrtUint<F> {
    let mut value = BigUint::from(0u64);
    for i in 0..limbs.len() {
        value += (BigUint::from(1u64) << (64 * i)) * fe_to_biguint(limbs[i].value());
    }

    let assigned_uint = OverflowInteger::new(limbs.to_vec(), 64);
    let assigned_native = OverflowInteger::evaluate_native(
        ctx,
        fp_chip.range().gate(),
        limbs.to_vec(),
        &fp_chip.limb_bases
    );
    let assigned_uint = CRTInteger::new(assigned_uint, assigned_native, value.to_bigint().unwrap());

    fp_chip.carry_mod(ctx, assigned_uint)
}

pub(crate) fn mod_inverse<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    num: ProperCrtUint<F>
) -> ProperCrtUint<F> {
    let one = ctx.load_constant(F::ONE);
    let one_int = fp_chip.load_constant_uint(ctx, BigUint::from(1u64));

    let p = fp_chip.p.to_biguint().unwrap();
    let p_minus_two = p.clone() - 2u64;

    let num_native = num.value();
    let inverse_native = num_native.modpow(&p_minus_two, &p);
    assert_eq!((num_native * inverse_native.clone()) % p, BigUint::from(1u64));

    let mod_inverse = fp_chip.load_constant_uint(ctx, inverse_native);
    let is_one = fp_chip.mul(ctx, num, mod_inverse.clone());
    let is_equal = fp_chip.is_equal(ctx, is_one, one_int);
    ctx.constrain_equal(&is_equal, &one);

    mod_inverse
}
