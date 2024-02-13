use halo2_base::{ gates::RangeChip, utils::BigPrimeField, AssignedValue, Context };
use num_bigint::BigUint;
use num_integer::div_ceil;
use num_traits::Num;
use crate::{ bigint::ProperCrtUint, secp256k1::FpChip };
use super::util::limbs_le_to_bigint;

pub(crate) fn get_z_pad<F: BigPrimeField>(ctx: &mut Context<F>) -> Vec<AssignedValue<F>> {
    let zero = ctx.load_zero();
    vec![zero; 64]
}

pub(crate) fn get_lib_str<F: BigPrimeField>(ctx: &mut Context<F>) -> Vec<AssignedValue<F>> {
    let zero = ctx.load_zero();
    let ninety_six = ctx.load_constant(F::from(96));
    vec![zero, ninety_six]
}

pub(crate) fn get_dst_prime<F: BigPrimeField>(ctx: &mut Context<F>) -> Vec<AssignedValue<F>> {
    let dst_prime = [
        81, 85, 85, 88, 45, 86, 48, 49, 45, 67, 83, 48, 50, 45, 119, 105, 116, 104, 45, 115, 101, 99,
        112, 50, 53, 54, 107, 49, 95, 88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87,
        85, 95, 82, 79, 95, 49,
    ];
    dst_prime
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>()
}

// Z = 115792089237316195423570985008687907853269984665640564039457584007908834671652
pub(crate) fn get_Z<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let z = BigUint::from_str_radix(
        "115792089237316195423570985008687907853269984665640564039457584007908834671652",
        10
    )
        .unwrap()
        .to_bytes_le();

    let mut z_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(z.len(), 11));
    for chunk in z.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        z_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, z_limbs.as_slice())
}

// A = 28734576633528757162648956269730739219262246272443394170905244663053633733939
pub(crate) fn get_A<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let a = BigUint::from_str_radix(
        "28734576633528757162648956269730739219262246272443394170905244663053633733939",
        10
    )
        .unwrap()
        .to_bytes_le();

    let mut a_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(a.len(), 11));
    for chunk in a.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        a_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, a_limbs.as_slice())
}

pub(crate) fn get_B<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let b = BigUint::from(1771).to_bytes_le();

    let mut b_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(b.len(), 11));
    for chunk in b.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        b_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, b_limbs.as_slice())
}

pub(crate) fn get_C1<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let c1 = [12250307269654431171, 7923238676646950141, 11532678464006552332, 848203876191778994];
    let c1 = c1
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();

    limbs_le_to_bigint(ctx, range, fp_chip, c1.as_slice(), 64)
}

pub(crate) fn get_C2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let c2 = [1676976732802240618, 15092790605762360413, 6707906935894382405, 5030930201920786804];
    let c2 = c2
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();

    limbs_le_to_bigint(ctx, range, fp_chip, c2.as_slice(), 64)
}

// k_(1,0) = 0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7
pub(crate) fn get_k_1_0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(1,1) = 0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581
pub(crate) fn get_k_1_1<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(1,2) = 0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262
pub(crate) fn get_k_1_2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(1,3) = 0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c
pub(crate) fn get_k_1_3<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(2,0) = 0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b
pub(crate) fn get_k_2_0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(2,1) = 0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14
pub(crate) fn get_k_2_1<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(3,0) = 0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c
pub(crate) fn get_k_3_0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(3,1) = 0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3
pub(crate) fn get_k_3_1<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(3,2) = 0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931
pub(crate) fn get_k_3_2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(3,3) = 0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84
pub(crate) fn get_k_3_3<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(4,0) = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b
pub(crate) fn get_k_4_0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(4,1) = 0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573
pub(crate) fn get_k_4_1<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}

// k_(4,2) = 0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f
pub(crate) fn get_k_4_2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fp_chip: &FpChip<'_, F>
) -> ProperCrtUint<F> {
    let k_bytes = BigUint::from_str_radix(
        "0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f",
        16
    )
        .unwrap()
        .to_bytes_le();

    let mut k_limbs = Vec::<AssignedValue<F>>::with_capacity(div_ceil(k_bytes.len(), 11));
    for chunk in k_bytes.chunks(11) {
        let limb = ctx.load_witness(F::from_bytes_le(chunk));
        k_limbs.push(limb);
    }

    limbs_le_to_bigint(ctx, range, fp_chip, k_limbs.as_slice())
}
