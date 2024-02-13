use halo2_base::{ utils::BigPrimeField, AssignedValue, Context };

use crate::{ bigint::ProperCrtUint, ecc::EcPoint };

use self::{ hash_to_field::hash_to_field, map_to_curve::map_to_curve };

use super::{ sha256::Sha256Chip, Secp256k1Chip };

pub mod constants;
pub mod expand_message_xmd;
pub mod hash_to_field;
pub mod iso_map;
pub mod map_to_curve;
pub mod util;

pub fn hash_to_curve<F: BigPrimeField>(
    ctx: &mut Context<F>,
    secp256k1_chip: Secp256k1Chip<'_, F>,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>],
    q0_gx1_sqrt: ProperCrtUint<F>,
    q0_gx2_sqrt: ProperCrtUint<F>,
    q0_y_pos: ProperCrtUint<F>,
    q0_x_mapped: ProperCrtUint<F>,
    q0_y_mapped: ProperCrtUint<F>,
    q1_gx1_sqrt: ProperCrtUint<F>,
    q1_gx2_sqrt: ProperCrtUint<F>,
    q1_y_pos: ProperCrtUint<F>,
    q1_x_mapped: ProperCrtUint<F>,
    q1_y_mapped: ProperCrtUint<F>
) -> EcPoint<F, ProperCrtUint<F>> {
    let fp_chip = secp256k1_chip.field_chip();

    // Step 1: u = hash_to_field(msg)
    let (u0, u1) = hash_to_field(ctx, fp_chip, sha256_chip, msg_bytes);

    // Step 2: Q0 = map_to_curve(u[0])
    let (q0_x, q0_y2) = map_to_curve(
        ctx,
        fp_chip,
        u0,
        q0_gx1_sqrt,
        q0_gx2_sqrt,
        q0_y_pos,
        q0_x_mapped.clone(),
        q0_y_mapped.clone()
    );

    // Step 3: Q1 = map_to_curve(u[1])
    let (q1_x, q1_y2) = map_to_curve(
        ctx,
        fp_chip,
        u1,
        q1_gx1_sqrt,
        q1_gx2_sqrt,
        q1_y_pos,
        q1_x_mapped.clone(),
        q1_y_mapped.clone()
    );

    // Step 4: return A + B
    let q0 = EcPoint::<F, ProperCrtUint<F>>::new(q0_x_mapped, q0_y_mapped);
    let q1 = EcPoint::<F, ProperCrtUint<F>>::new(q1_x_mapped, q1_y_mapped);

    let point_add = secp256k1_chip.add_unequal(ctx, q0, q1, false);

    point_add
}

#[cfg(test)]
mod test {
    use halo2_base::{
        halo2_proofs::halo2curves::{ grumpkin::Fq as Fr, secp256k1::Secp256k1Affine, CurveAffine },
        utils::testing::base_test,
    };

    use crate::{
        ecc::EccChip,
        fields::FieldChip,
        secp256k1::{ sha256::Sha256Chip, FpChip, FqChip },
    };

    use super::hash_to_curve;

    #[test]
    fn test_hash_to_curve() {
        let msg = b"abcdef0123456789";
        let q0_gx1_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            8436907082510902807u64, 16481306271273964905u64, 12340693169241754123u64, 5840290864233247061u64,
        ]);
        let q0_gx2_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1u64, 0u64, 0u64, 0u64,
        ]);
        let q0_y_pos = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            8436907082510902807u64, 16481306271273964905u64, 12340693169241754123u64, 5840290864233247061u64,
        ]);
        let q0_x_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1666473185380682589u64, 5940335290811295862u64, 16073821616946219607u64, 6299765855519516506u64,
        ]);
        let q0_y_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            14183132322842682307u64, 3799824159173722014u64, 17680812620347148404u64, 7222729814779291343u64,
        ]);
        let q1_gx1_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            909194377947652581u64, 9506023292142230081u64, 13109065517192500057u64, 2140988711709947970u64,
        ]);
        let q1_gx2_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1u64, 0u64, 0u64, 0u64,
        ]);
        let q1_y_pos = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            909194377947652581u64, 9506023292142230081u64, 13109065517192500057u64, 2140988711709947970u64,
        ]);
        let q1_x_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            15496950058064191480u64, 16608196343028055450u64, 6698082460314400323u64, 17914594903168254206u64,
        ]);
        let q1_y_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            17158098838744772439u64, 14635829310764858396u64, 7975190798015443370u64, 12914166355471935767u64,
        ]);

        base_test()
            .k(15)
            .lookup_bits(14)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let fp_chip = FpChip::<Fr>::new(range, 64, 4);
                let fq_chip = FqChip::<Fr>::new(range, 64, 4);
                let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                let sha256_chip = Sha256Chip::new(range);

                let msg_bytes = msg
                    .iter()
                    .map(|&x| ctx.load_witness(Fr::from(x as u64)))
                    .collect::<Vec<_>>();

                let q0_gx1_sqrt = fq_chip.load_private(ctx, q0_gx1_sqrt);
                let q0_gx2_sqrt = fq_chip.load_private(ctx, q0_gx2_sqrt);
                let q0_y_pos = fq_chip.load_private(ctx, q0_y_pos);
                let q0_x_mapped = fq_chip.load_private(ctx, q0_x_mapped);
                let q0_y_mapped = fq_chip.load_private(ctx, q0_y_mapped);
                let q1_gx1_sqrt = fq_chip.load_private(ctx, q1_gx1_sqrt);
                let q1_gx2_sqrt = fq_chip.load_private(ctx, q1_gx2_sqrt);
                let q1_y_pos = fq_chip.load_private(ctx, q1_y_pos);
                let q1_x_mapped = fq_chip.load_private(ctx, q1_x_mapped);
                let q1_y_mapped = fq_chip.load_private(ctx, q1_y_mapped);

                let point = hash_to_curve(
                    ctx,
                    ecc_chip,
                    &sha256_chip,
                    msg_bytes.as_slice(),
                    q0_gx1_sqrt,
                    q0_gx2_sqrt,
                    q0_y_pos,
                    q0_x_mapped,
                    q0_y_mapped,
                    q1_gx1_sqrt,
                    q1_gx2_sqrt,
                    q1_y_pos,
                    q1_x_mapped,
                    q1_y_mapped
                );

                println!("point x: {:?}", point.x);
                println!("point y: {:?}", point.y);
            })
    }
}
