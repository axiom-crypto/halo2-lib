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
        // msg = "abc"
        let msg = vec![97u64, 98u64, 99u64];
        let q0_gx1_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1664545361815120357u64, 10283872013620121914u64, 9380010581010034654u64, 4261145792225450732u64,
        ]);
        let q0_gx2_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1u64, 0u64, 0u64, 0u64,
        ]);
        let q0_y_pos = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1664545361815120357u64, 10283872013620121914u64, 9380010581010034654u64, 4261145792225450732u64,
        ]);
        let q0_x_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            5925487804738118359u64, 4856574525535083224u64, 12797074899347248930u64, 566772074147120223u64,
        ]);
        let q0_y_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            4617496280555238207u64, 14690993926117989357u64, 3636581750055392523u64, 6937101362475356158u64,
        ]);
        let q1_gx1_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            7355280221998350180u64, 4783425048112263089u64, 5071308975172430165u64, 3916832897263395160u64,
        ]);
        let q1_gx2_sqrt = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1u64, 0u64, 0u64, 0u64,
        ]);
        let q1_y_pos = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            7355280221998350180u64, 4783425048112263089u64, 5071308975172430165u64, 3916832897263395160u64,
        ]);
        let q1_x_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            13296707460026998648u64, 318503968633800990u64, 15989839026330281858u64, 16856858595694562935u64,
        ]);
        let q1_y_mapped = <Secp256k1Affine as CurveAffine>::ScalarExt::from([
            1338026386978707379u64, 6209856281762218480u64, 13772974005733639516u64, 14629888772142879508u64,
        ]);

        base_test()
            .k(20)
            .lookup_bits(19)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let fp_chip = FpChip::<Fr>::new(range, 88, 3);
                let fq_chip = FqChip::<Fr>::new(range, 88, 3);
                let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                let sha256_chip = Sha256Chip::new(range);

                let msg_bytes = msg
                    .iter()
                    .map(|&x| ctx.load_witness(Fr::from(x)))
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
