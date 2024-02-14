use halo2_base::{utils::BigPrimeField, AssignedValue, Context};

use crate::{bigint::ProperCrtUint, ecc::EcPoint};

use self::{hash_to_field::hash_to_field, map_to_curve::map_to_curve};

use super::{sha256::Sha256Chip, Secp256k1Chip};

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
) -> EcPoint<F, ProperCrtUint<F>> {
    let fp_chip = secp256k1_chip.field_chip();

    // Step 1: u = hash_to_field(msg)
    let (u0, u1) = hash_to_field(ctx, fp_chip, sha256_chip, msg_bytes);

    // Step 2: Q0 = map_to_curve(u[0])
    let (q0_x, q0_y) = map_to_curve(ctx, fp_chip, &u0);

    // Step 3: Q1 = map_to_curve(u[1])
    let (q1_x, q1_y) = map_to_curve(ctx, fp_chip, &u1);

    // Step 4: return A + B
    let q0 = EcPoint::<F, ProperCrtUint<F>>::new(q0_x, q0_y);
    let q1 = EcPoint::<F, ProperCrtUint<F>>::new(q1_x, q1_y);

    let point_add = secp256k1_chip.add_unequal(ctx, q0, q1, false);

    point_add
}

#[cfg(test)]
mod test {
    use halo2_base::{halo2_proofs::halo2curves::grumpkin::Fq as Fr, utils::testing::base_test};

    use crate::{
        ecc::EccChip,
        secp256k1::{sha256::Sha256Chip, FpChip},
    };

    use super::hash_to_curve;

    #[test]
    fn test_hash_to_curve() {
        let msg = b"abc";

        base_test().k(15).lookup_bits(14).expect_satisfied(true).run(|ctx, range| {
            let fp_chip = FpChip::<Fr>::new(range, 64, 4);
            let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

            let sha256_chip = Sha256Chip::new(range);

            let msg_bytes =
                msg.iter().map(|&x| ctx.load_witness(Fr::from(x as u64))).collect::<Vec<_>>();

            let point = hash_to_curve(ctx, ecc_chip, &sha256_chip, msg_bytes.as_slice());

            println!("point x: {:?}", point.x.value().to_str_radix(16));
            println!("point y: {:?}", point.y.value().to_str_radix(16));
        })
    }
}
