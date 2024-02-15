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
    secp256k1_chip: &Secp256k1Chip<'_, F>,
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

    struct TestData {
        message: String,
        point: (String, String),
    }

    #[test]
    fn test_hash_to_curve() {
        let test_data = vec![
            TestData {
                message: String::from(""),
                point: (
                    String::from(
                        "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"
                    ),
                    String::from(
                        "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"
                    ),
                ),
            },
            TestData {
                message: String::from("abc"),
                point: (
                    String::from(
                        "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"
                    ),
                    String::from(
                        "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"
                    ),
                ),
            },
            TestData {
                message: String::from("abcdef0123456789"),
                point: (
                    String::from(
                        "bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a"
                    ),
                    String::from(
                        "4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828"
                    ),
                ),
            },
            TestData {
                message: String::from(
                    "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
                ),
                point: (
                    String::from(
                        "e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9"
                    ),
                    String::from(
                        "f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873"
                    ),
                ),
            },
            TestData {
                message: String::from(
                    "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                point: (
                    String::from(
                        "e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998"
                    ),
                    String::from(
                        "8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6"
                    ),
                ),
            }
        ];

        base_test().k(15).lookup_bits(14).expect_satisfied(true).run(|ctx, range| {
            let fp_chip = FpChip::<Fr>::new(range, 88, 3);
            let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

            let sha256_chip = Sha256Chip::new(range);

            for i in 0..test_data.len() {
                let msg_bytes = test_data[i]
                    .message
                    .as_bytes()
                    .iter()
                    .map(|&x| ctx.load_witness(Fr::from(x as u64)))
                    .collect::<Vec<_>>();

                let point = hash_to_curve(ctx, &ecc_chip, &sha256_chip, msg_bytes.as_slice());

                assert_eq!(point.x.value().to_str_radix(16), test_data[i].point.0);
                assert_eq!(point.y.value().to_str_radix(16), test_data[i].point.1);
            }
        });
    }
}
