//! The chip that implements `draft-irtf-cfrg-hash-to-curve-16` for BLS12-381 (G2).
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use super::{Fq2, G2};
use crate::bigint::utils::decode_into_bn;
use crate::ecc::hash_to_curve::{
    ExpandMessageChip, HashCurveExt, HashInstructions, HashToCurveInstructions,
};
use crate::ff::Field;
use crate::halo2_base::{Context, QuantumCell};
use crate::halo2_proofs::plonk::Error;
use crate::{
    ecc::EccChip,
    fields::{vector::FieldVector, FieldChip},
};
use halo2_base::gates::flex_gate::threads::CommonCircuitBuilder;
use halo2_base::gates::RangeInstructions;
use halo2_base::utils::BigPrimeField;
use itertools::Itertools;
use num_bigint::BigUint;

use super::{Fp2Chip, Fp2Point, G2Point};

const G2_EXT_DEGREE: usize = 2;
// L = ceil((ceil(log2(p)) + k) / 8) (see section 5 of ietf draft link above)
const L: usize = 64;

impl<'chip, F: BigPrimeField> HashToCurveInstructions<F, Fp2Chip<'chip, F>, G2>
    for EccChip<'chip, F, Fp2Chip<'chip, F>>
{
    fn field_chip(&self) -> &Fp2Chip<'chip, F> {
        self.field_chip
    }

    /// Implements [section 5.2 of `draft-irtf-cfrg-hash-to-curve-16`][hash_to_field].
    ///
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.2
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L49
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L128
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L11
    fn hash_to_field<HC: HashInstructions<F>, XC: ExpandMessageChip>(
        &self,
        thread_pool: &mut HC::CircuitBuilder,
        hash_chip: &HC,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
    ) -> Result<[Fp2Point<F>; 2], Error> {
        let fp_chip = self.field_chip().fp_chip();
        let range = fp_chip.range();
        let gate = range.gate();

        // constants
        let zero = thread_pool.main().load_zero();

        let extended_msg =
            XC::expand_message(thread_pool, hash_chip, range, msg, dst, 2 * G2_EXT_DEGREE * L)?;

        let ctx = thread_pool.main();

        // 2^256
        let two_pow_256 = fp_chip.load_constant_uint(ctx, BigUint::from(2u8).pow(256));
        let fq_bytes = 48; //((Fq::NUM_BITS as f64) / 8f64).ceil() as usize;

        let u = extended_msg
            .chunks(L)
            .chunks(G2_EXT_DEGREE)
            .into_iter()
            .map(|elm_chunk| {
                FieldVector(
                    elm_chunk
                        .map(|tv| {
                            let mut buf = vec![zero; fq_bytes];
                            let rem = fq_bytes - 32;
                            buf[rem..].copy_from_slice(&tv[..32]);
                            let lo = decode_into_bn::<F>(
                                ctx,
                                gate,
                                buf.iter().copied().rev().collect_vec(),
                                &fp_chip.limb_bases,
                                fp_chip.limb_bits(),
                            );

                            buf[rem..].copy_from_slice(&tv[32..]);
                            let hi = decode_into_bn::<F>(
                                ctx,
                                gate,
                                buf.into_iter().rev().collect_vec(),
                                &fp_chip.limb_bases,
                                fp_chip.limb_bits(),
                            );

                            let lo_2_256 = fp_chip.mul_no_carry(ctx, lo, two_pow_256.clone());
                            let lo_2_356_hi = fp_chip.add_no_carry(ctx, lo_2_256, hi);
                            fp_chip.carry_mod(ctx, lo_2_356_hi)
                        })
                        .collect_vec(),
                )
            })
            .collect_vec()
            .try_into()
            .unwrap();

        Ok(u)
    }

    /// Implements [Appendix E.3 of draft-irtf-cfrg-hash-to-curve-16][isogeny_map_g2]
    ///
    /// [isogeny_map_g2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-E.3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/g2.rs#L1153
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L167
    fn isogeny_map(&self, ctx: &mut Context<F>, p: G2Point<F>) -> G2Point<F> {
        let fp2_chip = self.field_chip();
        // constants
        let iso_coeffs = [
            G2::ISO_XNUM.to_vec(),
            G2::ISO_XDEN.to_vec(),
            G2::ISO_YNUM.to_vec(),
            G2::ISO_YDEN.to_vec(),
        ]
        .map(|coeffs| coeffs.into_iter().map(|iso| fp2_chip.load_constant(ctx, iso)).collect_vec());

        let fq2_zero = fp2_chip.load_constant(ctx, Fq2::ZERO);

        let [x_num, x_den, y_num, y_den] = iso_coeffs.map(|coeffs| {
            coeffs.into_iter().fold(fq2_zero.clone(), |acc, v| {
                let acc = fp2_chip.mul(ctx, acc, &p.x);
                let no_carry = fp2_chip.add_no_carry(ctx, acc, v);
                fp2_chip.carry_mod(ctx, no_carry)
            })
        });

        let x = { fp2_chip.divide_unsafe(ctx, x_num, x_den) };

        let y = {
            let tv = fp2_chip.divide_unsafe(ctx, y_num, y_den);
            fp2_chip.mul(ctx, &p.y, tv)
        };

        G2Point::new(x, y)
    }

    /// Implements [Appendix G.3 of draft-irtf-cfrg-hash-to-curve-16][clear_cofactor]
    ///
    /// [clear_cofactor]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-G.3
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/g2.rs#L956
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/bls12-381.ts#L1111
    fn clear_cofactor(&self, ctx: &mut Context<F>, p: G2Point<F>) -> G2Point<F> {
        let t1 = {
            // scalar multiplication is very expensive in terms of rows used
            // TODO: is there other ways to clear cofactor that avoid scalar multiplication?
            let tv = self.mul_by_bls_x(ctx, p.clone());
            self.negate(ctx, tv)
        }; // [-x]P

        let t2 = self.psi(ctx, p.clone()); // Ψ(P)

        let t3 = self.double(ctx, p.clone()); // 2P
        let t3 = self.psi2(ctx, t3); // Ψ²(2P)
        let t3 = self.sub_unequal(ctx, t3, t2.clone(), false); // Ψ²(2P) - Ψ(P)

        let t2 = self.add_unequal(ctx, t1.clone(), t2, false); // [-x]P + Ψ(P)
        let t2 = {
            let tv = self.mul_by_bls_x(ctx, t2);
            self.negate(ctx, tv)
        }; // [x²]P - [x]Ψ(P)

        // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P)
        let t3 = self.add_unequal(ctx, t3, t2, false);
        // Ψ²(2P) - Ψ(Plet ) + [x²]P - [x]Ψ(P) + [x]P
        let t3 = self.sub_unequal(ctx, t3, t1, false);

        // Ψ²(2P) - Ψ(P) + [x²]P - [x]Ψ(P) + [x]P - 1P => [x²-x-1]P + [x-1]Ψ(P) + Ψ²(2P)
        self.sub_unequal(ctx, t3, p, false)
    }
}

mod bls12_381 {
    #[cfg(feature = "halo2-axiom")]
    use halo2_base::halo2_proofs::halo2curves::bls12_381::{Fq, G2};
    #[cfg(feature = "halo2-pse")]
    use halo2curves::bls12_381::{Fq, G2};

    use super::HashCurveExt;

    impl HashCurveExt for G2 {
        const BLS_X: u64 = 0xd201000000010000;

        const SWU_A: Self::Base = Self::Base {
            c0: Fq::zero(),
            c1: Fq::from_raw_unchecked([
                0xe53a_0000_0313_5242,
                0x0108_0c0f_def8_0285,
                0xe788_9edb_e340_f6bd,
                0x0b51_3751_2631_0601,
                0x02d6_9857_17c7_44ab,
                0x1220_b4e9_79ea_5467,
            ]),
        };

        const SWU_B: Self::Base = Self::Base {
            c0: Fq::from_raw_unchecked([
                0x22ea_0000_0cf8_9db2,
                0x6ec8_32df_7138_0aa4,
                0x6e1b_9440_3db5_a66e,
                0x75bf_3c53_a794_73ba,
                0x3dd3_a569_412c_0a34,
                0x125c_db5e_74dc_4fd1,
            ]),
            c1: Fq::from_raw_unchecked([
                0x22ea_0000_0cf8_9db2,
                0x6ec8_32df_7138_0aa4,
                0x6e1b_9440_3db5_a66e,
                0x75bf_3c53_a794_73ba,
                0x3dd3_a569_412c_0a34,
                0x125c_db5e_74dc_4fd1,
            ]),
        };

        const SWU_Z: Self::Base = Self::Base {
            c0: Fq::from_raw_unchecked([
                0x87eb_ffff_fff9_555c,
                0x656f_ffe5_da8f_fffa,
                0x0fd0_7493_45d3_3ad2,
                0xd951_e663_0665_76f4,
                0xde29_1a3d_41e9_80d3,
                0x0815_664c_7dfe_040d,
            ]),
            c1: Fq::from_raw_unchecked([
                0x43f5_ffff_fffc_aaae,
                0x32b7_fff2_ed47_fffd,
                0x07e8_3a49_a2e9_9d69,
                0xeca8_f331_8332_bb7a,
                0xef14_8d1e_a0f4_c069,
                0x040a_b326_3eff_0206,
            ]),
        };

        /// Coefficients of the 3-isogeny x map's numerator
        const ISO_XNUM: [Self::Base; 4] = [
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x40aa_c71c_71c7_25ed,
                    0x1909_5555_7a84_e38e,
                    0xd817_050a_8f41_abc3,
                    0xd864_85d4_c87f_6fb1,
                    0x696e_b479_f885_d059,
                    0x198e_1a74_3280_02d2,
                ]),
                c1: Fq::zero(),
            },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x0a0c_5555_5559_71c3,
                    0xdb0c_0010_1f9e_aaae,
                    0xb1fb_2f94_1d79_7997,
                    0xd396_0742_ef41_6e1c,
                    0xb700_40e2_c205_56f4,
                    0x149d_7861_e581_393b,
                ]),
                c1: Fq::from_raw_unchecked([
                    0xaff2_aaaa_aaa6_38e8,
                    0x439f_ffee_91b5_5551,
                    0xb535_a30c_d937_7c8c,
                    0x90e1_4442_0443_a4a2,
                    0x941b_66d3_8146_55e2,
                    0x0563_9988_53fe_ad5e,
                ]),
            },
            Self::Base {
                c0: Fq::zero(),
                c1: Fq::from_raw_unchecked([
                    0x5fe5_5555_554c_71d0,
                    0x873f_ffdd_236a_aaa3,
                    0x6a6b_4619_b26e_f918,
                    0x21c2_8884_0887_4945,
                    0x2836_cda7_028c_abc5,
                    0x0ac7_3310_a7fd_5abd,
                ]),
            },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x47f6_71c7_1ce0_5e62,
                    0x06dd_5707_1206_393e,
                    0x7c80_cd2a_f3fd_71a2,
                    0x0481_03ea_9e6c_d062,
                    0xc545_16ac_c8d0_37f6,
                    0x1380_8f55_0920_ea41,
                ]),
                c1: Fq::from_raw_unchecked([
                    0x47f6_71c7_1ce0_5e62,
                    0x06dd_5707_1206_393e,
                    0x7c80_cd2a_f3fd_71a2,
                    0x0481_03ea_9e6c_d062,
                    0xc545_16ac_c8d0_37f6,
                    0x1380_8f55_0920_ea41,
                ]),
            },
        ];

        /// Coefficients of the 3-isogeny x map's denominator
        const ISO_XDEN: [Self::Base; 3] = [
            // Self::Fp::zero(),
            Self::Base { c0: Fq::one(), c1: Fq::zero() },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x4476_0000_0027_552e,
                    0xdcb8_009a_4348_0020,
                    0x6f7e_e9ce_4a6e_8b59,
                    0xb103_30b7_c0a9_5bc6,
                    0x6140_b1fc_fb1e_54b7,
                    0x0381_be09_7f0b_b4e1,
                ]),
                c1: Fq::from_raw_unchecked([
                    0x7588_ffff_ffd8_557d,
                    0x41f3_ff64_6e0b_ffdf,
                    0xf7b1_e8d2_ac42_6aca,
                    0xb374_1acd_32db_b6f8,
                    0xe9da_f5b9_482d_581f,
                    0x167f_53e0_ba74_31b8,
                ]),
            },
            Self::Base {
                c0: Fq::zero(),
                c1: Fq::from_raw_unchecked([
                    0x1f3a_ffff_ff13_ab97,
                    0xf25b_fc61_1da3_ff3e,
                    0xca37_57cb_3819_b208,
                    0x3e64_2736_6f8c_ec18,
                    0x0397_7bc8_6095_b089,
                    0x04f6_9db1_3f39_a952,
                ]),
            },
        ];

        /// Coefficients of the 3-isogeny y map's numerator
        const ISO_YNUM: [Self::Base; 4] = [
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0xa470_bda1_2f67_f35c,
                    0xc0fe_38e2_3327_b425,
                    0xc9d3_d0f2_c6f0_678d,
                    0x1c55_c993_5b5a_982e,
                    0x27f6_c0e2_f074_6764,
                    0x117c_5e6e_28aa_9054,
                ]),
                c1: Fq::zero(),
            },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0xd7f9_5555_5553_1c74,
                    0x21cf_fff7_48da_aaa8,
                    0x5a9a_d186_6c9b_be46,
                    0x4870_a221_0221_d251,
                    0x4a0d_b369_c0a3_2af1,
                    0x02b1_ccc4_29ff_56af,
                ]),
                c1: Fq::from_raw_unchecked([
                    0xe205_aaaa_aaac_8e37,
                    0xfcdc_0007_6879_5556,
                    0x0c96_011a_8a15_37dd,
                    0x1c06_a963_f163_406e,
                    0x010d_f44c_82a8_81e6,
                    0x174f_4526_0f80_8feb,
                ]),
            },
            Self::Base {
                c0: Fq::zero(),
                c1: Fq::from_raw_unchecked([
                    0xbf0a_71c7_1c91_b406,
                    0x4d6d_55d2_8b76_38fd,
                    0x9d82_f98e_5f20_5aee,
                    0xa27a_a27b_1d1a_18d5,
                    0x02c3_b2b2_d293_8e86,
                    0x0c7d_1342_0b09_807f,
                ]),
            },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x96d8_f684_bdfc_77be,
                    0xb530_e4f4_3b66_d0e2,
                    0x184a_88ff_3796_52fd,
                    0x57cb_23ec_fae8_04e1,
                    0x0fd2_e39e_ada3_eba9,
                    0x08c8_055e_31c5_d5c3,
                ]),
                c1: Fq::from_raw_unchecked([
                    0x96d8_f684_bdfc_77be,
                    0xb530_e4f4_3b66_d0e2,
                    0x184a_88ff_3796_52fd,
                    0x57cb_23ec_fae8_04e1,
                    0x0fd2_e39e_ada3_eba9,
                    0x08c8_055e_31c5_d5c3,
                ]),
            },
        ];

        /// Coefficients of the 3-isogeny y map's denominator
        const ISO_YDEN: [Self::Base; 4] = [
            Self::Base { c0: Fq::one(), c1: Fq::zero() },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x66b1_0000_003a_ffc5,
                    0xcb14_00e7_64ec_0030,
                    0xa73e_5eb5_6fa5_d106,
                    0x8984_c913_a0fe_09a9,
                    0x11e1_0afb_78ad_7f13,
                    0x0542_9d0e_3e91_8f52,
                ]),
                c1: Fq::from_raw_unchecked([
                    0x534d_ffff_ffc4_aae6,
                    0x5397_ff17_4c67_ffcf,
                    0xbff2_73eb_870b_251d,
                    0xdaf2_8271_5287_0915,
                    0x393a_9cba_ca9e_2dc3,
                    0x14be_74db_faee_5748,
                ]),
            },
            Self::Base {
                c0: Fq::zero(),
                c1: Fq::from_raw_unchecked([
                    0x5db0_ffff_fd3b_02c5,
                    0xd713_f523_58eb_fdba,
                    0x5ea6_0761_a84d_161a,
                    0xbb2c_75a3_4ea6_c44a,
                    0x0ac6_7359_21c1_119b,
                    0x0ee3_d913_bdac_fbf6,
                ]),
            },
            Self::Base {
                c0: Fq::from_raw_unchecked([
                    0x0162_ffff_fa76_5adf,
                    0x8f7b_ea48_0083_fb75,
                    0x561b_3c22_59e9_3611,
                    0x11e1_9fc1_a9c8_75d5,
                    0xca71_3efc_0036_7660,
                    0x03c6_a03d_41da_1151,
                ]),
                c1: Fq::from_raw_unchecked([
                    0x0162_ffff_fa76_5adf,
                    0x8f7b_ea48_0083_fb75,
                    0x561b_3c22_59e9_3611,
                    0x11e1_9fc1_a9c8_75d5,
                    0xca71_3efc_0036_7660,
                    0x03c6_a03d_41da_1151,
                ]),
            },
        ];

        const PSI_X: Self::Base = Self::Base {
            c0: Fq::zero(),
            c1: Fq::from_raw_unchecked([
                0x890dc9e4867545c3,
                0x2af322533285a5d5,
                0x50880866309b7e2c,
                0xa20d1b8c7e881024,
                0x14e4f04fe2db9068,
                0x14e56d3f1564853a,
            ]),
        };

        const PSI_Y: Self::Base = Self::Base {
            c0: Fq::from_raw_unchecked([
                0x3e2f585da55c9ad1,
                0x4294213d86c18183,
                0x382844c88b623732,
                0x92ad2afd19103e18,
                0x1d794e4fac7cf0b9,
                0x0bd592fc7d825ec8,
            ]),
            c1: Fq::from_raw_unchecked([
                0x7bcfa7a25aa30fda,
                0xdc17dec12a927e7c,
                0x2f088dd86b4ebef1,
                0xd1ca2087da74d4a7,
                0x2da2596696cebc1d,
                0x0e2b7eedbbfd87d2,
            ]),
        };

        const PSI2_X: Self::Base = Self::Base {
            c0: Fq::from_raw_unchecked([
                0xcd03c9e48671f071,
                0x5dab22461fcda5d2,
                0x587042afd3851b95,
                0x8eb60ebe01bacb9e,
                0x03f97d6e83d050d2,
                0x18f0206554638741,
            ]),
            c1: Fq::zero(),
        };
    }
}
