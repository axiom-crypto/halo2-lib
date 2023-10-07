//! The chip that implements `draft-irtf-cfrg-hash-to-curve-16`
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use std::{iter, marker::PhantomData};

use super::utils::*;
use crate::ecc::EcPoint;
use crate::ff::Field;
use crate::fields::FieldChipExt;
use crate::halo2_base::{AssignedValue, Context, QuantumCell};
use crate::halo2_proofs::plonk::Error;
use crate::{
    ecc::EccChip,
    fields::{vector::FieldVector, FieldChip, Selectable},
};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bls12_381::{Fq2, G2};
use halo2_base::halo2_proofs::halo2curves::CurveExt;
use halo2_base::utils::BigPrimeField;
use itertools::Itertools;
use num_bigint::BigUint;

use super::{Fp2Chip, Fp2Point, G2Point};

pub trait HashInstructions<F: BigPrimeField> {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    type ThreadBuidler;

    /// Digests input using hash function and returns finilized output.
    /// `MAX_INPUT_SIZE` is the maximum size of input that can be processed by the hash function.
    /// `strict` flag indicates whether to perform range check on input bytes.
    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        ctx: &mut Self::ThreadBuidler,
        input: impl Iterator<Item = QuantumCell<F>>,
        strict: bool,
    ) -> Result<AssignedHashResult<F>, Error>;
}

pub trait HashEccChip<F: BigPrimeField, FC: FieldChipExt<F>, C: HashCurveExt<Base = FC::FieldType>>
where
    FC::FieldType: crate::ff::PrimeField,
    FC: Selectable<F, FC::FieldPoint>,
{
    fn field_chip(&self) -> &FC;

    fn scalar_mult_bits(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
        bits: Vec<AssignedValue<F>>,
        window_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint>;

    fn hash_to_field<HC: HashInstructions<F, ThreadBuidler = Context<F>>, XC: ExpandMessageChip>(
        &self,
        ctx: &mut HC::ThreadBuidler,
        hash_chip: &HC,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
    ) -> Result<[FC::FieldPoint; 2], Error>;

    fn isogeny_map(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>;

    fn clear_cofactor(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>;

    fn mul_by_bls_x(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint> {
        let bls_x_bits = (0..64)
            .map(|i| ((C::BLS_X >> i) & 1) as u8)
            .map(|b| ctx.load_constant(F::from(b as u64)))
            .collect_vec();

        self.scalar_mult_bits(ctx, p, bls_x_bits, 4)
    }

    fn psi(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint> {
        // 1 / ((u+1) ^ ((q-1)/3))
        let psi_x = self.field_chip().load_constant(ctx, C::PSI_X);

        // 1 / ((u+1) ^ (p-1)/2)
        let psi_y = self.field_chip().load_constant(ctx, C::PSI_Y);

        let x_frob = self.field_chip().conjugate(ctx, p.x);
        let y_frob = self.field_chip().conjugate(ctx, p.y);

        let x = self.field_chip().mul(ctx, x_frob, psi_x.clone());
        let y = self.field_chip().mul(ctx, y_frob, psi_y.clone());

        EcPoint::new(x, y)
    }

    fn psi2(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint> {
        // 1 / 2 ^ ((q-1)/3)
        let psi2_x = self.field_chip().load_constant(ctx, C::PSI2_X);

        let x = self.field_chip().mul(ctx, p.x, psi2_x.clone());
        let y = self.field_chip().negate(ctx, p.y);

        EcPoint::new(x, y)
    }
}

#[derive(Debug, Clone)]
pub struct AssignedHashResult<F: BigPrimeField> {
    // pub input_len: AssignedValue<F>,
    pub input_bytes: Vec<AssignedValue<F>>,
    pub output_bytes: [AssignedValue<F>; 32],
}

#[derive(Debug)]
pub struct HashToCurveChip<
    'chip,
    F: BigPrimeField,
    FC: FieldChip<F>,
    HC: HashInstructions<F>,
    C: HashCurveExt,
> {
    hash_chip: &'chip HC,
    ecc_chip: EccChip<'chip, F, FC>,
    _curve: PhantomData<C>,
}

impl<
        'chip,
        F: BigPrimeField,
        C: HashCurveExt<Base = FC::FieldType>,
        FC: FieldChipExt<F>,
        HC: HashInstructions<F, ThreadBuidler = Context<F>> + 'chip,
    > HashToCurveChip<'chip, F, FC, HC, C>
where
    FC::FieldType: crate::ff::PrimeField,
    FC: Selectable<F, FC::FieldPoint>,
    EccChip<'chip, F, FC>: HashEccChip<F, FC, C>,
{
    pub fn new(hash_chip: &'chip HC, field_chip: &'chip FC) -> Self {
        Self { hash_chip, ecc_chip: EccChip::new(field_chip), _curve: PhantomData }
    }

    pub fn hash_to_curve<XC: ExpandMessageChip>(
        &self,
        ctx: &mut HC::ThreadBuidler,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
    ) -> Result<EcPoint<F, FC::FieldPoint>, Error> {
        let u = self.ecc_chip.hash_to_field::<_, XC>(ctx, self.hash_chip, msg, dst)?;
        let p = self.map_to_curve(ctx, u)?;
        Ok(p)
    }

    fn map_to_curve(
        &self,
        ctx: &mut Context<F>,
        u: [FC::FieldPoint; 2],
    ) -> Result<EcPoint<F, FC::FieldPoint>, Error> {
        let [u0, u1] = u;

        let p1 = self.map_to_curve_simple_swu(ctx, u0);
        let p2 = self.map_to_curve_simple_swu(ctx, u1);

        let p_sum = self.ecc_chip.add_unequal(ctx, p1, p2, false);

        let iso_p = self.ecc_chip.isogeny_map(ctx, p_sum);

        Ok(self.ecc_chip.clear_cofactor(ctx, iso_p))
    }

    /// Implements [section 6.2 of draft-irtf-cfrg-hash-to-curve-16][map_to_curve_simple_swu]
    ///
    /// [map_to_curve_simple_swu]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.2
    ///
    /// References:
    /// - https://github.com/mikelodder7/bls12_381_plus/blob/ml/0.5.6/src/hash_to_curve/map_g2.rs#L388
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/weierstrass.ts#L1175
    fn map_to_curve_simple_swu(
        &self,
        ctx: &mut Context<F>,
        u: FC::FieldPoint,
    ) -> EcPoint<F, FC::FieldPoint> {
        let field_chip = self.ecc_chip.field_chip();
        let gate = field_chip.range().gate();

        // constants
        let swu_a = field_chip.load_constant(ctx, C::SWU_A);
        let swu_b = field_chip.load_constant(ctx, C::SWU_B);
        let swu_z = field_chip.load_constant(ctx, C::SWU_Z);
        let fq2_one = field_chip.load_constant(ctx, <C::Base as crate::ff::Field>::ONE);

        let usq = field_chip.mul(ctx, u.clone(), u.clone()); // 1.  tv1 = u^2
        let z_usq = field_chip.mul(ctx, usq, swu_z.clone()); // 2.  tv1 = Z * tv1
        let zsq_u4 = field_chip.mul(ctx, z_usq.clone(), z_usq.clone()); // 3.  tv2 = tv1^2
        let tv2 = field_chip.add(ctx, zsq_u4, z_usq.clone()); // 4.  tv2 = tv2 + tv1
        let tv3 = field_chip.add_no_carry(ctx, tv2.clone(), fq2_one); // 5.  tv3 = tv2 + 1
        let x0_num = field_chip.mul(ctx, tv3, swu_b.clone()); // 6.  tv3 = B * tv3

        let x_den = {
            let tv2_is_zero = field_chip.is_zero(ctx, tv2.clone());
            let tv2_neg = field_chip.negate(ctx, tv2);

            field_chip.select(ctx, swu_z, tv2_neg, tv2_is_zero) // tv2_is_zero ? swu_z : tv2_neg
        }; // 7.  tv4 = tv2 != 0 ? -tv2 : Z

        let x_den = field_chip.mul(ctx, x_den, swu_a.clone()); // 8.  tv4 = A * tv4

        let x0_num_sqr = field_chip.mul(ctx, x0_num.clone(), x0_num.clone()); // 9.  tv2 = tv3^2
        let x_densq = field_chip.mul(ctx, x_den.clone(), x_den.clone()); // 10. tv6 = tv4^2
        let ax_densq = field_chip.mul(ctx, x_densq.clone(), swu_a); // 11. tv5 = A * tv6
        let tv2 = field_chip.add_no_carry(ctx, x0_num_sqr, ax_densq); // 12. tv2 = tv2 + tv5
        let tv2 = field_chip.mul(ctx, tv2, x0_num.clone()); // 13. tv2 = tv2 * tv3
        let gx_den = field_chip.mul(ctx, x_densq, x_den.clone()); // 14. tv6 = tv6 * tv4
        let tv5 = field_chip.mul(ctx, gx_den.clone(), swu_b); // 15. tv5 = B * tv6
        let gx0_num = field_chip.add(ctx, tv2, tv5); // 16. tv2 = tv2 + tv5

        let x = field_chip.mul(ctx, &z_usq, &x0_num); // 17.  x = tv1 * tv3

        let (is_gx1_square, y1) = self.sqrt_ratio(ctx, gx0_num, gx_den); // 18.  (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

        let y = field_chip.mul(ctx, &z_usq, &u); // 19.  y = tv1 * u
        let y = field_chip.mul(ctx, y, y1.clone()); // 20.  y = y * y1
        let x = field_chip.select(ctx, x0_num, x, is_gx1_square); // 21.  x = is_gx1_square ? tv3 : x
        let y = field_chip.select(ctx, y1, y, is_gx1_square); // 22.  y = is_gx1_square ? y1 : y

        let to_neg = {
            let u_sgn = field_chip.sgn0(ctx, u);
            let y_sgn = field_chip.sgn0(ctx, y.clone());
            gate.xor(ctx, u_sgn, y_sgn)
        }; // 23.  e1 = sgn0(u) == sgn0(y) // we implement an opposite condition: !e1 = sgn0(u) ^ sgn0(y)

        let y_neg = field_chip.negate(ctx, y.clone());
        let y = field_chip.select(ctx, y_neg, y, to_neg); // 24.  y = !e1 ? -y : y
        let x = field_chip.divide(ctx, x, x_den); // 25.  x = x / tv4

        EcPoint::new(x, y)
    }

    // Implements [Appendix F.2.1 of draft-irtf-cfrg-hash-to-curve-16][sqrt_ration]
    //
    // [sqrt_ration]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-F.2.1
    fn sqrt_ratio(
        &self,
        ctx: &mut Context<F>,
        num: FC::FieldPoint,
        div: FC::FieldPoint,
    ) -> (AssignedValue<F>, FC::FieldPoint) {
        let field_chip = self.ecc_chip.field_chip();
        let num_v = field_chip.get_assigned_value(&num.clone().into());
        let div_v = field_chip.get_assigned_value(&div.clone().into());

        let (is_square, y) = FC::FieldType::sqrt_ratio(&num_v, &div_v);

        let is_square = ctx.load_witness(F::from(is_square.unwrap_u8() as u64));
        field_chip.gate().assert_bit(ctx, is_square); // assert is_square is boolean

        let y_assigned = field_chip.load_private(ctx, y);
        let y_sqr = field_chip.mul(ctx, y_assigned.clone(), y_assigned.clone()); // y_sqr = y1^2

        let ratio = field_chip.divide(ctx, num, div); // r = u / v

        let swu_z = field_chip.load_constant(ctx, C::SWU_Z);
        let ratio_z = field_chip.mul(ctx, ratio.clone(), swu_z.clone()); // r_z = r * z

        let y_check = field_chip.select(ctx, ratio, ratio_z, is_square); // y_check = is_square ? ratio : r_z

        field_chip.assert_equal(ctx, y_check, y_sqr); // assert y_check == y_sqr

        (is_square, y_assigned)
    }
}

const G2_EXT_DEGREE: usize = 2;

// L = ceil((ceil(log2(p)) + k) / 8) (see section 5 of ietf draft link above)
const L: usize = 64;

impl<'chip, F: BigPrimeField> HashEccChip<F, Fp2Chip<'chip, F>, G2>
    for EccChip<'chip, F, Fp2Chip<'chip, F>>
{
    fn field_chip(&self) -> &Fp2Chip<'chip, F> {
        self.field_chip
    }

    fn scalar_mult_bits(
        &self,
        ctx: &mut Context<F>,
        p: G2Point<F>,
        bits: Vec<AssignedValue<F>>,
        window_bits: usize,
    ) -> G2Point<F> {
        self.scalar_mult_bits(ctx, p, bits, window_bits)
    }

    /// Implements [section 5.2 of `draft-irtf-cfrg-hash-to-curve-16`][hash_to_field].
    ///
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.2
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L49
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L128
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L11
    fn hash_to_field<HC: HashInstructions<F, ThreadBuidler = Context<F>>, XC: ExpandMessageChip>(
        &self,
        ctx: &mut HC::ThreadBuidler,
        hash_chip: &HC,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
    ) -> Result<[Fp2Point<F>; 2], Error> {
        let fp_chip = self.field_chip().fp_chip();
        let range = fp_chip.range();
        let gate = range.gate();

        // constants
        let zero = ctx.load_zero();

        let extended_msg =
            XC::expand_message(ctx, hash_chip, range, msg, dst, 2 * G2_EXT_DEGREE * L)?;

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
                            let lo = decode_into_field_be::<F, _>(
                                ctx,
                                gate,
                                buf.to_vec(),
                                &fp_chip.limb_bases,
                                fp_chip.limb_bits(),
                            );

                            buf[rem..].copy_from_slice(&tv[32..]);
                            let hi = decode_into_field_be::<F, _>(
                                ctx,
                                gate,
                                buf.to_vec(),
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

pub trait ExpandMessageChip {
    fn expand_message<F: BigPrimeField, HC: HashInstructions<F, ThreadBuidler = Context<F>>>(
        ctx: &mut HC::ThreadBuidler,
        hash_chip: &HC,
        range: &impl RangeInstructions<F>,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;
}

pub struct ExpandMsgXmd;

impl ExpandMessageChip for ExpandMsgXmd {
    /// Implements [section 5.3 of `draft-irtf-cfrg-hash-to-curve-16`][expand_message_xmd].
    ///
    /// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3
    ///
    /// References:
    /// - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6ce20a1/poc/hash_to_field.py#L89
    /// - https://github.com/paulmillr/noble-curves/blob/bf70ba9/src/abstract/hash-to-curve.ts#L63
    /// - https://github.com/succinctlabs/telepathy-circuits/blob/d5c7771/circuits/hash_to_field.circom#L139
    fn expand_message<F: BigPrimeField, HC: HashInstructions<F, ThreadBuidler = Context<F>>>(
        ctx: &mut HC::ThreadBuidler,
        hash_chip: &HC,
        range: &impl RangeInstructions<F>,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gate = range.gate();

        let zero = ctx.load_zero();
        let one = ctx.load_constant(F::ONE);

        // assign DST bytes & cache them
        let dst_len = ctx.load_constant(F::from(dst.as_ref().len() as u64));
        let dst_prime = dst
            .as_ref()
            .iter()
            .map(|&b| ctx.load_constant(F::from(b as u64)))
            .chain(iter::once(dst_len))
            .collect_vec();

        // padding and length strings
        let z_pad = i2osp(0, HC::BLOCK_SIZE, |_| zero);
        let l_i_b_str = i2osp(len_in_bytes as u128, 2, |b| ctx.load_constant(b));

        let assigned_msg = msg
            .map(|cell| match cell {
                QuantumCell::Existing(v) => v,
                QuantumCell::Witness(v) => ctx.load_witness(v),
                QuantumCell::Constant(v) => ctx.load_constant(v),
                _ => unreachable!(),
            })
            .collect_vec();

        // compute blocks
        let ell = (len_in_bytes as f64 / HC::DIGEST_SIZE as f64).ceil() as usize;
        let mut b_vals = Vec::with_capacity(ell);
        let msg_prime = z_pad
            .into_iter()
            .chain(assigned_msg)
            .chain(l_i_b_str)
            .chain(iter::once(zero))
            .chain(dst_prime.clone())
            .map(QuantumCell::Existing);

        let b_0 = hash_chip.digest::<143>(ctx, msg_prime, false)?.output_bytes;

        b_vals.insert(
            0,
            hash_chip
                .digest::<77>(
                    ctx,
                    b_0.into_iter()
                        .chain(iter::once(one))
                        .chain(dst_prime.clone())
                        .map(QuantumCell::Existing),
                    false,
                )?
                .output_bytes,
        );

        for i in 1..ell {
            let preimg = strxor(b_0, b_vals[i - 1], gate, ctx)
                .into_iter()
                .chain(iter::once(ctx.load_constant(F::from(i as u64 + 1))))
                .chain(dst_prime.clone())
                .map(QuantumCell::Existing);

            b_vals.insert(i, hash_chip.digest::<77>(ctx, preimg, false)?.output_bytes);
        }

        let uniform_bytes = b_vals.into_iter().flatten().take(len_in_bytes).collect_vec();

        Ok(uniform_bytes)
    }
}

pub trait HashCurveExt: CurveExt
where
    Self::Base: crate::ff::PrimeField,
{
    type Fp: crate::ff::PrimeField + crate::ff::WithSmallOrderMulGroup<3>;

    const BLS_X: u64;

    const SWU_A: Self::Base;
    const SWU_B: Self::Base;
    const SWU_Z: Self::Base;

    const ISO_XNUM: [Self::Base; 4];
    const ISO_XDEN: [Self::Base; 3];
    const ISO_YNUM: [Self::Base; 4];
    const ISO_YDEN: [Self::Base; 4];

    const PSI_X: Self::Base;
    const PSI_Y: Self::Base;
    const PSI2_X: Self::Base;
}

mod bls12_381 {
    use halo2_base::halo2_proofs::halo2curves::bls12_381::{Fq, G2};

    use super::HashCurveExt;

    impl HashCurveExt for G2 {
        type Fp = Fq;

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
