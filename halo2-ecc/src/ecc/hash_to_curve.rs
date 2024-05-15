//! Implements `draft-irtf-cfrg-hash-to-curve-16`.
//! https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16

use std::{iter, marker::PhantomData};

use halo2_base::{
    gates::{flex_gate::threads::CommonCircuitBuilder, GateInstructions, RangeInstructions},
    halo2_proofs::{halo2curves::CurveExt, plonk::Error},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;

use crate::ff::Field;
use crate::fields::{FieldChip, FieldChipExt, Selectable};

use super::{scalar_multiply_bits, EcPoint, EccChip};

/// Trait that defines basic interfaces of hash chips supporting custom region manangers (e.g. [`SinglePhaseCoreManager`]).
pub trait HashInstructions<F: BigPrimeField> {
    // Number of bytes absorbed in a single rount of hashing.
    const BLOCK_SIZE: usize;
    // Number of bytes in the output.
    const DIGEST_SIZE: usize;

    // Type of region manager used by the hash function.
    type CircuitBuilder: CommonCircuitBuilder<F>;
    // Type of output produced by the hash function.
    type Output: IntoIterator<Item = AssignedValue<F>>;

     /// Hashes the input of fixed size and returns finilized output.
    fn digest(
        &self,
        ctx: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
    ) -> Result<Self::Output, Error>;

    /// Hashes the input of dynamic (but capped) size and and returns finilized output.
    /// `max_input_len` is the maximum size of input that can be processed by the hash function.
    fn digest_varlen(
        &self,
        ctx: &mut Self::CircuitBuilder,
        input: impl IntoIterator<Item = QuantumCell<F>>,
        max_input_len: usize,
    ) -> Result<Self::Output, Error>;
}

/// Trait that extneds [`CurveExt`] with constants specific to hash to curve operations.
pub trait HashCurveExt: CurveExt
where
    Self::Base: crate::ff::PrimeField,
{
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

    const BLS_X: u64;
}

/// A trait for message expansion methods supported by [`HashToCurveChip`].
pub trait ExpandMessageChip {
    fn expand_message<F: BigPrimeField, HC: HashInstructions<F>>(
        thread_pool: &mut HC::CircuitBuilder,
        hash_chip: &HC,
        range: &impl RangeInstructions<F>,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;
}

/// Trait that defines methods used by the [`HashToCurveChip`] to the curve point for [`EccChip`].
pub trait HashToCurveInstructions<
    F: BigPrimeField,
    FC: FieldChipExt<F>,
    C: HashCurveExt<Base = FC::FieldType>,
> where
    FC::FieldType: crate::ff::PrimeField,
    FC: Selectable<F, FC::FieldPoint>,
{
    fn field_chip(&self) -> &FC;

    /// Computes `scalar * P` where scalar is represented as vector of [bits].
    fn scalar_mult_bits(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
        bits: Vec<AssignedValue<F>>,
        window_bits: usize,
    ) -> EcPoint<F, FC::FieldPoint> {
        let max_bits = bits.len();
        scalar_multiply_bits(self.field_chip(), ctx, p, bits, max_bits, window_bits, true)
    }

    /// Hashes a byte string of arbitrary length into one or more elements of `Self`,
    /// using [`ExpandMessage`] variant `X`.
    ///
    /// Implements [section 5.2 of `draft-irtf-cfrg-hash-to-curve-16`][hash_to_field].
    ///
    /// [hash_to_field]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.2
    fn hash_to_field<HC: HashInstructions<F>, XC: ExpandMessageChip>(
        &self,
        thread_pool: &mut HC::CircuitBuilder,
        hash_chip: &HC,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
    ) -> Result<[FC::FieldPoint; 2], Error>;

    /// Implements [Appendix E.3 of draft-irtf-cfrg-hash-to-curve-16][isogeny_map_g2]
    ///
    /// [isogeny_map_g2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-E.3
    fn isogeny_map(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>;

    /// Implements [Appendix G.3 of draft-irtf-cfrg-hash-to-curve-16][clear_cofactor]
    ///
    /// [clear_cofactor]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-G.3
    fn clear_cofactor(
        &self,
        ctx: &mut Context<F>,
        p: EcPoint<F, FC::FieldPoint>,
    ) -> EcPoint<F, FC::FieldPoint>;

    /// Specific case of `scalar * P` multiplication where scalar is [C::BLS_X] variant of [C: HashCurveExt].
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

    /// Computes the endomorphism psi for point [p].
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

    /// Efficiently omputes psi(psi(P)) for point [p].
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

/// Implementation of random oracle maps to the curve.
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
        HC: HashInstructions<F> + 'chip,
    > HashToCurveChip<'chip, F, FC, HC, C>
where
    FC::FieldType: crate::ff::PrimeField,
    FC: Selectable<F, FC::FieldPoint>,
    EccChip<'chip, F, FC>: HashToCurveInstructions<F, FC, C>,
{
    pub fn new(hash_chip: &'chip HC, field_chip: &'chip FC) -> Self {
        Self { hash_chip, ecc_chip: EccChip::new(field_chip), _curve: PhantomData }
    }

    /// Implements a uniform encoding from byte strings to elements of [`EcPoint<F, FC::FieldPoint>`].
    pub fn hash_to_curve<XC: ExpandMessageChip>(
        &self,
        thread_pool: &mut HC::CircuitBuilder,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
    ) -> Result<EcPoint<F, FC::FieldPoint>, Error> {
        let u = self.ecc_chip.hash_to_field::<_, XC>(thread_pool, self.hash_chip, msg, dst)?;
        let p = self.map_to_curve(thread_pool.main(), u)?;
        Ok(p)
    }

    /// Maps an element of the finite field `FC::FieldPoint` to a point on the curve [`EcPoint<F, FC::FieldPoint>`].
    fn map_to_curve(
        &self,
        ctx: &mut Context<F>,
        u: [FC::FieldPoint; 2],
    ) -> Result<EcPoint<F, FC::FieldPoint>, Error> {
        let [u0, u1] = u;

        let p1 = self.map_to_curve_simple_swu(ctx, u0);
        let p2 = self.map_to_curve_simple_swu(ctx, u1);

        let p_sum = self.ecc_chip.add_unequal(ctx, p1, p2, true);

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
    // Assumption: `num` != 0
    // Warning: `y_assigned` returned value can be sqrt(y_sqr) and -sqrt(y_sqr).
    // The sign of `y_assigned` must be constrainted at the callsite according to the composed algorithm.
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

        let num_is_zero = field_chip.is_zero(ctx, num.clone());
        field_chip.gate().assert_is_const(ctx, &num_is_zero, &F::ZERO);

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

/// Constructor for `expand_message_xmd` for a given digest hash function, message, DST,
/// and output length.
///
/// Implements [section 5.3.1 of `draft-irtf-cfrg-hash-to-curve-16`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.1
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
    fn expand_message<F: BigPrimeField, HC: HashInstructions<F>>(
        thread_pool: &mut HC::CircuitBuilder,
        hash_chip: &HC,
        range: &impl RangeInstructions<F>,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gate = range.gate();
        let ell = (len_in_bytes as f64 / HC::DIGEST_SIZE as f64).ceil() as usize;

        assert!(len_in_bytes >= 32, "Expand length must be at least 32 bytes");
        assert!(len_in_bytes <= 65535, "abort if len_in_bytes > 65535");
        assert!(dst.len() <= 255, "abort if DST len > 255");
        assert!(ell <= 255, "abort if ell > 255");

        let zero = thread_pool.main().load_zero();
        let one = thread_pool.main().load_constant(F::ONE);

        // assign DST bytes & cache them
        let dst_len = thread_pool.main().load_constant(F::from(dst.as_ref().len() as u64));
        let dst_prime = dst
            .as_ref()
            .iter()
            .map(|&b| thread_pool.main().load_constant(F::from(b as u64)))
            .chain(iter::once(dst_len))
            .collect_vec();

        // padding and length strings
        let z_pad = i2osp(0, HC::BLOCK_SIZE, |_| zero);
        let l_i_b_str = i2osp(len_in_bytes as u128, 2, |b| thread_pool.main().load_constant(b));

        let assigned_msg = msg
            .map(|cell| match cell {
                QuantumCell::Existing(v) => v,
                QuantumCell::Constant(v) => thread_pool.main().load_constant(v),
                _ => panic!("passing unassigned witness to this function is insecure"),
            })
            .collect_vec();

        // compute blocks
        let mut b_vals = Vec::with_capacity(ell);
        let msg_prime = z_pad
            .into_iter()
            .chain(assigned_msg)
            .chain(l_i_b_str)
            .chain(iter::once(zero))
            .chain(dst_prime.clone())
            .map(QuantumCell::Existing);

        let b_0 = hash_chip.digest(thread_pool, msg_prime)?.into_iter().collect_vec();

        b_vals.insert(
            0,
            hash_chip
                .digest(
                    thread_pool,
                    b_0.iter()
                        .copied()
                        .chain(iter::once(one))
                        .chain(dst_prime.clone())
                        .map(QuantumCell::Existing),
                )?
                .into_iter()
                .collect_vec(),
        );

        for i in 1..ell {
            let preimg = strxor(
                b_0.iter().copied(),
                b_vals[i - 1].iter().copied(),
                gate,
                thread_pool.main(),
            )
            .into_iter()
            .chain(iter::once(thread_pool.main().load_constant(F::from(i as u64 + 1))))
            .chain(dst_prime.clone())
            .map(QuantumCell::Existing);

            b_vals.insert(
                i,
                hash_chip.digest(thread_pool, preimg)?.into_iter().collect_vec(),
            );
        }

        let uniform_bytes = b_vals.into_iter().flatten().take(len_in_bytes).collect_vec();

        Ok(uniform_bytes)
    }
}

/// Integer to Octet Stream (numberToBytesBE)
pub fn i2osp<F: BigPrimeField>(
    mut value: u128,
    length: usize,
    mut f: impl FnMut(F) -> AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    let mut octet_string = vec![0; length];
    for i in (0..length).rev() {
        octet_string[i] = value & 0xff;
        value >>= 8;
    }
    octet_string.into_iter().map(|b| f(F::from(b as u64))).collect()
}

pub fn strxor<F: BigPrimeField>(
    a: impl IntoIterator<Item = AssignedValue<F>>,
    b: impl IntoIterator<Item = AssignedValue<F>>,
    gate: &impl GateInstructions<F>,
    ctx: &mut Context<F>,
) -> Vec<AssignedValue<F>> {
    a.into_iter().zip(b).map(|(a, b)| gate.bitwise_xor::<8>(ctx, a, b)).collect()
}
