use std::iter;

use halo2_base::{
    gates::{GateInstructions, RangeInstructions, flex_gate::threads::ThreadManager},
    halo2_proofs::{halo2curves::CurveExt, plonk::Error},
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;

use crate::fields::{FieldChipExt, Selectable};

use super::{scalar_multiply_bits, EcPoint};

pub trait HashInstructions<F: BigPrimeField> {
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    type ThreadManager: ThreadManager<F>;
    type Output: IntoIterator<Item = AssignedValue<F>>;

    /// Digests input using hash function and returns finilized output.
    /// `MAX_INPUT_SIZE` is the maximum size of input that can be processed by the hash function.
    /// `strict` flag indicates whether to perform range check on input bytes.
    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        ctx: &mut Self::ThreadManager,
        input: impl Iterator<Item = QuantumCell<F>>,
        strict: bool,
    ) -> Result<Self::Output, Error>;
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

pub trait ExpandMessageChip {
    fn expand_message<F: BigPrimeField, HC: HashInstructions<F>>(
        ctx: &mut HC::ThreadManager,
        hash_chip: &HC,
        range: &impl RangeInstructions<F>,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error>;
}

pub trait HashToCurveInstructions<
    F: BigPrimeField,
    FC: FieldChipExt<F>,
    C: HashCurveExt<Base = FC::FieldType>,
> where
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
    ) -> EcPoint<F, FC::FieldPoint> {
        let max_bits = bits.len();
        scalar_multiply_bits(self.field_chip(), ctx, p, bits, max_bits, window_bits, true)
    }

    fn hash_to_field<HC: HashInstructions<F>, XC: ExpandMessageChip>(
        &self,
        thread_pool: &mut HC::ThreadManager,
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
        thread_pool: &mut HC::ThreadManager,
        hash_chip: &HC,
        range: &impl RangeInstructions<F>,
        msg: impl Iterator<Item = QuantumCell<F>>,
        dst: &[u8],
        len_in_bytes: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let gate = range.gate();

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
                QuantumCell::Witness(v) => thread_pool.main().load_witness(v),
                QuantumCell::Constant(v) => thread_pool.main().load_constant(v),
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

        let b_0 = hash_chip.digest::<143>(thread_pool, msg_prime, false)?.into_iter().collect_vec();

        b_vals.insert(
            0,
            hash_chip
                .digest::<77>(
                    thread_pool,
                    b_0.iter()
                        .copied()
                        .chain(iter::once(one))
                        .chain(dst_prime.clone())
                        .map(QuantumCell::Existing),
                    false,
                )?
                .into_iter()
                .collect_vec(),
        );

        for i in 1..ell {
            let preimg = strxor(b_0.iter().copied(), b_vals[i - 1].iter().copied(), gate, thread_pool.main())
                .into_iter()
                .chain(iter::once(thread_pool.main().load_constant(F::from(i as u64 + 1))))
                .chain(dst_prime.clone())
                .map(QuantumCell::Existing);

            b_vals.insert(i, hash_chip.digest::<77>(thread_pool, preimg, false)?.into_iter().collect_vec());
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
