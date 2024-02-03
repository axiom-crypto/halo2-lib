use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::plonk::Error,
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;

use crate::secp256k1::util::{bits_le_to_fe, fe_to_bits_le};

use super::spread::SpreadChip;

pub const NUM_ROUND: usize = 64;
pub const NUM_STATE_WORD: usize = 8;
const ROUND_CONSTANTS: [u32; NUM_ROUND] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const INIT_STATE: [u32; NUM_STATE_WORD] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

pub type SpreadU32<'a, F> = (AssignedValue<F>, AssignedValue<F>);

pub fn sha256_compression<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    assigned_input_bytes: &[AssignedValue<F>],
    pre_state_words: &[AssignedValue<F>],
) -> Result<Vec<AssignedValue<F>>, Error> {
    debug_assert_eq!(assigned_input_bytes.len(), 64);
    debug_assert_eq!(pre_state_words.len(), 8);
    let range = spread_chip.range();
    let gate = range.gate();
    // message schedule.
    let mut i = 0;
    let mut message_u32s = assigned_input_bytes
        .chunks(4)
        .map(|bytes| {
            let mut sum = ctx.load_zero();
            for idx in 0..4 {
                sum = gate.mul_add(
                    ctx,
                    QuantumCell::Existing(bytes[3 - idx]),
                    QuantumCell::Constant(F::from(1u64 << (8 * idx))),
                    QuantumCell::Existing(sum),
                );
            }
            i += 1;
            // println!("idx {} sum {:?}", i, sum.value());
            sum
        })
        .collect_vec();

    // let mut message_bits = message_u32s
    //     .iter()
    //     .map(|val: &AssignedValue<F>| gate.num_to_bits(ctx, val, 32))
    //     .collect_vec();
    let mut message_spreads = message_u32s
        .iter()
        .map(|dense| state_to_spread_u32(ctx, spread_chip, dense))
        .collect::<Result<Vec<SpreadU32<F>>, Error>>()?;
    for idx in 16..64 {
        // let w_2_spread = state_to_spread_u32(ctx, range, ctx_spread, &message_u32s[idx - 2])?;
        // let w_15_spread = state_to_spread_u32(ctx, range, ctx_spread, &message_u32s[idx - 15])?;
        let term1 = sigma_lower1(ctx, spread_chip, &message_spreads[idx - 2])?;
        let term3 = sigma_lower0(ctx, spread_chip, &message_spreads[idx - 15])?;
        // let term1_u32 = bits2u32(ctx, gate, &term1_bits);
        // let term3_u32 = bits2u32(ctx, gate, &term3_bits);
        let new_w = {
            let mut sum = gate.add(ctx, term1, message_u32s[idx - 7]);
            sum = gate.add(ctx, sum, term3);
            sum = gate.add(ctx, sum, message_u32s[idx - 16]);
            mod_u32(ctx, range, &sum)
        };
        // println!(
        //     "idx {} term1 {:?}, term3 {:?}, new_w {:?}",
        //     idx,
        //     term1.value(),
        //     term3.value(),
        //     new_w.value()
        // );
        message_u32s.push(new_w);
        let new_w_spread = state_to_spread_u32(ctx, spread_chip, &new_w)?;
        message_spreads.push(new_w_spread);
        // if idx <= 61 {
        //     let new_w_bits = gate.num_to_bits(ctx, &new_w, 32);
        //     message_bits.push(new_w_bits);
        // }
    }

    // compression
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        pre_state_words[0],
        pre_state_words[1],
        pre_state_words[2],
        pre_state_words[3],
        pre_state_words[4],
        pre_state_words[5],
        pre_state_words[6],
        pre_state_words[7],
    );
    let mut a_spread = state_to_spread_u32(ctx, spread_chip, &a)?;
    let mut b_spread = state_to_spread_u32(ctx, spread_chip, &b)?;
    let mut c_spread = state_to_spread_u32(ctx, spread_chip, &c)?;
    // let mut d_spread = state_to_spread_u32(ctx, range, ctx_spread, &d)?;
    let mut e_spread = state_to_spread_u32(ctx, spread_chip, &e)?;
    let mut f_spread = state_to_spread_u32(ctx, spread_chip, &f)?;
    let mut g_spread = state_to_spread_u32(ctx, spread_chip, &g)?;
    // let mut h_spread = state_to_spread_u32(ctx, range, ctx_spread, &h)?;
    // let mut a_bits = gate.num_to_bits(ctx, &a, 32);
    // let mut b_bits = gate.num_to_bits(ctx, &b, 32);
    // let mut c_bits = gate.num_to_bits(ctx, &c, 32);
    // let mut e_bits = gate.num_to_bits(ctx, &e, 32);
    // let mut f_bits = gate.num_to_bits(ctx, &f, 32);
    // let mut g_bits = gate.num_to_bits(ctx, &g, 32);
    #[allow(unused_assignments)]
    let mut t1 = ctx.load_zero();
    #[allow(unused_assignments)]
    let mut t2 = ctx.load_zero();
    for idx in 0..64 {
        t1 = {
            // let e_spread = state_to_spread_u32(ctx, range, ctx_spread, &e)?;
            // let f_spread = state_to_spread_u32(ctx, range, ctx_spread, &f)?;
            // let g_spread = state_to_spread_u32(ctx, range, ctx_spread, &g)?;
            let sigma_term = sigma_upper1(ctx, spread_chip, &e_spread)?;
            let ch_term = ch(ctx, spread_chip, &e_spread, &f_spread, &g_spread)?;
            // println!(
            //     "idx {} sigma {:?} ch {:?}",
            //     idx,
            //     sigma_term.value(),
            //     ch_term.value()
            // );
            let add1 = gate.add(ctx, h, sigma_term);
            let add2 = gate.add(ctx, QuantumCell::Existing(add1), QuantumCell::Existing(ch_term));
            let add3 = gate.add(
                ctx,
                QuantumCell::Existing(add2),
                QuantumCell::Constant(F::from(ROUND_CONSTANTS[idx] as u64)),
            );
            let add4 = gate.add(
                ctx,
                QuantumCell::Existing(add3),
                QuantumCell::Existing(message_u32s[idx]),
            );
            mod_u32(ctx, range, &add4)
        };
        t2 = {
            // let a_spread = state_to_spread_u32(ctx, range, ctx_spread, &a)?;
            // let b_spread = state_to_spread_u32(ctx, range, ctx_spread, &b)?;
            // let c_spread = state_to_spread_u32(ctx, range, ctx_spread, &c)?;
            let sigma_term = sigma_upper0(ctx, spread_chip, &a_spread)?;
            let maj_term = maj(ctx, spread_chip, &a_spread, &b_spread, &c_spread)?;
            let add =
                gate.add(ctx, QuantumCell::Existing(sigma_term), QuantumCell::Existing(maj_term));
            mod_u32(ctx, range, &add)
        };
        // println!("idx {}, t1 {:?}, t2 {:?}", idx, t1.value(), t2.value());
        h = g;
        // h_spread = g_spread;
        g = f;
        g_spread = f_spread;
        f = e;
        f_spread = e_spread;
        e = {
            let add = gate.add(ctx, QuantumCell::Existing(d), QuantumCell::Existing(t1));
            mod_u32(ctx, range, &add)
        };
        e_spread = state_to_spread_u32(ctx, spread_chip, &e)?;
        d = c;
        // d_spread = c_spread;
        c = b;
        c_spread = b_spread;
        b = a;
        b_spread = a_spread;
        a = {
            let add = gate.add(ctx, QuantumCell::Existing(t1), QuantumCell::Existing(t2));
            mod_u32(ctx, range, &add)
        };
        a_spread = state_to_spread_u32(ctx, spread_chip, &a)?;
    }
    let new_states = [a, b, c, d, e, f, g, h];
    let next_state_words = new_states
        .iter()
        .copied()
        .zip(pre_state_words.iter().copied())
        .map(|(x, y)| {
            let add = gate.add(ctx, QuantumCell::Existing(x), QuantumCell::Existing(y));
            // println!(
            //     "pre {:?} new {:?} add {:?}",
            //     y.value(),
            //     x.value(),
            //     add.value()
            // );
            mod_u32(ctx, range, &add)
        })
        .collect_vec();
    Ok(next_state_words)
}

fn state_to_spread_u32<'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x: &AssignedValue<F>,
) -> Result<SpreadU32<'a, F>, Error> {
    let gate = spread_chip.range().gate();
    let lo = F::from((x.value().get_lower_32() & ((1 << 16) - 1)) as u64);
    let hi = F::from((x.value().get_lower_32() >> 16) as u64);
    let assigned_lo = ctx.load_witness(lo);
    let assigned_hi = ctx.load_witness(hi);
    let composed = gate.mul_add(
        ctx,
        QuantumCell::Existing(assigned_hi),
        QuantumCell::Constant(F::from(1u64 << 16)),
        QuantumCell::Existing(assigned_lo),
    );
    ctx.constrain_equal(x, &composed);
    let lo_spread = spread_chip.spread(ctx, &assigned_lo)?;
    let hi_spread = spread_chip.spread(ctx, &assigned_hi)?;
    Ok((lo_spread, hi_spread))
}

fn mod_u32<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &impl RangeInstructions<F>,
    x: &AssignedValue<F>,
) -> AssignedValue<F> {
    let gate = range.gate();
    let lo = F::from(x.value().get_lower_32() as u64);
    let hi = F::from((x.value().get_lower_64() >> 32) & ((1u64 << 32) - 1));
    let assigned_lo = ctx.load_witness(lo);
    let assigned_hi = ctx.load_witness(hi);
    range.range_check(ctx, assigned_lo, 32);
    let composed =
        gate.mul_add(ctx, assigned_hi, QuantumCell::Constant(F::from(1u64 << 32)), assigned_lo);
    ctx.constrain_equal(x, &composed);
    assigned_lo
}

fn ch<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x: &SpreadU32<'a, F>,
    y: &SpreadU32<'a, F>,
    z: &SpreadU32<'a, F>,
) -> Result<AssignedValue<F>, Error> {
    let (x_lo, x_hi) = *x;
    let (y_lo, y_hi) = *y;
    let (z_lo, z_hi) = *z;
    let range = spread_chip.range();
    let gate = range.gate();
    let p_lo = gate.add(ctx, QuantumCell::Existing(x_lo), QuantumCell::Existing(y_lo));
    let p_hi = gate.add(ctx, QuantumCell::Existing(x_hi), QuantumCell::Existing(y_hi));
    const MASK_EVEN_32: u64 = 0x55555555;
    let x_neg_lo = gate.neg(ctx, QuantumCell::Existing(x_lo));
    let x_neg_hi = gate.neg(ctx, QuantumCell::Existing(x_hi));
    let q_lo = three_add(
        ctx,
        gate,
        QuantumCell::Constant(F::from(MASK_EVEN_32)),
        QuantumCell::Existing(x_neg_lo),
        QuantumCell::Existing(z_lo),
    );
    let q_hi = three_add(
        ctx,
        gate,
        QuantumCell::Constant(F::from(MASK_EVEN_32)),
        QuantumCell::Existing(x_neg_hi),
        QuantumCell::Existing(z_hi),
    );
    let (p_lo_even, p_lo_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &p_lo)?;
    let (p_hi_even, p_hi_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &p_hi)?;
    let (q_lo_even, q_lo_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &q_lo)?;
    let (q_hi_even, q_hi_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &q_hi)?;
    {
        let even_spread = spread_chip.spread(ctx, &p_lo_even)?;
        let odd_spread = spread_chip.spread(ctx, &p_lo_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &p_lo);
    }
    {
        let even_spread = spread_chip.spread(ctx, &p_hi_even)?;
        let odd_spread = spread_chip.spread(ctx, &p_hi_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &p_hi);
    }
    {
        let even_spread = spread_chip.spread(ctx, &q_lo_even)?;
        let odd_spread = spread_chip.spread(ctx, &q_lo_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &q_lo);
    }
    {
        let even_spread = spread_chip.spread(ctx, &q_hi_even)?;
        let odd_spread = spread_chip.spread(ctx, &q_hi_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &q_hi);
    }
    let out_lo = gate.add(ctx, QuantumCell::Existing(p_lo_odd), QuantumCell::Existing(q_lo_odd));
    let out_hi = gate.add(ctx, QuantumCell::Existing(p_hi_odd), QuantumCell::Existing(q_hi_odd));
    let out = gate.mul_add(
        ctx,
        QuantumCell::Existing(out_hi),
        QuantumCell::Constant(F::from(1u64 << 16)),
        QuantumCell::Existing(out_lo),
    );
    Ok(out)
}

fn maj<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x: &SpreadU32<'a, F>,
    y: &SpreadU32<'a, F>,
    z: &SpreadU32<'a, F>,
) -> Result<AssignedValue<F>, Error> {
    let (x_lo, x_hi) = *x;
    let (y_lo, y_hi) = *y;
    let (z_lo, z_hi) = *z;
    let range = spread_chip.range();
    let gate = range.gate();
    let m_lo = three_add(
        ctx,
        range.gate(),
        QuantumCell::Existing(x_lo),
        QuantumCell::Existing(y_lo),
        QuantumCell::Existing(z_lo),
    );
    let m_hi = three_add(
        ctx,
        range.gate(),
        QuantumCell::Existing(x_hi),
        QuantumCell::Existing(y_hi),
        QuantumCell::Existing(z_hi),
    );
    let (m_lo_even, m_lo_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &m_lo)?;
    let (m_hi_even, m_hi_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &m_hi)?;
    {
        let even_spread = spread_chip.spread(ctx, &m_lo_even)?;
        let odd_spread = spread_chip.spread(ctx, &m_lo_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &m_lo);
    }
    {
        let even_spread = spread_chip.spread(ctx, &m_hi_even)?;
        let odd_spread = spread_chip.spread(ctx, &m_hi_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &m_hi);
    }
    let m = gate.mul_add(
        ctx,
        QuantumCell::Existing(m_hi_odd),
        QuantumCell::Constant(F::from(1u64 << 16)),
        QuantumCell::Existing(m_lo_odd),
    );
    Ok(m)
}

fn three_add<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    x: QuantumCell<F>,
    y: QuantumCell<F>,
    z: QuantumCell<F>,
) -> AssignedValue<F> {
    let add1 = gate.add(ctx, x, y);
    gate.add(ctx, QuantumCell::Existing(add1), z)
}

fn sigma_upper0<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x_spread: &SpreadU32<F>,
) -> Result<AssignedValue<F>, Error> {
    const STARTS: [usize; 4] = [0, 2, 13, 22];
    const ENDS: [usize; 4] = [2, 13, 22, 32];
    const PADDINGS: [usize; 4] = [6, 5, 7, 6];
    let coeffs = [
        F::from((1u64 << 60) + (1u64 << 38) + (1u64 << 20)),
        F::from((1u64 << 0) + (1u64 << 42) + (1u64 << 24)),
        F::from((1u64 << 22) + (1u64 << 0) + (1u64 << 46)),
        F::from((1u64 << 40) + (1u64 << 18) + (1u64 << 0)),
    ];
    sigma_generic(ctx, spread_chip, x_spread, &STARTS, &ENDS, &PADDINGS, &coeffs)
}

fn sigma_upper1<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x_spread: &SpreadU32<F>,
) -> Result<AssignedValue<F>, Error> {
    const STARTS: [usize; 4] = [0, 6, 11, 25];
    const ENDS: [usize; 4] = [6, 11, 25, 32];
    const PADDINGS: [usize; 4] = [2, 3, 2, 1];
    let coeffs = [
        F::from((1u64 << 52) + (1u64 << 42) + (1u64 << 14)),
        F::from((1u64 << 0) + (1u64 << 54) + (1u64 << 26)),
        F::from((1u64 << 10) + (1u64 << 0) + (1u64 << 36)),
        F::from((1u64 << 38) + (1u64 << 28) + (1u64 << 0)),
    ];
    sigma_generic(ctx, spread_chip, x_spread, &STARTS, &ENDS, &PADDINGS, &coeffs)
}

fn sigma_lower0<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x_spread: &SpreadU32<F>,
) -> Result<AssignedValue<F>, Error> {
    const STARTS: [usize; 4] = [0, 3, 7, 18];
    const ENDS: [usize; 4] = [3, 7, 18, 32];
    const PADDINGS: [usize; 4] = [5, 4, 5, 2];
    let coeffs = [
        F::from((1u64 << 50) + (1u64 << 28)),
        F::from((1u64 << 0) + (1u64 << 56) + (1u64 << 34)),
        F::from((1u64 << 8) + (1u64 << 0) + (1u64 << 42)),
        F::from((1u64 << 30) + (1u64 << 22) + (1u64 << 0)),
    ];
    sigma_generic(ctx, spread_chip, x_spread, &STARTS, &ENDS, &PADDINGS, &coeffs)
}

fn sigma_lower1<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x_spread: &SpreadU32<F>,
) -> Result<AssignedValue<F>, Error> {
    const STARTS: [usize; 4] = [0, 10, 17, 19];
    const ENDS: [usize; 4] = [10, 17, 19, 32];
    const PADDINGS: [usize; 4] = [6, 1, 6, 3];
    let coeffs = [
        F::from((1u64 << 30) + (1u64 << 26)),
        F::from((1u64 << 0) + (1u64 << 50) + (1u64 << 46)),
        F::from((1u64 << 14) + (1u64 << 0) + (1u64 << 60)),
        F::from((1u64 << 18) + (1u64 << 4) + (1u64 << 0)),
    ];
    sigma_generic(ctx, spread_chip, x_spread, &STARTS, &ENDS, &PADDINGS, &coeffs)
}

#[allow(clippy::too_many_arguments)]
fn sigma_generic<'a, 'b: 'a, F: BigPrimeField>(
    ctx: &mut Context<F>,
    spread_chip: &SpreadChip<'a, F>,
    x_spread: &SpreadU32<F>,
    starts: &[usize; 4],
    ends: &[usize; 4],
    paddings: &[usize; 4],
    coeffs: &[F; 4],
) -> Result<AssignedValue<F>, Error> {
    let range = spread_chip.range();
    let gate = range.gate();
    // let x_spread = spread_config.spread(ctx, range, x)?;
    let bits_val = {
        let (lo, hi) = (x_spread.0.value(), x_spread.1.value());
        let mut bits = fe_to_bits_le(lo, 32);
        bits.append(&mut fe_to_bits_le(hi, 32));
        bits
    };
    let mut assign_bits = |bits: &Vec<bool>, start: usize, end: usize, _padding: usize| {
        let fe_val: F = {
            let mut bits = bits[2 * start..2 * end].to_vec();
            bits.extend_from_slice(&vec![false; 64 - bits.len()]);
            bits_le_to_fe(&bits)
        };

        // let assigned_spread = spread_config.spread(ctx, range, &assigned_dense)?;
        // let result: Result<AssignedValue<F>, Error> = Ok(assigned_spread);
        ctx.load_witness(fe_val)
    };
    let assigned_a = assign_bits(&bits_val, starts[0], ends[0], paddings[0]);
    let assigned_b = assign_bits(&bits_val, starts[1], ends[1], paddings[1]);
    let assigned_c = assign_bits(&bits_val, starts[2], ends[2], paddings[2]);
    let assigned_d = assign_bits(&bits_val, starts[3], ends[3], paddings[3]);
    {
        let mut sum = assigned_a;
        sum = gate.mul_add(
            ctx,
            assigned_b,
            QuantumCell::Constant(F::from(1 << (2 * starts[1]))),
            sum,
        );
        sum = gate.mul_add(
            ctx,
            assigned_c,
            QuantumCell::Constant(F::from(1 << (2 * starts[2]))),
            sum,
        );
        sum = gate.mul_add(
            ctx,
            assigned_d,
            QuantumCell::Constant(F::from(1 << (2 * starts[3]))),
            sum,
        );
        let x_composed =
            gate.mul_add(ctx, x_spread.1, QuantumCell::Constant(F::from(1 << 32)), x_spread.0);
        ctx.constrain_equal(&x_composed, &sum);
    }

    let r_spread = {
        // let a_coeff = F::from(1u64 << 60 + 1u64 << 38 + 1u64 << 20);
        // let b_coeff = F::from(1u64 << 0 + 1u64 << 42 + 1u64 << 24);
        // let c_coeff = F::from(1u64 << 22 + 1u64 << 0 + 1u64 << 46);
        // let d_coeff = F::from(1u64 << 40 + 1u64 << 18 + 1u64 << 0);
        let mut sum = ctx.load_zero();
        // let assigned_a_spread = spread_config.spread(ctx, range, &assigned_a)?;
        // let assigned_b_spread = spread_config.spread(ctx, range, &assigned_b)?;
        // let assigned_c_spread = spread_config.spread(ctx, range, &assigned_c)?;
        // let assigned_d_spread = spread_config.spread(ctx, range, &assigned_d)?;
        sum = gate.mul_add(ctx, QuantumCell::Constant(coeffs[0]), assigned_a, sum);
        sum = gate.mul_add(ctx, QuantumCell::Constant(coeffs[1]), assigned_b, sum);
        sum = gate.mul_add(ctx, QuantumCell::Constant(coeffs[2]), assigned_c, sum);
        sum = gate.mul_add(ctx, QuantumCell::Constant(coeffs[3]), assigned_d, sum);
        sum
    };
    let (r_lo, r_hi) = {
        let lo = F::from(r_spread.value().get_lower_32() as u64);
        let hi = F::from(((r_spread.value().get_lower_64() >> 32) & ((1u64 << 32) - 1)) as u64);
        let assigned_lo = ctx.load_witness(lo);
        let assigned_hi = ctx.load_witness(hi);
        range.range_check(ctx, assigned_lo, 32);
        range.range_check(ctx, assigned_hi, 32);
        let composed = gate.mul_add(
            ctx,
            QuantumCell::Existing(assigned_hi),
            QuantumCell::Constant(F::from(1u64 << 32)),
            QuantumCell::Existing(assigned_lo),
        );
        ctx.constrain_equal(&r_spread, &composed);
        (assigned_lo, assigned_hi)
    };

    let (r_lo_even, r_lo_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &r_lo)?;
    let (r_hi_even, r_hi_odd) = spread_chip.decompose_even_and_odd_unchecked(ctx, &r_hi)?;

    {
        let even_spread = spread_chip.spread(ctx, &r_lo_even)?;
        let odd_spread = spread_chip.spread(ctx, &r_lo_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &r_lo);
    }

    {
        let even_spread = spread_chip.spread(ctx, &r_hi_even)?;
        let odd_spread = spread_chip.spread(ctx, &r_hi_odd)?;
        let sum = gate.mul_add(
            ctx,
            QuantumCell::Constant(F::from(2)),
            QuantumCell::Existing(odd_spread),
            QuantumCell::Existing(even_spread),
        );
        ctx.constrain_equal(&sum, &r_hi);
    }

    let r = gate.mul_add(
        ctx,
        QuantumCell::Existing(r_hi_even),
        QuantumCell::Constant(F::from(1 << 16)),
        QuantumCell::Existing(r_lo_even),
    );

    Ok(r)
}
