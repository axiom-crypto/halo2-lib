use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    poseidon::hasher::{PoseidonCompactChunkInput, PoseidonHasher},
    safe_types::{FixLenBytesVec, SafeByte, SafeTypeChip, VarLenBytesVec},
    utils::bit_length,
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;
use num_bigint::BigUint;
use snark_verifier_sdk::{snark_verifier, NativeLoader};

use crate::{
    keccak::vanilla::{keccak_packed_multi::get_num_keccak_f, param::*},
    util::eth_types::Field,
};

use super::param::*;

// TODO: Abstract this module into a trait for all component circuits.

/// Module to encode raw inputs into lookup keys for looking up keccak results. The encoding is
/// designed to be efficient in component circuits.

/// Encode a native input bytes into its corresponding lookup key. This function can be considered as the spec of the encoding.
pub fn encode_native_input<F: Field>(bytes: &[u8]) -> F {
    let witnesses_per_keccak_f = pack_native_input(bytes);
    // Absorb witnesses keccak_f by keccak_f.
    let mut native_poseidon_sponge =
        snark_verifier::util::hash::Poseidon::<F, F, POSEIDON_T, POSEIDON_RATE>::new::<
            POSEIDON_R_F,
            POSEIDON_R_P,
            POSEIDON_SECURE_MDS,
        >(&NativeLoader);
    for witnesses in witnesses_per_keccak_f {
        for absorbing in witnesses.chunks(POSEIDON_RATE) {
            // To avoid absorbing witnesses crossing keccak_fs together, pad 0s to make sure absorb.len() == RATE.
            let mut padded_absorb = [F::ZERO; POSEIDON_RATE];
            padded_absorb[..absorbing.len()].copy_from_slice(absorbing);
            native_poseidon_sponge.update(&padded_absorb);
        }
    }
    native_poseidon_sponge.squeeze()
}

/// Pack native input bytes into num_word_per_witness field elements which are more poseidon friendly.
pub fn pack_native_input<F: Field>(bytes: &[u8]) -> Vec<Vec<F>> {
    assert!(NUM_BITS_PER_WORD <= u128::BITS as usize);
    let multipliers: Vec<F> = get_words_to_witness_multipliers::<F>();
    let num_word_per_witness = num_word_per_witness::<F>();
    let len = bytes.len();

    // Divide the bytes input into Keccak words(each word has NUM_BYTES_PER_WORD bytes).
    let mut words = bytes
        .chunks(NUM_BYTES_PER_WORD)
        .map(|chunk| {
            let mut padded_chunk = [0; u128::BITS as usize / NUM_BITS_PER_BYTE];
            padded_chunk[..chunk.len()].copy_from_slice(chunk);
            u128::from_le_bytes(padded_chunk)
        })
        .collect_vec();
    // An extra keccak_f is performed if len % NUM_BYTES_TO_ABSORB == 0.
    if len % NUM_BYTES_TO_ABSORB == 0 {
        words.extend([0; NUM_WORDS_TO_ABSORB]);
    }
    // 1. Split Keccak words into keccak_fs(each keccak_f has NUM_WORDS_TO_ABSORB).
    // 2. Append an extra word into the beginning of each keccak_f. In the first keccak_f, this word is the byte length of the input. Otherwise 0.
    let words_per_keccak_f = words
        .chunks(NUM_WORDS_TO_ABSORB)
        .enumerate()
        .map(|(i, chunk)| {
            let mut padded_chunk = [0; NUM_WORDS_TO_ABSORB + 1];
            padded_chunk[0] = if i == 0 { len as u128 } else { 0 };
            padded_chunk[1..(chunk.len() + 1)].copy_from_slice(chunk);
            padded_chunk
        })
        .collect_vec();
    // Compress every num_word_per_witness words into a witness.
    let witnesses_per_keccak_f = words_per_keccak_f
        .iter()
        .map(|chunk| {
            chunk
                .chunks(num_word_per_witness)
                .map(|c| {
                    c.iter().zip(multipliers.iter()).fold(F::ZERO, |acc, (word, multipiler)| {
                        acc + F::from_u128(*word) * multipiler
                    })
                })
                .collect_vec()
        })
        .collect_vec();
    witnesses_per_keccak_f
}

/// Encode a VarLenBytesVec into its corresponding lookup key.
pub fn encode_var_len_bytes_vec<F: Field>(
    ctx: &mut Context<F>,
    range_chip: &impl RangeInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    bytes: &VarLenBytesVec<F>,
) -> AssignedValue<F> {
    let max_len = bytes.max_len();
    let max_num_keccak_f = get_num_keccak_f(max_len);
    // num_keccak_f = len / NUM_BYTES_TO_ABSORB + 1
    let num_bits = bit_length(max_len as u64);
    let (num_keccak_f, _) =
        range_chip.div_mod(ctx, *bytes.len(), BigUint::from(NUM_BYTES_TO_ABSORB), num_bits);
    let f_indicator = range_chip.gate().idx_to_indicator(ctx, num_keccak_f, max_num_keccak_f);

    let bytes = bytes.ensure_0_padding(ctx, range_chip.gate());
    let chunk_input_per_f = format_input(ctx, range_chip.gate(), bytes.bytes(), *bytes.len());

    let chunk_inputs = chunk_input_per_f
        .into_iter()
        .zip(&f_indicator)
        .map(|(chunk_input, is_final)| {
            let is_final = SafeTypeChip::unsafe_to_bool(*is_final);
            PoseidonCompactChunkInput::new(chunk_input, is_final)
        })
        .collect_vec();

    let compact_outputs =
        initialized_hasher.hash_compact_chunk_inputs(ctx, range_chip.gate(), &chunk_inputs);
    range_chip.gate().select_by_indicator(
        ctx,
        compact_outputs.into_iter().map(|o| o.hash()),
        f_indicator,
    )
}

/// Encode a FixLenBytesVec into its corresponding lookup key.
pub fn encode_fix_len_bytes_vec<F: Field>(
    ctx: &mut Context<F>,
    gate_chip: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    bytes: &FixLenBytesVec<F>,
) -> AssignedValue<F> {
    // Constant witnesses
    let len_witness = ctx.load_constant(F::from(bytes.len() as u64));

    let chunk_input_per_f = format_input(ctx, gate_chip, bytes.bytes(), len_witness);
    let flatten_inputs = chunk_input_per_f
        .into_iter()
        .flat_map(|chunk_input| chunk_input.into_iter().flatten())
        .collect_vec();

    initialized_hasher.hash_fix_len_array(ctx, gate_chip, &flatten_inputs)
}

// For reference, when F is bn254::Fr:
// num_word_per_witness = 3
// num_witness_per_keccak_f = 6
// num_poseidon_absorb_per_keccak_f = 3

/// Number of Keccak words in each encoded input for Poseidon.
/// When `F` is `bn254::Fr`, this is 3.
pub const fn num_word_per_witness<F: Field>() -> usize {
    (F::CAPACITY as usize) / NUM_BITS_PER_WORD
}

/// Number of witnesses to represent inputs in a keccak_f.
///
/// Assume the representation of <length of raw input> is not longer than a Keccak word.
///
/// When `F` is `bn254::Fr`, this is 6.
pub const fn num_witness_per_keccak_f<F: Field>() -> usize {
    // With <length of raw input>, a keccak_f could have NUM_WORDS_TO_ABSORB + 1 words.
    // ceil((NUM_WORDS_TO_ABSORB + 1) / num_word_per_witness)
    NUM_WORDS_TO_ABSORB / num_word_per_witness::<F>() + 1
}

/// Number of Poseidon absorb rounds per keccak_f.
///
/// When `F` is `bn254::Fr`, with our fixed `POSEIDON_RATE = 2`, this is 3.
pub const fn num_poseidon_absorb_per_keccak_f<F: Field>() -> usize {
    // Each absorb round consumes RATE witnesses.
    // ceil(num_witness_per_keccak_f / RATE)
    (num_witness_per_keccak_f::<F>() - 1) / POSEIDON_RATE + 1
}

pub(crate) fn get_words_to_witness_multipliers<F: Field>() -> Vec<F> {
    let num_word_per_witness = num_word_per_witness::<F>();
    let mut multiplier_f = F::ONE;
    let mut multipliers = Vec::with_capacity(num_word_per_witness);
    multipliers.push(multiplier_f);
    let base_f = F::from_u128(1u128 << NUM_BITS_PER_WORD);
    for _ in 1..num_word_per_witness {
        multiplier_f *= base_f;
        multipliers.push(multiplier_f);
    }
    multipliers
}

pub(crate) fn get_bytes_to_words_multipliers<F: Field>() -> Vec<F> {
    let mut multiplier_f = F::ONE;
    let mut multipliers = Vec::with_capacity(NUM_BYTES_PER_WORD);
    multipliers.push(multiplier_f);
    let base_f = F::from_u128(1 << NUM_BITS_PER_BYTE);
    for _ in 1..NUM_BYTES_PER_WORD {
        multiplier_f *= base_f;
        multipliers.push(multiplier_f);
    }
    multipliers
}

pub fn format_input<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    bytes: &[SafeByte<F>],
    len: AssignedValue<F>,
) -> Vec<Vec<[AssignedValue<F>; POSEIDON_RATE]>> {
    // Constant witnesses
    let zero_const = ctx.load_zero();
    let bytes_to_words_multipliers_val =
        get_bytes_to_words_multipliers::<F>().into_iter().map(|m| Constant(m)).collect_vec();
    let words_to_witness_multipliers_val =
        get_words_to_witness_multipliers::<F>().into_iter().map(|m| Constant(m)).collect_vec();

    let mut bytes_witnesses = bytes.to_vec();
    // Append a zero to the end because An extra keccak_f is performed if len % NUM_BYTES_TO_ABSORB == 0.
    bytes_witnesses.push(SafeTypeChip::unsafe_to_byte(zero_const));
    let words = bytes_witnesses
        .chunks(NUM_BYTES_PER_WORD)
        .map(|c| {
            let len = c.len();
            let multipliers = bytes_to_words_multipliers_val[..len].to_vec();
            gate.inner_product(ctx, c.iter().map(|sb| *sb.as_ref()), multipliers)
        })
        .collect_vec();

    let words_per_f = words
        .chunks(NUM_WORDS_TO_ABSORB)
        .enumerate()
        .map(|(i, words_per_f)| {
            let mut buffer = [zero_const; NUM_WORDS_TO_ABSORB + 1];
            buffer[0] = if i == 0 { len } else { zero_const };
            buffer[1..words_per_f.len() + 1].copy_from_slice(words_per_f);
            buffer
        })
        .collect_vec();

    let witnesses_per_f = words_per_f
        .iter()
        .map(|words| {
            words
                .chunks(num_word_per_witness::<F>())
                .map(|c| {
                    gate.inner_product(ctx, c.to_vec(), words_to_witness_multipliers_val.clone())
                })
                .collect_vec()
        })
        .collect_vec();

    witnesses_per_f
        .iter()
        .map(|words| {
            words
                .chunks(POSEIDON_RATE)
                .map(|c| {
                    let mut buffer = [zero_const; POSEIDON_RATE];
                    buffer[..c.len()].copy_from_slice(c);
                    buffer
                })
                .collect_vec()
        })
        .collect_vec()
}
