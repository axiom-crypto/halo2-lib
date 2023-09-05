use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    poseidon::hasher::{PoseidonCompactInput, PoseidonCompactOutput, PoseidonHasher},
    safe_types::SafeTypeChip,
    Context,
};
use itertools::Itertools;

use crate::{keccak::param::*, util::eth_types::Field};

use super::{circuit::LoadedKeccakF, param::*};

// TODO: Abstract this module into a trait for all coprocessor circuits.

/// Module to encode raw inputs into lookup keys for looking up keccak results. The encoding is
/// designed to be efficient in coprocessor circuits.

/// Encode a native input bytes into its corresponding lookup key. This function can be considered as the spec of the encoding.
pub fn encode_native_input<F: Field>(bytes: &[u8]) -> F {
    assert!(NUM_BITS_PER_WORD <= u128::BITS as usize);
    let multipilers = get_words_to_witness_multipilers::<F>();
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
    let words_per_chunk = words
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
    let witnesses_per_chunk = words_per_chunk
        .iter()
        .map(|chunk| {
            chunk
                .chunks(num_word_per_witness)
                .map(|c| {
                    c.iter().zip(multipilers.iter()).fold(F::ZERO, |acc, (word, multipiler)| {
                        acc + F::from_u128(*word) * multipiler
                    })
                })
                .collect_vec()
        })
        .collect_vec();
    // Absorb witnesses keccak_f by keccak_f.
    let mut native_poseidon_sponge =
        pse_poseidon::Poseidon::<F, POSEIDON_T, POSEIDON_RATE>::new(POSEIDON_R_F, POSEIDON_R_P);
    for witnesses in witnesses_per_chunk {
        for absorb in witnesses.chunks(POSEIDON_RATE) {
            // To avoid abosring witnesses crossing keccak_fs together, pad 0s to make sure absorb.len() == RATE.
            let mut padded_absorb = [F::ZERO; POSEIDON_RATE];
            padded_absorb[..absorb.len()].copy_from_slice(absorb);
            native_poseidon_sponge.update(&padded_absorb);
        }
    }
    native_poseidon_sponge.squeeze()
}

// TODO: Add a function to encode a VarLenBytes into a lookup key. The function should be used by App Circuits.

/// Encode raw inputs from Keccak circuit witnesses into lookup keys.
///
/// Each element in the return value corrresponds to a Keccak chunk. If is_final = true, this element is the lookup key of the corresponding logical input.
pub(crate) fn encode_inputs_from_keccak_fs<F: Field>(
    ctx: &mut Context<F>,
    range_chip: &impl RangeInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    loaded_keccak_fs: &[LoadedKeccakF<F>],
) -> Vec<PoseidonCompactOutput<F>> {
    // Circuit parameters
    let num_poseidon_absorb_per_keccak_f = num_poseidon_absorb_per_keccak_f::<F>();
    let num_word_per_witness = num_word_per_witness::<F>();
    let num_witness_per_keccak_f = POSEIDON_RATE * num_poseidon_absorb_per_keccak_f;

    // Constant witnesses
    let rate_witness = ctx.load_constant(F::from(POSEIDON_RATE as u64));
    let one_witness = ctx.load_constant(F::ONE);
    let zero_witness = ctx.load_zero();
    let multiplier_witnesses = ctx.assign_witnesses(get_words_to_witness_multipilers::<F>());

    let compact_input_len = loaded_keccak_fs.len() * num_poseidon_absorb_per_keccak_f;
    let mut compact_inputs = Vec::with_capacity(compact_input_len);
    let mut is_final_last = one_witness;
    for loaded_keccak_f in loaded_keccak_fs {
        // If this keccak_f is the last of a logical input.
        let is_final = loaded_keccak_f.is_final;
        let mut poseidon_absorb_data = Vec::with_capacity(num_witness_per_keccak_f);

        // First witness of a keccak_f: [<len_word>, word_values[0], word_values[1], ...]
        // <len_word> is the length of the input if this is the first keccak_f of a logical input. Otherwise 0.
        let mut words = Vec::with_capacity(num_word_per_witness);
        let len_word =
            range_chip.gate().select(ctx, loaded_keccak_f.bytes_left, zero_witness, is_final_last);
        words.push(len_word);
        words.extend_from_slice(&loaded_keccak_f.word_values[0..(num_word_per_witness - 1)]);
        let first_witness = range_chip.gate().inner_product(
            ctx,
            multiplier_witnesses.clone(),
            words.iter().map(|w| halo2_base::QuantumCell::Existing(*w)),
        );
        poseidon_absorb_data.push(first_witness);

        // Turn every num_word_per_witness words later into a witness.
        for words in &loaded_keccak_f
            .word_values
            .into_iter()
            .skip(num_word_per_witness - 1)
            .chunks(num_word_per_witness)
        {
            let mut words = words.collect_vec();
            words.resize(num_word_per_witness, zero_witness);
            let witness = range_chip.gate().inner_product(
                ctx,
                multiplier_witnesses.clone(),
                words.iter().map(|w| halo2_base::QuantumCell::Existing(*w)),
            );
            poseidon_absorb_data.push(witness);
        }
        // Pad 0s to make sure poseidon_absorb_data.len() % RATE == 0.
        poseidon_absorb_data.resize(num_witness_per_keccak_f, zero_witness);
        for (i, poseidon_absorb) in poseidon_absorb_data.chunks(POSEIDON_RATE).enumerate() {
            compact_inputs.push(PoseidonCompactInput::new(
                poseidon_absorb.try_into().unwrap(),
                if i + 1 == num_poseidon_absorb_per_keccak_f {
                    SafeTypeChip::unsafe_to_bool(is_final)
                } else {
                    SafeTypeChip::unsafe_to_bool(zero_witness)
                },
                rate_witness,
            ));
        }
        is_final_last = is_final;
    }

    let compact_outputs = initialized_hasher.hash_compact_input(ctx, range_chip, &compact_inputs);

    compact_outputs
        .into_iter()
        .skip(num_poseidon_absorb_per_keccak_f - 1)
        .step_by(num_poseidon_absorb_per_keccak_f)
        .collect_vec()
}

/// Number of Keccak words in each encoded input for Poseidon.
pub fn num_word_per_witness<F: Field>() -> usize {
    (F::CAPACITY as usize) / NUM_BITS_PER_WORD
}

/// Number of witnesses to represent inputs in a keccak_f.
///
/// Assume the representation of <length of raw input> is not longer than a Keccak word.
pub fn num_witness_per_keccak_f<F: Field>() -> usize {
    // With <length of raw input>, a keccak_f could have NUM_WORDS_TO_ABSORB + 1 words.
    // ceil((NUM_WORDS_TO_ABSORB + 1) / num_word_per_witness)
    NUM_WORDS_TO_ABSORB / num_word_per_witness::<F>() + 1
}

/// Number of Poseidon absorb rounds per keccak_f.
pub fn num_poseidon_absorb_per_keccak_f<F: Field>() -> usize {
    // Each absorb round consumes RATE witnesses.
    // ceil(num_witness_per_keccak_f / RATE)
    (num_witness_per_keccak_f::<F>() - 1) / POSEIDON_RATE + 1
}

fn get_words_to_witness_multipilers<F: Field>() -> Vec<F> {
    let num_word_per_witness = num_word_per_witness::<F>();
    let mut multiplier_f = F::ONE;
    let mut multipliers = Vec::with_capacity(num_word_per_witness);
    multipliers.push(multiplier_f);
    let base_f = F::from_u128(1 << NUM_BITS_PER_WORD);
    for _ in 1..num_word_per_witness {
        multiplier_f *= base_f;
        multipliers.push(multiplier_f);
    }
    multipliers
}
