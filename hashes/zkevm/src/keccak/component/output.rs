use std::sync::RwLock;

use super::{create_native_poseidon_sponge, encode::encode_native_input};
use crate::{keccak::vanilla::keccak_packed_multi::get_num_keccak_f, util::eth_types::Field};
use itertools::Itertools;
use lazy_static::lazy_static;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha3::{Digest, Keccak256};
use type_map::concurrent::TypeMap;

/// Witnesses to be exposed as circuit outputs.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct KeccakCircuitOutput<E> {
    /// Key for App circuits to lookup keccak hash.
    pub key: E,
    /// Low 128 bits of Keccak hash.
    pub hash_lo: E,
    /// High 128 bits of Keccak hash.
    pub hash_hi: E,
}

/// Return circuit outputs of the specified Keccak corprocessor circuit for a specified input.
pub fn multi_inputs_to_circuit_outputs<F: Field>(
    inputs: &[Vec<u8>],
    capacity: usize,
) -> Vec<KeccakCircuitOutput<F>> {
    assert!(u128::BITS <= F::CAPACITY);
    let mut outputs: Vec<_> =
        inputs.par_iter().flat_map(|input| input_to_circuit_outputs::<F>(input)).collect();
    assert!(outputs.len() <= capacity);
    outputs.resize(capacity, dummy_circuit_output());
    outputs
}

/// Return corresponding circuit outputs of a native input in bytes. An logical input could produce multiple
/// outputs. The last one is the lookup key and hash of the input. Other outputs are paddings which are the lookup
/// key and hash of an empty input.
pub fn input_to_circuit_outputs<F: Field>(bytes: &[u8]) -> Vec<KeccakCircuitOutput<F>> {
    assert!(u128::BITS <= F::CAPACITY);
    let len = bytes.len();
    let num_keccak_f = get_num_keccak_f(len);

    let mut output = Vec::with_capacity(num_keccak_f);
    output.resize(num_keccak_f - 1, dummy_circuit_output());

    let key = encode_native_input(bytes);
    let hash = Keccak256::digest(bytes);
    let hash_lo = F::from_u128(u128::from_be_bytes(hash[16..].try_into().unwrap()));
    let hash_hi = F::from_u128(u128::from_be_bytes(hash[..16].try_into().unwrap()));
    output.push(KeccakCircuitOutput { key, hash_lo, hash_hi });

    output
}

lazy_static! {
    static ref DUMMY_CIRCUIT_OUTPUT_CACHE: RwLock<TypeMap> = Default::default();
}

/// Return the dummy circuit output for padding.
pub fn dummy_circuit_output<F: Field>() -> KeccakCircuitOutput<F> {
    let output = DUMMY_CIRCUIT_OUTPUT_CACHE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get::<KeccakCircuitOutput<F>>()
        .cloned();
    if let Some(output) = output {
        return output;
    }
    let output = {
        let mut to_write = DUMMY_CIRCUIT_OUTPUT_CACHE.write().unwrap_or_else(|e| e.into_inner());
        let output = dummy_circuit_output_impl();
        to_write.insert(output);
        output
    };
    output
}

fn dummy_circuit_output_impl<F: Field>() -> KeccakCircuitOutput<F> {
    assert!(u128::BITS <= F::CAPACITY);
    let key = encode_native_input(&[]);
    // Output of Keccak256::digest is big endian.
    let hash = Keccak256::digest([]);
    let hash_lo = F::from_u128(u128::from_be_bytes(hash[16..].try_into().unwrap()));
    let hash_hi = F::from_u128(u128::from_be_bytes(hash[..16].try_into().unwrap()));
    KeccakCircuitOutput { key, hash_lo, hash_hi }
}

/// Calculate the commitment of circuit outputs.
pub fn calculate_circuit_outputs_commit<F: Field>(outputs: &[KeccakCircuitOutput<F>]) -> F {
    let mut native_poseidon_sponge = create_native_poseidon_sponge();
    native_poseidon_sponge.update(
        &outputs
            .iter()
            .flat_map(|output| [output.key, output.hash_lo, output.hash_hi])
            .collect_vec(),
    );
    native_poseidon_sponge.squeeze()
}
