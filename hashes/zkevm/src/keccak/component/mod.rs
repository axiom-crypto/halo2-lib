use std::sync::RwLock;

use halo2_base::poseidon::hasher::spec::OptimizedPoseidonSpec;
use lazy_static::lazy_static;
use snark_verifier_sdk::{snark_verifier, NativeLoader};
use type_map::concurrent::TypeMap;

use crate::util::eth_types::Field;

use self::param::{POSEIDON_RATE, POSEIDON_R_F, POSEIDON_R_P, POSEIDON_SECURE_MDS, POSEIDON_T};

/// Module of Keccak component circuit(s).
pub mod circuit;
/// Module of encoding raw inputs to component circuit lookup keys.
pub mod encode;
/// Module for Rust native processing of input bytes into resized fixed length format to match vanilla circuit LoadedKeccakF
pub mod ingestion;
/// Module of Keccak component circuit output.
pub mod output;
/// Module of Keccak component circuit constant parameters.
pub mod param;
#[cfg(test)]
mod tests;

lazy_static! {
    static ref POSEIDON_SPEC_CACHE: RwLock<TypeMap> = Default::default();
}

pub(crate) fn get_poseidon_spec<F: Field>() -> OptimizedPoseidonSpec<F, POSEIDON_T, POSEIDON_RATE> {
    let spec = POSEIDON_SPEC_CACHE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get::<OptimizedPoseidonSpec<F, POSEIDON_T, POSEIDON_RATE>>()
        .cloned();
    if let Some(spec) = spec {
        return spec;
    }
    let spec = {
        let mut to_write = POSEIDON_SPEC_CACHE.write().unwrap_or_else(|e| e.into_inner());
        let spec = OptimizedPoseidonSpec::<F, POSEIDON_T, POSEIDON_RATE>::new::<
            POSEIDON_R_F,
            POSEIDON_R_P,
            POSEIDON_SECURE_MDS,
        >();
        to_write.insert(spec.clone());
        spec
    };
    spec
}

pub(crate) fn create_native_poseidon_sponge<F: Field>(
) -> snark_verifier::util::hash::Poseidon<F, F, POSEIDON_T, POSEIDON_RATE> {
    snark_verifier::util::hash::Poseidon::<F, F, POSEIDON_T, POSEIDON_RATE>::from_spec(
        &NativeLoader,
        get_poseidon_spec(),
    )
}
