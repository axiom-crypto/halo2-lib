use ethers_core::{types::H256, utils::keccak256};

use crate::keccak::vanilla::param::NUM_BYTES_TO_ABSORB;

/// Fixed length format for one keccak_f.
/// This closely matches [crate::keccak::component::circuit::shard::LoadedKeccakF].
#[derive(Clone, Debug)]
pub struct KeccakIngestionFormat {
    pub bytes_per_keccak_f: [u8; NUM_BYTES_TO_ABSORB],
    /// In the first keccak_f of a full keccak, this will be the length in bytes of the input. Otherwise 0.
    pub byte_len_placeholder: usize,
    /// Is this the last keccak_f of a full keccak? Note that the last keccak_f includes input padding.
    pub is_final: bool,
    /// If `is_final = true`, the output of the full keccak, split into two 128-bit chunks. Otherwise `keccak256([])` in hi-lo form.
    pub hash_lo: u128,
    pub hash_hi: u128,
}

impl Default for KeccakIngestionFormat {
    fn default() -> Self {
        Self::new([0; NUM_BYTES_TO_ABSORB], 0, true, H256(keccak256([])))
    }
}

impl KeccakIngestionFormat {
    fn new(
        bytes_per_keccak_f: [u8; NUM_BYTES_TO_ABSORB],
        byte_len_placeholder: usize,
        is_final: bool,
        hash: H256,
    ) -> Self {
        let hash_lo = u128::from_be_bytes(hash[16..].try_into().unwrap());
        let hash_hi = u128::from_be_bytes(hash[..16].try_into().unwrap());
        Self { bytes_per_keccak_f, byte_len_placeholder, is_final, hash_lo, hash_hi }
    }
}

/// We take all `requests` as a deduplicated ordered list.
/// We split each input into `KeccakIngestionFormat` chunks, one for each keccak_f needed to compute `keccak(input)`.
/// We then resize so there are exactly `capacity` total chunks.
///
/// Very similar to [crate::keccak::component::encode::encode_native_input] except we do not do the
/// encoding part (that will be done in circuit, not natively).
///
/// Returns `Err(true_capacity)` if `true_capacity > capacity`, where `true_capacity` is the number of keccak_f needed
/// to compute all requests.
pub fn format_requests_for_ingestion<B>(
    requests: impl IntoIterator<Item = (B, Option<H256>)>,
    capacity: usize,
) -> Result<Vec<KeccakIngestionFormat>, usize>
where
    B: AsRef<[u8]>,
{
    let mut ingestions = Vec::with_capacity(capacity);
    for (input, hash) in requests {
        let input = input.as_ref();
        let hash = hash.unwrap_or_else(|| H256(keccak256(input)));
        let len = input.len();
        for (i, chunk) in input.chunks(NUM_BYTES_TO_ABSORB).enumerate() {
            let byte_len = if i == 0 { len } else { 0 };
            let mut bytes_per_keccak_f = [0; NUM_BYTES_TO_ABSORB];
            bytes_per_keccak_f[..chunk.len()].copy_from_slice(chunk);
            ingestions.push(KeccakIngestionFormat::new(
                bytes_per_keccak_f,
                byte_len,
                false,
                H256::zero(),
            ));
        }
        // An extra keccak_f is performed if len % NUM_BYTES_TO_ABSORB == 0.
        if len % NUM_BYTES_TO_ABSORB == 0 {
            ingestions.push(KeccakIngestionFormat::default());
        }
        let last_mut = ingestions.last_mut().unwrap();
        last_mut.is_final = true;
        last_mut.hash_hi = u128::from_be_bytes(hash[..16].try_into().unwrap());
        last_mut.hash_lo = u128::from_be_bytes(hash[16..].try_into().unwrap());
    }
    log::info!("Actual number of keccak_f used = {}", ingestions.len());
    if ingestions.len() > capacity {
        Err(ingestions.len())
    } else {
        ingestions.resize_with(capacity, Default::default);
        Ok(ingestions)
    }
}
