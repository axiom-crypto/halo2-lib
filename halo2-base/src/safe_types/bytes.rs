#![allow(clippy::len_without_is_empty)]
use crate::AssignedValue;

use super::{SafeByte, ScalarField};

use getset::Getters;

/// Represents a variable length byte array in circuit.
///
/// Each element is guaranteed to be a byte, given by type [`SafeByte`].
/// To represent a variable length array, we must know the maximum possible length `MAX_LEN` the array could be -- this is some additional context the user must provide.
/// Then we right pad the array with 0s to the maximum length (we do **not** constrain that these paddings must be 0s).
#[derive(Debug, Clone, Getters)]
pub struct VarLenBytes<F: ScalarField, const MAX_LEN: usize> {
    /// The byte array, right padded
    #[getset(get = "pub")]
    bytes: [SafeByte<F>; MAX_LEN],
    /// Witness representing the actual length of the byte array. Upon construction, this is range checked to be at most `MAX_LEN`
    #[getset(get = "pub")]
    len: AssignedValue<F>,
}

impl<F: ScalarField, const MAX_LEN: usize> VarLenBytes<F, MAX_LEN> {
    // VarLenBytes can be only created by SafeChip.
    pub(super) fn new(bytes: [SafeByte<F>; MAX_LEN], len: AssignedValue<F>) -> Self {
        assert!(
            len.value().le(&F::from_u128(MAX_LEN as u128)),
            "Invalid length which exceeds MAX_LEN {}",
            MAX_LEN
        );
        Self { bytes, len }
    }

    /// Returns the maximum length of the byte array.
    pub fn max_len(&self) -> usize {
        MAX_LEN
    }
}

/// Represents a variable length byte array in circuit. Not encourged to use because `MAX_LEN` cannot be verified at compile time.
///
/// Each element is guaranteed to be a byte, given by type [`SafeByte`].
/// To represent a variable length array, we must know the maximum possible length `MAX_LEN` the array could be -- this is some additional context the user must provide.
/// Then we right pad the array with 0s to the maximum length (we do **not** constrain that these paddings must be 0s).
#[derive(Debug, Clone, Getters)]
pub struct VarLenBytesVec<F: ScalarField> {
    /// The byte array, right padded
    #[getset(get = "pub")]
    bytes: Vec<SafeByte<F>>,
    /// Witness representing the actual length of the byte array. Upon construction, this is range checked to be at most `MAX_LEN`
    #[getset(get = "pub")]
    len: AssignedValue<F>,
}

impl<F: ScalarField> VarLenBytesVec<F> {
    // VarLenBytesVec can be only created by SafeChip.
    pub(super) fn new(bytes: Vec<SafeByte<F>>, len: AssignedValue<F>, max_len: usize) -> Self {
        assert!(
            len.value().le(&F::from_u128(max_len as u128)),
            "Invalid length which exceeds MAX_LEN {}",
            max_len
        );
        assert!(bytes.len() == max_len, "bytes is not padded correctly");
        Self { bytes, len }
    }

    /// Returns the maximum length of the byte array.
    pub fn max_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Represents a fixed length byte array in circuit.
#[derive(Debug, Clone, Getters)]
pub struct FixLenBytes<F: ScalarField, const LEN: usize> {
    /// The byte array
    #[getset(get = "pub")]
    bytes: [SafeByte<F>; LEN],
}

impl<F: ScalarField, const LEN: usize> FixLenBytes<F, LEN> {
    // FixLenBytes can be only created by SafeChip.
    pub(super) fn new(bytes: [SafeByte<F>; LEN]) -> Self {
        Self { bytes }
    }

    /// Returns the length of the byte array.
    pub fn len(&self) -> usize {
        LEN
    }
}
