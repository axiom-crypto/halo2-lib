use crate::AssignedValue;

use super::{SafeByte, ScalarField};

/// Represents a variable length byte array in circuit.
///
/// Each element is guaranteed to be a byte, given by type [`SafeByte`].
/// To represent a variable length array, we must know the maximum possible length `MAX_LEN` the array could be -- this is some additional context the user must provide.
/// Then we right pad the array with 0s to the maximum length (we do **not** constrain that these paddings must be 0s).
#[derive(Debug, Clone)]
pub struct VarLenBytes<F: ScalarField, const MAX_LEN: usize> {
    /// The byte array, right padded with 0s
    pub bytes: [SafeByte<F>; MAX_LEN],
    /// Witness representing the actual length of the byte array. Upon construction, this is range checked to be at most `MAX_LEN`
    pub var_len: AssignedValue<F>,
}

impl<F: ScalarField, const MAX_LEN: usize> VarLenBytes<F, MAX_LEN> {
    fn new(bytes: [SafeByte<F>; MAX_LEN], var_len: AssignedValue<F>) -> Self {
        Self { bytes, var_len }
    }

    pub fn max_len(&self) -> usize {
        MAX_LEN
    }
}

impl<F: ScalarField, const MAX_LEN: usize> AsRef<[SafeByte<F>]> for VarLenBytes<F, MAX_LEN> {
    fn as_ref(&self) -> &[SafeByte<F>] {
        &self.bytes
    }
}

impl<F: ScalarField, const MAX_LEN: usize> AsMut<[SafeByte<F>]> for VarLenBytes<F, MAX_LEN> {
    fn as_mut(&mut self) -> &mut [SafeByte<F>] {
        &mut self.bytes
    }
}

/// Represents a variable length byte array in circuit.
///
/// Each element is guaranteed to be a byte, given by type [`SafeByte`].
/// To represent a variable length array, we must know the maximum possible length `MAX_LEN` the array could be -- this is some additional context the user must provide.
/// Then we right pad the array with 0s to the maximum length (we do **not** constrain that these paddings must be 0s).
#[derive(Debug, Clone)]
pub struct VarLenBytesVec<F: ScalarField> {
    /// The byte array, right padded with 0s
    bytes: Vec<SafeByte<F>>,
    /// Witness representing the actual length of the byte array. Upon construction, this is range checked to be at most `MAX_LEN`
    pub var_len: AssignedValue<F>,
}
