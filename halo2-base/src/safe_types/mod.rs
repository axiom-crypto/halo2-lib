pub use crate::{
    gates::{
        flex_gate::GateInstructions,
        range::{RangeChip, RangeInstructions},
    },
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use std::cmp::{max, min};
use std::sync::Arc;

#[cfg(test)]
pub mod tests;

type RawAssignedValues<F> = Vec<AssignedValue<F>>;

const BITS_PER_BYTE: usize = 8;

/// SafeType's goal is to avoid out-of-range undefined behavior.
/// When building circuits, it's common to use mulitple AssignedValue<F> to represent
/// a logical varaible. For example, we might want to represent a hash with 32 AssignedValue<F>
/// where each AssignedValue represents 1 byte. However, the range of AssignedValue<F> is much
/// larger than 1 byte(0~255). If a circuit takes 32 AssignedValue<F> as inputs and some of them
/// are actually greater than 255, there could be some undefined behaviors.
/// SafeType gurantees the value range of its owned AssignedValue<F>. So circuits don't need to
/// do any extra value checking if they take SafeType as inputs.
#[derive(Clone, Debug)]
pub struct SafeType<F: ScalarField, const BYTES_PER_ELE: usize, const TOTAL_BITS: usize> 
where [(); (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE * BITS_PER_BYTE)]: Sized {
    // value is stored in little-endian. (BYTES_PER_ELE * BITS_PER_BYTE) is the number of bits of a single element.
    value: [AssignedValue<F>; (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE * BITS_PER_BYTE)],
}

impl<F: ScalarField, const BYTES_PER_ELE: usize, const TOTAL_BITS: usize> SafeType<F, BYTES_PER_ELE, TOTAL_BITS> 
where [(); (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE * BITS_PER_BYTE)]: Sized {
    pub const BYTES_PER_ELE: usize = BYTES_PER_ELE;
    pub const TOTAL_BITS: usize = TOTAL_BITS;
    pub const BITS_PER_ELE: usize = min(TOTAL_BITS, BYTES_PER_ELE * BITS_PER_BYTE);
    pub const VALUE_LENGTH: usize = (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE * BITS_PER_BYTE);

    // new is private so Safetype can only be constructed by this crate.
    fn new(raw_values: RawAssignedValues<F>) -> Self {
        Self { value: raw_values.try_into().unwrap() }
    }

    // Return values in littile-endian.
    pub fn value(&self) -> &[AssignedValue<F>; (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE * BITS_PER_BYTE)] {
        &self.value
    }
}

/// Represent TOTAL_BITS with the least number of AssignedValue<F>.
/// (2^(F::NUM_BITS) - 1) might not be a valid value for F. e.g. max value of F is a prime in [2^(F::NUM_BITS-1), 2^(F::NUM_BITS) - 1]
type CompactSafeType<F: ScalarField, const TOTAL_BITS: usize> = SafeType<F, { ((F::NUM_BITS - 1) / 8) as usize}, TOTAL_BITS>;

/// SafeType for bool.
pub type SafeBool<F> = CompactSafeType<F, 1>;
/// SafeType for uint8.
pub type SafeUint8<F> = CompactSafeType<F, 8>;
/// SafeType for uint16.
pub type SafeUint16<F> = CompactSafeType<F, 16>;
/// SafeType for uint32.
pub type SafeUint32<F> = CompactSafeType<F, 32>;
/// SafeType for uint64.
pub type SafeUint64<F> = CompactSafeType<F, 64>;
/// SafeType for uint128.
pub type SafeUint128<F> = CompactSafeType<F, 128>;
/// SafeType for uint256.
pub type SafeUint256<F> = CompactSafeType<F, 256>;
/// SafeType for bytes32.
pub type SafeBytes32<F> = SafeType<F, 1, 256>;

pub struct SafeTypeChip<F: ScalarField> {
    pub range_chip: Arc<RangeChip<F>>,
}

impl<F: ScalarField> SafeTypeChip< F> {
    /// Construct a SafeTypeChip.
    pub fn new(range_chip: Arc<RangeChip<F>>) -> Self {
        Self { range_chip: Arc::clone(&range_chip) }
    }

    /// Convert a vector of AssignedValue to a SafeType. The number of bytes of inputs must equal to the number of bytes of outputs.
    /// This function also add contraints that a AssignedValue in inputs must be in the range of a byte.
    pub fn raw_bytes_to<const BYTES_PER_ELE: usize, const TOTAL_BITS: usize>(
        &self,
        ctx: &mut Context<F>,
        inputs: RawAssignedValues<F>,
    ) -> SafeType<F, BYTES_PER_ELE, TOTAL_BITS>
    where [(); (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE  * BITS_PER_BYTE)]: Sized {
        let element_bits = SafeType::<F, BYTES_PER_ELE, TOTAL_BITS>::BITS_PER_ELE;
        let bits = TOTAL_BITS;
        assert!(
            inputs.len() * BITS_PER_BYTE == max(bits, BITS_PER_BYTE),
            "number of bits doesn't match"
        );
        self.add_bytes_constraints(ctx, &inputs, bits);
        // inputs is a bool or uint8.
        if element_bits == BITS_PER_BYTE {
            return SafeType::<F, BYTES_PER_ELE, TOTAL_BITS>::new(inputs);
        };

        let mut value = vec![];
        let mut byte_base = vec![];
        for i in 0..BYTES_PER_ELE {
            byte_base.push(Witness(self.range_chip.gate.pow_of_two[i * BITS_PER_BYTE]));
        }
        for chunk in inputs.chunks(BYTES_PER_ELE) {
            let acc = self.range_chip.gate.inner_product(
                ctx,
                chunk.to_vec(),
                byte_base[..chunk.len()].to_vec(),
            );
            value.push(acc);
        }
        SafeType::<F, BYTES_PER_ELE, TOTAL_BITS>::new(value)
    }

    fn add_bytes_constraints(
        &self,
        ctx: &mut Context<F>,
        inputs: &RawAssignedValues<F>,
        bits: usize,
    ) {
        let mut bits_left = bits;
        for input in inputs {
            let num_bit = min(bits_left, BITS_PER_BYTE);
            self.range_chip.range_check(ctx, *input,num_bit);
            bits_left -= num_bit;
        }
    }

    // TODO: Add comprasion. e.g. is_less_than(SafeUint8, SafeUint8) -> SafeBool
    // TODO: Add type castings. e.g. uint256 -> bytes32/uint32 -> uint64
}
