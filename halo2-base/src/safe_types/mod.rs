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
/// TOTAL_BITS is the number of total bits of this type.
/// BYTES_PER_ELE is the number of bytes of each element.
#[derive(Clone, Debug)]
pub struct SafeType<F: ScalarField, const BYTES_PER_ELE: usize, const TOTAL_BITS: usize> {
    // value is stored in little-endian.
    value: RawAssignedValues<F>,
}

impl<F: ScalarField, const BYTES_PER_ELE: usize, const TOTAL_BITS: usize>
    SafeType<F, BYTES_PER_ELE, TOTAL_BITS>
{
    /// Number of bytes of each element.
    pub const BYTES_PER_ELE: usize = BYTES_PER_ELE;
    /// Total bits of this type.
    pub const TOTAL_BITS: usize = TOTAL_BITS;
    /// Number of bits of each element.
    pub fn bits_per_ele() -> usize {
        min(TOTAL_BITS, BYTES_PER_ELE * BITS_PER_BYTE)
    }
    /// Number of elements of this type.
    pub const VALUE_LENGTH: usize =
        (TOTAL_BITS + BYTES_PER_ELE * BITS_PER_BYTE - 1) / (BYTES_PER_ELE * BITS_PER_BYTE);

    // new is private so Safetype can only be constructed by this crate.
    fn new(raw_values: RawAssignedValues<F>) -> Self {
        assert!(raw_values.len() == Self::VALUE_LENGTH, "Invalid raw values length");
        Self { value: raw_values }
    }

    /// Return values in littile-endian.
    pub fn value(&self) -> &RawAssignedValues<F> {
        &self.value
    }
}

/// Represent TOTAL_BITS with the least number of AssignedValue<F>.
/// (2^(F::NUM_BITS) - 1) might not be a valid value for F. e.g. max value of F is a prime in [2^(F::NUM_BITS-1), 2^(F::NUM_BITS) - 1]
#[allow(type_alias_bounds)]
type CompactSafeType<F: ScalarField, const TOTAL_BITS: usize> =
    SafeType<F, { ((F::NUM_BITS - 1) / 8) as usize }, TOTAL_BITS>;

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
/// SafeType for uint160.
pub type SafeUint160<F> = CompactSafeType<F, 160>;
/// SafeType for uint256.
pub type SafeUint256<F> = CompactSafeType<F, 256>;
/// SafeType for Address.
pub type SafeAddress<F> = SafeType<F, 1, 160>;
/// SafeType for bytes32.
pub type SafeBytes32<F> = SafeType<F, 1, 256>;

/// Chip for SafeType
pub struct SafeTypeChip<'a, F: ScalarField> {
    range_chip: &'a RangeChip<F>,
}

impl<'a, F: ScalarField> SafeTypeChip<'a, F> {
    /// Construct a SafeTypeChip.
    pub fn new(range_chip: &'a RangeChip<F>) -> Self {
        Self { range_chip }
    }

    /// Convert a vector of AssignedValue(treated as little-endian) to a SafeType.
    /// The number of bytes of inputs must equal to the number of bytes of outputs.
    /// This function also add contraints that a AssignedValue in inputs must be in the range of a byte.
    pub fn raw_bytes_to<const BYTES_PER_ELE: usize, const TOTAL_BITS: usize>(
        &self,
        ctx: &mut Context<F>,
        inputs: RawAssignedValues<F>,
    ) -> SafeType<F, BYTES_PER_ELE, TOTAL_BITS> {
        let element_bits = SafeType::<F, BYTES_PER_ELE, TOTAL_BITS>::bits_per_ele();
        let bits = TOTAL_BITS;
        assert!(
            inputs.len() * BITS_PER_BYTE == max(bits, BITS_PER_BYTE),
            "number of bits doesn't match"
        );
        self.add_bytes_constraints(ctx, &inputs, bits);
        // inputs is a bool or uint8.
        if bits == 1 || element_bits == BITS_PER_BYTE {
            return SafeType::<F, BYTES_PER_ELE, TOTAL_BITS>::new(inputs);
        };

        let byte_base = (0..BYTES_PER_ELE)
            .map(|i| Witness(self.range_chip.gate.pow_of_two[i * BITS_PER_BYTE]))
            .collect::<Vec<_>>();
        let value = inputs
            .chunks(BYTES_PER_ELE)
            .map(|chunk| {
                self.range_chip.gate.inner_product(
                    ctx,
                    chunk.to_vec(),
                    byte_base[..chunk.len()].to_vec(),
                )
            })
            .collect::<Vec<_>>();
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
            self.range_chip.range_check(ctx, *input, num_bit);
            bits_left -= num_bit;
        }
    }

    // TODO: Add comprasion. e.g. is_less_than(SafeUint8, SafeUint8) -> SafeBool
    // TODO: Add type castings. e.g. uint256 -> bytes32/uint32 -> uint64
}
