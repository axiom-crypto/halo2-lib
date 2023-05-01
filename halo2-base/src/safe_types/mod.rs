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

type RawAssignedValues<F> = Vec<AssignedValue<F>>;

const BITS_PER_BYTE: usize = 8;
// Each AssignedValue can at most represent 8 bytes.
const MAX_BYTE_PER_ELEMENT: usize = 8;

// SafeType's goal is to avoid out-of-range undefined behavior.
// When building circuits, it's common to use mulitple AssignedValue<F> to represent
// a logical varaible. For example, we might want to represent a hash with 32 AssignedValue<F>
// where each AssignedValue represents 1 byte. However, the range of AssignedValue<F> is much
// larger than 1 byte(0~255). If a circuit takes 32 AssignedValue<F> as inputs and some of them
// are actually greater than 255, there could be some undefined behaviors.
// SafeType gurantees the value range of its owned AssignedValue<F>. So circuits don't need to
// do any extra value checking if they take SafeType as inputs.
#[derive(Clone, Debug)]
pub struct SafeType<F: ScalarField, const B: usize, const L: usize> {
    value: RawAssignedValues<F>,
}

impl<F: ScalarField, const B: usize, const L: usize> SafeType<F, B, L> {
    // new is private so Safetype can only be constructed by this crate.
    fn new(raw_values: RawAssignedValues<F>) -> Self {
        Self { value: raw_values }
    }

    // Return values in littile-endian.
    pub fn value(&self) -> &RawAssignedValues<F> {
        &self.value
    }

    // length of value() must equal to value_length().
    pub fn value_length() -> usize {
        L
    }

    // All elements in value() need to be in [0, element_limit()].
    pub fn element_limit() -> u64 {
        ((1u128 << B) - 1) as u64
    }

    // Each element in value() has element_bits() bits.
    pub fn element_bits() -> usize {
        B
    }
}

pub type SafeBool<F> = SafeType<F, 1, 1>;
pub type SafeUint8<F> = SafeType<F, 8, 1>;
pub type SafeUint16<F> = SafeType<F, 16, 1>;
pub type SafeUint32<F> = SafeType<F, 32, 1>;
pub type SafeUint64<F> = SafeType<F, 64, 1>;
pub type SafeUint128<F> = SafeType<F, 64, 2>;
pub type SafeUint256<F> = SafeType<F, 64, 4>;
pub type SafeBytes32<F> = SafeType<F, 8, 32>;

pub struct SafeTypeChip<F: ScalarField> {
    pub range_chip: RangeChip<F>,
    pub byte_bases: Vec<QuantumCell<F>>,
}

impl<F: ScalarField> SafeTypeChip<F> {
    pub fn new(lookup_bits: usize) -> Self {
        let byte_base = F::from(1u64 << BITS_PER_BYTE);
        let mut running_base = F::one();
        let num_bases = MAX_BYTE_PER_ELEMENT;
        let mut byte_bases = Vec::with_capacity(num_bases);
        for _ in 0..num_bases {
            byte_bases.push(Constant(running_base));
            running_base *= &byte_base;
        }

        Self { range_chip: RangeChip::default(lookup_bits), byte_bases }
    }

    pub fn raw_bytes_to<const B: usize, const L: usize>(
        &self,
        ctx: &mut Context<F>,
        inputs: RawAssignedValues<F>,
    ) -> SafeType<F, B, L> {
        let value_length = SafeType::<F, B, L>::value_length();
        let element_bits = SafeType::<F, B, L>::element_bits();
        let bits = value_length * element_bits;
        assert!(
            inputs.len() * BITS_PER_BYTE == max(bits, BITS_PER_BYTE),
            "number of bits doesn't match"
        );
        self.add_bytes_constraints(ctx, &inputs, bits);
        if value_length == 1 || element_bits == BITS_PER_BYTE {
            return SafeType::<F, B, L>::new(inputs);
        };
        let bytes_per_element = element_bits / BITS_PER_BYTE;
        let mut value = vec![];
        for i in 0..value_length {
            let start = i * bytes_per_element;
            let end = start + bytes_per_element;
            let acc = self.range_chip.gate.inner_product(
                ctx,
                inputs[start..end].to_vec(),
                self.byte_bases[..bytes_per_element].to_vec(),
            );
            value.push(acc);
        }
        SafeType::<F, B, L>::new(value)
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
            self.range_chip.check_less_than_safe(ctx, *input, 1u64 << num_bit);
            bits_left -= num_bit;
        }
    }

    // TODO: Add comprasion. e.g. is_less_than(SafeUint8, SafeUint8) -> SafeBool
    // TODO: Add type castings. e.g. uint256 -> bytes32/uint32 -> uint64
}
