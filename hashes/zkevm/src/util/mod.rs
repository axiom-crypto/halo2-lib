pub mod constraint_builder;
pub mod eth_types;
pub mod expression;

/// Packs bits into bytes
pub mod to_bytes {
    use crate::util::eth_types::Field;
    use crate::util::expression::Expr;
    use halo2_base::halo2_proofs::plonk::Expression;

    pub fn expr<F: Field>(bits: &[Expression<F>]) -> Vec<Expression<F>> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0.expr();
            let mut multiplier = F::one();
            for byte in byte_bits.iter() {
                value = value + byte.expr() * multiplier;
                multiplier *= F::from(2);
            }
            bytes.push(value);
        }
        bytes
    }

    pub fn value(bits: &[u8]) -> Vec<u8> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0u8;
            for (idx, bit) in byte_bits.iter().enumerate() {
                value += *bit << idx;
            }
            bytes.push(value);
        }
        bytes
    }
}

/// Returns the random linear combination of the inputs.
/// For list [v_0, ..., v_{l-1}],
/// RLC([v]) = v_0 * R^{l-1} + v_1 * R^{l-2} + ... + v_{l-1}
///
/// Note: this may be different from zkEVM RLC, depending on where it appears.
pub(crate) mod rlc {
    use halo2_base::halo2_proofs::halo2curves::FieldExt;

    pub(crate) fn value<'a, F: FieldExt, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        values.into_iter().fold(F::zero(), |acc, value| acc * randomness + F::from(*value as u64))
    }
}
