pub mod constraint_builder;
pub mod eth_types;
pub mod expression;

/// Packs bits into bytes
pub mod to_bytes {
    use std::iter::successors;

    use crate::util::eth_types::Field;
    use crate::util::expression::Expr;
    use halo2_base::halo2_proofs::plonk::Expression;

    pub fn expr<F: Field>(bits: &[Expression<F>]) -> Vec<Expression<F>> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let two = F::from(2);
        let multipliers =
            successors(Some(F::ONE), |prev| Some(two * prev)).take(8).collect::<Vec<_>>();

        let mut bytes = Vec::with_capacity(bits.len() / 8);
        for byte_bits in bits.chunks_exact(8) {
            let mut value = 0.expr();
            for (byte, &multiplier) in byte_bits.iter().zip(multipliers.iter()) {
                value = value + byte.expr() * multiplier;
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

pub mod word;
