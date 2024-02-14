use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::plonk::Error,
    utils::BigPrimeField,
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;

use self::compression::{sha256_compression, INIT_STATE};

use self::spread::SpreadChip;

mod compression;
mod spread;

#[derive(Debug, Clone)]
pub struct Sha256Chip<'a, F: BigPrimeField> {
    spread: SpreadChip<'a, F>,
}

impl<'a, F: BigPrimeField> Sha256Chip<'a, F> {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    pub fn new(range: &'a RangeChip<F>) -> Self {
        // Spread chip requires 16 % lookup_bits == 0 so we set it to either 8 or 16 based on circuit degree.
        let lookup_bits = if range.lookup_bits() > 8 { 16 } else { 8 };

        Self { spread: SpreadChip::new(range, lookup_bits) }
    }

    fn digest_varlen(
        &self,
        ctx: &mut Context<F>,
        input: impl IntoIterator<Item = QuantumCell<F>>,
        max_len: usize,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let max_processed_bytes = {
            let mut max_bytes = max_len + 9;
            let remainder = max_bytes % 64;
            if remainder != 0 {
                max_bytes += 64 - remainder;
            }
            max_bytes
        };

        let mut assigned_input_bytes = input
            .into_iter()
            .map(|cell| match cell {
                QuantumCell::Existing(v) => v,
                QuantumCell::Witness(v) => ctx.load_witness(v),
                QuantumCell::Constant(v) => ctx.load_constant(v),
                _ => unreachable!(),
            })
            .collect_vec();

        let input_byte_size = assigned_input_bytes.len();
        let input_byte_size_with_9 = input_byte_size + 9;
        let range = self.spread.range();
        let gate = &range.gate;

        assert!(input_byte_size <= max_len);

        let one_round_size = Self::BLOCK_SIZE;

        let num_round = if input_byte_size_with_9 % one_round_size == 0 {
            input_byte_size_with_9 / one_round_size
        } else {
            input_byte_size_with_9 / one_round_size + 1
        };
        let padded_size = one_round_size * num_round;
        let zero_padding_byte_size = padded_size - input_byte_size_with_9;

        let mut assign_byte = |byte: u8| ctx.load_witness(F::from(byte as u64));

        assigned_input_bytes.push(assign_byte(0x80));

        for _ in 0..zero_padding_byte_size {
            assigned_input_bytes.push(assign_byte(0u8));
        }

        let mut input_len_bytes = [0; 8];
        let le_size_bytes = (8 * input_byte_size).to_le_bytes();
        input_len_bytes[0..le_size_bytes.len()].copy_from_slice(&le_size_bytes);
        for byte in input_len_bytes.iter().rev() {
            assigned_input_bytes.push(assign_byte(*byte));
        }

        assert_eq!(assigned_input_bytes.len(), num_round * one_round_size);

        let assigned_num_round = ctx.load_witness(F::from(num_round as u64));

        // compute an initial state from the precomputed_input.
        let last_state = INIT_STATE;

        let mut assigned_last_state_vec = vec![last_state
            .iter()
            .map(|state| ctx.load_witness(F::from(*state as u64)))
            .collect_vec()];

        let mut num_processed_input = 0;
        while num_processed_input < max_processed_bytes {
            let assigned_input_word_at_round =
                &assigned_input_bytes[num_processed_input..num_processed_input + one_round_size];
            let new_assigned_hs_out = sha256_compression(
                ctx,
                &self.spread,
                assigned_input_word_at_round,
                assigned_last_state_vec.last().unwrap(),
            )?;

            assigned_last_state_vec.push(new_assigned_hs_out);
            num_processed_input += one_round_size;
        }

        let zero = ctx.load_zero();
        let mut output_h_out = vec![zero; 8];
        for (n_round, assigned_state) in assigned_last_state_vec.into_iter().enumerate() {
            let selector = gate.is_equal(
                ctx,
                QuantumCell::Constant(F::from(n_round as u64)),
                assigned_num_round,
            );
            for i in 0..8 {
                output_h_out[i] = gate.select(ctx, assigned_state[i], output_h_out[i], selector);
            }
        }
        let output_digest_bytes = output_h_out
            .into_iter()
            .flat_map(|assigned_word| {
                let be_bytes = assigned_word.value().get_lower_32().to_be_bytes().to_vec();
                let assigned_bytes = (0..4)
                    .map(|idx| {
                        let assigned = ctx.load_witness(F::from(be_bytes[idx] as u64));
                        range.range_check(ctx, assigned, 8);
                        assigned
                    })
                    .collect_vec();
                let mut sum = ctx.load_zero();
                for (idx, assigned_byte) in assigned_bytes.iter().copied().enumerate() {
                    sum = gate.mul_add(
                        ctx,
                        assigned_byte,
                        QuantumCell::Constant(F::from(1u64 << (24 - 8 * idx))),
                        sum,
                    );
                }
                ctx.constrain_equal(&assigned_word, &sum);
                assigned_bytes
            })
            .collect_vec();

        Ok(output_digest_bytes)
    }

    pub fn digest(
        &self,
        ctx: &mut Context<F>,
        input: impl IntoIterator<Item = QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let input = input.into_iter().collect_vec();
        let input_len = input.len();
        self.digest_varlen(ctx, input, input_len)
    }

    pub fn digest_le(
        &self,
        ctx: &mut Context<F>,
        input: impl IntoIterator<Item = QuantumCell<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut digest = self.digest(ctx, input).unwrap();
        digest.reverse();
        Ok(digest)
    }
}

#[cfg(test)]
mod test {
    use halo2_base::{
        gates::RangeInstructions, halo2_proofs::halo2curves::grumpkin::Fq as Fr,
        utils::testing::base_test, QuantumCell,
    };
    use itertools::Itertools;
    use sha2::{Digest, Sha256};

    use super::Sha256Chip;

    #[test]
    fn test_sha256() {
        let preimage = b"hello world";

        let mut hasher = Sha256::new();
        hasher.update(preimage);
        let result = hasher.finalize();

        base_test().k(14).lookup_bits(13).expect_satisfied(true).run(|ctx, range| {
            let preimage_assigned = preimage
                .iter()
                .map(|byte| QuantumCell::Existing(ctx.load_witness(Fr::from(*byte as u64))))
                .collect_vec();

            let result_assinged = result
                .iter()
                .map(|byte| {
                    let assigned = ctx.load_witness(Fr::from(*byte as u64));
                    range.range_check(ctx, assigned, 8);
                    assigned
                })
                .collect_vec();

            let sha256_chip = Sha256Chip::new(range);
            let digest = sha256_chip.digest(ctx, preimage_assigned).unwrap();

            for (assigned, expected) in digest.iter().zip(result_assinged.iter()) {
                ctx.constrain_equal(assigned, expected);
            }
        })
    }
}
