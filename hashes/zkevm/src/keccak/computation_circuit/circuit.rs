use std::cell::RefCell;

use super::poseidon_params;
use crate::{
    keccak::{
        multi_keccak,
        param::{NUM_ROUNDS, NUM_WORDS_TO_ABSORB},
        KeccakAssignedRow, KeccakCircuitConfig, KeccakConfigParams,
    },
    util::eth_types::Field,
};
use halo2_base::{
    gates::{
        circuit::{builder::RangeCircuitBuilder, BaseConfig},
        GateInstructions, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonCompactInput, PoseidonHasher},
    safe_types::SafeTypeChip,
    AssignedValue,
};
use itertools::{izip, Itertools};
use sha3::{Digest, Keccak256};

/// Keccak Computation Circuit
pub struct KeccakComputationCircuit<F: Field> {
    range_circuit_builder: RefCell<RangeCircuitBuilder<F>>,
    inputs: Vec<Vec<u8>>,
    capacity: usize,
    config_params: KeccakComputationCircuitParams,
}

#[derive(Default, Clone)]
pub struct KeccakComputationCircuitParams {
    k: usize,
    keccak_circuit_params: KeccakConfigParams,
}

#[derive(Clone)]
pub struct KeccakComputationConfig<F: Field> {
    range_circuit_config: BaseConfig<F>,
    keccak_circuit_config: KeccakCircuitConfig<F>,
}

impl<F: Field> Circuit<F> for KeccakComputationCircuit<F> {
    type Config = KeccakComputationConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = KeccakComputationCircuitParams;

    fn params(&self) -> Self::Params {
        self.config_params.clone()
    }

    /// Creates a new instance of the [RangeCircuitBuilder] without witnesses by setting the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`BaseConfigParams`]
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let range_circuit_config = RangeCircuitBuilder::configure(meta);
        let keccak_circuit_config = KeccakCircuitConfig::new(meta, params.keccak_circuit_params);
        Self::Config { range_circuit_config, keccak_circuit_config }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("You must use configure_with_params");
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let k = self.config_params.k;
        config.keccak_circuit_config.load_aux_tables(&mut layouter, k as u32)?;
        // TODO: do I need SKIP_FIRST_PASS?
        let (keccak_rows, _) = multi_keccak::<F>(
            &self.inputs,
            Some(self.capacity),
            self.params().keccak_circuit_params,
        );
        let mut keccak_assigned_rows: Vec<KeccakAssignedRow<'_, F>> = Vec::default();
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                keccak_assigned_rows =
                    config.keccak_circuit_config.assign(&mut region, &keccak_rows);
                Ok(())
            },
        )?;
        let loaded_assigned_rows = self.load_keccak_assigned_rows(keccak_assigned_rows);

        let (compact_inputs, result_selector_per_chunk) =
            self.generate_poseidon_inputs(&loaded_assigned_rows);

        let _circuit_final_output = self.compute_circuit_final_output(
            &loaded_assigned_rows,
            &compact_inputs,
            &result_selector_per_chunk,
        );

        self.range_circuit_builder.borrow().synthesize(config.range_circuit_config, layouter)?;
        Ok(())
    }
}

/// Witnesses to be exposed as circuit outputs.
struct KeccakCircuitOutput<F: Field> {
    pub(crate) input_poseidon: AssignedValue<F>,
    pub(crate) hash_lo: AssignedValue<F>,
    pub(crate) hash_hi: AssignedValue<F>,
}

struct LoadedKeccakAssignedRow<F: Field> {
    pub(crate) is_final: AssignedValue<F>,
    pub(crate) hash_lo: AssignedValue<F>,
    pub(crate) hash_hi: AssignedValue<F>,
    pub(crate) bytes_left: AssignedValue<F>,
    pub(crate) word_value: AssignedValue<F>,
}

impl<F: Field> KeccakComputationCircuit<F> {
    /// Load keccak assigned rows into halo2-lib.
    fn load_keccak_assigned_rows(
        &self,
        assigned_rows: Vec<KeccakAssignedRow<'_, F>>,
    ) -> Vec<LoadedKeccakAssignedRow<F>> {
        let mut loaded_assigned_rows = Vec::with_capacity(assigned_rows.len());
        let range_circuit_builder = self.range_circuit_builder.borrow();
        let mut copy_manager = range_circuit_builder.core().copy_manager.lock().unwrap();
        for assigned_row in assigned_rows {
            loaded_assigned_rows.push(LoadedKeccakAssignedRow {
                is_final: copy_manager.load_external_assigned(assigned_row.is_final),
                hash_lo: copy_manager.load_external_assigned(assigned_row.hash_lo),
                hash_hi: copy_manager.load_external_assigned(assigned_row.hash_hi),
                bytes_left: copy_manager.load_external_assigned(assigned_row.bytes_left),
                word_value: copy_manager.load_external_assigned(assigned_row.word_value),
            });
        }
        loaded_assigned_rows
    }

    // Generate compact inputs for Poseidon based on raw inputs in Keccak witnesses.
    //
    // To illustrate how this function works, let's take the following example:
    // Parameters: RATE = 2, NUM_WORDS_TO_ABSORB = 2, NUM_ROUNDS = 3
    // Considering the following logical input in little endian bytes:
    // logical_input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25]
    // Keccak witnesses represent the input in 2 chunks(NUM_ROUNDS + 1 rows per chunk):
    // loaded_assigned_rows = [
    //     {bytes_left:  21, word_value: 0x0807060504030201, is_final:   N/A},
    //     {bytes_left:  13, word_value: 0x1817161514131211, is_final:   N/A},
    //     {bytes_left: N/A, word_value:                N/A, is_final:   N/A},    // No input/output information after first NUM_WORDS_TO_ABSORB rows.
    //     {bytes_left: N/A, word_value:                N/A, is_final: false},
    //     {bytes_left:   5, word_value: 0x0000002524232221, is_final:   N/A},
    //     {bytes_left:   0, word_value: 0x0000000000000000, is_final:   N/A},
    //     {bytes_left: N/A, word_value:                N/A, is_final:   N/A},    // No input/output information after first NUM_WORDS_TO_ABSORB rows.
    //     {bytes_left: N/A, word_value:                N/A, is_final:  true},
    // ]
    // For easier Poseidon processing, the raw input is encoded in the following way:
    // If the logic input is empty, [0; RATE].
    // If the logic input is empty, each word is encoded as RATE witnesses. First word is encoded
    // as [<byte length of logical input>, logical_input[0], 0..]. Other words are encoded as [logical_input[i], 0, 0..].
    // Note: With this encoding, App circuits should be able to compute Poseidons of variable length inputs easily.
    // Then we get the following compact inputs for Poseidon hasher:
    // poseidon_compact_inputs = [
    //  {inputs: [                21, 0x0807060504030201], len: 2, is_final: false},   // 21 is the length of the logical input.
    //  {inputs: [0x1817161514131211,                0x0], len: 2, is_final: false},
    //  {inputs: [0x0000002524232221,                0x0], len: 2, is_final: true},    // The last row of the logical input.
    //  {inputs: [               0x0,                0x0], len: 2, is_final: true},    // This row corresponds to the padding row in loaded_assigned_rows.
    // ]
    // The Poseidon results will be:
    // poseidon_compact_outputs = [
    //  {hash:                                N/A, is_final: false},
    //  {hash:                                N/A, is_final: false},
    //  {hash: <poseidon(<encoded logical input>), is_final:  true},
    //  {hash:               poseidon([0x0, 0x0]), is_final:  true},
    // ]
    // Because of the padding rows, is_final cannot tell which row is the result of a logical input. Therefore
    // we also build a selector array(2d, <num of chunks> * NUM_WORDS_TO_ABSORB) to select reuslts:
    // poseidon_selector: [[0, 0], [1, 0]]
    fn generate_poseidon_inputs(
        &self,
        loaded_assigned_rows: &[LoadedKeccakAssignedRow<F>],
    ) -> (
        Vec<PoseidonCompactInput<F, { poseidon_params::RATE }>>,
        Vec<[AssignedValue<F>; NUM_WORDS_TO_ABSORB]>,
    ) {
        let rows_per_round = self.config_params.keccak_circuit_params.rows_per_round;
        let mut range_circuit_builder_mut = self.range_circuit_builder.borrow_mut();
        let ctx = range_circuit_builder_mut.main(0);
        let range_chip = self.range_circuit_builder.borrow().range_chip();

        let num_chunks = (loaded_assigned_rows.len() / rows_per_round - 1) / (NUM_ROUNDS + 1);
        let compact_input_len = num_chunks * (NUM_WORDS_TO_ABSORB);
        let mut result_selector_per_chunk = Vec::with_capacity(num_chunks);
        let mut compact_inputs = Vec::with_capacity(compact_input_len);

        let rate_witness = ctx.load_constant(F::from(poseidon_params::RATE as u64));
        let zero_witness = ctx.load_zero();
        let mut chunk_is_final_last = zero_witness;

        // Skip the first round which is dummy.
        for chunk in
            &loaded_assigned_rows.iter().step_by(rows_per_round).skip(1).chunks(NUM_ROUNDS + 1)
        {
            let chunk = chunk.collect_vec();
            // If this chunk is the last chunk of a logical input.
            let chunk_is_final = chunk[NUM_ROUNDS].is_final;
            let mut result_selector = [zero_witness; NUM_WORDS_TO_ABSORB];
            let mut result_selector_is_set = zero_witness;
            for round_idx in 0..NUM_WORDS_TO_ABSORB {
                let round = chunk[round_idx];
                // First word is encoded as [bytes_left, word_value, 0..]. Here bytes_left equals to the length of the input.
                // Other words are encoded as [word_value, 0, 0..].
                let mut inputs = [zero_witness; { poseidon_params::RATE }];
                if round_idx == 0 {
                    inputs[0] = range_chip.gate().select(
                        ctx,
                        round.bytes_left,
                        round.word_value,
                        chunk_is_final_last,
                    );
                    inputs[1] = range_chip.gate().select(
                        ctx,
                        round.word_value,
                        zero_witness,
                        chunk_is_final_last,
                    );
                } else {
                    inputs[0] = round.word_value;
                }
                let is_final = if round_idx == NUM_WORDS_TO_ABSORB - 1 {
                    chunk_is_final
                } else {
                    let next_bytes_left_is_zero =
                        range_chip.gate().is_zero(ctx, chunk[round_idx + 1].bytes_left);
                    range_chip.gate().and(ctx, next_bytes_left_is_zero, chunk_is_final)
                };
                // First round with is_final == true outputs the poseidon result of the input.
                // All later rounds are dummies.
                result_selector[round_idx] =
                    range_chip.gate().select(ctx, zero_witness, is_final, result_selector_is_set);
                result_selector_is_set =
                    range_chip.gate().or(ctx, result_selector_is_set, result_selector[round_idx]);

                compact_inputs.push(PoseidonCompactInput::new(
                    inputs,
                    SafeTypeChip::unsafe_to_bool(is_final),
                    rate_witness,
                ));
            }
            result_selector_per_chunk.push(result_selector);
            chunk_is_final_last = chunk_is_final;
        }
        (compact_inputs, result_selector_per_chunk)
    }

    // Compute poseidon hash of logical inputs then combine with Keccak256 hash.
    fn compute_circuit_final_output(
        &self,
        loaded_assigned_rows: &[LoadedKeccakAssignedRow<F>],
        compact_inputs: &[PoseidonCompactInput<F, { poseidon_params::RATE }>],
        result_selector_per_chunk: &[[AssignedValue<F>; NUM_WORDS_TO_ABSORB]],
    ) -> Vec<KeccakCircuitOutput<F>> {
        let rows_per_round = self.config_params.keccak_circuit_params.rows_per_round;
        let mut range_circuit_builder_mut = self.range_circuit_builder.borrow_mut();
        let ctx = range_circuit_builder_mut.main(0);
        let range_chip = self.range_circuit_builder.borrow().range_chip();

        let num_chunks = (loaded_assigned_rows.len() / rows_per_round - 1) / (NUM_ROUNDS + 1);

        let zero_witness = ctx.load_zero();

        // Filter out the first row of the last round of each chunk, which contains keccak hash result.
        let keccak_output_rows = loaded_assigned_rows
            .iter()
            .step_by(rows_per_round)
            .step_by(NUM_ROUNDS + 1)
            .skip(1)
            .collect_vec();

        // Construct in-circuit Poseidon hasher. Assuming SECURE_MDS = 0.
        let spec =
            OptimizedPoseidonSpec::<F, { poseidon_params::T }, { poseidon_params::RATE }>::new::<
                { poseidon_params::R_F },
                { poseidon_params::R_P },
                { poseidon_params::SECURE_MDS },
            >();
        let mut poseidon_hasher =
            PoseidonHasher::<F, { poseidon_params::T }, { poseidon_params::RATE }>::new(spec);
        assert!(poseidon_params::RATE >= 2, "Poseidon RATE must be at least to encode inputs");
        poseidon_hasher.initialize_consts(ctx, range_chip.gate());
        let dummy_input_poseidon = poseidon_hasher.hash_fix_len_array(
            ctx,
            &range_chip,
            &[zero_witness; { poseidon_params::RATE }],
        );
        let mut circuit_final_outputs = Vec::with_capacity(num_chunks);
        // Output of Keccak256::digest is big endian.
        let dummy_keccak_val = Keccak256::digest(&[]);
        let dummy_keccak_val_lo = u128::from_be_bytes(dummy_keccak_val[16..].try_into().unwrap());
        let dummy_keccak_val_hi = u128::from_be_bytes(dummy_keccak_val[..16].try_into().unwrap());
        let dummy_keccak_lo_witness = ctx.load_constant(F::from_u128(dummy_keccak_val_lo));
        let dummy_keccak_hi_witness = ctx.load_constant(F::from_u128(dummy_keccak_val_hi));
        let compact_outputs = poseidon_hasher.hash_compact_input(ctx, &range_chip, &compact_inputs);
        for (compact_output, keccak_output_row, result_selector) in izip!(
            compact_outputs.chunks(NUM_WORDS_TO_ABSORB),
            keccak_output_rows,
            result_selector_per_chunk,
        ) {
            let mut input_poseidon = range_chip.gate().inner_product(
                ctx,
                compact_output.iter().map(|o| *o.hash()),
                result_selector.iter().map(|s| halo2_base::QuantumCell::Existing(*s)),
            );
            input_poseidon = range_chip.gate().select(
                ctx,
                input_poseidon,
                dummy_input_poseidon,
                keccak_output_row.is_final,
            );
            let hash_lo = range_chip.gate().select(
                ctx,
                keccak_output_row.hash_lo,
                dummy_keccak_lo_witness,
                keccak_output_row.is_final,
            );
            let hash_hi = range_chip.gate().select(
                ctx,
                keccak_output_row.hash_hi,
                dummy_keccak_hi_witness,
                keccak_output_row.is_final,
            );
            circuit_final_outputs.push(KeccakCircuitOutput { input_poseidon, hash_lo, hash_hi });
        }
        circuit_final_outputs
    }
}
