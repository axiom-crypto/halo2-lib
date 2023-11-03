use std::cell::RefCell;

use crate::{
    keccak::{
        component::{
            encode::{
                get_words_to_witness_multipliers, num_poseidon_absorb_per_keccak_f,
                num_word_per_witness,
            },
            output::{dummy_circuit_output, KeccakCircuitOutput},
            param::*,
        },
        vanilla::{
            keccak_packed_multi::get_num_keccak_f, param::*, witness::multi_keccak,
            KeccakAssignedRow, KeccakCircuitConfig, KeccakConfigParams,
        },
    },
    util::eth_types::Field,
};
use getset::{CopyGetters, Getters};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        flex_gate::MultiPhaseThreadBreakPoints,
        GateChip, GateInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    poseidon::hasher::{
        spec::OptimizedPoseidonSpec, PoseidonCompactChunkInput, PoseidonCompactOutput,
        PoseidonHasher,
    },
    safe_types::{SafeBool, SafeTypeChip},
    AssignedValue, Context,
    QuantumCell::Constant,
};
use itertools::Itertools;

/// Keccak Component Shard Circuit
#[derive(Getters)]
pub struct KeccakComponentShardCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,

    /// Parameters of this circuit. The same parameters always construct the same circuit.
    #[getset(get = "pub")]
    params: KeccakComponentShardCircuitParams,

    base_circuit_builder: RefCell<BaseCircuitBuilder<F>>,
    hasher: RefCell<PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>>,
    gate_chip: GateChip<F>,
}

/// Parameters of KeccakComponentCircuit.
#[derive(Default, Clone, CopyGetters)]
pub struct KeccakComponentShardCircuitParams {
    /// This circuit has 2^k rows.
    #[getset(get_copy = "pub")]
    k: usize,
    // Number of unusable rows withhold by Halo2.
    #[getset(get_copy = "pub")]
    num_unusable_row: usize,
    /// Max keccak_f this circuits can aceept. The circuit can at most process <capacity> of inputs
    /// with < NUM_BYTES_TO_ABSORB bytes or an input with <capacity> * NUM_BYTES_TO_ABSORB - 1 bytes.
    #[getset(get_copy = "pub")]
    capacity: usize,
    // If true, publish raw outputs. Otherwise, publish Poseidon commitment of raw outputs.
    #[getset(get_copy = "pub")]
    publish_raw_outputs: bool,

    // Derived parameters of sub-circuits.
    pub keccak_circuit_params: KeccakConfigParams,
    pub base_circuit_params: BaseCircuitParams,
}

impl KeccakComponentShardCircuitParams {
    /// Create a new KeccakComponentShardCircuitParams.
    pub fn new(
        k: usize,
        num_unusable_row: usize,
        capacity: usize,
        publish_raw_outputs: bool,
    ) -> Self {
        assert!(1 << k > num_unusable_row, "Number of unusable rows must be less than 2^k");
        let max_rows = (1 << k) - num_unusable_row;
        // Derived from [crate::keccak::native_circuit::keccak_packed_multi::get_keccak_capacity].
        let rows_per_round = max_rows / (capacity * (NUM_ROUNDS + 1) + 1 + NUM_WORDS_TO_ABSORB);
        assert!(rows_per_round > 0, "No enough rows for the speficied capacity");
        let keccak_circuit_params = KeccakConfigParams { k: k as u32, rows_per_round };
        let base_circuit_params = BaseCircuitParams {
            k,
            lookup_bits: None,
            num_instance_columns: if publish_raw_outputs {
                OUTPUT_NUM_COL_RAW
            } else {
                OUTPUT_NUM_COL_COMMIT
            },
            ..Default::default()
        };
        Self {
            k,
            num_unusable_row,
            capacity,
            publish_raw_outputs,
            keccak_circuit_params,
            base_circuit_params,
        }
    }
}

/// Circuit::Config for Keccak Component Shard Circuit.
#[derive(Clone)]
pub struct KeccakComponentShardConfig<F: Field> {
    pub base_circuit_config: BaseConfig<F>,
    pub keccak_circuit_config: KeccakCircuitConfig<F>,
}

impl<F: Field> Circuit<F> for KeccakComponentShardCircuit<F> {
    type Config = KeccakComponentShardConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = KeccakComponentShardCircuitParams;

    fn params(&self) -> Self::Params {
        self.params.clone()
    }

    /// Creates a new instance of the [KeccakCoprocessorLeafCircuit] without witnesses by setting the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`BaseConfigParams`]
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let keccak_circuit_config = KeccakCircuitConfig::new(meta, params.keccak_circuit_params);
        let base_circuit_params = params.base_circuit_params;
        // BaseCircuitBuilder::configure_with_params must be called in the end in order to get the correct
        // unusable_rows.
        let base_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_params.clone());
        Self::Config { base_circuit_config, keccak_circuit_config }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("You must use configure_with_params");
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let k = self.params.k;
        config.keccak_circuit_config.load_aux_tables(&mut layouter, k as u32)?;
        let mut keccak_assigned_rows: Vec<KeccakAssignedRow<'_, F>> = Vec::default();
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                let (keccak_rows, _) = multi_keccak::<F>(
                    &self.inputs,
                    Some(self.params.capacity),
                    self.params.keccak_circuit_params,
                );
                keccak_assigned_rows =
                    config.keccak_circuit_config.assign(&mut region, &keccak_rows);
                Ok(())
            },
        )?;

        // Base circuit witness generation.
        let loaded_keccak_fs = self.load_keccak_assigned_rows(keccak_assigned_rows);
        self.generate_base_circuit_witnesses(&loaded_keccak_fs);

        self.base_circuit_builder.borrow().synthesize(config.base_circuit_config, layouter)?;

        // Reset the circuit to the initial state so synthesize could be called multiple times.
        self.base_circuit_builder.borrow_mut().clear();
        self.hasher.borrow_mut().clear();
        Ok(())
    }
}

/// Witnesses of a keccak_f which are necessary to be loaded into halo2-lib.
#[derive(Clone, Copy, Debug, CopyGetters, Getters)]
pub struct LoadedKeccakF<F: Field> {
    /// bytes_left of the first row of the first round of this keccak_f. This could be used to determine the length of the input.
    #[getset(get_copy = "pub")]
    pub(crate) bytes_left: AssignedValue<F>,
    /// Input words (u64) of this keccak_f.
    #[getset(get = "pub")]
    pub(crate) word_values: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
    /// The output of this keccak_f. is_final/hash_lo/hash_hi come from the first row of the last round(NUM_ROUNDS).
    #[getset(get_copy = "pub")]
    pub(crate) is_final: SafeBool<F>,
    /// The lower 16 bits (in big-endian, 16..) of the output of this keccak_f.
    #[getset(get_copy = "pub")]
    pub(crate) hash_lo: AssignedValue<F>,
    /// The high 16 bits (in big-endian, ..16) of the output of this keccak_f.
    #[getset(get_copy = "pub")]
    pub(crate) hash_hi: AssignedValue<F>,
}

impl<F: Field> LoadedKeccakF<F> {
    pub fn new(
        bytes_left: AssignedValue<F>,
        word_values: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
        is_final: SafeBool<F>,
        hash_lo: AssignedValue<F>,
        hash_hi: AssignedValue<F>,
    ) -> Self {
        Self { bytes_left, word_values, is_final, hash_lo, hash_hi }
    }
}

impl<F: Field> KeccakComponentShardCircuit<F> {
    /// Create a new KeccakComponentShardCircuit.
    pub fn new(
        inputs: Vec<Vec<u8>>,
        params: KeccakComponentShardCircuitParams,
        witness_gen_only: bool,
    ) -> Self {
        let input_size = inputs.iter().map(|input| get_num_keccak_f(input.len())).sum::<usize>();
        assert!(input_size < params.capacity, "Input size exceeds capacity");
        let mut base_circuit_builder = BaseCircuitBuilder::new(witness_gen_only);
        base_circuit_builder.set_params(params.base_circuit_params.clone());
        Self {
            inputs,
            params,
            base_circuit_builder: RefCell::new(base_circuit_builder),
            hasher: RefCell::new(create_hasher()),
            gate_chip: GateChip::new(),
        }
    }

    /// Get break points of BaseCircuitBuilder.
    pub fn base_circuit_break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.base_circuit_builder.borrow().break_points()
    }

    /// Set break points of BaseCircuitBuilder.
    pub fn set_base_circuit_break_points(&self, break_points: MultiPhaseThreadBreakPoints) {
        self.base_circuit_builder.borrow_mut().set_break_points(break_points);
    }

    pub fn update_base_circuit_params(&mut self, params: &BaseCircuitParams) {
        self.params.base_circuit_params = params.clone();
        self.base_circuit_builder.borrow_mut().set_params(params.clone());
    }

    /// Simulate witness generation of the base circuit to determine BaseCircuitParams because the number of columns
    /// of the base circuit can only be known after witness generation.
    pub fn calculate_base_circuit_params(
        params: &KeccakComponentShardCircuitParams,
    ) -> BaseCircuitParams {
        // Create a simulation circuit to calculate base circuit parameters.
        let simulation_circuit = Self::new(vec![], params.clone(), false);
        let loaded_keccak_fs = simulation_circuit.mock_load_keccak_assigned_rows();
        simulation_circuit.generate_base_circuit_witnesses(&loaded_keccak_fs);

        let base_circuit_params = simulation_circuit
            .base_circuit_builder
            .borrow_mut()
            .calculate_params(Some(params.num_unusable_row));
        // prevent drop warnings
        simulation_circuit.base_circuit_builder.borrow_mut().clear();

        base_circuit_params
    }

    /// Mock loading Keccak assigned rows from Keccak circuit. This function doesn't create any witnesses/constraints.
    fn mock_load_keccak_assigned_rows(&self) -> Vec<LoadedKeccakF<F>> {
        let base_circuit_builder = self.base_circuit_builder.borrow();
        let mut copy_manager = base_circuit_builder.core().copy_manager.lock().unwrap();
        (0..self.params.capacity)
            .map(|_| LoadedKeccakF {
                bytes_left: copy_manager.mock_external_assigned(F::ZERO),
                word_values: core::array::from_fn(|_| copy_manager.mock_external_assigned(F::ZERO)),
                is_final: SafeTypeChip::unsafe_to_bool(
                    copy_manager.mock_external_assigned(F::ZERO),
                ),
                hash_lo: copy_manager.mock_external_assigned(F::ZERO),
                hash_hi: copy_manager.mock_external_assigned(F::ZERO),
            })
            .collect_vec()
    }

    /// Load needed witnesses into halo2-lib from keccak assigned rows. This function doesn't create any witnesses/constraints.
    fn load_keccak_assigned_rows(
        &self,
        assigned_rows: Vec<KeccakAssignedRow<'_, F>>,
    ) -> Vec<LoadedKeccakF<F>> {
        let rows_per_round = self.params.keccak_circuit_params.rows_per_round;
        let base_circuit_builder = self.base_circuit_builder.borrow();
        let mut copy_manager = base_circuit_builder.core().copy_manager.lock().unwrap();
        assigned_rows
            .into_iter()
            .step_by(rows_per_round)
            // Skip the first round which is dummy.
            .skip(1)
            .chunks(NUM_ROUNDS + 1)
            .into_iter()
            .map(|rounds| {
                let mut rounds = rounds.collect_vec();
                assert_eq!(rounds.len(), NUM_ROUNDS + 1);
                let bytes_left = copy_manager.load_external_assigned(rounds[0].bytes_left.clone());
                let output_row = rounds.pop().unwrap();
                let word_values = core::array::from_fn(|i| {
                    let assigned_row = &rounds[i];
                    copy_manager.load_external_assigned(assigned_row.word_value.clone())
                });
                let is_final = SafeTypeChip::unsafe_to_bool(
                    copy_manager.load_external_assigned(output_row.is_final),
                );
                let hash_lo = copy_manager.load_external_assigned(output_row.hash_lo);
                let hash_hi = copy_manager.load_external_assigned(output_row.hash_hi);
                LoadedKeccakF { bytes_left, word_values, is_final, hash_lo, hash_hi }
            })
            .collect()
    }

    /// Generate witnesses of the base circuit.
    fn generate_base_circuit_witnesses(&self, loaded_keccak_fs: &[LoadedKeccakF<F>]) {
        let gate = &self.gate_chip;
        let circuit_final_outputs = {
            let mut base_circuit_builder_mut = self.base_circuit_builder.borrow_mut();
            let ctx = base_circuit_builder_mut.main(0);
            let mut hasher = self.hasher.borrow_mut();
            hasher.initialize_consts(ctx, gate);

            let lookup_key_per_keccak_f =
                encode_inputs_from_keccak_fs(ctx, gate, &hasher, loaded_keccak_fs);
            Self::generate_circuit_final_outputs(
                ctx,
                gate,
                &lookup_key_per_keccak_f,
                loaded_keccak_fs,
            )
        };
        self.publish_outputs(&circuit_final_outputs);
    }

    /// Combine lookup keys and Keccak results to generate final outputs of the circuit.
    pub fn generate_circuit_final_outputs(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        lookup_key_per_keccak_f: &[PoseidonCompactOutput<F>],
        loaded_keccak_fs: &[LoadedKeccakF<F>],
    ) -> Vec<KeccakCircuitOutput<AssignedValue<F>>> {
        let KeccakCircuitOutput {
            key: dummy_key_val,
            hash_lo: dummy_keccak_val_lo,
            hash_hi: dummy_keccak_val_hi,
        } = dummy_circuit_output::<F>();

        // Dummy row for keccak_fs with is_final = false. The corresponding logical input is empty.
        let dummy_key_witness = ctx.load_constant(dummy_key_val);
        let dummy_keccak_lo_witness = ctx.load_constant(dummy_keccak_val_lo);
        let dummy_keccak_hi_witness = ctx.load_constant(dummy_keccak_val_hi);

        let mut circuit_final_outputs = Vec::with_capacity(loaded_keccak_fs.len());
        for (compact_output, loaded_keccak_f) in
            lookup_key_per_keccak_f.iter().zip_eq(loaded_keccak_fs)
        {
            let is_final = AssignedValue::from(loaded_keccak_f.is_final);
            let key = gate.select(ctx, *compact_output.hash(), dummy_key_witness, is_final);
            let hash_lo =
                gate.select(ctx, loaded_keccak_f.hash_lo, dummy_keccak_lo_witness, is_final);
            let hash_hi =
                gate.select(ctx, loaded_keccak_f.hash_hi, dummy_keccak_hi_witness, is_final);
            circuit_final_outputs.push(KeccakCircuitOutput { key, hash_lo, hash_hi });
        }
        circuit_final_outputs
    }

    /// Publish outputs of the circuit as public instances.
    fn publish_outputs(&self, outputs: &[KeccakCircuitOutput<AssignedValue<F>>]) {
        // The length of outputs should always equal to params.capacity.
        assert_eq!(outputs.len(), self.params.capacity);
        if !self.params.publish_raw_outputs {
            let gate = &self.gate_chip;
            let mut base_circuit_builder_mut = self.base_circuit_builder.borrow_mut();
            let ctx = base_circuit_builder_mut.main(0);

            // TODO: wrap this into a function which should be shared with App circuits.
            let output_commitment = self.hasher.borrow().hash_fix_len_array(
                ctx,
                gate,
                &outputs
                    .iter()
                    .flat_map(|output| [output.key, output.hash_lo, output.hash_hi])
                    .collect_vec(),
            );

            let assigned_instances = &mut base_circuit_builder_mut.assigned_instances;
            // The commitment should be in the first row.
            assert!(assigned_instances[OUTPUT_COL_IDX_COMMIT].is_empty());
            assigned_instances[OUTPUT_COL_IDX_COMMIT].push(output_commitment);
        } else {
            let assigned_instances = &mut self.base_circuit_builder.borrow_mut().assigned_instances;

            // Outputs should be in the top of instance columns.
            assert!(assigned_instances[OUTPUT_COL_IDX_KEY].is_empty());
            assert!(assigned_instances[OUTPUT_COL_IDX_HASH_LO].is_empty());
            assert!(assigned_instances[OUTPUT_COL_IDX_HASH_HI].is_empty());
            for output in outputs {
                assigned_instances[OUTPUT_COL_IDX_KEY].push(output.key);
                assigned_instances[OUTPUT_COL_IDX_HASH_LO].push(output.hash_lo);
                assigned_instances[OUTPUT_COL_IDX_HASH_HI].push(output.hash_hi);
            }
        }
    }
}

pub(crate) fn create_hasher<F: Field>() -> PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE> {
    // Construct in-circuit Poseidon hasher.
    let spec = OptimizedPoseidonSpec::<F, POSEIDON_T, POSEIDON_RATE>::new::<
        POSEIDON_R_F,
        POSEIDON_R_P,
        POSEIDON_SECURE_MDS,
    >();
    PoseidonHasher::<F, POSEIDON_T, POSEIDON_RATE>::new(spec)
}

/// Encode raw inputs from Keccak circuit witnesses into lookup keys.
///
/// Each element in the return value corrresponds to a Keccak chunk. If is_final = true, this element is the lookup key of the corresponding logical input.
pub fn encode_inputs_from_keccak_fs<F: Field>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    loaded_keccak_fs: &[LoadedKeccakF<F>],
) -> Vec<PoseidonCompactOutput<F>> {
    // Circuit parameters
    let num_poseidon_absorb_per_keccak_f = num_poseidon_absorb_per_keccak_f::<F>();
    let num_word_per_witness = num_word_per_witness::<F>();
    let num_witness_per_keccak_f = POSEIDON_RATE * num_poseidon_absorb_per_keccak_f;

    // Constant witnesses
    let one_const = ctx.load_constant(F::ONE);
    let zero_const = ctx.load_zero();
    let multipliers_val = get_words_to_witness_multipliers::<F>()
        .into_iter()
        .map(|multiplier| Constant(multiplier))
        .collect_vec();

    let mut compact_chunk_inputs = Vec::with_capacity(loaded_keccak_fs.len());
    let mut last_is_final = one_const;
    for loaded_keccak_f in loaded_keccak_fs {
        // If this keccak_f is the last of a logical input.
        let is_final = loaded_keccak_f.is_final;
        let mut poseidon_absorb_data = Vec::with_capacity(num_witness_per_keccak_f);

        // First witness of a keccak_f: [<length_placeholder>, word_values[0], word_values[1], ...]
        // <length_placeholder> is the length of the input if this is the first keccak_f of a logical input. Otherwise 0.
        let mut words = Vec::with_capacity(num_word_per_witness);
        let input_bytes_len = gate.mul(ctx, loaded_keccak_f.bytes_left, last_is_final);
        words.push(input_bytes_len);
        words.extend_from_slice(&loaded_keccak_f.word_values);

        // Turn every num_word_per_witness words later into a witness.
        for words in words.chunks(num_word_per_witness) {
            let mut words = words.to_vec();
            words.resize(num_word_per_witness, zero_const);
            let witness = gate.inner_product(ctx, words, multipliers_val.clone());
            poseidon_absorb_data.push(witness);
        }
        // Pad 0s to make sure poseidon_absorb_data.len() % RATE == 0.
        poseidon_absorb_data.resize(num_witness_per_keccak_f, zero_const);
        let compact_inputs: Vec<_> = poseidon_absorb_data
            .chunks_exact(POSEIDON_RATE)
            .map(|chunk| chunk.to_vec().try_into().unwrap())
            .collect_vec();
        debug_assert_eq!(compact_inputs.len(), num_poseidon_absorb_per_keccak_f);
        compact_chunk_inputs.push(PoseidonCompactChunkInput::new(compact_inputs, is_final));
        last_is_final = is_final.into();
    }

    initialized_hasher.hash_compact_chunk_inputs(ctx, gate, &compact_chunk_inputs)
}
