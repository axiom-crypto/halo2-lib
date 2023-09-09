use std::cell::RefCell;

use crate::{
    keccak::{
        coprocessor::{
            encode::{
                get_words_to_witness_multipliers, num_poseidon_absorb_per_keccak_f,
                num_word_per_witness,
            },
            output::{dummy_circuit_output, KeccakCircuitOutput},
            param::*,
        },
        vanilla::{
            param::*, witness::multi_keccak, KeccakAssignedRow, KeccakCircuitConfig,
            KeccakConfigParams,
        },
    },
    util::eth_types::Field,
};
use getset::{CopyGetters, Getters};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        GateInstructions, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    poseidon::hasher::{
        spec::OptimizedPoseidonSpec, PoseidonCompactInput, PoseidonCompactOutput, PoseidonHasher,
    },
    safe_types::SafeTypeChip,
    AssignedValue, Context,
};
use itertools::Itertools;

/// Keccak Coprocessor Leaf Circuit
#[derive(Getters)]
pub struct KeccakCoprocessorLeafCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,

    /// Parameters of this circuit. The same parameters always construct the same circuit.
    #[getset(get = "pub")]
    params: KeccakCoprocessorLeafCircuitParams,

    base_circuit_builder: RefCell<BaseCircuitBuilder<F>>,
    hasher: RefCell<PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>>,
}

/// Parameters of KeccakCoprocessorLeafCircuit.
#[derive(Default, Clone, CopyGetters)]
pub struct KeccakCoprocessorLeafCircuitParams {
    /// This circuit has 2^k rows.
    #[getset(get_copy = "pub")]
    k: usize,
    // Number of unusable rows withhold by Halo2.
    #[getset(get_copy = "pub")]
    num_unusable_row: usize,
    /// The bits of lookup table for RangeChip.
    #[getset(get_copy = "pub")]
    lookup_bits: usize,
    /// Max keccak_f this circuits can aceept. The circuit can at most process <capacity> of inputs
    /// with < NUM_BYTES_TO_ABSORB bytes or an input with <capacity> * NUM_BYTES_TO_ABSORB - 1 bytes.
    #[getset(get_copy = "pub")]
    capacity: usize,
    // If true, publish raw outputs. Otherwise, publish Poseidon commitment of raw outputs.
    #[getset(get_copy = "pub")]
    publish_raw_outputs: bool,

    // Derived parameters of sub-circuits.
    keccak_circuit_params: KeccakConfigParams,
}

impl KeccakCoprocessorLeafCircuitParams {
    /// Create a new KeccakCoprocessorLeafCircuitParams.
    pub fn new(
        k: usize,
        num_unusable_row: usize,
        lookup_bits: usize,
        capacity: usize,
        publish_raw_outputs: bool,
    ) -> Self {
        assert!(1 << k > num_unusable_row, "Number of unusable rows must be less than 2^k");
        let max_rows = (1 << k) - num_unusable_row;
        // Derived from [crate::keccak::native_circuit::keccak_packed_multi::get_keccak_capacity].
        let rows_per_round = max_rows / (capacity * (NUM_ROUNDS + 1) + 1 + NUM_WORDS_TO_ABSORB);
        assert!(rows_per_round > 0, "No enough rows for the speficied capacity");
        let keccak_circuit_params = KeccakConfigParams { k: k as u32, rows_per_round };
        Self {
            k,
            num_unusable_row,
            lookup_bits,
            capacity,
            publish_raw_outputs,
            keccak_circuit_params,
        }
    }
}

/// Circuit::Config for Keccak Coprocessor Leaf Circuit.
#[derive(Clone)]
pub struct KeccakCoprocessorLeafConfig<F: Field> {
    base_circuit_params: BaseCircuitParams,
    base_circuit_config: BaseConfig<F>,
    keccak_circuit_config: KeccakCircuitConfig<F>,
}

impl<F: Field> Circuit<F> for KeccakCoprocessorLeafCircuit<F> {
    type Config = KeccakCoprocessorLeafConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = KeccakCoprocessorLeafCircuitParams;

    fn params(&self) -> Self::Params {
        self.params.clone()
    }

    /// Creates a new instance of the [RangeCircuitBuilder] without witnesses by setting the witness_gen_only flag to false
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    /// Configures a new circuit using [`BaseConfigParams`]
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let base_circuit_params = Self::calculate_base_circuit_params(params.clone());
        let base_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_params.clone());
        let keccak_circuit_config = KeccakCircuitConfig::new(meta, params.keccak_circuit_params);
        Self::Config { base_circuit_params, base_circuit_config, keccak_circuit_config }
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

        self.base_circuit_builder.borrow_mut().set_params(config.base_circuit_params);
        // Base circuit witness generation.
        let loaded_keccak_fs = self.load_keccak_assigned_rows(keccak_assigned_rows);
        self.generate_base_circuit_phase0_witnesses(&loaded_keccak_fs);

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
    pub(crate) is_final: AssignedValue<F>,
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
        is_final: AssignedValue<F>,
        hash_lo: AssignedValue<F>,
        hash_hi: AssignedValue<F>,
    ) -> Self {
        Self { bytes_left, word_values, is_final, hash_lo, hash_hi }
    }
}

impl<F: Field> KeccakCoprocessorLeafCircuit<F> {
    /// Create a new KeccakCoprocessorLeafCircuit
    pub fn new(inputs: Vec<Vec<u8>>, params: KeccakCoprocessorLeafCircuitParams) -> Self {
        Self::new_impl(inputs, params, false)
    }

    /// Implementation of Self::new. witness_gen_only can be customized.
    fn new_impl(
        inputs: Vec<Vec<u8>>,
        params: KeccakCoprocessorLeafCircuitParams,
        witness_gen_only: bool,
    ) -> Self {
        let mut base_circuit_builder = BaseCircuitBuilder::new(witness_gen_only)
            .use_k(params.k)
            .use_lookup_bits(params.lookup_bits);
        base_circuit_builder.set_instance_columns(if params.publish_raw_outputs {
            OUTPUT_NUM_COL_RAW
        } else {
            OUTPUT_NUM_COL_COMMIT
        });
        Self {
            inputs,
            params,
            base_circuit_builder: RefCell::new(base_circuit_builder),
            hasher: RefCell::new(create_hasher()),
        }
    }

    /// Simulate witness generation of the base circuit to determine BaseCircuitParams because the number of columns
    /// of the base circuit can only be known after witness generation.
    pub fn calculate_base_circuit_params(
        params: KeccakCoprocessorLeafCircuitParams,
    ) -> BaseCircuitParams {
        // Create a simulation circuit to calculate base circuit parameters.
        let simulation_circuit = Self::new_impl(vec![], params.clone(), false);
        let loaded_keccak_fs = simulation_circuit.mock_load_keccak_assigned_rows();
        simulation_circuit.generate_base_circuit_phase0_witnesses(&loaded_keccak_fs);

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
                is_final: copy_manager.mock_external_assigned(F::ZERO),
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
        let loaded_keccak_fs = assigned_rows
            .iter()
            .step_by(rows_per_round)
            // Skip the first round which is dummy.
            .skip(1)
            .chunks(NUM_ROUNDS + 1)
            .into_iter()
            .map(|rounds| {
                let rounds = rounds.collect_vec();
                let bytes_left = copy_manager.load_external_assigned(rounds[0].bytes_left.clone());
                let word_values = core::array::from_fn(|i| {
                    let assigned_row = rounds[i];
                    copy_manager.load_external_assigned(assigned_row.word_value.clone())
                });
                let output_row = rounds[NUM_ROUNDS];
                let is_final = copy_manager.load_external_assigned(output_row.is_final.clone());
                let hash_lo = copy_manager.load_external_assigned(output_row.hash_lo.clone());
                let hash_hi = copy_manager.load_external_assigned(output_row.hash_hi.clone());
                LoadedKeccakF { bytes_left, word_values, is_final, hash_lo, hash_hi }
            })
            .collect_vec();
        loaded_keccak_fs
    }

    /// Generate phase0 witnesses of the base circuit.
    fn generate_base_circuit_phase0_witnesses(&self, loaded_keccak_fs: &[LoadedKeccakF<F>]) {
        let circuit_final_outputs;
        {
            let range_chip = self.base_circuit_builder.borrow().range_chip();
            let mut base_circuit_builder_mut = self.base_circuit_builder.borrow_mut();
            let ctx = base_circuit_builder_mut.main(0);
            let mut hasher = self.hasher.borrow_mut();
            hasher.initialize_consts(ctx, range_chip.gate());

            let lookup_key_per_keccak_f =
                encode_inputs_from_keccak_fs(ctx, &range_chip, &hasher, loaded_keccak_fs);
            circuit_final_outputs = Self::generate_circuit_final_outputs(
                ctx,
                &range_chip,
                &lookup_key_per_keccak_f,
                loaded_keccak_fs,
            );
        }
        self.publish_outputs(&circuit_final_outputs);
    }

    /// Combine lookup keys and Keccak results to generate final outputs of the circuit.
    fn generate_circuit_final_outputs(
        ctx: &mut Context<F>,
        range_chip: &impl RangeInstructions<F>,
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
            lookup_key_per_keccak_f.iter().zip(loaded_keccak_fs)
        {
            let key = range_chip.gate().select(
                ctx,
                *compact_output.hash(),
                dummy_key_witness,
                loaded_keccak_f.is_final,
            );
            let hash_lo = range_chip.gate().select(
                ctx,
                loaded_keccak_f.hash_lo,
                dummy_keccak_lo_witness,
                loaded_keccak_f.is_final,
            );
            let hash_hi = range_chip.gate().select(
                ctx,
                loaded_keccak_f.hash_hi,
                dummy_keccak_hi_witness,
                loaded_keccak_f.is_final,
            );
            circuit_final_outputs.push(KeccakCircuitOutput { key, hash_lo, hash_hi });
        }
        circuit_final_outputs
    }

    /// Publish outputs of the circuit as public instances.
    fn publish_outputs(&self, outputs: &[KeccakCircuitOutput<AssignedValue<F>>]) {
        if !self.params.publish_raw_outputs {
            let range_chip = self.base_circuit_builder.borrow().range_chip();
            let mut base_circuit_builder_mut = self.base_circuit_builder.borrow_mut();
            let ctx = base_circuit_builder_mut.main(0);

            // TODO: wrap this into a function which should be shared wiht App circuits.
            // The length of outputs is determined at compile time.
            let output_commitment = self.hasher.borrow().hash_fix_len_array(
                ctx,
                &range_chip,
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

fn create_hasher<F: Field>() -> PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE> {
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
    range_chip: &impl RangeInstructions<F>,
    initialized_hasher: &PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>,
    loaded_keccak_fs: &[LoadedKeccakF<F>],
) -> Vec<PoseidonCompactOutput<F>> {
    // Circuit parameters
    let num_poseidon_absorb_per_keccak_f = num_poseidon_absorb_per_keccak_f::<F>();
    let num_word_per_witness = num_word_per_witness::<F>();
    let num_witness_per_keccak_f = POSEIDON_RATE * num_poseidon_absorb_per_keccak_f;

    // Constant witnesses
    let rate_witness = ctx.load_constant(F::from(POSEIDON_RATE as u64));
    let one_witness = ctx.load_constant(F::ONE);
    let zero_witness = ctx.load_zero();
    let multiplier_witnesses = ctx.load_constants(&get_words_to_witness_multipliers::<F>());

    let compact_input_len = loaded_keccak_fs.len() * num_poseidon_absorb_per_keccak_f;
    let mut compact_inputs = Vec::with_capacity(compact_input_len);
    let mut is_final_last = one_witness;
    for loaded_keccak_f in loaded_keccak_fs {
        // If this keccak_f is the last of a logical input.
        let is_final = loaded_keccak_f.is_final;
        let mut poseidon_absorb_data = Vec::with_capacity(num_witness_per_keccak_f);

        // First witness of a keccak_f: [<len_word>, word_values[0], word_values[1], ...]
        // <len_word> is the length of the input if this is the first keccak_f of a logical input. Otherwise 0.
        let mut words = Vec::with_capacity(num_word_per_witness);
        let len_word =
            range_chip.gate().select(ctx, loaded_keccak_f.bytes_left, zero_witness, is_final_last);
        words.push(len_word);
        words.extend_from_slice(&loaded_keccak_f.word_values[0..(num_word_per_witness - 1)]);
        let first_witness = range_chip.gate().inner_product(
            ctx,
            multiplier_witnesses.clone(),
            words.iter().map(|w| halo2_base::QuantumCell::Existing(*w)),
        );
        poseidon_absorb_data.push(first_witness);

        // Turn every num_word_per_witness words later into a witness.
        for words in &loaded_keccak_f
            .word_values
            .into_iter()
            .skip(num_word_per_witness - 1)
            .chunks(num_word_per_witness)
        {
            let mut words = words.collect_vec();
            words.resize(num_word_per_witness, zero_witness);
            let witness = range_chip.gate().inner_product(
                ctx,
                multiplier_witnesses.clone(),
                words.iter().map(|w| halo2_base::QuantumCell::Existing(*w)),
            );
            poseidon_absorb_data.push(witness);
        }
        // Pad 0s to make sure poseidon_absorb_data.len() % RATE == 0.
        poseidon_absorb_data.resize(num_witness_per_keccak_f, zero_witness);
        for (i, poseidon_absorb) in poseidon_absorb_data.chunks(POSEIDON_RATE).enumerate() {
            compact_inputs.push(PoseidonCompactInput::new(
                poseidon_absorb.try_into().unwrap(),
                if i + 1 == num_poseidon_absorb_per_keccak_f {
                    SafeTypeChip::unsafe_to_bool(is_final)
                } else {
                    SafeTypeChip::unsafe_to_bool(zero_witness)
                },
                rate_witness,
            ));
        }
        is_final_last = is_final;
    }

    let compact_outputs = initialized_hasher.hash_compact_input(ctx, range_chip, &compact_inputs);

    compact_outputs
        .into_iter()
        .skip(num_poseidon_absorb_per_keccak_f - 1)
        .step_by(num_poseidon_absorb_per_keccak_f)
        .collect_vec()
}
