use std::cell::RefCell;

use super::{
    encode::{encode_inputs_from_keccak_fs, encode_native_input},
    param::*,
};
use crate::{
    keccak::{
        keccak_packed_multi::get_num_keccak_f, multi_keccak, param::*, KeccakAssignedRow,
        KeccakCircuitConfig, KeccakConfigParams,
    },
    util::eth_types::Field,
};
use getset::Getters;
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        GateInstructions, RangeInstructions,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonCompactOutput, PoseidonHasher},
    AssignedValue, Context,
};
use itertools::Itertools;
use sha3::{Digest, Keccak256};

/// Keccak Coprocessor Circuit
#[derive(Getters)]
pub struct KeccakCoprocessorCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,

    /// Parameters of this circuit. The same parameters always construct the same circuit.
    params: KeccakCoprocessorCircuitParams,

    base_circuit_builder: RefCell<BaseCircuitBuilder<F>>,
    hasher: RefCell<PoseidonHasher<F, POSEIDON_T, POSEIDON_RATE>>,
}

/// Parameters of KeccakCoprocessorCircuit.
#[derive(Default, Clone, Getters)]
pub struct KeccakCoprocessorCircuitParams {
    /// This circuit has 2^k rows.
    #[getset(get = "pub")]
    k: usize,
    // Number of unusable rows withhold by Halo2.
    #[getset(get = "pub")]
    num_unusable_row: usize,
    /// The bits of lookup table for RangeChip.
    #[getset(get = "pub")]
    lookup_bits: usize,
    /// Max keccak_f this circuits can aceept. The circuit can at most process <capacity> of inputs
    /// with < NUM_BYTES_TO_ABSORB bytes or an input with <capacity> * NUM_BYTES_TO_ABSORB - 1 bytes.
    #[getset(get = "pub")]
    capacity: usize,
    // If true, publish raw outputs. Otherwise, publish Poseidon commitment of raw outputs.
    #[getset(get = "pub")]
    publish_raw_outputs: bool,

    // Derived parameters of sub-circuits.
    keccak_circuit_params: KeccakConfigParams,
}

impl KeccakCoprocessorCircuitParams {
    /// Create a new KeccakCoprocessorCircuitParams.
    pub fn new(
        k: usize,
        num_unusable_row: usize,
        lookup_bits: usize,
        capacity: usize,
        publish_raw_outputs: bool,
    ) -> Self {
        assert!(1 << k > num_unusable_row, "Number of unusable rows must be less than 2^k");
        let max_rows = (1 << k) - num_unusable_row;
        // Derived from [crate::keccak::keccak_packed_multi::get_keccak_capacity].
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

/// Circuit::Config for Keccak Coprocessor Circuit.
#[derive(Clone)]
pub struct KeccakCoprocessorConfig<F: Field> {
    base_circuit_params: BaseCircuitParams,
    base_circuit_config: BaseConfig<F>,
    keccak_circuit_config: KeccakCircuitConfig<F>,
}

impl<F: Field> Circuit<F> for KeccakCoprocessorCircuit<F> {
    type Config = KeccakCoprocessorConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = KeccakCoprocessorCircuitParams;

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
        Ok(())
    }
}

/// Witnesses to be exposed as circuit outputs.
#[derive(Clone)]
pub struct KeccakCircuitOutput<E> {
    /// Key for App circuits to lookup keccak hash.
    pub key: E,
    /// Low 128 bits of Keccak hash.
    pub hash_lo: E,
    /// High 128 bits of Keccak hash.
    pub hash_hi: E,
}

/// Witnesses of a keccak_f which are necessary to be loaded into halo2-lib.
pub(crate) struct LoadedKeccakF<F: Field> {
    // bytes_left of the first row of the first round of this keccak_f. This could be used to determine the length of the input.
    pub(crate) bytes_left: AssignedValue<F>,
    // Input words of this keccak_f.
    pub(crate) word_values: [AssignedValue<F>; NUM_WORDS_TO_ABSORB],
    // The output of this keccak_f. is_final/hash_lo/hash_hi come from the first row of the last round(NUM_ROUNDS).
    pub(crate) is_final: AssignedValue<F>,
    pub(crate) hash_lo: AssignedValue<F>,
    pub(crate) hash_hi: AssignedValue<F>,
}

impl<F: Field> KeccakCoprocessorCircuit<F> {
    /// Create a new KeccakComputationCircuit
    pub fn new(inputs: Vec<Vec<u8>>, params: KeccakCoprocessorCircuitParams) -> Self {
        Self::new_impl(inputs, params, false)
    }

    /// Implementation of Self::new. witness_gen_only can be customized.
    fn new_impl(
        inputs: Vec<Vec<u8>>,
        params: KeccakCoprocessorCircuitParams,
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
        // Construct in-circuit Poseidon hasher.
        let spec = OptimizedPoseidonSpec::<F, POSEIDON_T, POSEIDON_RATE>::new::<
            POSEIDON_R_F,
            POSEIDON_R_P,
            POSEIDON_SECURE_MDS,
        >();
        let poseidon_hasher = PoseidonHasher::<F, POSEIDON_T, POSEIDON_RATE>::new(spec);
        Self {
            inputs,
            params,
            base_circuit_builder: RefCell::new(base_circuit_builder),
            hasher: RefCell::new(poseidon_hasher),
        }
    }

    /// Simulate witness generation of the base circuit to determine BaseCircuitParams because the number of columns
    /// of the base circuit can only be known after witness generation.
    pub fn calculate_base_circuit_params(
        params: KeccakCoprocessorCircuitParams,
    ) -> BaseCircuitParams {
        // Create a simulation circuit to calculate base circuit parameters.
        let simulation_circuit = Self::new_impl(vec![], params.clone(), false);
        let loaded_keccak_fs = simulation_circuit.mock_load_keccak_assigned_rows();
        simulation_circuit.generate_base_circuit_phase0_witnesses(&loaded_keccak_fs);

        let base_circuit_params = simulation_circuit
            .base_circuit_builder
            .borrow_mut()
            .calculate_params(Some(params.num_unusable_row));

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
            println!("In circuit: {:?}", key.value());
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

            // The length of outputs is determined at compile time.
            let output_commitment = self.hasher.borrow().hash_fix_len_array(
                ctx,
                &range_chip,
                &outputs
                    .iter()
                    .flat_map(|output| [output.key, output.hash_hi, output.hash_lo])
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

/// Return circuit outputs of the specified Keccak corprocessor circuit for a specified input.
pub fn multi_inputs_to_circuit_outputs<F: Field>(
    inputs: &[Vec<u8>],
    params: &KeccakCoprocessorCircuitParams,
) -> Vec<KeccakCircuitOutput<F>> {
    assert!(u128::BITS <= F::CAPACITY);
    let mut outputs =
        inputs.iter().flat_map(|input| input_to_circuit_outputs::<F>(input)).collect_vec();
    assert!(outputs.len() <= params.capacity);
    outputs.resize(params.capacity, dummy_circuit_output());
    outputs
}

/// Return corresponding circuit outputs of a native input in bytes. An logical input could produce multiple
/// outputs. The last one is the lookup key and hash of the input. Other outputs are paddings which are the lookup
/// key and hash of an empty input.
pub fn input_to_circuit_outputs<F: Field>(bytes: &[u8]) -> Vec<KeccakCircuitOutput<F>> {
    assert!(u128::BITS <= F::CAPACITY);
    let len = bytes.len();
    let num_keccak_f = get_num_keccak_f(len);

    let mut output = Vec::with_capacity(num_keccak_f);
    output.resize(num_keccak_f - 1, dummy_circuit_output());

    let key = encode_native_input(bytes);
    let hash = Keccak256::digest(bytes);
    let hash_lo = F::from_u128(u128::from_be_bytes(hash[16..].try_into().unwrap()));
    let hash_hi = F::from_u128(u128::from_be_bytes(hash[..16].try_into().unwrap()));
    output.push(KeccakCircuitOutput { key, hash_lo, hash_hi });

    output
}

/// Return the dummy circuit output for padding.
pub fn dummy_circuit_output<F: Field>() -> KeccakCircuitOutput<F> {
    assert!(u128::BITS <= F::CAPACITY);
    let key = encode_native_input(&[]);
    // Output of Keccak256::digest is big endian.
    let hash = Keccak256::digest([]);
    let hash_lo = F::from_u128(u128::from_be_bytes(hash[16..].try_into().unwrap()));
    let hash_hi = F::from_u128(u128::from_be_bytes(hash[..16].try_into().unwrap()));
    KeccakCircuitOutput { key, hash_lo, hash_hi }
}
