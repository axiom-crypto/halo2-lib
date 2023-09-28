use std::{fs, path::Path};

use crate::{
    halo2_proofs::halo2curves::bn256::Fr,
    keccak::coprocessor::circuit::leaf::{
        KeccakCoprocessorLeafCircuit, KeccakCoprocessorLeafCircuitParams,
    },
};

use halo2_base::{
    gates::circuit::CircuitBuilderStage, halo2_proofs::plonk::Circuit, utils::fs::gen_srs,
};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{
        aggregation::{AggregationCircuit, AggregationConfigParams, VerifierUniversality},
        gen_snark_shplonk,
    },
    Snark, SHPLONK,
};
use test_case::test_case;

fn create_snark_leaf_circuit_commit(k: usize, unusable_rows: usize, capacity: usize) -> Snark {
    let lookup_bits: usize = 4; // keccak leaf circuit doesn't actually use range checks. put dummy value for now so `.range_chip()` doesn't panic
    let publish_raw_outputs: bool = false;

    let inputs = vec![];
    let mut circuit_params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        unusable_rows,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let base_circuit_params =
        KeccakCoprocessorLeafCircuit::<Fr>::calculate_base_circuit_params(&circuit_params);
    circuit_params.base_circuit_params = base_circuit_params;
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs, circuit_params.clone(), false);

    let params = gen_srs(k as u32);
    let pk = gen_pk(&params, &circuit, Some(Path::new("keccak_leaf.pk")));
    let break_points = circuit.base_circuit_break_points();
    let circuit_params = circuit.params();

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];

    let circuit =
        KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), circuit_params.clone(), true);
    circuit.set_base_circuit_break_points(break_points);

    gen_snark_shplonk(&params, &pk, circuit, None::<&str>)
}

// RUST_LOG=info cargo t single_layer_aggregate_leaf_circuits_commit::_1_rows_per_round_single_shard -- --nocapture
// Aggregation will be huge, will likely OOM
// #[test_case(15, 23, 1308, 1, 23;"1 rows_per_round, single shard")]
// RUST_LOG=info cargo t single_layer_aggregate_leaf_circuits_commit::_9_rows_per_round_single_shard -- --nocapture
// #[test_case(15, 55, 144, 1, 20;"9 rows_per_round, single shard")]
// #[test_case(15, 67, 61, 1, 18;"21 rows_per_round, single shard")]
fn single_layer_aggregate_leaf_circuits_commit(
    leaf_k: usize,
    unusable_rows: usize,
    target_capacity: usize,
    num_shards: usize,
    agg_k: u32,
) {
    let _ = env_logger::builder().is_test(true).try_init();
    let capacity = target_capacity / num_shards;

    fs::remove_file("keccak_leaf.pk").unwrap_or_default();
    let shard = create_snark_leaf_circuit_commit(leaf_k, unusable_rows, capacity);
    let shards = vec![shard; num_shards];
    fs::remove_file("keccak_leaf.pk").unwrap_or_default();

    let params = gen_srs(agg_k);
    let aggregate_shards = |stage: CircuitBuilderStage| {
        AggregationCircuit::new::<SHPLONK>(
            stage,
            AggregationConfigParams {
                degree: agg_k,
                lookup_bits: agg_k as usize - 1,
                ..Default::default()
            },
            &params,
            shards.clone(),
            VerifierUniversality::Full,
        )
    };

    let mut circuit = aggregate_shards(CircuitBuilderStage::Keygen);
    circuit.calculate_params(Some(unusable_rows));
    let pk = gen_pk(&params, &circuit, None);
    let agg_config = circuit.params();
    let break_points = circuit.break_points();
    drop(circuit);

    let circuit = aggregate_shards(CircuitBuilderStage::Prover)
        .use_params(agg_config)
        .use_break_points(break_points);
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
}

#[derive(Serialize, Deserialize, FieldNames, Default)]
struct HeaderBenchRecord {
    k: usize,
    n_pow: usize,
    capacity: usize,
    proof_ms: u128,
    verify_ms: u128,
    gate_advice_phase0: usize,
    gate_advice_phase1: usize,
    lookup_advice_phase0: usize,
    rlc_advice: usize,
}

impl BenchRecord<(usize, usize)> for HeaderBenchRecord {
    fn get_parameter(&self) -> (usize, usize) {
        (self.k, self.n_pow)
    }
}

#[test]
#[ignore = "bench"]
fn bench_keccak_aggregation() {
    let agg_capacity_list = [200, 500, 1000, 5000];
    let num_shards_list = [1, 2, 4, 8];
    let leaf_k = 20;
    let agg_k = 20;
    let unusable_rows = 55;
    for agg_capacity in agg_capacity_list {
        for num_shards in num_shards_list {
            single_layer_aggregate_leaf_circuits_commit(
                leaf_k,
                unusable_rows,
                agg_capacity,
                num_shards,
                agg_k,
            );
        }
    }
}
