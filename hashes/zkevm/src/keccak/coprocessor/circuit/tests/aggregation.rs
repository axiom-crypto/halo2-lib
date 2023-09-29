use std::{fs, path::Path, time::Instant};

use crate::{
    halo2_proofs::halo2curves::bn256::Fr,
    keccak::{
        coprocessor::circuit::{
            bench_circuit,
            leaf::{KeccakCoprocessorLeafCircuit, KeccakCoprocessorLeafCircuitParams},
            BenchRecord,
        },
        vanilla::param::NUM_ROUNDS,
    },
};

use field_names::FieldNames;
use halo2_base::{
    gates::circuit::CircuitBuilderStage, halo2_proofs::plonk::Circuit, utils::fs::gen_srs,
};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{
        aggregation::{AggregationCircuit, AggregationConfigParams, VerifierUniversality},
        gen_snark_shplonk,
    },
    Snark, SHPLONK,
};

fn create_snark_leaf_circuit_commit(
    k: usize,
    unusable_rows: usize,
    capacity: usize,
) -> (Snark, u128) {
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

    let start = Instant::now();
    let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
    let shard_proof_ms = start.elapsed().as_millis();
    (snark, shard_proof_ms)
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
    agg_capacity: usize,
    num_shards: usize,
    agg_k: u32,
) -> AggBenchRecord {
    let _ = env_logger::builder().is_test(true).try_init();
    let capacity = agg_capacity / num_shards;

    fs::remove_file("keccak_leaf.pk").unwrap_or_default();
    let (shard, shard_proof_ms) = create_snark_leaf_circuit_commit(leaf_k, unusable_rows, capacity);

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

    let start = Instant::now();
    let circuit = aggregate_shards(CircuitBuilderStage::Prover)
        .use_params(agg_config.clone())
        .use_break_points(break_points);
    gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
    let agg_proof_ms = start.elapsed().as_millis();

    let AggregationConfigParams {
        degree: _,
        num_advice,
        num_lookup_advice,
        num_fixed,
        lookup_bits,
    } = agg_config;
    AggBenchRecord {
        agg_capacity,
        num_shards,
        agg_k: agg_k as usize,
        leaf_k,
        agg_proof_ms,
        shard_proof_ms,
        num_advice,
        num_lookup_advice,
        num_fixed,
        lookup_bits,
    }
}

#[derive(Serialize, Deserialize, FieldNames, Default)]
struct AggBenchRecord {
    agg_capacity: usize,
    num_shards: usize,
    agg_k: usize,
    leaf_k: usize,
    agg_proof_ms: u128,
    shard_proof_ms: u128,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
}

impl BenchRecord<(usize, usize)> for AggBenchRecord {
    fn get_parameter(&self) -> (usize, usize) {
        (self.agg_capacity, self.num_shards)
    }
}

#[test]
#[ignore = "bench"]
fn bench_keccak_aggregation() {
    let agg_capacity_list = [200, 500, 1000, 5000];
    let num_shards_list = [1, 2, 4];
    let mut parameters = vec![];
    for agg_capacity in agg_capacity_list {
        for num_shards in num_shards_list {
            parameters.push((agg_capacity, num_shards));
        }
    }
    bench_circuit(
        "keccakagg",
        parameters,
        &AggBenchRecord::FIELDS,
        |(agg_capacity, num_shards)| {
            let mut leaf_k = 20;
            let target_capacity = agg_capacity / num_shards;
            // To fix # of halo2-lib column
            // 14000 is a rough estimation of cell consumation for a keccak_f.
            let halo2_lib_columns = 8;
            let halo2_lib_rows = target_capacity * 14000 / halo2_lib_columns;

            let agg_k = 20;
            let unusable_rows = 100;

            let maximum_k = ((halo2_lib_rows + unusable_rows) as f64).log2().ceil() as usize;
            if leaf_k > maximum_k {
                leaf_k = maximum_k;
            }
            single_layer_aggregate_leaf_circuits_commit(
                leaf_k,
                unusable_rows,
                agg_capacity,
                num_shards,
                agg_k,
            )
        },
    )
    .unwrap();
}
