use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::Bn256,
        halo2curves::bn256::Fr,
        plonk::{keygen_pk, keygen_vk},
    },
    keccak::coprocessor::{
        circuit::leaf::{KeccakCoprocessorLeafCircuit, KeccakCoprocessorLeafCircuitParams},
        output::{calculate_circuit_outputs_commit, multi_inputs_to_circuit_outputs},
    },
};

use halo2_base::{
    halo2_proofs::poly::kzg::commitment::ParamsKZG,
    utils::testing::{check_proof_with_instances, gen_proof_with_instances},
};
use itertools::Itertools;
use rand_core::OsRng;

#[test]
fn test_mock_leaf_circuit_raw_outputs() {
    let k: usize = 18;
    let num_unusable_row: usize = 109;
    let lookup_bits: usize = 4;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = true;

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];

    let mut params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let base_circuit_params =
        KeccakCoprocessorLeafCircuit::<Fr>::calculate_base_circuit_params(&params);
    params.base_circuit_params = base_circuit_params;
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), params.clone(), false);
    let circuit_outputs = multi_inputs_to_circuit_outputs::<Fr>(&inputs, params.capacity());

    let instances = vec![
        circuit_outputs.iter().map(|o| o.key).collect_vec(),
        circuit_outputs.iter().map(|o| o.hash_lo).collect_vec(),
        circuit_outputs.iter().map(|o| o.hash_hi).collect_vec(),
    ];

    let prover = MockProver::<Fr>::run(k as u32, &circuit, instances).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_prove_leaf_circuit_raw_outputs() {
    let _ = env_logger::builder().is_test(true).try_init();

    let k: usize = 18;
    let num_unusable_row: usize = 109;
    let lookup_bits: usize = 4;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = true;

    let inputs = vec![];
    let mut circuit_params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let base_circuit_params =
        KeccakCoprocessorLeafCircuit::<Fr>::calculate_base_circuit_params(&circuit_params);
    circuit_params.base_circuit_params = base_circuit_params;
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs, circuit_params.clone(), false);

    let params = ParamsKZG::<Bn256>::setup(k as u32, OsRng);

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit_outputs = multi_inputs_to_circuit_outputs::<Fr>(&inputs, circuit_params.capacity());
    let instances: Vec<Vec<Fr>> = vec![
        circuit_outputs.iter().map(|o| o.key).collect_vec(),
        circuit_outputs.iter().map(|o| o.hash_lo).collect_vec(),
        circuit_outputs.iter().map(|o| o.hash_hi).collect_vec(),
    ];

    let break_points = circuit.base_circuit_break_points();
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs, circuit_params, true);
    circuit.set_base_circuit_break_points(break_points);

    let proof = gen_proof_with_instances(
        &params,
        &pk,
        circuit,
        instances.iter().map(|f| f.as_slice()).collect_vec().as_slice(),
    );
    check_proof_with_instances(
        &params,
        pk.get_vk(),
        &proof,
        instances.iter().map(|f| f.as_slice()).collect_vec().as_slice(),
        true,
    );
}

#[test]
fn test_mock_leaf_circuit_commit() {
    let k: usize = 18;
    let num_unusable_row: usize = 109;
    let lookup_bits: usize = 4;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = false;

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];

    let mut params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let base_circuit_params =
        KeccakCoprocessorLeafCircuit::<Fr>::calculate_base_circuit_params(&params);
    params.base_circuit_params = base_circuit_params;
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), params.clone(), false);
    let circuit_outputs = multi_inputs_to_circuit_outputs::<Fr>(&inputs, params.capacity());

    let instances = vec![vec![calculate_circuit_outputs_commit(&circuit_outputs)]];

    let prover = MockProver::<Fr>::run(k as u32, &circuit, instances).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_prove_leaf_circuit_commit() {
    let _ = env_logger::builder().is_test(true).try_init();

    let k: usize = 18;
    let num_unusable_row: usize = 109;
    let lookup_bits: usize = 4;
    let capacity: usize = 10;
    let publish_raw_outputs: bool = false;

    let inputs = vec![];
    let mut circuit_params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let base_circuit_params =
        KeccakCoprocessorLeafCircuit::<Fr>::calculate_base_circuit_params(&circuit_params);
    circuit_params.base_circuit_params = base_circuit_params;
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs, circuit_params.clone(), false);

    let params = ParamsKZG::<Bn256>::setup(k as u32, OsRng);

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];

    let break_points = circuit.base_circuit_break_points();
    let circuit =
        KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), circuit_params.clone(), true);
    circuit.set_base_circuit_break_points(break_points);

    let circuit_outputs = multi_inputs_to_circuit_outputs::<Fr>(&inputs, circuit_params.capacity());
    let instances = vec![vec![calculate_circuit_outputs_commit(&circuit_outputs)]];

    let proof = gen_proof_with_instances(
        &params,
        &pk,
        circuit,
        instances.iter().map(|f| f.as_slice()).collect_vec().as_slice(),
    );
    check_proof_with_instances(
        &params,
        pk.get_vk(),
        &proof,
        instances.iter().map(|f| f.as_slice()).collect_vec().as_slice(),
        true,
    );
}
