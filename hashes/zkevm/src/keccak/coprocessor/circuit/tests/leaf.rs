use crate::{
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::Fr,
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    keccak::coprocessor::{
        circuit::leaf::{KeccakCoprocessorLeafCircuit, KeccakCoprocessorLeafCircuitParams},
        output::multi_inputs_to_circuit_outputs,
    },
};

use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
use itertools::Itertools;
use rand_core::OsRng;

#[test]
fn test_mock_leaf_circuit() {
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

    let params = KeccakCoprocessorLeafCircuitParams::new(
        k,
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), params.clone());
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
fn test_prove_leaf_circuit() {
    let k: usize = 15;
    let num_unusable_row: usize = 109;
    let lookup_bits: usize = 4;
    let capacity: usize = 1;
    let publish_raw_outputs: bool = true;

    let inputs = vec![
        // (0u8..200).collect::<Vec<_>>(),
        // vec![],
        (0u8..1).collect::<Vec<_>>(),
        // (0u8..135).collect::<Vec<_>>(),
        // (0u8..136).collect::<Vec<_>>(),
        // (0u8..200).collect::<Vec<_>>(),
    ];

    let circuit_params = KeccakCoprocessorLeafCircuitParams::new(
        k.clone(),
        num_unusable_row,
        lookup_bits,
        capacity,
        publish_raw_outputs,
    );
    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), circuit_params.clone());

    let _circuit_outputs =
        multi_inputs_to_circuit_outputs::<Fr>(&inputs, circuit_params.capacity());
    let instances: Vec<Vec<Fr>> = vec![
        vec![],
        vec![],
        vec![],
        // circuit_outputs.iter().map(|o| o.key).collect_vec(),
        // circuit_outputs.iter().map(|o| o.hash_lo).collect_vec(),
        // circuit_outputs.iter().map(|o| o.hash_hi).collect_vec(),
    ];

    // let prover = MockProver::<Fr>::run(k as u32, &circuit, instances.clone()).unwrap();
    // prover.assert_satisfied();

    println!("After mock prover");

    let _ = env_logger::builder().is_test(true).try_init();

    let params = ParamsKZG::<Bn256>::setup(k as u32, OsRng);

    let vk = keygen_vk(&params, &circuit).unwrap();
    // println!("{:?}", &circuit.base_circuit_builder().borrow().clone());
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    // println!("{:?}", &circuit.base_circuit_builder().borrow().clone());

    let circuit = KeccakCoprocessorLeafCircuit::<Fr>::new(inputs.clone(), circuit_params.clone());
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
