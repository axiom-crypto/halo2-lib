use crate::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme, commitment::ParamsKZG, multiopen::ProverSHPLONK,
            multiopen::VerifierSHPLONK, strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    safe_types::SafeTypeChip,
    utils::testing::base_test,
    Context,
};
use rand::rngs::OsRng;
use std::vec;

// =========== Utilies ===============
fn mock_circuit_test<FM: FnMut(&mut Context<Fr>, SafeTypeChip<'_, Fr>)>(mut f: FM) {
    let mut builder = GateThreadBuilder::mock();
    let range = RangeChip::default(8);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    f(ctx, safe);
    let mut params = builder.config(10, Some(9));
    params.lookup_bits = Some(3);
    let circuit = RangeCircuitBuilder::mock(builder, params);
    MockProver::run(10 as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

// =========== Mock Prover ===========

// Circuit Satisfied for valid inputs
#[test]
fn pos_var_len_bytes() {
    base_test().k(10).lookup_bits(8).run(|ctx, range| {
        let safe = SafeTypeChip::new(&range);
        let fake_bytes = ctx.assign_witnesses(
            vec![255u64, 255u64, 255u64, 255u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        let len = ctx.load_witness(Fr::from(3u64));
        safe.raw_to_var_len_bytes::<4>(ctx, fake_bytes.try_into().unwrap(), len);
    });
}

// Checks circuit is unsatisfied for AssignedValue<F>'s are not in range 0..256
#[test]
#[should_panic(expected = "circuit was not satisfied")]
fn neg_var_len_bytes_witness_values_not_bytes() {
    mock_circuit_test(|ctx: &mut Context<Fr>, safe: SafeTypeChip<'_, Fr>| {
        let len = ctx.load_witness(Fr::from(3u64));
        let fake_bytes = ctx.assign_witnesses(
            vec![500u64, 500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        safe.raw_to_var_len_bytes::<4>(ctx, fake_bytes.try_into().unwrap(), len);
    });
}

//Checks assertion len < max_len
#[test]
#[should_panic]
fn neg_var_len_bytes_len_less_than_max_len() {
    mock_circuit_test(|ctx: &mut Context<Fr>, safe: SafeTypeChip<'_, Fr>| {
        let len = ctx.load_witness(Fr::from(5u64));
        let fake_bytes = ctx.assign_witnesses(
            vec![500u64, 500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        safe.raw_to_var_len_bytes::<4>(ctx, fake_bytes.try_into().unwrap(), len);
    });
}

// Circuit Satisfied for valid inputs
#[test]
fn pos_var_len_bytes_vec() {
    base_test().k(10).lookup_bits(8).run(|ctx, range| {
        let safe = SafeTypeChip::new(&range);
        let fake_bytes = ctx.assign_witnesses(
            vec![255u64, 255u64, 255u64, 255u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        let len = ctx.load_witness(Fr::from(3u64));
        safe.raw_to_var_len_bytes_vec(ctx, fake_bytes, len, 4);
    });
}

// Checks circuit is unsatisfied for AssignedValue<F>'s are not in range 0..256
#[test]
#[should_panic(expected = "circuit was not satisfied")]
fn neg_var_len_bytes_vec_witness_values_not_bytes() {
    mock_circuit_test(|ctx: &mut Context<Fr>, safe: SafeTypeChip<'_, Fr>| {
        let len = ctx.load_witness(Fr::from(3u64));
        let fake_bytes = ctx.assign_witnesses(
            vec![500u64, 500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        let max_len = fake_bytes.len();
        safe.raw_to_var_len_bytes_vec(ctx, fake_bytes, len, max_len);
    });
}

//Checks assertion len != max_len
#[test]
#[should_panic]
fn neg_var_len_bytes_vec_len_less_than_max_len() {
    mock_circuit_test(|ctx: &mut Context<Fr>, safe: SafeTypeChip<'_, Fr>| {
        let len = ctx.load_witness(Fr::from(5u64));
        let fake_bytes = ctx.assign_witnesses(
            vec![500u64, 500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        let max_len = 5;
        safe.raw_to_var_len_bytes_vec(ctx, fake_bytes, len, max_len);
    });
}

// Circuit Satisfied for valid inputs
#[test]
fn pos_fix_len_bytes_vec() {
    base_test().k(10).lookup_bits(8).run(|ctx, range| {
        let safe = SafeTypeChip::new(&range);
        let fake_bytes = ctx.assign_witnesses(
            vec![255u64, 255u64, 255u64, 255u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
        );
        safe.raw_to_fix_len_bytes::<4>(ctx, fake_bytes.try_into().unwrap());
    });
}

// =========== Prover ===========
#[test]
fn pos_prover_satisfied() {
    const KEYGEN_MAX_LEN: usize = 4;
    const PROVER_MAX_LEN: usize = 4;
    let keygen_inputs = (vec![1u64, 2u64, 3u64, 4u64], 3);
    let proof_inputs = (vec![1u64, 2u64, 3u64, 4u64], 3);
    prover_satisfied::<KEYGEN_MAX_LEN, PROVER_MAX_LEN>(keygen_inputs, proof_inputs).unwrap();
}

#[test]
fn pos_diff_len_same_max_len() {
    const KEYGEN_MAX_LEN: usize = 4;
    const PROVER_MAX_LEN: usize = 4;
    let keygen_inputs = (vec![1u64, 2u64, 3u64, 4u64], 3);
    let proof_inputs = (vec![1u64, 2u64, 3u64, 4u64], 2);
    prover_satisfied::<KEYGEN_MAX_LEN, PROVER_MAX_LEN>(keygen_inputs, proof_inputs).unwrap();
}

#[test]
#[should_panic]
fn neg_different_proof_max_len() {
    const KEYGEN_MAX_LEN: usize = 4;
    const PROVER_MAX_LEN: usize = 3;
    let keygen_inputs = (vec![1u64, 2u64, 3u64, 4u64], 4);
    let proof_inputs = (vec![1u64, 2u64, 3u64], 3);
    prover_satisfied::<KEYGEN_MAX_LEN, PROVER_MAX_LEN>(keygen_inputs, proof_inputs).unwrap();
}

//test circuit
fn var_byte_array_circuit<const MAX_LEN: usize>(
    k: usize,
    phase: bool,
    (bytes, len): (Vec<u64>, usize),
) -> RangeCircuitBuilder<Fr> {
    let lookup_bits = 3;
    let mut builder = match phase {
        true => GateThreadBuilder::prover(),
        false => GateThreadBuilder::keygen(),
    };
    let range = RangeChip::<Fr>::default(lookup_bits);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    let len = ctx.load_witness(Fr::from(len as u64));
    let fake_bytes = ctx.assign_witnesses(bytes.into_iter().map(Fr::from).collect::<Vec<_>>());
    safe.raw_to_var_len_bytes::<MAX_LEN>(ctx, fake_bytes.try_into().unwrap(), len);
    let mut params = builder.config(k, Some(9));
    params.lookup_bits = Some(lookup_bits);
    let circuit = match phase {
        true => RangeCircuitBuilder::prover(builder, params, vec![vec![]]),
        false => RangeCircuitBuilder::keygen(builder, params),
    };
    circuit
}

//Prover test
fn prover_satisfied<const KEYGEN_MAX_LEN: usize, const PROVER_MAX_LEN: usize>(
    keygen_inputs: (Vec<u64>, usize),
    proof_inputs: (Vec<u64>, usize),
) -> Result<(), Box<dyn std::error::Error>> {
    let k = 11;
    let rng = OsRng;
    let params = ParamsKZG::<Bn256>::setup(k as u32, rng);
    let keygen_circuit = var_byte_array_circuit::<KEYGEN_MAX_LEN>(k, false, keygen_inputs);
    let vk = keygen_vk(&params, &keygen_circuit).unwrap();
    let pk = keygen_pk(&params, vk, &keygen_circuit).unwrap();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let proof_circuit = var_byte_array_circuit::<PROVER_MAX_LEN>(k, true, proof_inputs);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
    let proof = transcript.finalize();

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
    .unwrap();
    Ok(())
}
