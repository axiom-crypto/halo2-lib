use crate::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{
            create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey,
        },
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
};
use rand::rngs::OsRng;
use std::{env::set_var, vec};

// =========== Mock Prover ===========

// Circuit Satisfied for valid inputs
#[test]
fn pos_var_assigned_bytes() {
    set_var("LOOKUP_BITS", "8");
    let mut builder = GateThreadBuilder::mock();
    let range = RangeChip::default(8);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    let fake_bytes = ctx.assign_witnesses(
        vec![255u64, 255u64, 255u64, 255u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
    );
    let var_len = ctx.load_witness(Fr::from(3u64));
    safe.raw_var_bytes_to::<4>(ctx, fake_bytes, var_len);
    builder.config(10, Some(9));
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(10 as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

// Checks circuit is unsatisfied for AssignedValue<F>'s are not in range 0..256
#[test]
#[should_panic(expected = "circuit was not satisfied")]
fn witness_values_not_bytes() {
    let mut builder = GateThreadBuilder::mock();
    let range = RangeChip::default(8);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    let var_len = ctx.load_witness(Fr::from(3u64));
    let fake_bytes = ctx.assign_witnesses(
        vec![500u64, 500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
    );
    safe.raw_var_bytes_to::<4>(ctx, fake_bytes, var_len);
    builder.config(10, Some(9));
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(10 as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

//Checks assertion max_var_len == bytes.len()
#[test]
#[should_panic(expected = "len of bytes must equal max_var_len")]
fn bytes_len_not_equal_max_var_len() {
    let mut builder = GateThreadBuilder::mock();
    let range = RangeChip::default(8);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    let var_len = ctx.load_witness(Fr::from(3u64));
    let fake_bytes = ctx.assign_witnesses(
        vec![500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
    );
    safe.raw_var_bytes_to::<4>(ctx, fake_bytes, var_len);
}

//Checks assertion var_len < max_var_len
#[test]
#[should_panic(expected = "circuit was not satisfied")]
fn neg_var_len_less_than_max_var_len() {
    let mut builder = GateThreadBuilder::mock();
    let range = RangeChip::default(8);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    let var_len = ctx.load_witness(Fr::from(5u64));
    let fake_bytes = ctx.assign_witnesses(
        vec![500u64, 500u64, 500u64, 500u64].into_iter().map(Fr::from).collect::<Vec<_>>(),
    );
    safe.raw_var_bytes_to::<4>(ctx, fake_bytes, var_len);
    builder.config(10, Some(9));
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(10 as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

// =========== Prover ===========
#[test]
fn pos_prover_satisfied() {
    const KEYGEN_MAX_VAR_LEN: usize = 4;
    const PROVER_MAX_VAR_LEN: usize = 4;
    let keygen_inputs = (vec![1u64, 2u64, 3u64, 4u64], 3);
    let proof_inputs = (vec![1u64, 2u64, 3u64, 4u64], 3);
    prover_satisfied::<KEYGEN_MAX_VAR_LEN, PROVER_MAX_VAR_LEN>(keygen_inputs, proof_inputs)
        .unwrap();
}

#[test]
fn pos_diff_var_len_same_max_len() {
    const KEYGEN_MAX_VAR_LEN: usize = 4;
    const PROVER_MAX_VAR_LEN: usize = 4;
    let keygen_inputs = (vec![1u64, 2u64, 3u64, 4u64], 3);
    let proof_inputs = (vec![1u64, 2u64, 3u64, 4u64], 2);
    prover_satisfied::<KEYGEN_MAX_VAR_LEN, PROVER_MAX_VAR_LEN>(keygen_inputs, proof_inputs)
        .unwrap();
}

#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value: ConstraintSystemFailure")]
fn neg_different_proof_max_var_len() {
    const KEYGEN_MAX_VAR_LEN: usize = 4;
    const PROVER_MAX_VAR_LEN: usize = 3;
    let keygen_inputs = (vec![1u64, 2u64, 3u64, 4u64], 4);
    let proof_inputs = (vec![1u64, 2u64, 3u64], 3);
    prover_satisfied::<KEYGEN_MAX_VAR_LEN, PROVER_MAX_VAR_LEN>(keygen_inputs, proof_inputs)
        .unwrap();
}

//test circuit
fn var_byte_array_circuit<const MAX_VAR_LEN: usize>(
    k: usize,
    phase: bool,
    (bytes, var_len): (Vec<u64>, usize),
) -> RangeCircuitBuilder<Fr> {
    let lookup_bits = 3;
    set_var("LOOKUP_BITS", lookup_bits.to_string());
    let k = 11;
    let mut builder = match phase {
        true => GateThreadBuilder::prover(),
        false => GateThreadBuilder::keygen(),
    };
    let range = RangeChip::<Fr>::default(lookup_bits);
    let safe = SafeTypeChip::new(&range);
    let ctx = builder.main(0);
    let var_len = ctx.load_witness(Fr::from(var_len as u64));
    let fake_bytes = ctx.assign_witnesses(bytes.into_iter().map(Fr::from).collect::<Vec<_>>());
    safe.raw_var_bytes_to::<MAX_VAR_LEN>(ctx, fake_bytes, var_len);
    builder.config(k, Some(9));
    let circuit = match phase {
        true => RangeCircuitBuilder::prover(builder, vec![vec![]]),
        false => RangeCircuitBuilder::keygen(builder),
    };
    circuit
}

//Prover test
fn prover_satisfied<const KEYGEN_MAX_VAR_LEN: usize, const PROVER_MAX_VAR_LEN: usize>(
    keygen_inputs: (Vec<u64>, usize),
    proof_inputs: (Vec<u64>, usize),
) -> Result<(), Box<dyn std::error::Error>> {
    let k = 11;
    let rng = OsRng;
    let params = ParamsKZG::<Bn256>::setup(k as u32, rng);
    let keygen_circuit = var_byte_array_circuit::<KEYGEN_MAX_VAR_LEN>(k, false, keygen_inputs);
    let vk = keygen_vk(&params, &keygen_circuit).unwrap();
    let pk = keygen_pk(&params, vk, &keygen_circuit).unwrap();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let proof_circuit = var_byte_array_circuit::<PROVER_MAX_VAR_LEN>(k, true, proof_inputs);
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
