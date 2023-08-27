use super::*;
use crate::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    plonk::{Circuit, FirstPhase},
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
};
use halo2_base::{
    halo2_proofs::halo2curves::ff::FromUniformBytes, utils::value_to_option, SKIP_FIRST_PASS,
};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};
use test_case::test_case;

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field> {
    config: KeccakConfigParams,
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    verify_output: bool,
    _marker: PhantomData<F>,
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = KeccakConfigParams;

    fn params(&self) -> Self::Params {
        self.config
    }

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        // MockProver complains if you only have columns in SecondPhase, so let's just make an empty column in FirstPhase
        meta.advice_column();

        let challenge = meta.challenge_usable_after(FirstPhase);
        KeccakCircuitConfig::new(meta, challenge, params)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let params = config.parameters;
        config.load_aux_tables(&mut layouter, params.k)?;
        let mut challenge = layouter.get_challenge(config.challenge);
        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let (witness, squeeze_digests) = multi_keccak_phase0(
                    &self.inputs,
                    self.num_rows.map(|nr| get_keccak_capacity(nr, params.rows_per_round)),
                    params,
                );
                let assigned_rows = config.assign(&mut region, &witness);
                if self.verify_output {
                    let mut input_offset = 0;
                    // only look at last row in each round
                    // first round is dummy, so ignore
                    // only look at last round per absorb of RATE_IN_BITS
                    for assigned_row in assigned_rows
                        .into_iter()
                        .step_by(config.parameters.rows_per_round)
                        .step_by(NUM_ROUNDS + 1)
                        .skip(1)
                    {
                        let KeccakAssignedRow { is_final, length, hash_lo, hash_hi } = assigned_row;
                        let is_final_val = extract_value(is_final).ne(&F::ZERO);
                        let hash_lo_val = u128::from_le_bytes(
                            extract_value(hash_lo).to_bytes_le()[..16].try_into().unwrap(),
                        );
                        let hash_hi_val = u128::from_le_bytes(
                            extract_value(hash_hi).to_bytes_le()[..16].try_into().unwrap(),
                        );
                        println!(
                            "is_final: {:?}, len: {:?}, hash_lo: {:#x}, hash_hi: {:#x}",
                            is_final_val,
                            length.value(),
                            hash_lo_val,
                            hash_hi_val,
                        );

                        if input_offset < self.inputs.len() && is_final_val {
                            // out is in big endian.
                            let out = Keccak256::digest(&self.inputs[input_offset]);
                            let lo = u128::from_be_bytes(out[16..].try_into().unwrap());
                            let hi = u128::from_be_bytes(out[..16].try_into().unwrap());
                            println!("lo: {:#x}, hi: {:#x}", lo, hi);
                            assert_eq!(lo, hash_lo_val);
                            assert_eq!(hi, hash_hi_val);
                            input_offset += 1;
                        }
                    }
                }

                #[cfg(feature = "halo2-axiom")]
                {
                    region.next_phase();
                    challenge = region.get_challenge(config.challenge);
                }
                multi_keccak_phase1(
                    &mut region,
                    &config.keccak_table,
                    self.inputs.iter().map(|v| v.as_slice()),
                    challenge,
                    squeeze_digests,
                    params,
                );
                println!("finished keccak circuit");
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: Field> KeccakCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(
        config: KeccakConfigParams,
        num_rows: Option<usize>,
        inputs: Vec<Vec<u8>>,
        verify_output: bool,
    ) -> Self {
        KeccakCircuit { config, inputs, num_rows, _marker: PhantomData, verify_output }
    }
}

fn verify<F: Field + Ord + FromUniformBytes<64>>(
    config: KeccakConfigParams,
    inputs: Vec<Vec<u8>>,
    _success: bool,
) {
    let k = config.k;
    let circuit = KeccakCircuit::new(config, Some(2usize.pow(k) - 109), inputs, true);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

fn extract_value<'v, F: Field>(assigned_value: KeccakAssignedValue<'v, F>) -> F {
    let assigned = **value_to_option(assigned_value.value()).unwrap();
    match assigned {
        halo2_base::halo2_proofs::plonk::Assigned::Zero => F::ZERO,
        halo2_base::halo2_proofs::plonk::Assigned::Trivial(f) => f,
        _ => panic!("value should be trival"),
    }
}

#[test_case(14, 28; "k: 14, rows_per_round: 28")]
fn packed_multi_keccak_simple(k: u32, rows_per_round: usize) {
    let _ = env_logger::builder().is_test(true).try_init();

    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    verify::<Fr>(KeccakConfigParams { k, rows_per_round }, inputs, true);
}

#[test_case(14, 25 ; "k: 14, rows_per_round: 25")]
#[test_case(18, 9 ; "k: 18, rows_per_round: 9")]
fn packed_multi_keccak_prover(k: u32, rows_per_round: usize) {
    let _ = env_logger::builder().is_test(true).try_init();

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit = KeccakCircuit::new(
        KeccakConfigParams { k, rows_per_round },
        Some(2usize.pow(k)),
        inputs,
        false,
    );

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let start = std::time::Instant::now();
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    dbg!(start.elapsed());

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&params);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, pk.get_vk(), strategy, &[&[]], &mut verifier_transcript)
    .expect("failed to verify bench circuit");
}
