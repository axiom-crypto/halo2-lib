use super::*;
use crate::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::Circuit,
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

        KeccakCircuitConfig::new(meta, params)
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
        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let (witness, _) = multi_keccak(
                    &self.inputs,
                    self.num_rows.map(|nr| get_keccak_capacity(nr, params.rows_per_round)),
                    params,
                );
                let assigned_rows = config.assign(&mut region, &witness);
                if self.verify_output {
                    self.verify_output_witnesses(&assigned_rows);
                    self.verify_input_witnesses(&assigned_rows);
                }
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

    fn verify_output_witnesses<'v>(&self, assigned_rows: &[KeccakAssignedRow<'v, F>]) {
        let mut input_offset = 0;
        // only look at last row in each round
        // first round is dummy, so ignore
        // only look at last round per absorb of RATE_IN_BITS
        for assigned_row in
            assigned_rows.iter().step_by(self.config.rows_per_round).step_by(NUM_ROUNDS + 1).skip(1)
        {
            let KeccakAssignedRow { is_final, hash_lo, hash_hi, .. } = assigned_row.clone();
            let is_final_val = extract_value(is_final).ne(&F::ZERO);
            let hash_lo_val = extract_u128(hash_lo);
            let hash_hi_val = extract_u128(hash_hi);

            if input_offset < self.inputs.len() && is_final_val {
                // out is in big endian.
                let out = Keccak256::digest(&self.inputs[input_offset]);
                let lo = u128::from_be_bytes(out[16..].try_into().unwrap());
                let hi = u128::from_be_bytes(out[..16].try_into().unwrap());
                assert_eq!(lo, hash_lo_val);
                assert_eq!(hi, hash_hi_val);
                input_offset += 1;
            }
        }
    }

    fn verify_input_witnesses<'v>(&self, assigned_rows: &[KeccakAssignedRow<'v, F>]) {
        let rows_per_round = self.config.rows_per_round;
        let mut input_offset = 0;
        let mut input_byte_offset = 0;
        // first round is dummy, so ignore
        for absorb_chunk in &assigned_rows.chunks(rows_per_round).skip(1).chunks(NUM_ROUNDS + 1) {
            let mut abosrbed = false;
            for (round_idx, assigned_rows) in absorb_chunk.enumerate() {
                for (row_idx, assigned_row) in assigned_rows.iter().enumerate() {
                    let KeccakAssignedRow { is_final, word_value, bytes_left, .. } =
                        assigned_row.clone();
                    let is_final_val = extract_value(is_final).ne(&F::ZERO);
                    let word_value_val = extract_u128(word_value);
                    let bytes_left_val = extract_u128(bytes_left);
                    // Padded inputs - all empty.
                    if input_offset >= self.inputs.len() {
                        assert_eq!(word_value_val, 0);
                        assert_eq!(bytes_left_val, 0);
                        continue;
                    }
                    let input_len = self.inputs[input_offset].len();
                    if round_idx == NUM_ROUNDS && row_idx == 0 && is_final_val {
                        abosrbed = true;
                    }
                    if row_idx == 0 {
                        assert_eq!(bytes_left_val, input_len as u128 - input_byte_offset as u128);
                        // Only these rows could contain inputs.
                        let end = if round_idx < NUM_WORDS_TO_ABSORB {
                            std::cmp::min(input_byte_offset + NUM_BYTES_PER_WORD, input_len)
                        } else {
                            input_byte_offset
                        };
                        let mut expected_val_le_bytes =
                            self.inputs[input_offset][input_byte_offset..end].to_vec().clone();
                        expected_val_le_bytes.resize(NUM_BYTES_PER_WORD, 0);
                        assert_eq!(
                            word_value_val,
                            u64::from_le_bytes(expected_val_le_bytes.try_into().unwrap()) as u128,
                        );
                        input_byte_offset = end;
                    }
                }
            }
            if abosrbed {
                input_offset += 1;
                input_byte_offset = 0;
            }
        }
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

fn extract_u128<'v, F: Field>(assigned_value: KeccakAssignedValue<'v, F>) -> u128 {
    let le_bytes = extract_value(assigned_value).to_bytes_le();
    let hi = u128::from_le_bytes(le_bytes[16..].try_into().unwrap());
    assert_eq!(hi, 0);
    u128::from_le_bytes(le_bytes[..16].try_into().unwrap())
}

#[test_case(14, 28; "k: 14, rows_per_round: 28")]
#[test_case(12, 5; "k: 12, rows_per_round: 5")]
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
