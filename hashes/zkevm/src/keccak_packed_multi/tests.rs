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
use halo2_base::{halo2_proofs::halo2curves::ff::FromUniformBytes, SKIP_FIRST_PASS};
use rand_core::OsRng;
use test_case::test_case;

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field> {
    config: KeccakConfigParams,
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
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
                let lengths = config.assign(&mut region, &witness);
                // only look at last row in each round
                // first round is dummy, so ignore
                // only look at last round per absorb of RATE_IN_BITS
                for length in lengths
                    .into_iter()
                    .step_by(config.parameters.rows_per_round)
                    .step_by(NUM_ROUNDS + 1)
                    .skip(1)
                {
                    println!("len: {:?}", length.value());
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
    pub fn new(config: KeccakConfigParams, num_rows: Option<usize>, inputs: Vec<Vec<u8>>) -> Self {
        KeccakCircuit { config, inputs, num_rows, _marker: PhantomData }
    }
}

fn verify<F: Field + Ord + FromUniformBytes<64>>(
    config: KeccakConfigParams,
    inputs: Vec<Vec<u8>>,
    _success: bool,
) {
    let k = config.k;
    let circuit = KeccakCircuit::new(config, Some(2usize.pow(k) - 109), inputs);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
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
    let circuit =
        KeccakCircuit::new(KeccakConfigParams { k, rows_per_round }, Some(2usize.pow(k)), inputs);

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
