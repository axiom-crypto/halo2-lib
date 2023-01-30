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
use rand_core::OsRng;

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    _marker: PhantomData<F>,
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenge = meta.challenge_usable_after(FirstPhase);
        KeccakCircuitConfig::new(meta, challenge)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_aux_tables(&mut layouter)?;
        let mut challenge = layouter.get_challenge(config.challenge);
        let mut first_pass = true;
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let (witness, squeeze_digests) = multi_keccak_phase0(&self.inputs, self.capacity());
                config.assign(&mut region, &witness);

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
                );
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: Field> KeccakCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: Option<usize>, inputs: Vec<Vec<u8>>) -> Self {
        KeccakCircuit { inputs, num_rows, _marker: PhantomData }
    }

    /// The number of keccak_f's that can be done in this circuit
    pub fn capacity(&self) -> Option<usize> {
        // Subtract two for unusable rows
        self.num_rows.map(|num_rows| num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    }
}

fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, _success: bool) {
    let circuit = KeccakCircuit::new(Some(2usize.pow(k)), inputs);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

/// Cmdline: KECCAK_ROWS=28 KECCAK_DEGREE=14 RUST_LOG=info cargo test -- --nocapture packed_multi_keccak_simple
#[test]
fn packed_multi_keccak_simple() {
    let _ = env_logger::builder().is_test(true).try_init();

    let k = 14;
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    verify::<Fr>(k, inputs, true);
}

#[test]
fn packed_multi_keccak_prover() {
    let _ = env_logger::builder().is_test(true).try_init();

    let k: u32 = var("KECCAK_DEGREE").unwrap_or_else(|_| "14".to_string()).parse().unwrap();
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit = KeccakCircuit::new(Some(2usize.pow(k)), inputs);

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

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
