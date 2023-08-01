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
    halo2_proofs::{circuit::Layouter, plonk::Error},
    SKIP_FIRST_PASS,
};
use rand_core::OsRng;
use test_case::test_case;

/// Sha256BitCircuit
#[derive(Default)]
pub struct Sha256BitCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for Sha256BitCircuit<F> {
    type Config = Sha256BitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // MockProver complains if you only have columns in SecondPhase, so let's just make an empty column in FirstPhase
        meta.advice_column();
        let challenge = meta.challenge_usable_after(FirstPhase);
        Sha256BitConfig::configure(meta, challenge)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut challenge = layouter.get_challenge(config.challenge);
        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "sha256 bit circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let w = config.multi_sha256_phase0(
                    &mut region,
                    self.inputs.clone(),
                    self.num_rows.map(get_sha2_capacity),
                );
                for length in &w.input_len {
                    println!("len: {:?}", length.value());
                }
                #[cfg(feature = "halo2-axiom")]
                {
                    region.next_phase();
                    challenge = region.get_challenge(config.challenge);
                }
                config.multi_sha256_phase1(&mut region, w, challenge);
                Ok(())
            },
        )
    }
}

impl<F: Field> Sha256BitCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: Option<usize>, inputs: Vec<Vec<u8>>) -> Self {
        Sha256BitCircuit { num_rows, inputs, _marker: PhantomData }
    }
}

fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, success: bool) {
    let circuit = Sha256BitCircuit::new(Some(2usize.pow(k) - 109usize), inputs);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    if success {
        prover.assert_satisfied();
    } else {
        assert!(prover.verify().is_err());
    }
}

#[test_case(10; "k: 14")]
fn bit_sha256_simple(k: u32) {
    let _ = env_logger::builder().is_test(true).try_init();
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..54).collect::<Vec<_>>(),
        (0u8..55).collect::<Vec<_>>(),
        (0u8..56).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    verify::<Fr>(k, inputs, true);
}
