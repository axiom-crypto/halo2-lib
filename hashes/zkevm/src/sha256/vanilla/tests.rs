use std::marker::PhantomData;

use super::{columns::Sha256CircuitConfig, util::get_sha2_capacity, *};
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
    halo2_proofs::{
        circuit::Layouter,
        plonk::{ConstraintSystem, Error},
    },
    SKIP_FIRST_PASS,
};
use rand_core::OsRng;
use test_case::test_case;

use crate::util::eth_types::Field;

/// Sha256BitCircuit
#[derive(Default)]
pub struct Sha256BitCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for Sha256BitCircuit<F> {
    type Config = Sha256CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Sha256CircuitConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "SHA256 Bit Circuit",
            |mut region| {
                let blocks = config.multi_sha256(
                    &mut region,
                    self.inputs.clone(),
                    self.num_rows.map(get_sha2_capacity),
                );
                for block in &blocks {
                    println!("{:?}", block.length().value());
                }
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
        (0u8..55).collect::<Vec<_>>(), // with padding 55 + 1 + 8 = 64 bytes, still fits in 1 block
        (0u8..56).collect::<Vec<_>>(), // needs 2 blocks, due to padding
        (0u8..200).collect::<Vec<_>>(),
    ];
    verify::<Fr>(k, inputs, true);
}
