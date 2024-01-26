use std::marker::PhantomData;

use rand::{rngs::StdRng, Rng};
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

use super::{
    columns::Sha256CircuitConfig,
    param::SHA256_NUM_ROWS,
    util::{get_num_sha2_blocks, get_sha2_capacity},
    witness::AssignedSha256Block,
};
use crate::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::Circuit,
    plonk::{keygen_pk, keygen_vk},
};
use halo2_base::{
    halo2_proofs::{
        circuit::Layouter,
        plonk::{Assigned, ConstraintSystem, Error},
    },
    utils::{
        fs::gen_srs,
        halo2::Halo2AssignedCell,
        testing::{check_proof, gen_proof},
        value_to_option,
    },
};
use test_case::test_case;

use crate::util::eth_types::Field;

/// Sha256BitCircuit
#[derive(Default)]
pub struct Sha256BitCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    verify_output: bool,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for Sha256BitCircuit<F> {
    type Config = Sha256CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

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
                let start = std::time::Instant::now();
                let blocks = config.multi_sha256(
                    &mut region,
                    self.inputs.clone(),
                    self.num_rows.map(get_sha2_capacity),
                );
                println!("Witness generation time: {:?}", start.elapsed());

                if self.verify_output {
                    self.verify_output_witness(&blocks);
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> Sha256BitCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: Option<usize>, inputs: Vec<Vec<u8>>, verify_output: bool) -> Self {
        Sha256BitCircuit { num_rows, inputs, verify_output, _marker: PhantomData }
    }

    fn verify_output_witness(&self, assigned_blocks: &[AssignedSha256Block<F>]) {
        let mut input_offset = 0;
        let mut input = vec![];
        let extract_value = |a: Halo2AssignedCell<F>| {
            let value = *value_to_option(a.value()).unwrap();
            #[cfg(feature = "halo2-axiom")]
            let value = *value;
            #[cfg(not(feature = "halo2-axiom"))]
            let value = value.clone();
            match value {
                Assigned::Trivial(v) => v,
                Assigned::Zero => F::ZERO,
                Assigned::Rational(a, b) => a * b.invert().unwrap(),
            }
        };
        for input_block in assigned_blocks {
            let AssignedSha256Block { is_final, output, word_values, length, .. } =
                input_block.clone();
            let [is_final, output_lo, output_hi, length] =
                [is_final, output.lo(), output.hi(), length].map(extract_value);
            let word_values = word_values.iter().cloned().map(extract_value).collect::<Vec<_>>();
            for word in word_values {
                let word = word.get_lower_32().to_le_bytes();
                input.extend_from_slice(&word);
            }
            let is_final = is_final == F::ONE;
            if is_final {
                let empty = vec![];
                let true_input = self.inputs.get(input_offset).unwrap_or(&empty);
                let true_length = true_input.len();
                assert_eq!(length.get_lower_64(), true_length as u64, "Length does not match");
                // clear global input and make it local
                let mut input = std::mem::take(&mut input);
                input.truncate(true_length);
                assert_eq!(&input, true_input, "Inputs do not match");
                let output_lo = output_lo.to_repr(); // u128 as 32 byte LE
                let output_hi = output_hi.to_repr();
                let mut output = [&output_lo[..16], &output_hi[..16]].concat();
                output.reverse(); // = [output_hi_be, output_lo_be].concat()

                let mut hasher = Sha256::new();
                hasher.update(true_input);
                assert_eq!(output, hasher.finalize().to_vec(), "Outputs do not match");

                input_offset += 1;
            }
        }
    }
}

fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, success: bool) {
    let circuit = Sha256BitCircuit::new(Some(2usize.pow(k) - 109usize), inputs, success);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    if success {
        prover.assert_satisfied();
    } else {
        assert!(prover.verify().is_err());
    }
}

#[test_case(10; "k: 10")]
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

#[test_case(18; "k: 18")]
fn bit_sha256_mock_random(k: u32) {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut rng = StdRng::seed_from_u64(0);
    let mut rows = 0;
    let mut inputs = vec![];
    let max_rows = 2usize.pow(k) - 109usize;
    while rows < max_rows {
        let num_bytes = rng.gen_range(0..1000);
        let input = (0..num_bytes).map(|_| rng.gen()).collect::<Vec<_>>();
        rows += get_num_sha2_blocks(num_bytes) * SHA256_NUM_ROWS;
        if rows > max_rows {
            break;
        }
        inputs.push(input);
    }
    verify::<Fr>(k, inputs, true);
}

#[test_case(10; "k: 10")]
#[test_case(20; "k: 20")]
fn bit_sha256_prover(k: u32) {
    let _ = env_logger::builder().is_test(true).try_init();

    let params = gen_srs(k);

    let dummy_circuit = Sha256BitCircuit::new(Some(2usize.pow(k) - 100), vec![], false);
    let vk = keygen_vk(&params, &dummy_circuit).unwrap();
    let pk = keygen_pk(&params, vk, &dummy_circuit).unwrap();

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..54).collect::<Vec<_>>(),
        (0u8..55).collect::<Vec<_>>(), // with padding 55 + 1 + 8 = 64 bytes, still fits in 1 block
        (0u8..56).collect::<Vec<_>>(), // needs 2 blocks, due to padding
    ];
    let circuit = Sha256BitCircuit::new(Some(2usize.pow(k) - 100), inputs, false);
    let capacity = get_sha2_capacity(circuit.num_rows.unwrap());

    let start = std::time::Instant::now();
    let proof = gen_proof(&params, &pk, circuit);
    println!("Proving time for {} SHA256 blocks: {:?}", capacity, start.elapsed());

    check_proof(&params, pk.get_vk(), &proof, true);
}
