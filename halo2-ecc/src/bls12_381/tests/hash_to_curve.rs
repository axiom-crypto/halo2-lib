use std::{fs::File, marker::PhantomData};

use super::*;
use crate::{
    bls12_381::hash_to_curve::{AssignedHashResult, HashInstructions, HashToCurveChip},
    fields::{FpStrategy, FieldChip},
};
use halo2_base::{
    gates::RangeChip, halo2_proofs::plonk::Error, utils::BigPrimeField, Context, QuantumCell,
};
extern crate pairing;
use itertools::Itertools;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct HashToCurveCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct Sha256MockChip<F: BigPrimeField>(PhantomData<F>);

impl<F: BigPrimeField> HashInstructions<F> for Sha256MockChip<F> {
    const BLOCK_SIZE: usize = 64;
    const DIGEST_SIZE: usize = 32;

    type ThreadBuidler = Context<F>;

    fn digest<const MAX_INPUT_SIZE: usize>(
        &self,
        ctx: &mut Self::ThreadBuidler,
        input: impl Iterator<Item = QuantumCell<F>>,
        _strict: bool,
    ) -> Result<AssignedHashResult<F>, Error> {
        use sha2::{Digest, Sha256};
        let input_bytes = input
            .map(|b| match b {
                QuantumCell::Witness(b) => b.get_lower_32() as u8,
                QuantumCell::Constant(b) => b.get_lower_32() as u8,
                QuantumCell::Existing(av) => av.value().get_lower_32() as u8,
                _ => unreachable!(),
            })
            .collect_vec();

        let output_bytes = Sha256::digest(input_bytes)
            .into_iter()
            .map(|b| ctx.load_witness(F::from(b as u64)))
            .collect_vec()
            .try_into()
            .unwrap();
        Ok(AssignedHashResult { input_bytes: vec![], output_bytes })
    }
}

fn hash_to_g2_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    params: HashToCurveCircuitParams,
    msg: Vec<u8>,
) {
    let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
    let fp2_chip = Fp2Chip::new(&fp_chip);

    let sha256 = Sha256MockChip::<F>::default();

    let h2c_chip = HashToCurveChip::new(&sha256, &fp2_chip);

    let hp = h2c_chip
        .hash_to_curve(
            ctx,
            msg.into_iter().map(|b| QuantumCell::Witness(F::from(b as u64))),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
        )
        .unwrap();

    println!(
        "msghash: {:?}",
        (fp2_chip.get_assigned_value(&hp.x.into()), fp2_chip.get_assigned_value(&hp.y.into()))
    );

    // Verify off-circuit

    // Compare the 2 results
}

#[test]
fn test_hash_to_g2() {
    let run_path = "configs/bls12_381/hash_to_curve_circuit.config";
    let path = run_path;
    let params: HashToCurveCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!("num_advice: {num_advice}", num_advice = params.num_advice);

    let test_input = vec![0u8; 32];

    base_test().k(params.degree).lookup_bits(params.lookup_bits).run(|ctx, range| {
        hash_to_g2_test(ctx, range, params, test_input);
    })
}
