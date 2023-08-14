use crate::{
    halo2_proofs::{halo2curves::bn256::Fr, poly::kzg::commitment::ParamsKZG},
    utils::testing::{check_proof, gen_proof},
};

use super::*;
use crate::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{
        plonk::keygen_pk,
        plonk::{keygen_vk, Assigned},
    },
};
use itertools::Itertools;
use rand::rngs::OsRng;

// soundness checks for `raw_bytes_to` function
fn test_raw_bytes_to_gen<const BYTES_PER_ELE: usize, const TOTAL_BITS: usize>(
    k: u32,
    raw_bytes: &[Fr],
    outputs: &[Fr],
    expect_satisfied: bool,
) {
    // first create proving and verifying key
    let mut builder = GateThreadBuilder::<Fr>::keygen();
    let lookup_bits = 3;
    let range_chip = RangeChip::<Fr>::default(lookup_bits);
    let safe_type_chip = SafeTypeChip::new(&range_chip);

    let dummy_raw_bytes = builder
        .main(0)
        .assign_witnesses((0..raw_bytes.len()).map(|_| Fr::zero()).collect::<Vec<_>>());

    let safe_value =
        safe_type_chip.raw_bytes_to::<BYTES_PER_ELE, TOTAL_BITS>(builder.main(0), dummy_raw_bytes);
    // get the offsets of the safe value cells for later 'pranking'
    let safe_value_offsets =
        safe_value.value().iter().map(|v| v.cell.unwrap().offset).collect::<Vec<_>>();

    let mut config_params = builder.config(k as usize, Some(9));
    config_params.lookup_bits = Some(lookup_bits);
    let circuit = RangeCircuitBuilder::keygen(builder, config_params.clone());

    let params = ParamsKZG::setup(k, OsRng);
    // generate proving key
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let vk = pk.get_vk(); // pk consumed vk

    // now create different proofs to test the soundness of the circuit
    let gen_pf = |inputs: &[Fr], outputs: &[Fr]| {
        let mut builder = GateThreadBuilder::<Fr>::prover();
        let range_chip = RangeChip::<Fr>::default(lookup_bits);
        let safe_type_chip = SafeTypeChip::new(&range_chip);

        let assigned_raw_bytes = builder.main(0).assign_witnesses(inputs.to_vec());
        safe_type_chip
            .raw_bytes_to::<BYTES_PER_ELE, TOTAL_BITS>(builder.main(0), assigned_raw_bytes);
        // prank the safe value cells
        for (offset, witness) in safe_value_offsets.iter().zip_eq(outputs) {
            builder.main(0).advice[*offset] = Assigned::<Fr>::Trivial(*witness);
        }
        let circuit = RangeCircuitBuilder::prover(builder, config_params, vec![vec![]]); // no break points
        gen_proof(&params, &pk, circuit)
    };
    let pf = gen_pf(raw_bytes, outputs);
    check_proof(&params, vk, &pf, expect_satisfied);
}

#[test]
fn test_raw_bytes_to_bool() {
    let k = 8;
    test_raw_bytes_to_gen::<1, 1>(k, &[Fr::from(0)], &[Fr::from(0)], true);
    test_raw_bytes_to_gen::<1, 1>(k, &[Fr::from(1)], &[Fr::from(1)], true);
    test_raw_bytes_to_gen::<1, 1>(k, &[Fr::from(1)], &[Fr::from(0)], false);
    test_raw_bytes_to_gen::<1, 1>(k, &[Fr::from(0)], &[Fr::from(1)], false);
    test_raw_bytes_to_gen::<1, 1>(k, &[Fr::from(3)], &[Fr::from(0)], false);
    test_raw_bytes_to_gen::<1, 1>(k, &[Fr::from(3)], &[Fr::from(1)], false);
}

#[test]
fn test_raw_bytes_to_uint256() {
    const BYTES_PER_ELE: usize = SafeUint256::<Fr>::BYTES_PER_ELE;
    const TOTAL_BITS: usize = SafeUint256::<Fr>::TOTAL_BITS;
    let k = 11;
    // [0x0; 32] -> [0x0, 0x0]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0); 32],
        &[Fr::from(0), Fr::from(0)],
        true,
    );
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(1)].as_slice(), [Fr::from(0); 31].as_slice()].concat(),
        &[Fr::from(1), Fr::from(0)],
        true,
    );
    // [0x1, 0x2] + [0x0; 30] -> [0x201, 0x0]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(1), Fr::from(2)].as_slice(), [Fr::from(0); 30].as_slice()].concat(),
        &[Fr::from(0x201), Fr::from(0)],
        true,
    );
    // [[0xff; 32] -> [2^248 - 1, 0xff]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0xff); 32],
        &[
            Fr::from_raw([
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffff,
            ]),
            Fr::from(0xff),
        ],
        true,
    );

    // invalid raw_bytes, last bytes > 0xff
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(0); 31].as_slice(), [Fr::from(0x1ff)].as_slice()].concat(),
        &[Fr::from(0), Fr::from(0xff)],
        false,
    );
    // 0xff != 0xff00000000000000000000000000000000000000000000000000000000000000
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(0xff)].as_slice(), [Fr::from(0); 31].as_slice()].concat(),
        &[Fr::from(0), Fr::from(0xff)],
        false,
    );
    // outputs overflow
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0xff); 32],
        &[
            Fr::from_raw([
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0xffffffffffffff,
            ]),
            Fr::from(0x1ff),
        ],
        false,
    );
}

#[test]
fn test_raw_bytes_to_uint64() {
    const BYTES_PER_ELE: usize = SafeUint64::<Fr>::BYTES_PER_ELE;
    const TOTAL_BITS: usize = SafeUint64::<Fr>::TOTAL_BITS;
    let k = 10;
    // [0x0; 8] -> [0x0]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(k, &[Fr::from(0); 8], &[Fr::from(0)], true);
    // [0x1, 0x2] + [0x0; 6] -> [0x201]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(1), Fr::from(2)].as_slice(), [Fr::from(0); 6].as_slice()].concat(),
        &[Fr::from(0x201)],
        true,
    );
    // [[0xff; 8] -> [2^64-1]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0xff); 8],
        &[Fr::from(0xffffffffffffffff)],
        true,
    );

    // invalid raw_bytes, last bytes > 0xff
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(0); 7].as_slice(), [Fr::from(0x1ff)].as_slice()].concat(),
        &[Fr::from(0xff00000000000000)],
        false,
    );
    // 0xff != 0xff00000000000000000000000000000000000000000000000000000000000000
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(0xff)].as_slice(), [Fr::from(0); 7].as_slice()].concat(),
        &[Fr::from(0xff00000000000000)],
        false,
    );
    // outputs overflow
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0xff); 8],
        &[Fr::from_raw([0xffffffffffffffff, 0x1, 0x0, 0x0])],
        false,
    );
}

#[test]
fn test_raw_bytes_to_bytes32() {
    const BYTES_PER_ELE: usize = SafeBytes32::<Fr>::BYTES_PER_ELE;
    const TOTAL_BITS: usize = SafeBytes32::<Fr>::TOTAL_BITS;
    let k = 10;
    // [0x0; 32] -> [0x0; 32]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0); 32],
        &[Fr::from(0); 32],
        true,
    );
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(1)].as_slice(), [Fr::from(0); 31].as_slice()].concat(),
        &[[Fr::from(1)].as_slice(), [Fr::from(0); 31].as_slice()].concat(),
        true,
    );
    // [0x1, 0x2] + [0x0; 30] -> [0x201, 0x0]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(1), Fr::from(2)].as_slice(), [Fr::from(0); 30].as_slice()].concat(),
        &[[Fr::from(1), Fr::from(2)].as_slice(), [Fr::from(0); 30].as_slice()].concat(),
        true,
    );
    // [[0xff; 32] -> [2^248 - 1, 0xff]
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0xff); 32],
        &[Fr::from(0xff); 32],
        true,
    );

    // invalid raw_bytes, last bytes > 0xff
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(0); 31].as_slice(), [Fr::from(0x1ff)].as_slice()].concat(),
        &[[Fr::from(0); 31].as_slice(), [Fr::from(0x1ff)].as_slice()].concat(),
        false,
    );
    // 0xff != 0xff00000000000000000000000000000000000000000000000000000000000000
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[[Fr::from(0xff)].as_slice(), [Fr::from(0); 31].as_slice()].concat(),
        &[[Fr::from(0); 31].as_slice(), [Fr::from(0xff)].as_slice()].concat(),
        false,
    );
    // outputs overflow
    test_raw_bytes_to_gen::<BYTES_PER_ELE, TOTAL_BITS>(
        k,
        &[Fr::from(0xff); 32],
        &[Fr::from(0x1ff); 32],
        false,
    );
}
