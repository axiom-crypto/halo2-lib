use crate::keccak::coprocessor::output::{
    dummy_circuit_output, input_to_circuit_outputs, multi_inputs_to_circuit_outputs,
    KeccakCircuitOutput,
};
use halo2_base::halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use itertools::Itertools;
use lazy_static::lazy_static;

lazy_static! {
    static ref OUTPUT_EMPTY: KeccakCircuitOutput<Fr> = KeccakCircuitOutput {
        key: Fr::from_raw([
            0x54595a1525d3534a,
            0xf90e160f1b4648ef,
            0x34d557ddfb89da5d,
            0x04ffe3d4b8885928,
        ]),
        hash_lo: Fr::from_u128(0xe500b653ca82273b7bfad8045d85a470),
        hash_hi: Fr::from_u128(0xc5d2460186f7233c927e7db2dcc703c0),
    };
    static ref OUTPUT_0: KeccakCircuitOutput<Fr> = KeccakCircuitOutput {
        key: Fr::from_raw([
            0xc009f26a12e2f494,
            0xb4a9d43c17609251,
            0x68068b5344cba120,
            0x1531327ea92d38ba,
        ]),
        hash_lo: Fr::from_u128(0x6612f7b477d66591ff96a9e064bcc98a),
        hash_hi: Fr::from_u128(0xbc36789e7a1e281436464229828f817d),
    };
    static ref OUTPUT_0_135: KeccakCircuitOutput<Fr> = KeccakCircuitOutput {
        key: Fr::from_raw([
            0x9a88287adab4da1c,
            0xe9ff61b507cfd8c2,
            0xdbf697a6a3ad66a1,
            0x1eb1d5cc8cdd1532,
        ]),
        hash_lo: Fr::from_u128(0x290b0e1706f6a82e5a595b9ce9faca62),
        hash_hi: Fr::from_u128(0xcbdfd9dee5faad3818d6b06f95a219fd),
    };
    static ref OUTPUT_0_136: KeccakCircuitOutput<Fr> = KeccakCircuitOutput {
        key: Fr::from_raw([
            0x39c1a578acb62676,
            0x0dc19a75e610c062,
            0x3f158e809150a14a,
            0x2367059ac8c80538,
        ]),
        hash_lo: Fr::from_u128(0xff11fe3e38e17df89cf5d29c7d7f807e),
        hash_hi: Fr::from_u128(0x7ce759f1ab7f9ce437719970c26b0a66),
    };
    static ref OUTPUT_0_200: KeccakCircuitOutput<Fr> = KeccakCircuitOutput {
        key: Fr::from_raw([
            0x379bfca638552583,
            0x1bf7bd603adec30e,
            0x05efe90ad5dbd814,
            0x053c729cb8908ccb,
        ]),
        hash_lo: Fr::from_u128(0xb4543f3d2703c0923c6901c2af57b890),
        hash_hi: Fr::from_u128(0xbfb0aa97863e797943cf7c33bb7e880b),
    };
}

#[test]
fn test_dummy_circuit_output() {
    let KeccakCircuitOutput { key, hash_lo, hash_hi } = dummy_circuit_output::<Fr>();
    assert_eq!(key, OUTPUT_EMPTY.key);
    assert_eq!(hash_lo, OUTPUT_EMPTY.hash_lo);
    assert_eq!(hash_hi, OUTPUT_EMPTY.hash_hi);
}

#[test]
fn test_input_to_circuit_outputs_empty() {
    let result = input_to_circuit_outputs::<Fr>(&[]);
    assert_eq!(result, vec![*OUTPUT_EMPTY]);
}

#[test]
fn test_input_to_circuit_outputs_1_keccak_f() {
    let result = input_to_circuit_outputs::<Fr>(&[0]);
    assert_eq!(result, vec![*OUTPUT_0]);
}

#[test]
fn test_input_to_circuit_outputs_1_keccak_f_full() {
    let result = input_to_circuit_outputs::<Fr>(&(0..135).collect_vec());
    assert_eq!(result, vec![*OUTPUT_0_135]);
}

#[test]
fn test_input_to_circuit_outputs_2_keccak_f_2nd_empty() {
    let result = input_to_circuit_outputs::<Fr>(&(0..136).collect_vec());
    assert_eq!(result, vec![*OUTPUT_EMPTY, *OUTPUT_0_136]);
}

#[test]
fn test_input_to_circuit_outputs_2_keccak_f() {
    let result = input_to_circuit_outputs::<Fr>(&(0..200).collect_vec());
    assert_eq!(result, vec![*OUTPUT_EMPTY, *OUTPUT_0_200]);
}

#[test]
fn test_multi_input_to_circuit_outputs() {
    let results = multi_inputs_to_circuit_outputs::<Fr>(
        &[(0..135).collect_vec(), (0..200).collect_vec(), vec![], vec![0], (0..136).collect_vec()],
        10,
    );
    assert_eq!(
        results,
        vec![
            *OUTPUT_0_135,
            *OUTPUT_EMPTY,
            *OUTPUT_0_200,
            *OUTPUT_EMPTY,
            *OUTPUT_0,
            *OUTPUT_EMPTY,
            *OUTPUT_0_136,
            // Padding
            *OUTPUT_EMPTY,
            *OUTPUT_EMPTY,
            *OUTPUT_EMPTY,
        ]
    );
}

#[test]
#[should_panic]
fn test_multi_input_to_circuit_outputs_exceed_capacity() {
    let _ = multi_inputs_to_circuit_outputs::<Fr>(
        &[(0..135).collect_vec(), (0..200).collect_vec(), vec![], vec![0], (0..136).collect_vec()],
        2,
    );
}
