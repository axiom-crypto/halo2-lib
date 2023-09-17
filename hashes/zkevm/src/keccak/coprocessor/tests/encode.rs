use ethers_core::k256::elliptic_curve::Field;
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    safe_types::SafeTypeChip,
    utils::testing::base_test,
    Context,
};
use itertools::Itertools;

use crate::keccak::coprocessor::{
    circuit::leaf::create_hasher,
    encode::{encode_fix_len_bytes_vec, encode_native_input, encode_var_len_bytes_vec},
};

fn build_and_verify_encode_var_len_bytes_vec(
    inputs: Vec<(Vec<u8>, usize)>,
    ctx: &mut Context<Fr>,
    range_chip: &RangeChip<Fr>,
) {
    let mut hasher = create_hasher();
    hasher.initialize_consts(ctx, range_chip.gate());

    for (input, max_len) in inputs {
        let expected = encode_native_input::<Fr>(&input);
        let len = ctx.load_witness(Fr::from(input.len() as u64));
        let mut witnesses_val = vec![Fr::ZERO; max_len];
        witnesses_val[..input.len()]
            .copy_from_slice(&input.iter().map(|b| Fr::from(*b as u64)).collect_vec());
        let input_witnesses = ctx.assign_witnesses(witnesses_val);
        let var_len_bytes_vec =
            SafeTypeChip::unsafe_to_var_len_bytes_vec(input_witnesses, len, max_len);
        let encoded = encode_var_len_bytes_vec(ctx, range_chip, &hasher, &var_len_bytes_vec);
        assert_eq!(encoded.value(), &expected);
    }
}

fn build_and_verify_encode_fix_len_bytes_vec(
    inputs: Vec<Vec<u8>>,
    ctx: &mut Context<Fr>,
    gate_chip: &impl GateInstructions<Fr>,
) {
    let mut hasher = create_hasher();
    hasher.initialize_consts(ctx, gate_chip);

    for input in inputs {
        let expected = encode_native_input::<Fr>(&input);
        let len = input.len();
        let witnesses_val = input.into_iter().map(|b| Fr::from(b as u64)).collect_vec();
        let input_witnesses = ctx.assign_witnesses(witnesses_val);
        let fix_len_bytes_vec = SafeTypeChip::unsafe_to_fix_len_bytes_vec(input_witnesses, len);
        let encoded = encode_fix_len_bytes_vec(ctx, gate_chip, &hasher, &fix_len_bytes_vec);
        assert_eq!(encoded.value(), &expected);
    }
}

#[test]
fn mock_encode_var_len_bytes_vec() {
    let inputs = vec![
        (vec![], 1),
        (vec![], 136),
        ((1u8..135).collect_vec(), 136),
        ((1u8..135).collect_vec(), 134),
        ((1u8..135).collect_vec(), 137),
        ((1u8..135).collect_vec(), 272),
        ((1u8..135).collect_vec(), 136 * 3),
    ];
    base_test().k(18).lookup_bits(4).run(|ctx: &mut Context<Fr>, range_chip: &RangeChip<Fr>| {
        build_and_verify_encode_var_len_bytes_vec(inputs, ctx, range_chip);
    })
}

#[test]
fn prove_encode_var_len_bytes_vec() {
    let init_inputs = vec![
        (vec![], 1),
        (vec![], 136),
        (vec![], 136),
        (vec![], 137),
        (vec![], 272),
        (vec![], 136 * 3),
    ];
    let inputs = vec![
        (vec![], 1),
        (vec![], 136),
        ((1u8..135).collect_vec(), 136),
        ((1u8..135).collect_vec(), 137),
        ((1u8..135).collect_vec(), 272),
        ((1u8..135).collect_vec(), 136 * 3),
    ];
    base_test().k(18).lookup_bits(4).bench_builder(
        init_inputs,
        inputs,
        |core, range_chip, inputs| {
            let ctx = core.main();
            build_and_verify_encode_var_len_bytes_vec(inputs, ctx, range_chip);
        },
    );
}

#[test]
fn mock_encode_fix_len_bytes_vec() {
    let inputs =
        vec![vec![], (1u8..135).collect_vec(), (0u8..136).collect_vec(), (0u8..211).collect_vec()];
    base_test().k(18).lookup_bits(4).run(|ctx: &mut Context<Fr>, range_chip: &RangeChip<Fr>| {
        build_and_verify_encode_fix_len_bytes_vec(inputs, ctx, range_chip.gate());
    });
}

#[test]
fn prove_encode_fix_len_bytes_vec() {
    let init_inputs =
        vec![vec![], (2u8..136).collect_vec(), (1u8..137).collect_vec(), (2u8..213).collect_vec()];
    let inputs =
        vec![vec![], (1u8..135).collect_vec(), (0u8..136).collect_vec(), (0u8..211).collect_vec()];
    base_test().k(18).lookup_bits(4).bench_builder(
        init_inputs,
        inputs,
        |core, range_chip, inputs| {
            let ctx = core.main();
            build_and_verify_encode_fix_len_bytes_vec(inputs, ctx, range_chip.gate());
        },
    );
}
