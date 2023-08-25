use crate::{
    gates::range::{circuit::builder::RangeCircuitBuilder, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
    utils::{testing::base_test, BigPrimeField, ScalarField},
};
use pse_poseidon::Poseidon;
use rand::Rng;

#[derive(Clone)]
struct Payload<F: ScalarField> {
    // Represent value of a right-padded witness array with a variable length
    pub values: Vec<F>,
    // Length of `values`.
    pub len: usize,
}

// check if the results from hasher and native sponge are same.
fn hasher_compatiblity_verification<
    F: ScalarField,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
>(
    payloads: Vec<Payload<F>>,
) where
    F: BigPrimeField,
{
    let lookup_bits = 3;

    let mut builder = RangeCircuitBuilder::new(true).use_lookup_bits(lookup_bits);
    let range = builder.range_chip();
    let ctx = builder.main(0);

    // Construct in-circuit Poseidon hasher. Assuming SECURE_MDS = 0.
    let spec = OptimizedPoseidonSpec::<F, T, RATE>::new::<R_F, R_P, 0>();
    let mut hasher = PoseidonHasher::<F, T, RATE>::new(spec);
    hasher.initialize_consts(ctx, range.gate());

    for payload in payloads {
        // Construct native Poseidon sponge.
        let mut native_sponge = Poseidon::<F, T, RATE>::new(R_F, R_P);
        native_sponge.update(&payload.values[..payload.len]);
        let native_result = native_sponge.squeeze();
        let inputs = ctx.assign_witnesses(payload.values);
        let len = ctx.load_witness(F::from(payload.len as u64));
        let hasher_result = hasher.hash_var_len_array(ctx, &range, &inputs, len);
        // 0x1f0db93536afb96e038f897b4fb5548b6aa3144c46893a6459c4b847951a23b4
        assert_eq!(native_result, *hasher_result.value());
    }
}

fn random_payload<F: ScalarField>(max_len: usize, len: usize, max_value: usize) -> Payload<F> {
    assert!(len <= max_len);
    let mut rng = rand::thread_rng();
    let mut values = Vec::new();
    for _ in 0..max_len {
        values.push(F::from(rng.gen_range(0..=max_value) as u64));
    }
    Payload { values, len }
}

fn random_payload_without_len<F: ScalarField>(max_len: usize, max_value: usize) -> Payload<F> {
    let mut rng = rand::thread_rng();
    let mut values = Vec::new();
    for _ in 0..max_len {
        values.push(F::from(rng.gen_range(0..=max_value) as u64));
    }
    Payload { values, len: rng.gen_range(0..=max_len) }
}

#[test]
fn test_poseidon_hasher_compatiblity() {
    {
        const T: usize = 3;
        const RATE: usize = 2;
        let payloads = vec![
            // max_len = 0
            random_payload(0, 0, usize::MAX),
            // max_len % RATE == 0 && len = 0
            random_payload(RATE * 2, 0, usize::MAX),
            // max_len % RATE == 0 && 0 < len < max_len && len % RATE == 0
            random_payload(RATE * 2, RATE, usize::MAX),
            // max_len % RATE == 0 && 0 < len < max_len && len % RATE != 0
            random_payload(RATE * 5, RATE * 2 + 1, usize::MAX),
            // max_len % RATE == 0 && len == max_len
            random_payload(RATE * 2, RATE * 2, usize::MAX),
            random_payload(RATE * 5, RATE * 5, usize::MAX),
            // len % RATE != 0 && len = 0
            random_payload(RATE * 2 + 1, 0, usize::MAX),
            random_payload(RATE * 5 + 1, 0, usize::MAX),
            // len % RATE != 0 && 0 < len < max_len && len % RATE == 0
            random_payload(RATE * 2 + 1, RATE, usize::MAX),
            // len % RATE != 0 && 0 < len < max_len && len % RATE != 0
            random_payload(RATE * 5 + 1, RATE * 2 + 1, usize::MAX),
            // len % RATE != 0 && len = max_len
            random_payload(RATE * 2 + 1, RATE * 2 + 1, usize::MAX),
            random_payload(RATE * 5 + 1, RATE * 5 + 1, usize::MAX),
        ];
        hasher_compatiblity_verification::<Fr, T, RATE, 8, 57>(payloads);
    }
}

#[test]
fn test_poseidon_hasher_with_prover() {
    {
        const T: usize = 3;
        const RATE: usize = 2;
        const R_F: usize = 8;
        const R_P: usize = 57;

        let max_lens = vec![0, RATE * 2, RATE * 5, RATE * 2 + 1, RATE * 5 + 1];
        for max_len in max_lens {
            let init_input = random_payload_without_len(max_len, usize::MAX);
            let logic_input = random_payload_without_len(max_len, usize::MAX);
            base_test().k(12).bench_builder(init_input, logic_input, |pool, range, payload| {
                let ctx = pool.main();
                // Construct in-circuit Poseidon hasher. Assuming SECURE_MDS = 0.
                let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
                let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
                hasher.initialize_consts(ctx, range.gate());
                let inputs = ctx.assign_witnesses(payload.values);
                let len = ctx.load_witness(Fr::from(payload.len as u64));
                hasher.hash_var_len_array(ctx, range, &inputs, len);
            });
        }
    }
}
