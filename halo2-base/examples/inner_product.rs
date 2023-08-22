#![cfg(feature = "test-utils")]
use halo2_base::gates::flex_gate::{GateChip, GateInstructions};
use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
use halo2_base::safe_types::RangeInstructions;
use halo2_base::utils::testing::base_test;
use halo2_base::utils::ScalarField;
use halo2_base::{Context, QuantumCell::Existing};
use itertools::Itertools;
use rand::rngs::OsRng;

const K: u32 = 19;

fn inner_prod_bench<F: ScalarField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    a: Vec<F>,
    b: Vec<F>,
) {
    assert_eq!(a.len(), b.len());
    let a = ctx.assign_witnesses(a);
    let b = ctx.assign_witnesses(b);

    for _ in 0..(1 << K) / 16 - 10 {
        gate.inner_product(ctx, a.clone(), b.clone().into_iter().map(Existing));
    }
}

fn main() {
    base_test().k(12).bench_builder(
        (vec![Fr::ZERO; 5], vec![Fr::ZERO; 5]),
        (
            (0..5).map(|_| Fr::random(OsRng)).collect_vec(),
            (0..5).map(|_| Fr::random(OsRng)).collect_vec(),
        ),
        |builder, range, (a, b)| {
            inner_prod_bench(builder.main(0), range.gate(), a, b);
        },
    );
}
