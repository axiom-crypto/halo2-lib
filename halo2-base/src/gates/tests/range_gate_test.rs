use super::*;
use crate::{gates::{
    builder::{RangeCircuitBuilder,GateThreadBuilder},
    range::{RangeChip, RangeInstructions},
}, QuantumCell, utils::BigPrimeField};
use crate::halo2_proofs::dev::MockProver;
use crate::utils::ScalarField;
use crate::QuantumCell::Witness;
use num_bigint::BigUint;
use test_case::test_case;

#[test_case((Fr::from(100), 8); "range_check() pos")]
fn test_range_check<F: ScalarField>(inputs: (F, usize)) {
    std::env::set_var("LOOKUP_BITS", "3".to_string());
    let mut builder = GateThreadBuilder::mock();
    let ctx = builder.main(0);
    let chip = RangeChip::default(3);
    let a = ctx.assign_witnesses([inputs.0])[0]; 
    chip.range_check(ctx, a, inputs.1);
    // auto-tune circuit
    builder.config(11, Some(9));
    // create circuit
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(11 as u32, &circuit, vec![]).unwrap().assert_satisfied()
}