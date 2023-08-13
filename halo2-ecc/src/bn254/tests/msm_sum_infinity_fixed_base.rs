use crate::ff::PrimeField;
use halo2_base::gates::{
    builder::{
        set_lookup_bits, CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
        RangeCircuitBuilder,
    },
    RangeChip,
};
use rand_core::OsRng;
use std::fs::File;

use super::*;

fn msm_test(
    builder: &mut GateThreadBuilder<Fr>,
    params: MSMCircuitParams,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
    window_bits: usize,
) {
    set_lookup_bits(params.lookup_bits);
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let ctx = builder.main(0);
    let scalars_assigned =
        scalars.iter().map(|scalar| vec![ctx.load_witness(*scalar)]).collect::<Vec<_>>();
    let bases_assigned = bases;
    //.iter()
    //.map(|base| ecc_chip.load_private_unchecked(ctx, (base.x, base.y)))
    //.collect::<Vec<_>>();

    let msm = ecc_chip.fixed_base_msm_in::<G1Affine>(
        builder,
        &bases_assigned,
        scalars_assigned,
        Fr::NUM_BITS as usize,
        window_bits,
        0,
    );

    let msm_answer = bases_assigned
        .iter()
        .zip(scalars.iter())
        .map(|(base, scalar)| base * scalar)
        .reduce(|a, b| a + b)
        .unwrap()
        .to_affine();

    let msm_x = msm.x.value();
    let msm_y = msm.y.value();
    assert_eq!(msm_x, fe_to_biguint(&msm_answer.x));
    assert_eq!(msm_y, fe_to_biguint(&msm_answer.y));
}

fn custom_msm_circuit(
    params: MSMCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    msm_test(&mut builder, params, bases, scalars, params.window_bits);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(k, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

#[test]
fn test_fb_msm1() {
    let path = "configs/bn254/msm_circuit.config";
    let mut params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    params.batch_size = 3;

    let random_point = G1Affine::random(OsRng);
    let bases = vec![random_point, random_point, random_point];
    let scalars = vec![Fr::one(), Fr::one(), -Fr::one() - Fr::one()];

    let circuit = custom_msm_circuit(params, CircuitBuilderStage::Mock, None, bases, scalars);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_fb_msm2() {
    let path = "configs/bn254/msm_circuit.config";
    let mut params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    params.batch_size = 3;

    let random_point = G1Affine::random(OsRng);
    let bases = vec![random_point, random_point, (random_point + random_point).to_affine()];
    let scalars = vec![Fr::one(), Fr::one(), -Fr::one()];

    let circuit = custom_msm_circuit(params, CircuitBuilderStage::Mock, None, bases, scalars);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_fb_msm3() {
    let path = "configs/bn254/msm_circuit.config";
    let mut params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    params.batch_size = 4;

    let random_point = G1Affine::random(OsRng);
    let bases = vec![
        random_point,
        random_point,
        random_point,
        (random_point + random_point + random_point).to_affine(),
    ];
    let scalars = vec![Fr::one(), Fr::one(), Fr::one(), -Fr::one()];

    let circuit = custom_msm_circuit(params, CircuitBuilderStage::Mock, None, bases, scalars);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_fb_msm4() {
    let path = "configs/bn254/msm_circuit.config";
    let mut params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    params.batch_size = 4;

    let generator_point = G1Affine::generator();
    let bases = vec![
        generator_point,
        generator_point,
        generator_point,
        (generator_point + generator_point + generator_point).to_affine(),
    ];
    let scalars = vec![Fr::one(), Fr::one(), Fr::one(), -Fr::one()];

    let circuit = custom_msm_circuit(params, CircuitBuilderStage::Mock, None, bases, scalars);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_fb_msm5() {
    // Very similar example that does not add to infinity. It works fine.
    let path = "configs/bn254/msm_circuit.config";
    let mut params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    params.batch_size = 4;

    let random_point = G1Affine::random(OsRng);
    let bases =
        vec![random_point, random_point, random_point, (random_point + random_point).to_affine()];
    let scalars = vec![-Fr::one(), -Fr::one(), Fr::one(), Fr::one()];

    let circuit = custom_msm_circuit(params, CircuitBuilderStage::Mock, None, bases, scalars);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
