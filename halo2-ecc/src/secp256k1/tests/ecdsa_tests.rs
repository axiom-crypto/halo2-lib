#![allow(non_snake_case)]
use crate::ff::Field as _;
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
};
use crate::secp256k1::{FpChip, FqChip};
use crate::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::FieldChip,
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::{
        set_lookup_bits, CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
        RangeCircuitBuilder,
    },
    utils::BigPrimeField,
};

use halo2_base::gates::RangeChip;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
use halo2_base::Context;
use rand::random;
use rand_core::OsRng;
use std::fs::File;
use test_case::test_case;

use super::CircuitParams;

fn ecdsa_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    r: Fq,
    s: Fq,
    msghash: Fq,
    pk: Secp256k1Affine,
) {
    set_lookup_bits(params.lookup_bits);
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, r, s] = [msghash, r, s].map(|x| fq_chip.load_private(ctx, x));

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.assign_point(ctx, pk);
    // test ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    assert_eq!(res.value(), &F::ONE);
}

fn random_parameters_ecdsa() -> (Fq, Fq, Fq, Secp256k1Affine) {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);

    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msg_hash + (r * sk));

    (r, s, msg_hash, pubkey)
}

fn custom_parameters_ecdsa(sk: u64, msg_hash: u64, k: u64) -> (Fq, Fq, Fq, Secp256k1Affine) {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
    let pubkey = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::from(msg_hash);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::from(k);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);

    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msg_hash + (r * sk));

    (r, s, msg_hash, pubkey)
}

fn ecdsa_circuit(
    r: Fq,
    s: Fq,
    msg_hash: Fq,
    pubkey: Secp256k1Affine,
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };
    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    ecdsa_test(builder.main(0), params, r, s, msg_hash, pubkey);

    let circuit = match stage {
        CircuitBuilderStage::Mock => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::mock(builder)
        }
        CircuitBuilderStage::Keygen => {
            builder.config(params.degree as usize, Some(20));
            RangeCircuitBuilder::keygen(builder)
        }
        CircuitBuilderStage::Prover => RangeCircuitBuilder::prover(builder, break_points.unwrap()),
    };
    end_timer!(start0);
    circuit
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_ecdsa_msg_hash_zero() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = custom_parameters_ecdsa(random::<u64>(), 0, random::<u64>());

    let circuit = ecdsa_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_ecdsa_private_key_zero() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = custom_parameters_ecdsa(0, random::<u64>(), random::<u64>());

    let circuit = ecdsa_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_ecdsa_random_valid_inputs() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = random_parameters_ecdsa();

    let circuit = ecdsa_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test_case(1, 1, 1; "")]
fn test_ecdsa_custom_valid_inputs(sk: u64, msg_hash: u64, k: u64) {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = custom_parameters_ecdsa(sk, msg_hash, k);

    let circuit = ecdsa_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test_case(1, 1, 1; "")]
fn test_ecdsa_custom_valid_inputs_negative_s(sk: u64, msg_hash: u64, k: u64) {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (r, s, msg_hash, pubkey) = custom_parameters_ecdsa(sk, msg_hash, k);
    let s = -s;

    let circuit = ecdsa_circuit(r, s, msg_hash, pubkey, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
