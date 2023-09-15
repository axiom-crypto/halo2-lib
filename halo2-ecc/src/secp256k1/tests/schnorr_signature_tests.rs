use halo2_base::halo2_proofs::halo2curves::{secp256k1::Secp256k1Affine, CurveAffine};
use rand::{random, rngs::StdRng};
use rand_core::SeedableRng;
use test_case::test_case;

use super::schnorr_signature::{random_schnorr_signature_input, run_test, SchnorrInput};

fn custom_parameters_schnorr_signature(sk: u64, msg_hash: u64, k: u64) -> SchnorrInput {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::from(sk);
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::from(msg_hash);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::from(k);

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();

    let r = *x;
    let s = k + sk * msg_hash;

    SchnorrInput { r, s, msg_hash, pk }
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_schnorr_signature_msg_hash_zero() {
    let input = custom_parameters_schnorr_signature(random::<u64>(), 0, random::<u64>());
    run_test(input);
}

#[test]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_schnorr_signature_private_key_zero() {
    let input = custom_parameters_schnorr_signature(0, random::<u64>(), random::<u64>());
    run_test(input);
}

#[test_case(1, 1, 0; "")]
#[should_panic(expected = "assertion failed: `(left == right)`")]
fn test_schnorr_signature_k_zero(sk: u64, msg_hash: u64, k: u64) {
    let input = custom_parameters_schnorr_signature(sk, msg_hash, k);
    run_test(input);
}

#[test]
fn test_schnorr_signature_random_valid_inputs() {
    for i in 0..10 {
        let mut rng = StdRng::seed_from_u64(i);
        let input = random_schnorr_signature_input(&mut rng);
        println!("{:?}", input);
        run_test(input);
    }
}

#[test_case(1, 1, 1; "")]
fn test_schnorr_signature_custom_valid_inputs(sk: u64, msg_hash: u64, k: u64) {
    let input = custom_parameters_schnorr_signature(sk, msg_hash, k);
    run_test(input);
}
