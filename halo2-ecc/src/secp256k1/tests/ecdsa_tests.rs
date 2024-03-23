use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::secp256k1::{Fq, Secp256k1Affine},
};

use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
use rand::random;
use test_case::test_case;

use super::ecdsa::{run_test, ECDSAInput};

fn custom_parameters_ecdsa(sk: u64, msg_hash: u64, k: u64) -> ECDSAInput {
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

    ECDSAInput { r, s, msghash: msg_hash, pk: pubkey }
}

#[test]
#[should_panic(
    expected = "assertion `left == right` failed\n  left: 0x0000000000000000000000000000000000000000000000000000000000000000\n right: 0x0000000000000000000000000000000000000000000000000000000000000001"
)]
fn test_ecdsa_msg_hash_zero() {
    let input = custom_parameters_ecdsa(random::<u64>(), 0, random::<u64>());
    run_test(input);
}

#[test]
#[should_panic(
    expected = "assertion `left == right` failed\n  left: 0x0000000000000000000000000000000000000000000000000000000000000000\n right: 0x0000000000000000000000000000000000000000000000000000000000000001"
)]
fn test_ecdsa_private_key_zero() {
    let input = custom_parameters_ecdsa(0, random::<u64>(), random::<u64>());
    run_test(input);
}

#[test_case(1, 1, 1; "")]
fn test_ecdsa_custom_valid_inputs(sk: u64, msg_hash: u64, k: u64) {
    let input = custom_parameters_ecdsa(sk, msg_hash, k);
    run_test(input);
}

#[test_case(1, 1, 1; "")]
fn test_ecdsa_custom_valid_inputs_negative_s(sk: u64, msg_hash: u64, k: u64) {
    let mut input = custom_parameters_ecdsa(sk, msg_hash, k);
    input.s = -input.s;
    run_test(input);
}
