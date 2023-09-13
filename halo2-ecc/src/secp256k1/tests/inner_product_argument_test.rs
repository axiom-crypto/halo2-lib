#![allow(non_snake_case)]
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
};
use crate::secp256k1::{FpChip, FqChip};
use crate::{
    ecc::inner_product_argument::inner_product_argument,
    ecc::EccChip,
    fields::{FieldChip, PrimeField},
};
use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::{
    CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};

use group::cofactor::CofactorCurveAffine;
use halo2_base::gates::RangeChip;
use halo2_base::Context;
use rand_core::OsRng;
use std::fs::File;

use super::CircuitParams;

fn inner_product(a: Vec<Fq>, b: Vec<Fq>) -> Fq {
    assert_eq!(a.len(), b.len());
    let a_b = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a * b)
        .fold(<Secp256k1Affine as CurveAffine>::ScalarExt::zero(), |acc, x| acc + x);
    a_b
}

fn multi_scalar_multiply(
    a: impl IntoIterator<Item = Fq>,
    G: Vec<Secp256k1Affine>,
) -> Secp256k1Affine {
    let a_G = G
        .iter()
        .zip(a.into_iter())
        .map(|(g, a)| Secp256k1Affine::from(g * a))
        .fold(Secp256k1Affine::identity(), |acc, x| Secp256k1Affine::from(acc + x));
    a_G
}

fn random_inputs_ipa_prover_output(
    k: usize,
) -> (
    Fq,
    Fq,
    Vec<Secp256k1Affine>,
    Vec<Secp256k1Affine>,
    Secp256k1Affine,
    Secp256k1Affine,
    Vec<Secp256k1Affine>,
    Vec<Secp256k1Affine>,
    Vec<Fq>,
) {
    // generate random inputs
    let mut G = (0..2 ^ k)
        .map(|_| {
            Secp256k1Affine::from(
                Secp256k1Affine::generator()
                    * <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng),
            )
        })
        .collect::<Vec<_>>();
    let G_origin = G.clone();

    let mut H = (0..2 ^ k)
        .map(|_| {
            Secp256k1Affine::from(
                Secp256k1Affine::generator()
                    * <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng),
            )
        })
        .collect::<Vec<_>>();
    let H_origin = H.clone();

    let Q = Secp256k1Affine::from(
        Secp256k1Affine::generator() * <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng),
    );

    let mut a = (0..2 ^ k)
        .map(|_| <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng))
        .collect::<Vec<_>>();

    let mut b = (0..2 ^ k)
        .map(|_| <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng))
        .collect::<Vec<_>>();

    let u = (0..k)
        .map(|_| <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng))
        .collect::<Vec<_>>();

    // P = <a, G> + <b, H> + <a, b> Q
    let a_G = multi_scalar_multiply(a.clone(), G.clone());

    let b_H = multi_scalar_multiply(b.clone(), H.clone());

    let a_b = inner_product(a.clone(), b.clone());

    let P = Secp256k1Affine::from(a_G + b_H + (Q * a_b));

    // IPA proof generation
    let mut L_vec = Vec::with_capacity(k);
    let mut R_vec = Vec::with_capacity(k);

    for j in 0..k {
        let n = a.len() / 2;
        let (a_L, a_R) = a.split_at_mut(n);
        let (b_L, b_R) = b.split_at_mut(n);
        let (G_L, G_R) = G.split_at_mut(n);
        let (H_L, H_R) = H.split_at_mut(n);
        let L_j = Secp256k1Affine::from(
            multi_scalar_multiply(a_L.to_owned(), G_R.to_owned())
                + multi_scalar_multiply(b_R.to_owned(), H_L.to_owned())
                + (Q * inner_product(a_L.to_owned(), b_R.to_owned())),
        );
        let R_j = Secp256k1Affine::from(
            multi_scalar_multiply(a_R.to_owned(), G_L.to_owned())
                + multi_scalar_multiply(b_L.to_owned(), H_R.to_owned())
                + (Q * inner_product(a_R.to_owned(), b_L.to_owned())),
        );
        L_vec.push(L_j);
        R_vec.push(R_j);

        // a = a_L * u_j + u_j^-1 * a_R
        a = a_L
            .iter_mut()
            .zip(a_R.iter_mut())
            .map(|(a_L, a_R)| {
                let a_L = *a_L;
                let a_R = *a_R;
                let u_j = u.get(j).unwrap();
                let u_j_inv = u_j.invert().unwrap();
                a_L * u_j + a_R * u_j_inv
            })
            .collect::<Vec<_>>();

        // b = b_L * u_j^-1 + u_j * b_R
        b = b_L
            .iter_mut()
            .zip(b_R.iter_mut())
            .map(|(b_L, b_R)| {
                let b_L = *b_L;
                let b_R = *b_R;
                let u_j = u.get(j).unwrap();
                let u_j_inv = u_j.invert().unwrap();
                b_L * u_j_inv + b_R * u_j
            })
            .collect::<Vec<_>>();

        // G = G_L * u_j^-1 + u_j * G_R
        G = G_L
            .iter_mut()
            .zip(G_R.iter_mut())
            .map(|(G_L, G_R)| {
                let G_L = *G_L;
                let G_R = *G_R;
                let u_j = u.get(j).unwrap();
                let u_j_inv = u_j.invert().unwrap();
                Secp256k1Affine::from(G_L * u_j_inv + G_R * u_j)
            })
            .collect::<Vec<_>>();
        // H = H_L * u_j + u_j^-1 * H_R
        H = H_L
            .iter_mut()
            .zip(H_R.iter_mut())
            .map(|(H_L, H_R)| {
                let H_L = *H_L;
                let H_R = *H_R;
                let u_j = u.get(j).unwrap();
                let u_j_inv = u_j.invert().unwrap();
                Secp256k1Affine::from(H_L * u_j + H_R * u_j_inv)
            })
            .collect::<Vec<_>>();
    }

    assert!(a.len() == 1);
    assert!(b.len() == 1);
    let a = a.get(0).unwrap();
    let b = b.get(0).unwrap();
    (*a, *b, G_origin, H_origin, Q, P, L_vec, R_vec, u)
}

fn ipa_test<F: PrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    a: Fq,
    b: Fq,
    G: Vec<Secp256k1Affine>,
    H: Vec<Secp256k1Affine>,
    Q: Secp256k1Affine,
    P: Secp256k1Affine,
    L: Vec<Secp256k1Affine>,
    R: Vec<Secp256k1Affine>,
    u: Vec<Fq>,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    let a = fq_chip.load_private(ctx, a);
    let b = fq_chip.load_private(ctx, b);
    let G = G.iter().map(|g| ecc_chip.assign_point(ctx, *g)).collect::<Vec<_>>();
    let H = H.iter().map(|h| ecc_chip.assign_point(ctx, *h)).collect::<Vec<_>>();
    let Q = ecc_chip.assign_point(ctx, Q);
    let P = ecc_chip.assign_point(ctx, P);
    let L = L.iter().map(|l| ecc_chip.assign_point(ctx, *l)).collect::<Vec<_>>();
    let R = R.iter().map(|r| ecc_chip.assign_point(ctx, *r)).collect::<Vec<_>>();
    let u = u.iter().map(|u| fq_chip.load_private(ctx, *u)).collect::<Vec<_>>();

    // test inner product argument proof verification
    let is_valid_ipa_proof = inner_product_argument::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, P, G, H, L, R, Q, u, a, b, 4,
    );
    assert_eq!(is_valid_ipa_proof.value(), &F::one());
}

fn ipa_circuit(
    a: Fq,
    b: Fq,
    G: Vec<Secp256k1Affine>,
    H: Vec<Secp256k1Affine>,
    Q: Secp256k1Affine,
    P: Secp256k1Affine,
    L: Vec<Secp256k1Affine>,
    R: Vec<Secp256k1Affine>,
    u: Vec<Fq>,
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
    ipa_test(builder.main(0), params, a, b, G, H, Q, P, L, R, u);

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
fn test_inner_product_argument_random_valid_inputs() {
    let path = "configs/secp256k1/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let (a, b, G, H, Q, P, L, R, u) = random_inputs_ipa_prover_output(4);

    let circuit = ipa_circuit(a, b, G, H, Q, P, L, R, u, params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
