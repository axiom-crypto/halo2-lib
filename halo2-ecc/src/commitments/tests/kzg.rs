/*
 * Test suite for KZGChip.
 */
use std::fs::File;
use rand_core::OsRng;
use crate::{
    bn254::{pairing::PairingChip, Fp2Chip, FpChip, FrChip},
    commitments::{kzg::KZGChip, poly::PolyChip},
    ecc::EccChip,
    fields::{FpStrategy, FieldChip},
    halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G1, G2},
};
use halo2_base::{
    gates::{
        builder::{CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints, RangeCircuitBuilder},
        RangeChip,
    },
    halo2_proofs::{halo2curves::{bn256::G2Affine, FieldExt}, dev::MockProver},
};
use rand_core::{RngCore};
use serde::{Deserialize, Serialize};
use crate::commitments::utils::blob::{Blob, root_of_unity};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct KZGCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

/*
 * Assigns all input values for the KZGChip and proves multi-opens.
 */
fn kzg_multi_test(
    builder: &mut GateThreadBuilder<Fr>,
    params: KZGCircuitParams,
    q_bar: G1Affine,
    p_bar: G1Affine,
    ptau_g1: Vec<G1>,
    ptau_g2: Vec<G2>,
    z_coeffs: Vec<Fr>,
    r_coeffs: Vec<Fr>,
    open_idxs: Vec<Fr>,
    open_vals: Vec<Fr>
) {
    let ctx = builder.main(0);
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());

    // Initialize chips
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fr_chip = FrChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let g1_chip = EccChip::new(&fp_chip);
    let fp2_chip = Fp2Chip::<Fr>::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);
    let poly_chip = PolyChip::new(&fr_chip);

    // Load individual group elements
    let assigned_q_bar = g1_chip.assign_point(ctx, q_bar);
    let assigned_p_bar = g1_chip.assign_point(ctx, p_bar);

    // Load vectors
    let ptau_g1_loaded = 
        ptau_g1.iter().map(|x| g1_chip.assign_point(ctx, G1Affine::from(x))).collect::<Vec<_>>();
    let ptau_g2_loaded = 
        ptau_g2.iter().map(|x| g2_chip.assign_point(ctx, G2Affine::from(x))).collect::<Vec<_>>();

    let mut load_fr = |x: Vec<Fr>| x.into_iter().map(|c| fr_chip.load_private(ctx, c)).collect::<Vec<_>>();
    let open_idxs_loaded = load_fr(open_idxs);
    let open_vals_loaded = load_fr(open_vals);

    // Test chip
    let kzg_chip = KZGChip::new(&poly_chip, &pairing_chip, &g1_chip, &g2_chip);

    kzg_chip.opening_assert(
        builder,
        &ptau_g1_loaded[..],
        &ptau_g2_loaded[..],
        &open_idxs_loaded,
        &open_vals_loaded,
        assigned_p_bar,
        assigned_q_bar,
    );
}

/*
 * Commits to a random vector and proves a multi-open.
 */
fn random_kzg_multi_circuit(
    params: KZGCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let tau: Fr = Fr::from(111);
    let kzg_k: u32 = 2;
    let blob_len = 4;
    let openings: Vec<u64> = vec![2, 3];
    let n_openings = openings.len();
    let dummy_data: Vec<Fr> = (0..blob_len).map(|_| Fr::from(OsRng.next_u64())).collect();

    let pp = Blob::mock_trusted_setup(tau, blob_len, n_openings);
    let blob = Blob::new(dummy_data.clone(), pp.clone(), kzg_k);
    let p_bar = blob.commit_vector();
    let (q_bar, z_coeffs, r_coeffs) = blob.open_prf(&openings);
    
    let selected_root = root_of_unity(kzg_k as u32);

    kzg_multi_test(
        &mut builder,
        params,
        q_bar,
        p_bar,
        pp.ptau_g1[..n_openings].to_vec(),
        pp.ptau_g2[..=n_openings].to_vec(),
        z_coeffs,
        r_coeffs,
        openings.iter().map(|op| selected_root.pow(&[op.clone() as u64, 0, 0, 0])).collect(),
        openings.iter().map(|op| dummy_data[op.clone() as usize]).collect()
    );

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
    circuit
}

#[test]
fn test_kzg() {
    let path = "configs/commitments/kzg_circuit.config";
    let params: KZGCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_kzg_multi_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}
