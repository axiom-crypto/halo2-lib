use crate::commitments::FrChip;
/*
 * Test suite for KZGChip.
 */
use crate::commitments::utils::blob::{root_of_unity, Blob};
use crate::fields::poly::PolyChip;
use crate::{
    bn254::{pairing::PairingChip, Fp2Chip, FpChip},
    commitments::kzg::KZGChip,
    ecc::EccChip,
    fields::{FieldChip, FpStrategy},
    halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G1, G2},
};
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::utils::fs::gen_srs;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::{
        dev::MockProver,
        halo2curves::{bn256::G2Affine, FieldExt},
    },
};
use rand_core::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::File;

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
    p_bar: G1Affine,
    open_idxs: Vec<Fr>,
    open_vals: Vec<Fr>,
    q_bar: G1Affine,
    ptau_g1: Vec<G1>,
    ptau_g2: Vec<G2>,
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

    let mut load_fr =
        |x: Vec<Fr>| x.into_iter().map(|c| fr_chip.load_private(ctx, c)).collect::<Vec<_>>();
    let open_idxs_loaded = load_fr(open_idxs);
    let open_vals_loaded = load_fr(open_vals);

    // Test chip
    let kzg_chip = KZGChip::new(&poly_chip, &pairing_chip, &g1_chip, &g2_chip);
    kzg_chip.opening_assert(
        builder,
        assigned_p_bar,
        &open_idxs_loaded,
        &open_vals_loaded,
        assigned_q_bar,
        &ptau_g1_loaded[..],
        &ptau_g2_loaded[..],
    );
}

/*
 * Commits to a random vector and proves a multi-open. blob_len must be a power
 * of 2. 
 */
fn random_kzg_multi_circuit(
    params: KZGCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    blob_len: usize,
    n_openings: usize
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let tau: Fr = Fr::from(111);
    let kzg_k: u32 = blob_len.ilog2();
    let openings: Vec<u64> = (0..n_openings as u64).collect();
    let dummy_data: Vec<Fr> = (0..blob_len).map(|_| Fr::from(OsRng.next_u64())).collect();

    println!("check 0");
    let pp = Blob::mock_trusted_setup(tau, blob_len, n_openings);
    println!("check 1");
    let blob = Blob::new(dummy_data.clone(), pp.clone(), kzg_k);
    println!("check 2");
    let p_bar = blob.commit_vector();
    println!("check 3");
    let q_bar = blob.open_prf(&openings);
    println!("check 4");

    let selected_root = root_of_unity(kzg_k as u32);
    let open_idxs =
        openings.iter().map(|op| selected_root.pow(&[op.clone() as u64, 0, 0, 0])).collect();
    let open_vals = openings.iter().map(|op| dummy_data[op.clone() as usize]).collect();

    kzg_multi_test(
        &mut builder,
        params,
        p_bar,
        open_idxs,
        open_vals,
        q_bar,
        pp.ptau_g1[..n_openings].to_vec(),
        pp.ptau_g2[..=n_openings].to_vec(),
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

    let circuit = random_kzg_multi_circuit(params, CircuitBuilderStage::Mock, None, 16, 4);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

/*
 * May need to increase thread stack size to run this test. Euclidean div has a 
 * deep recursion tree. Can do this by 
 * setting `RUST_MIN_STACK=104857600 cargo test ...`
 */ 
#[test]
fn bench_kzg() {
    let rng = OsRng;
    let path = "configs/commitments/kzg_circuit.config";
    let bench_params: KZGCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let k = bench_params.degree;
    let params = gen_srs(k);

    let circuit = random_kzg_multi_circuit(bench_params, CircuitBuilderStage::Mock, None, 4096, 64);

    let vk_time = start_timer!(|| "Generating vkey");
    let vk = keygen_vk(&params, &circuit).unwrap();
    end_timer!(vk_time);

    let pk_time = start_timer!(|| "Generating pkey");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    let proof_time = start_timer!(|| "Proving time");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)
    .unwrap();
    let proof = transcript.finalize();
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "Verify time");
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
    .unwrap();
    end_timer!(verify_time);
}
