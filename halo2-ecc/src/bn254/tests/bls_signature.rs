use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use super::*;
use crate::{fields::FpStrategy, halo2_proofs::halo2curves::bn256::G2Affine};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::{
        halo2curves::{
            bn256::{multi_miller_loop, G2Prepared, Gt},
            pairing::MillerLoopResult,
        },
        poly::kzg::multiopen::{ProverGWC, VerifierGWC},
    },
    utils::fs::gen_srs,
    Context,
};
use rand_core::OsRng;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct BlsSignatureCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    num_aggregation: u32,
}

/// Verify e(g1, signature_agg) = e(pubkey_agg, H(m))
fn bls_signature_test<F: PrimeField>(
    ctx: &mut Context<F>,
    params: BlsSignatureCircuitParams,
    g1: G1Affine,
    signatures: &[G2Affine],
    pubkeys: &[G1Affine],
    msghash: G2Affine,
) {
    // Calculate halo2 pairing by multipairing
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let pairing_chip = PairingChip::new(&fp_chip);
    let bls_signature_chip = BlsSignatureChip::new(&fp_chip, &pairing_chip);
    let result = bls_signature_chip.bls_signature_verify(ctx, g1, signatures, pubkeys, msghash);

    // Calculate non-halo2 pairing by multipairing
    let signature_g2_prepared = G2Prepared::from(signatures.iter().sum::<G2Affine>());
    let pubkey_aggregated = pubkeys.iter().sum::<G1Affine>();
    let hash_m_prepared = G2Prepared::from(-msghash);
    let actual_result =
        multi_miller_loop(&[(&g1, &signature_g2_prepared), (&pubkey_aggregated, &hash_m_prepared)])
            .final_exponentiation();

    // Compare the 2 results
    assert_eq!(*result.value(), F::from(actual_result == Gt::identity()))
}

fn random_bls_signature_circuit(
    params: BlsSignatureCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    assert!(params.num_aggregation > 0, "Cannot aggregate 0 signatures!");

    // TODO: Implement hash_to_curve(msg) for arbitrary message
    let msg_hash = G2Affine::random(OsRng);
    let g1 = G1Affine::generator();

    let mut sks: Vec<Fr> = Vec::new();
    let mut signatures: Vec<G2Affine> = Vec::new();
    let mut pubkeys: Vec<G1Affine> = Vec::new();

    for _ in 0..params.num_aggregation {
        let sk = Fr::random(OsRng);
        let signature = G2Affine::from(msg_hash * sk);
        let pubkey = G1Affine::from(G1Affine::generator() * sk);

        sks.push(sk);
        signatures.push(signature);
        pubkeys.push(pubkey);
    }

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    bls_signature_test::<Fr>(builder.main(0), params, g1, &signatures, &pubkeys, msg_hash);

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
fn test_bls_signature() {
    let run_path = "configs/bn254/bls_signature_circuit.config";
    let path = run_path;
    let params: BlsSignatureCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    println!("num_advice: {num_advice}", num_advice = params.num_advice);
    let circuit = random_bls_signature_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_bls_signature() -> Result<(), Box<dyn std::error::Error>> {
    let rng = OsRng;
    let config_path = "configs/bn254/bench_bls_signature.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/bls_signature_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,num_aggregation,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: BlsSignatureCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let params = gen_srs(k);
        let circuit = random_bls_signature_circuit(bench_params, CircuitBuilderStage::Keygen, None);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let break_points = circuit.0.break_points.take();
        drop(circuit);
        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let circuit = random_bls_signature_circuit(
            bench_params,
            CircuitBuilderStage::Prover,
            Some(break_points),
        );
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            let path = format!(
                "data/bls_signature_bn254_circuit_proof_{}_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs,
                bench_params.num_aggregation
            );
            let mut fd = File::create(&path)?;
            fd.write_all(&proof)?;
            let size = fd.metadata().unwrap().len();
            fs::remove_file(path)?;
            size
        };

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

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.num_aggregation,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
