use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use super::*;
use crate::fields::FieldChip;
use crate::{fields::FpStrategy, halo2_proofs::halo2curves::bn256::G2Affine};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC},
    utils::fs::gen_srs,
    Context,
};
use rand_core::OsRng;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PairingCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn pairing_test<F: PrimeField>(
    ctx: &mut Context<F>,
    params: PairingCircuitParams,
    P: G1Affine,
    Q: G2Affine,
) {
    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let chip = PairingChip::new(&fp_chip);

    let P_assigned = chip.load_private_g1_unchecked(ctx, P);
    let Q_assigned = chip.load_private_g2_unchecked(ctx, Q);

    // test optimal ate pairing
    let f = chip.pairing(ctx, &Q_assigned, &P_assigned);

    let actual_f = pairing(&P, &Q);
    let fp12_chip = Fp12Chip::new(&fp_chip);
    // cannot directly compare f and actual_f because `Gt` has private field `Fq12`
    assert_eq!(
        format!("Gt({:?})", fp12_chip.get_assigned_value(&f.into())),
        format!("{actual_f:?}")
    );
}

fn random_pairing_circuit(
    params: PairingCircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let P = G1Affine::random(OsRng);
    let Q = G2Affine::random(OsRng);

    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    pairing_test::<Fr>(builder.main(0), params, P, Q);

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
fn test_pairing() {
    let path = "configs/bn254/pairing_circuit.config";
    let params: PairingCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_pairing_circuit(params, CircuitBuilderStage::Mock, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_pairing() -> Result<(), Box<dyn std::error::Error>> {
    let rng = OsRng;
    let config_path = "configs/bn254/bench_pairing.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/pairing_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: PairingCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);

        let params = gen_srs(k);
        let circuit = random_pairing_circuit(bench_params, CircuitBuilderStage::Keygen, None);

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
        let circuit =
            random_pairing_circuit(bench_params, CircuitBuilderStage::Prover, Some(break_points));
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
                "data/pairing_circuit_proof_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs
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
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
