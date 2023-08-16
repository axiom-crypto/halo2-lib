use crate::ff::{Field, PrimeField};
use crate::fields::FpStrategy;
use halo2_base::gates::builder::BaseConfigParams;
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder, MultiPhaseThreadBreakPoints,
            RangeCircuitBuilder,
        },
        RangeChip,
    },
    utils::fs::gen_srs,
};
use rand_core::OsRng;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use super::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct MSMCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    batch_size: usize,
    window_bits: usize,
}

fn msm_test(
    builder: &mut GateThreadBuilder<Fr>,
    params: MSMCircuitParams,
    bases: Vec<G1Affine>,
    scalars: Vec<Fr>,
    window_bits: usize,
) {
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::new(&fp_chip);

    let ctx = builder.main(0);
    let scalars_assigned =
        scalars.iter().map(|scalar| vec![ctx.load_witness(*scalar)]).collect::<Vec<_>>();
    let bases_assigned = bases
        .iter()
        .map(|base| ecc_chip.load_private_unchecked(ctx, (base.x, base.y)))
        .collect::<Vec<_>>();

    let msm = ecc_chip.variable_base_msm_in::<G1Affine>(
        builder,
        &bases_assigned,
        scalars_assigned,
        Fr::NUM_BITS as usize,
        window_bits,
        0,
    );

    let msm_answer = bases
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

fn random_msm_circuit(
    params: MSMCircuitParams,
    stage: CircuitBuilderStage,
    config_params: Option<BaseConfigParams>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    let k = params.degree as usize;
    let mut builder = match stage {
        CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
        CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
        CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
    };

    let (bases, scalars): (Vec<_>, Vec<_>) =
        (0..params.batch_size).map(|_| (G1Affine::random(OsRng), Fr::random(OsRng))).unzip();
    let start0 = start_timer!(|| format!("Witness generation for circuit in {stage:?} stage"));
    msm_test(&mut builder, params, bases, scalars, params.window_bits);

    let mut config_params = config_params.unwrap_or_else(|| builder.config(k, Some(20)));
    config_params.lookup_bits = Some(params.lookup_bits);
    let circuit = match stage {
        CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder, config_params),
        CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder, config_params),
        CircuitBuilderStage::Prover => {
            RangeCircuitBuilder::prover(builder, config_params, break_points.unwrap())
        }
    };
    end_timer!(start0);
    circuit
}

#[test]
fn test_msm() {
    let path = "configs/bn254/msm_circuit.config";
    let params: MSMCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let circuit = random_msm_circuit(params, CircuitBuilderStage::Mock, None, None);
    MockProver::run(params.degree, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_msm() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_msm.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();
    fs::create_dir_all("data").unwrap();

    let results_path = "results/bn254/msm_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,batch_size,window_bits,proof_time,proof_size,verify_time")?;

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: MSMCircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);
        let rng = OsRng;

        let params = gen_srs(k);
        println!("{bench_params:?}");

        let circuit = random_msm_circuit(bench_params, CircuitBuilderStage::Keygen, None, None);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let config_params = circuit.0.config_params.clone();
        let break_points = circuit.0.break_points.take();
        drop(circuit);
        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let circuit = random_msm_circuit(
            bench_params,
            CircuitBuilderStage::Prover,
            Some(config_params),
            Some(break_points),
        );
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            let path = format!(
                "data/msm_circuit_proof_{}_{}_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs,
                bench_params.batch_size,
                bench_params.window_bits
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
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .unwrap();
        end_timer!(verify_time);

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.batch_size,
            bench_params.window_bits,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
