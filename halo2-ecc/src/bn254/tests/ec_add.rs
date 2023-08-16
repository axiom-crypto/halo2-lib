use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};

use super::*;
use crate::fields::{FieldChip, FpStrategy};
use crate::group::cofactor::CofactorCurveAffine;
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::gates::builder::{GateThreadBuilder, RangeCircuitBuilder};
use halo2_base::gates::RangeChip;
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::BigPrimeField;
use halo2_base::Context;
use itertools::Itertools;
use rand_core::OsRng;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
    batch_size: usize,
}

fn g2_add_test<F: BigPrimeField>(
    ctx: &mut Context<F>,
    params: CircuitParams,
    _points: Vec<G2Affine>,
) {
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);

    let points =
        _points.iter().map(|pt| g2_chip.assign_point_unchecked(ctx, *pt)).collect::<Vec<_>>();

    let acc = g2_chip.sum::<G2Affine>(ctx, points);

    let answer = _points.iter().fold(G2Affine::identity(), |a, b| (a + b).to_affine());
    let x = fp2_chip.get_assigned_value(&acc.x.into());
    let y = fp2_chip.get_assigned_value(&acc.y.into());
    assert_eq!(answer.x, x);
    assert_eq!(answer.y, y);
}

#[test]
fn test_ec_add() {
    let path = "configs/bn254/ec_add_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let k = params.degree;
    let points = (0..params.batch_size).map(|_| G2Affine::random(OsRng)).collect_vec();

    let mut builder = GateThreadBuilder::<Fr>::mock();
    g2_add_test(builder.main(0), params, points);

    let mut config_params = builder.config(k as usize, Some(20));
    config_params.lookup_bits = Some(params.lookup_bits);
    let circuit = RangeCircuitBuilder::mock(builder, config_params);
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn bench_ec_add() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "configs/bn254/bench_ec_add.config";
    let bench_params_file =
        File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
    fs::create_dir_all("results/bn254").unwrap();

    let results_path = "results/bn254/ec_add_bench.csv";
    let mut fs_results = File::create(results_path).unwrap();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,batch_size,proof_time,proof_size,verify_time")?;
    fs::create_dir_all("data").unwrap();

    let bench_params_reader = BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        let k = bench_params.degree;
        println!("---------------------- degree = {k} ------------------------------",);
        let mut rng = OsRng;

        let params_time = start_timer!(|| "Params construction");
        let params = gen_srs(k);
        end_timer!(params_time);

        let start0 = start_timer!(|| "Witness generation for empty circuit");
        let circuit = {
            let points = vec![G2Affine::generator(); bench_params.batch_size];
            let mut builder = GateThreadBuilder::<Fr>::keygen();
            g2_add_test(builder.main(0), bench_params, points);
            let mut cp = builder.config(k as usize, Some(20));
            cp.lookup_bits = Some(bench_params.lookup_bits);
            RangeCircuitBuilder::keygen(builder, cp)
        };
        end_timer!(start0);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);
        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let cp = circuit.0.config_params.clone();
        let break_points = circuit.0.break_points.take();
        drop(circuit);

        // create a proof
        let points = (0..bench_params.batch_size).map(|_| G2Affine::random(&mut rng)).collect_vec();
        let proof_time = start_timer!(|| "Proving time");
        let proof_circuit = {
            let mut builder = GateThreadBuilder::<Fr>::prover();
            g2_add_test(builder.main(0), bench_params, points);
            RangeCircuitBuilder::prover(builder, cp, break_points)
        };
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            let path = format!(
                "data/ec_add_circuit_proof_{}_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs,
                bench_params.batch_size,
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
            "{},{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            bench_params.batch_size,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
