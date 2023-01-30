use std::{env::var, fs::File};

#[allow(unused_imports)]
use crate::ecc::fixed_base::FixedEcPoint;

use super::*;
use halo2_base::{halo2_proofs::halo2curves::bn256::G1, SKIP_FIRST_PASS};

#[derive(Serialize, Deserialize, Debug)]
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
    radix: usize,
    clump_factor: usize,
}

#[derive(Clone, Debug)]
struct MSMConfig<F: PrimeField> {
    fp_chip: FpChip<F>,
    batch_size: usize,
    _radix: usize,
    _clump_factor: usize,
}

impl<F: PrimeField> MSMConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        strategy: FpStrategy,
        num_advice: &[usize],
        num_lookup_advice: &[usize],
        num_fixed: usize,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
        p: BigUint,
        batch_size: usize,
        _radix: usize,
        _clump_factor: usize,
        context_id: usize,
        k: usize,
    ) -> Self {
        let fp_chip = FpChip::<F>::configure(
            meta,
            strategy,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
            limb_bits,
            num_limbs,
            p,
            context_id,
            k,
        );
        MSMConfig { fp_chip, batch_size, _radix, _clump_factor }
    }
}

struct MSMCircuit<F: PrimeField> {
    bases: Vec<G1Affine>,
    scalars: Vec<Option<Fr>>,
    _marker: PhantomData<F>,
}

impl Circuit<Fr> for MSMCircuit<Fr> {
    type Config = MSMConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            bases: self.bases.clone(),
            scalars: vec![None; self.scalars.len()],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = var("FIXED_MSM_CONFIG")
            .unwrap_or_else(|_| "./src/bn254/configs/fixed_msm_circuit.config".to_string());
        let params: MSMCircuitParams = serde_json::from_reader(
            File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        )
        .unwrap();

        MSMConfig::<Fr>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            BigUint::from_str_radix(&Fq::MODULUS[2..], 16).unwrap(),
            params.batch_size,
            params.radix,
            params.clump_factor,
            0,
            params.degree as usize,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        assert_eq!(config.batch_size, self.scalars.len());
        assert_eq!(config.batch_size, self.bases.len());

        config.fp_chip.load_lookup_table(&mut layouter)?;

        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "fixed base msm",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let witness_time = start_timer!(|| "Witness generation");

                let mut aux = config.fp_chip.new_context(region);
                let ctx = &mut aux;

                let mut scalars_assigned = Vec::new();
                for scalar in &self.scalars {
                    let assignment = config
                        .fp_chip
                        .range
                        .gate
                        .assign_witnesses(ctx, vec![scalar.map_or(Value::unknown(), Value::known)]);
                    scalars_assigned.push(assignment);
                }

                let ecc_chip = EccChip::construct(config.fp_chip.clone());

                // baseline
                /*
                let msm = {
                    let sm = self.bases.iter().zip(scalars_assigned.iter()).map(|(base, scalar)|
                        ecc_chip.fixed_base_scalar_mult(ctx, &FixedEcPoint::<Fr, G1Affine>::from_g1(base, config.fp_chip.num_limbs, config.fp_chip.limb_bits), scalar, Fr::NUM_BITS as usize, 4)).collect::<Vec<_>>();
                    ecc_chip.sum::<G1Affine>(ctx, sm.iter())
                };
                */

                let msm = ecc_chip.fixed_base_msm::<G1Affine>(
                    ctx,
                    &self.bases,
                    &scalars_assigned,
                    Fr::NUM_BITS as usize,
                    config._radix,
                    config._clump_factor,
                );

                config.fp_chip.finalize(ctx);
                end_timer!(witness_time);

                #[cfg(feature = "display")]
                if self.scalars[0].is_some() {
                    let mut elts: Vec<G1> = Vec::new();
                    for (base, scalar) in self.bases.iter().zip(&self.scalars) {
                        elts.push(base * biguint_to_fe::<Fr>(&fe_to_biguint(&scalar.unwrap())));
                    }
                    let msm_answer = elts.into_iter().reduce(|a, b| a + b).unwrap().to_affine();

                    let msm_x = value_to_option(msm.x.value).unwrap();
                    let msm_y = value_to_option(msm.y.value).unwrap();
                    assert_eq!(msm_x, fe_to_biguint(&msm_answer.x).into());
                    assert_eq!(msm_y, fe_to_biguint(&msm_answer.y).into());
                }

                #[cfg(feature = "display")]
                if self.scalars[0].is_some() {
                    ctx.print_stats(&["Range"]);
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
#[test]
fn test_fixed_base_msm() {
    use std::env::set_var;

    use crate::halo2_proofs::arithmetic::Field;

    let mut folder = std::path::PathBuf::new();
    folder.push("./src/bn254");
    folder.push("configs/fixed_msm_circuit.config");
    set_var("FIXED_MSM_CONFIG", &folder);
    let params_str = std::fs::read_to_string(folder.as_path())
        .expect("src/bn254/configs/fixed_msm_circuit.config file should exist");
    let params: MSMCircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
    let k = params.degree;

    let mut rng = rand::thread_rng();

    let mut bases = Vec::new();
    let mut scalars = Vec::new();
    for _ in 0..params.batch_size {
        bases.push(G1Affine::random(&mut rng));

        let new_scalar = Some(Fr::random(&mut rng));
        scalars.push(new_scalar);
    }

    let circuit = MSMCircuit::<Fr> { bases, scalars, _marker: PhantomData };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[cfg(test)]
#[test]
fn bench_fixed_base_msm() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        env::{set_var, var},
        fs,
        io::BufRead,
    };

    use halo2_base::utils::fs::gen_srs;
    use rand_core::OsRng;

    let mut folder = std::path::PathBuf::new();
    folder.push("./src/bn254");

    folder.push("configs/bench_fixed_msm.config");
    let bench_params_file = std::fs::File::open(folder.as_path())?;
    folder.pop();
    folder.pop();

    folder.push("results/fixed_msm_bench.csv");
    let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    folder.pop();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,batch_size,proof_time,proof_size,verify_time")?;
    folder.push("data");
    if !folder.is_dir() {
        std::fs::create_dir(folder.as_path())?;
    }

    let mut params_folder = std::path::PathBuf::new();
    params_folder.push("./params");
    if !params_folder.is_dir() {
        std::fs::create_dir(params_folder.as_path())?;
    }

    let bench_params_reader = std::io::BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: MSMCircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );
        let mut rng = OsRng;

        {
            folder.pop();
            folder.push("configs/fixed_msm_circuit.tmp.config");
            set_var("FIXED_MSM_CONFIG", &folder);
            let mut f = std::fs::File::create(folder.as_path())?;
            write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
            folder.pop();
            folder.pop();
            folder.push("data");
        }
        let params = gen_srs(bench_params.degree);

        println!("{bench_params:?}");

        let mut bases = Vec::new();
        let mut scalars = Vec::new();
        for _idx in 0..bench_params.batch_size {
            bases.push(G1Affine::random(&mut rng));

            let new_scalar = Some(Fr::random(&mut rng));
            scalars.push(new_scalar);
        }
        let circuit =
            MSMCircuit::<Fr> { bases, scalars: vec![None; scalars.len()], _marker: PhantomData };

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let circuit = MSMCircuit::<Fr> { scalars, ..circuit };
        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            MSMCircuit<Fr>,
        >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            folder.push(format!(
                "msm_circuit_proof_{}_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs,
                bench_params.batch_size,
            ));
            let mut fd = std::fs::File::create(folder.as_path()).unwrap();
            folder.pop();
            fd.write_all(&proof).unwrap();
            fd.metadata().unwrap().len()
        };

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .is_ok());
        end_timer!(verify_time);
        fs::remove_file(var("FIXED_MSM_CONFIG").unwrap())?;

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
