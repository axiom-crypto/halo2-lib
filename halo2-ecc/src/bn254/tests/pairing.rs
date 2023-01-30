use std::{
    env::{set_var, var},
    fs::{self, File},
};

use super::*;
use crate::halo2_proofs::halo2curves::bn256::G2Affine;
use halo2_base::SKIP_FIRST_PASS;
use rand_core::OsRng;

#[derive(Serialize, Deserialize)]
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

#[derive(Default)]
struct PairingCircuit<F: PrimeField> {
    P: Option<G1Affine>,
    Q: Option<G2Affine>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for PairingCircuit<F> {
    type Config = FpChip<F>;
    type FloorPlanner = SimpleFloorPlanner; // V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let path = var("PAIRING_CONFIG")
            .unwrap_or_else(|_| "./src/bn254/configs/pairing_circuit.config".to_string());
        let params: PairingCircuitParams = serde_json::from_reader(
            File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        )
        .unwrap();

        PairingChip::<F>::configure(
            meta,
            params.strategy,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            0,
            params.degree as usize,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.range.load_lookup_table(&mut layouter)?;
        let chip = PairingChip::<F>::construct(&config);

        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "pairing",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = config.new_context(region);
                let ctx = &mut aux;

                let P_assigned =
                    chip.load_private_g1(ctx, self.P.map(Value::known).unwrap_or(Value::unknown()));
                let Q_assigned =
                    chip.load_private_g2(ctx, self.Q.map(Value::known).unwrap_or(Value::unknown()));

                /*
                // test miller loop without final exp
                {
                    let f = chip.miller_loop(ctx, &Q_assigned, &P_assigned)?;
                    for fc in &f.coeffs {
                        assert_eq!(fc.value, fc.truncation.to_bigint());
                    }
                    if self.P != None {
                        let actual_f = multi_miller_loop(&[(
                            &self.P.unwrap(),
                            &G2Prepared::from_affine(self.Q.unwrap()),
                        )]);
                        let f_val: Vec<String> =
                            f.coeffs.iter().map(|x| x.value.clone().unwrap().to_str_radix(16)).collect();
                        println!("single miller loop:");
                        println!("actual f: {:#?}", actual_f);
                        println!("circuit f: {:#?}", f_val);
                    }
                }
                */

                // test optimal ate pairing
                {
                    let f = chip.pairing(ctx, &Q_assigned, &P_assigned);
                    #[cfg(feature = "display")]
                    for fc in &f.coeffs {
                        assert_eq!(
                            value_to_option(fc.value.clone()),
                            value_to_option(fc.truncation.to_bigint(chip.fp_chip.limb_bits))
                        );
                    }
                    #[cfg(feature = "display")]
                    if self.P.is_some() {
                        let actual_f = pairing(&self.P.unwrap(), &self.Q.unwrap());
                        let f_val: Vec<String> = f
                            .coeffs
                            .iter()
                            .map(|x| value_to_option(x.value.clone()).unwrap().to_str_radix(16))
                            //.map(|x| x.to_bigint().clone().unwrap().to_str_radix(16))
                            .collect();
                        println!("optimal ate pairing:");
                        println!("actual f: {actual_f:#?}");
                        println!("circuit f: {f_val:#?}");
                    }
                }

                // IMPORTANT: this copies cells to the lookup advice column to perform range check lookups
                // This is not optional.
                config.finalize(ctx);

                #[cfg(feature = "display")]
                if self.P.is_some() {
                    ctx.print_stats(&["Range"]);
                }
                Ok(())
            },
        )
    }
}

#[test]
fn test_pairing() {
    let mut folder = std::path::PathBuf::new();
    folder.push("./src/bn254");
    folder.push("configs/pairing_circuit.config");
    set_var("PAIRING_CONFIG", &folder);
    let params_str = std::fs::read_to_string(folder.as_path())
        .expect("src/bn254/configs/pairing_circuit.config file should exist");
    let params: PairingCircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
    let k = params.degree;

    let mut rng = OsRng;

    let P = Some(G1Affine::random(&mut rng));
    let Q = Some(G2Affine::random(&mut rng));

    let circuit = PairingCircuit::<Fr> { P, Q, _marker: PhantomData };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn bench_pairing() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::BufRead;

    use crate::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};

    let mut rng = OsRng;

    let mut folder = std::path::PathBuf::new();
    folder.push("./src/bn254");

    folder.push("configs/bench_pairing.config");
    let bench_params_file = std::fs::File::open(folder.as_path())?;
    folder.pop();
    folder.pop();

    folder.push("results/pairing_bench.csv");
    let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    folder.pop();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,vk_size,proof_time,proof_size,verify_time")?;
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
        let bench_params: PairingCircuitParams =
            serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );

        {
            folder.pop();
            folder.push("configs/pairing_circuit.tmp.config");
            set_var("PAIRING_CONFIG", &folder);
            let mut f = std::fs::File::create(folder.as_path())?;
            write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
            folder.pop();
            folder.pop();
            folder.push("data");
        }
        let params_time = start_timer!(|| "Params construction");
        let params = {
            params_folder.push(format!("kzg_bn254_{}.srs", bench_params.degree));
            let fd = std::fs::File::open(params_folder.as_path());
            let params = if let Ok(mut f) = fd {
                println!("Found existing params file. Reading params...");
                ParamsKZG::<Bn256>::read(&mut f).unwrap()
            } else {
                println!("Creating new params file...");
                let mut f = std::fs::File::create(params_folder.as_path())?;
                let params = ParamsKZG::<Bn256>::setup(bench_params.degree, &mut rng);
                params.write(&mut f).unwrap();
                params
            };
            params_folder.pop();
            params
        };

        let circuit = PairingCircuit::<Fr>::default();
        end_timer!(params_time);

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        /*
        let vk_size = {
            folder.push(format!(
                "pairing_circuit_{}_{}_{}_{}_{}_{}_{}.vkey",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs
            ));
            let mut fd = std::fs::File::create(folder.as_path()).unwrap();
            folder.pop();
            vk.write(&mut fd).unwrap();
            fd.metadata().unwrap().len()
        };
        */

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let mut rng = OsRng;
        let P = Some(G1Affine::random(&mut rng));
        let Q = Some(G2Affine::random(&mut rng));
        let proof_circuit = PairingCircuit::<Fr> { P, Q, _marker: PhantomData };

        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            PairingCircuit<Fr>,
        >(&params, &pk, &[proof_circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            folder.push(format!(
                "pairing_circuit_proof_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs
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
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .is_ok());
        end_timer!(verify_time);
        fs::remove_file(var("PAIRING_CONFIG").unwrap())?;

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
