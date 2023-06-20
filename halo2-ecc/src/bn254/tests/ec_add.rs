use std::env::set_var;
use std::fs;
use std::{env::var, fs::File};

use super::*;
use crate::fields::FieldChip;
use crate::halo2_proofs::halo2curves::{bn256::G2Affine, FieldExt};
use group::cofactor::CofactorCurveAffine;
use halo2_base::SKIP_FIRST_PASS;
use rand_core::OsRng;

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Clone, Debug)]
struct Config<F: PrimeField> {
    fp_chip: FpChip<F>,
    batch_size: usize,
}

impl<F: PrimeField> Config<F> {
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
        Self { fp_chip, batch_size }
    }
}

struct EcAddCircuit<F: PrimeField> {
    points: Vec<Option<G2Affine>>,
    batch_size: usize,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Default for EcAddCircuit<F> {
    fn default() -> Self {
        Self { points: vec![None; 100], batch_size: 100, _marker: PhantomData }
    }
}

impl Circuit<Fr> for EcAddCircuit<Fr> {
    type Config = Config<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            points: vec![None; self.batch_size],
            batch_size: self.batch_size,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = var("EC_ADD_CONFIG")
            .unwrap_or_else(|_| "./src/bn254/configs/ec_add_circuit.config".to_string());
        let params: CircuitParams = serde_json::from_reader(
            File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        )
        .unwrap();

        Config::<Fr>::configure(
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
            0,
            params.degree as usize,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        assert_eq!(config.batch_size, self.points.len());

        config.fp_chip.load_lookup_table(&mut layouter)?;
        let fp2_chip = Fp2Chip::<Fr>::construct(config.fp_chip.clone());
        let g2_chip = EccChip::construct(fp2_chip.clone());

        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "G2 add",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let mut aux = config.fp_chip.new_context(region);
                let ctx = &mut aux;

                let display = self.points[0].is_some();
                let points = self
                    .points
                    .iter()
                    .cloned()
                    .map(|pt| {
                        g2_chip.assign_point(ctx, pt.map(Value::known).unwrap_or(Value::unknown()))
                    })
                    .collect::<Vec<_>>();

                let acc = g2_chip.sum::<G2Affine>(ctx, points.iter().cloned());

                #[cfg(feature = "display")]
                if display {
                    let answer = self
                        .points
                        .iter()
                        .fold(G2Affine::identity(), |a, b| (a + b.unwrap()).to_affine());
                    let x = fp2_chip.get_assigned_value(&acc.x);
                    let y = fp2_chip.get_assigned_value(&acc.y);
                    x.map(|x| assert_eq!(answer.x, x));
                    y.map(|y| assert_eq!(answer.y, y));
                }

                config.fp_chip.finalize(ctx);

                #[cfg(feature = "display")]
                if display {
                    ctx.print_stats(&["Range"]);
                }
                Ok(())
            },
        )
    }
}

#[test]
fn test_ec_add() {
    let mut folder = std::path::PathBuf::new();
    folder.push("./src/bn254");
    folder.push("configs/ec_add_circuit.config");
    set_var("EC_ADD_CONFIG", &folder);
    let params_str = std::fs::read_to_string(folder.as_path())
        .unwrap_or_else(|_| panic!("{folder:?} file should exist"));
    let params: CircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
    let k = params.degree;

    let mut rng = OsRng;

    let mut points = Vec::new();
    for _ in 0..params.batch_size {
        let new_pt = Some(G2Affine::random(&mut rng));
        points.push(new_pt);
    }

    let circuit =
        EcAddCircuit::<Fr> { points, batch_size: params.batch_size, _marker: PhantomData };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn bench_ec_add() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::BufRead;

    let mut folder = std::path::PathBuf::new();
    folder.push("./src/bn254");

    folder.push("configs/bench_ec_add.config");
    let bench_params_file = std::fs::File::open(folder.as_path())?;
    folder.pop();
    folder.pop();

    folder.push("results/ec_add_bench.csv");
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
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );
        let mut rng = OsRng;

        {
            folder.pop();
            folder.push("configs/ec_add_circuit.tmp.config");
            set_var("EC_ADD_CONFIG", &folder);
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
        end_timer!(params_time);

        let circuit = EcAddCircuit::<Fr> {
            points: vec![None; bench_params.batch_size],
            batch_size: bench_params.batch_size,
            _marker: PhantomData,
        };

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        let mut points = Vec::new();
        for _ in 0..bench_params.batch_size {
            let new_pt = Some(G2Affine::random(&mut rng));
            points.push(new_pt);
        }

        let proof_circuit = EcAddCircuit::<Fr> {
            points,
            batch_size: bench_params.batch_size,
            _marker: PhantomData,
        };

        // create a proof
        let proof_time = start_timer!(|| "Proving time");
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
            folder.push(format!(
                "ec_add_circuit_proof_{}_{}_{}_{}_{}_{}_{}_{}.data",
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
        fs::remove_file(var("EC_ADD_CONFIG").unwrap())?;

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
