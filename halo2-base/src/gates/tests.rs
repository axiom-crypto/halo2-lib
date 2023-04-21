use super::{
    flex_gate::{FlexGateConfig, GateStrategy},
    range, GateInstructions, RangeInstructions,
};
use crate::halo2_proofs::{circuit::*, dev::MockProver, halo2curves::bn256::Fr, plonk::*};
use crate::{
    Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
    SKIP_FIRST_PASS,
};

#[derive(Default)]
struct MyCircuit<F> {
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
}

const NUM_ADVICE: usize = 2;

impl Circuit<Fr> for MyCircuit<Fr> {
    type Config = FlexGateConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        FlexGateConfig::configure(
            meta,
            GateStrategy::Vertical,
            &[NUM_ADVICE],
            1,
            0,
            6, /* params K */
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "gate",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.constants.clone(),
                    },
                );
                let ctx = &mut aux;

                let (a_cell, b_cell, c_cell) = {
                    let cells = config.assign_region_smart(
                        ctx,
                        vec![Witness(self.a), Witness(self.b), Witness(self.c)],
                        vec![],
                        vec![],
                        vec![],
                    );
                    (cells[0].clone(), cells[1].clone(), cells[2].clone())
                };

                // test add
                {
                    config.add(ctx, Existing(a_cell), Existing(b_cell));
                }

                // test sub
                {
                    config.sub(ctx, Existing(a_cell), Existing(b_cell));
                }

                // test multiply
                {
                    config.mul(ctx, Existing(c_cell), Existing(b_cell));
                }

                // test idx_to_indicator
                {
                    config.idx_to_indicator(ctx, Constant(Fr::from(3u64)), 4);
                }

                {
                    let bits = config.assign_witnesses(
                        ctx,
                        vec![Value::known(Fr::zero()), Value::known(Fr::one())],
                    );
                    config.bits_to_indicator(ctx, &bits);
                }

                #[cfg(feature = "display")]
                {
                    println!("total advice cells: {}", ctx.total_advice);
                    let const_rows = ctx.fixed_offset + 1;
                    println!("maximum rows used by a fixed column: {const_rows}");
                }

                Ok(())
            },
        )
    }
}

#[test]
fn test_gates() {
    let k = 6;
    let circuit = MyCircuit::<Fr> {
        a: Value::known(Fr::from(10u64)),
        b: Value::known(Fr::from(12u64)),
        c: Value::known(Fr::from(120u64)),
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
    // assert_eq!(prover.verify(), Ok(()));
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_gates() {
    let k = 5;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Gates Layout", ("sans-serif", 60)).unwrap();

    let circuit = MyCircuit::<Fr>::default();
    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}

#[derive(Default)]
struct RangeTestCircuit<F> {
    range_bits: usize,
    lt_bits: usize,
    a: Value<F>,
    b: Value<F>,
}

impl Circuit<Fr> for RangeTestCircuit<Fr> {
    type Config = range::RangeConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            range_bits: self.range_bits,
            lt_bits: self.lt_bits,
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        range::RangeConfig::configure(
            meta,
            range::RangeStrategy::Vertical,
            &[NUM_ADVICE],
            &[1],
            1,
            3,
            0,
            11, /* params K */
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.load_lookup_table(&mut layouter)?;

        /*
        // let's try a separate layouter for loading private inputs
        let (a, b) = layouter.assign_region(
            || "load private inputs",
            |region| {
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("default".to_string(), NUM_ADVICE)],
                        fixed_columns: config.gate.constants.clone(),
                    },
                );
                let cells = config.gate.assign_region_smart(
                    &mut aux,
                    vec![Witness(self.a), Witness(self.b)],
                    vec![],
                    vec![],
                    vec![],
                )?;
                Ok((cells[0].clone(), cells[1].clone()))
            },
        )?; */

        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "range",
            |region| {
                // If we uncomment out the line below, get_shape will be empty and the layouter will try to assign at row 0, but "load private inputs" has already assigned to row 0, so this will panic and fail

                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = Context::new(
                    region,
                    ContextParams {
                        max_rows: config.gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.gate.constants.clone(),
                    },
                );
                let ctx = &mut aux;

                let (a, b) = {
                    let cells = config.gate.assign_region_smart(
                        ctx,
                        vec![Witness(self.a), Witness(self.b)],
                        vec![],
                        vec![],
                        vec![],
                    );
                    (cells[0].clone(), cells[1].clone())
                };

                {
                    config.range_check(ctx, &a, self.range_bits);
                }
                {
                    config.check_less_than(ctx, Existing(a), Existing(b), self.lt_bits);
                }
                {
                    config.is_less_than(ctx, Existing(a), Existing(b), self.lt_bits);
                }
                {
                    config.is_less_than(ctx, Existing(b), Existing(a), self.lt_bits);
                }
                {
                    config.gate().is_equal(ctx, Existing(b), Existing(a));
                }
                {
                    config.gate().is_zero(ctx, &a);
                }

                config.finalize(ctx);

                #[cfg(feature = "display")]
                {
                    println!("total advice cells: {}", ctx.total_advice);
                    let const_rows = ctx.fixed_offset + 1;
                    println!("maximum rows used by a fixed column: {const_rows}");
                    println!("lookup cells used: {}", ctx.cells_to_lookup.len());
                }
                Ok(())
            },
        )
    }
}

#[test]
fn test_range() {
    let k = 11;
    let circuit = RangeTestCircuit::<Fr> {
        range_bits: 8,
        lt_bits: 8,
        a: Value::known(Fr::from(100u64)),
        b: Value::known(Fr::from(101u64)),
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
    //assert_eq!(prover.verify(), Ok(()));
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_range() {
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Range Layout", ("sans-serif", 60)).unwrap();

    let circuit = RangeTestCircuit::<Fr> {
        range_bits: 8,
        lt_bits: 8,
        a: Value::unknown(),
        b: Value::unknown(),
    };

    halo2_proofs::dev::CircuitLayout::default().render(7, &circuit, &root).unwrap();
}

mod lagrange {
    use crate::halo2_proofs::{
        arithmetic::Field,
        halo2curves::bn256::{Bn256, G1Affine},
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use ark_std::{end_timer, start_timer};
    use rand::rngs::OsRng;

    use super::*;

    #[derive(Default)]
    struct MyCircuit<F> {
        coords: Vec<Value<(F, F)>>,
        a: Value<F>,
    }

    const NUM_ADVICE: usize = 6;

    impl Circuit<Fr> for MyCircuit<Fr> {
        type Config = FlexGateConfig<Fr>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                coords: self.coords.iter().map(|_| Value::unknown()).collect(),
                a: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            FlexGateConfig::configure(meta, GateStrategy::PlonkPlus, &[NUM_ADVICE], 1, 0, 14)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let mut first_pass = SKIP_FIRST_PASS;

            layouter.assign_region(
                || "gate",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: config.max_rows,
                            num_context_ids: 1,
                            fixed_columns: config.constants.clone(),
                        },
                    );
                    let ctx = &mut aux;

                    let x =
                        config.assign_witnesses(ctx, self.coords.iter().map(|c| c.map(|c| c.0)));
                    let y =
                        config.assign_witnesses(ctx, self.coords.iter().map(|c| c.map(|c| c.1)));

                    let a = config.assign_witnesses(ctx, vec![self.a]).pop().unwrap();

                    config.lagrange_and_eval(
                        ctx,
                        &x.into_iter().zip(y.into_iter()).collect::<Vec<_>>(),
                        a,
                    );

                    #[cfg(feature = "display")]
                    {
                        println!("total advice cells: {}", ctx.total_advice);
                    }

                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_lagrange() -> Result<(), Box<dyn std::error::Error>> {
        let k = 14;
        let mut rng = OsRng;
        let circuit = MyCircuit::<Fr> {
            coords: (0..100)
                .map(|i: u64| Value::known((Fr::from(i), Fr::random(&mut rng))))
                .collect(),
            a: Value::known(Fr::from(100u64)),
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();

        let fd = std::fs::File::open(format!("../halo2_ecc/params/kzg_bn254_{k}.srs").as_str());
        let params = if let Ok(mut f) = fd {
            println!("Found existing params file. Reading params...");
            ParamsKZG::<Bn256>::read(&mut f).unwrap()
        } else {
            ParamsKZG::<Bn256>::setup(k, &mut rng)
        };

        let vk_time = start_timer!(|| "Generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        let pk_time = start_timer!(|| "Generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

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
        >(&params, &pk, &[circuit], &[&[]], rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

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

        Ok(())
    }
}
