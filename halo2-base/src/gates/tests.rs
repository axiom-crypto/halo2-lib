use std::cell::RefCell;
use std::rc::Rc;

use super::flex_gate::{FlexGateConfig, GateChip, GateInstructions, GateStrategy, MAX_PHASE};
use super::{
    assign_threads_in, FlexGateConfigParams, GateThreadBuilder, MultiPhaseThreadBreakPoints,
    ThreadBreakPoints,
};
use crate::halo2_proofs::{circuit::*, dev::MockProver, halo2curves::bn256::Fr, plonk::*};
use crate::utils::ScalarField;
use crate::{
    Context,
    QuantumCell::{Constant, Existing, Witness},
    SKIP_FIRST_PASS,
};

struct MyCircuit<F: ScalarField> {
    inputs: [F; 3],
    builder: RefCell<GateThreadBuilder<F>>, // trick `synthesize` to take ownership of `builder`
    break_points: RefCell<MultiPhaseThreadBreakPoints>,
}

impl<F: ScalarField> Circuit<F> for MyCircuit<F> {
    type Config = FlexGateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> FlexGateConfig<F> {
        let FlexGateConfigParams {
            strategy,
            num_advice_per_phase,
            num_lookup_advice_per_phase: _,
            num_fixed,
            k,
        } = serde_json::from_str(&std::env::var("FLEX_GATE_CONFIG_PARAMS").unwrap()).unwrap();
        FlexGateConfig::configure(meta, strategy, &num_advice_per_phase, num_fixed, k)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "gate",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let builder = self.builder.take();
                if !builder.witness_gen_only {
                    *self.break_points.borrow_mut() = builder.assign_all(&config, &[], &mut region);
                } else {
                    // only test first phase for now
                    let mut threads = builder.threads.into_iter();
                    assign_threads_in(
                        0,
                        threads.next().unwrap(),
                        &config,
                        &[],
                        &mut region,
                        self.break_points.borrow()[0].clone(),
                    )
                }

                Ok(())
            },
        )
    }
}

fn gate_tests<F: ScalarField>(ctx: &mut Context<F>, inputs: [F; 3]) {
    let [a, b, c]: [_; 3] = ctx.assign_witnesses(inputs).try_into().unwrap();
    let chip = GateChip::default();

    // test add
    chip.add(ctx, a, b);

    // test sub
    chip.sub(ctx, a, b);

    // test multiply
    chip.mul(ctx, c, b);

    // test idx_to_indicator
    chip.idx_to_indicator(ctx, Constant(F::from(3u64)), 4);

    let bits = ctx.assign_witnesses([F::zero(), F::one()]);
    chip.bits_to_indicator(ctx, &bits);
}

#[test]
fn test_gates() {
    let k = 6;
    let inputs = [10u64, 12u64, 120u64].map(Fr::from);
    let mut builder = GateThreadBuilder::new(false);
    gate_tests(builder.main(0), inputs);

    // auto-tune circuit
    builder.config(k, Some(9));
    // create circuit
    let circuit =
        MyCircuit { inputs, builder: RefCell::new(builder), break_points: RefCell::default() };

    MockProver::run(k as u32, &circuit, vec![]).unwrap().assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_gates() {
    let k = 5;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Gates Layout", ("sans-serif", 60)).unwrap();

    let inputs = [Fr::zero(); 3];
    let builder = GateThreadBuilder::new(false);
    gate_tests(builder.main(0), inputs);

    // auto-tune circuit
    builder.config(k);
    // create circuit
    let circuit = MyCircuit {
        inputs,
        builder: RefCell::new(builder.unknown(true)),
        break_points: RefCell::default(),
    };
    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}

/*
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
                    config.check_less_than(ctx, Existing(&a), Existing(&b), self.lt_bits);
                }
                {
                    config.is_less_than(ctx, Existing(&a), Existing(&b), self.lt_bits);
                }
                {
                    config.is_less_than(ctx, Existing(&b), Existing(&a), self.lt_bits);
                }
                {
                    config.gate().is_equal(ctx, Existing(&b), Existing(&a));
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
                        &a,
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
*/
