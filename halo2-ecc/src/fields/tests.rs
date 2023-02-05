mod fp {
    use crate::fields::{
        fp::{FpConfig, FpStrategy},
        FieldChip,
    };
    use crate::halo2_proofs::{
        circuit::*,
        dev::MockProver,
        halo2curves::bn256::{Fq, Fr},
        plonk::*,
    };
    use group::ff::Field;
    use halo2_base::{
        utils::{fe_to_biguint, modulus, PrimeField},
        SKIP_FIRST_PASS,
    };
    use num_bigint::BigInt;
    use rand::rngs::OsRng;
    use std::marker::PhantomData;

    #[derive(Default)]
    struct MyCircuit<F> {
        a: Value<Fq>,
        b: Value<Fq>,
        _marker: PhantomData<F>,
    }

    const NUM_ADVICE: usize = 1;
    const NUM_FIXED: usize = 1;
    const K: usize = 10;

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = FpConfig<F, Fq>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            FpConfig::<F, _>::configure(
                meta,
                FpStrategy::Simple,
                &[NUM_ADVICE],
                &[1],
                NUM_FIXED,
                9,
                88,
                3,
                modulus::<Fq>(),
                0,
                K,
            )
        }

        fn synthesize(
            &self,
            chip: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            chip.load_lookup_table(&mut layouter)?;

            let mut first_pass = SKIP_FIRST_PASS;

            layouter.assign_region(
                || "fp",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = chip.new_context(region);
                    let ctx = &mut aux;

                    let a_assigned =
                        chip.load_private(ctx, self.a.map(|a| BigInt::from(fe_to_biguint(&a))));
                    let b_assigned =
                        chip.load_private(ctx, self.b.map(|b| BigInt::from(fe_to_biguint(&b))));

                    // test fp_multiply
                    {
                        chip.mul(ctx, &a_assigned, &b_assigned);
                    }

                    // IMPORTANT: this copies advice cells to enable lookup
                    // This is not optional.
                    chip.finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        println!(
                            "Using {NUM_ADVICE} advice columns and {NUM_FIXED} fixed columns"
                        );
                        println!("total cells: {}", ctx.total_advice);

                        let (const_rows, _) = ctx.fixed_stats();
                        println!("maximum rows used by a fixed column: {const_rows}");
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_fp() {
        let a = Fq::random(OsRng);
        let b = Fq::random(OsRng);

        let circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let prover = MockProver::run(K as u32, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        //assert_eq!(prover.verify(), Ok(()));
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_fp() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

        let circuit = MyCircuit::<Fr>::default();
        halo2_proofs::dev::CircuitLayout::default().render(K as u32, &circuit, &root).unwrap();
    }
}

mod fp12 {
    use crate::fields::{
        fp::{FpConfig, FpStrategy},
        fp12::*,
        FieldChip,
    };
    use crate::halo2_proofs::{
        circuit::*,
        dev::MockProver,
        halo2curves::bn256::{Fq, Fq12, Fr},
        plonk::*,
    };
    use halo2_base::utils::modulus;
    use halo2_base::{utils::PrimeField, SKIP_FIRST_PASS};
    use std::marker::PhantomData;

    #[derive(Default)]
    struct MyCircuit<F> {
        a: Value<Fq12>,
        b: Value<Fq12>,
        _marker: PhantomData<F>,
    }

    const NUM_ADVICE: usize = 1;
    const NUM_FIXED: usize = 1;
    const XI_0: i64 = 9;

    impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
        type Config = FpConfig<F, Fq>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            FpConfig::<F, _>::configure(
                meta,
                FpStrategy::Simple,
                &[NUM_ADVICE],
                &[1],
                NUM_FIXED,
                22,
                88,
                3,
                modulus::<Fq>(),
                0,
                23,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.load_lookup_table(&mut layouter)?;
            let chip = Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::construct(&config);

            let mut first_pass = SKIP_FIRST_PASS;

            layouter.assign_region(
                || "fp12",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }

                    let mut aux = config.new_context(region);
                    let ctx = &mut aux;

                    let a_assigned = chip.load_private(
                        ctx,
                        Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::fe_to_witness(&self.a),
                    );
                    let b_assigned = chip.load_private(
                        ctx,
                        Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::fe_to_witness(&self.b),
                    );

                    // test fp_multiply
                    {
                        chip.mul(ctx, &a_assigned, &b_assigned);
                    }

                    // IMPORTANT: this copies advice cells to enable lookup
                    // This is not optional.
                    chip.fp_chip.finalize(ctx);

                    #[cfg(feature = "display")]
                    {
                        println!(
                            "Using {NUM_ADVICE} advice columns and {NUM_FIXED} fixed columns"
                        );
                        println!("total advice cells: {}", ctx.total_advice);

                        let (const_rows, _) = ctx.fixed_stats();
                        println!("maximum rows used by a fixed column: {const_rows}");
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_fp12() {
        let k = 23;
        let mut rng = rand::thread_rng();
        let a = Fq12::random(&mut rng);
        let b = Fq12::random(&mut rng);

        let circuit =
            MyCircuit::<Fr> { a: Value::known(a), b: Value::known(b), _marker: PhantomData };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
        // assert_eq!(prover.verify(), Ok(()));
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_fp12() {
        let k = 9;
        use plotters::prelude::*;

        let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Fp Layout", ("sans-serif", 60)).unwrap();

        let circuit = MyCircuit::<Fr>::default();
        halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
    }
}
