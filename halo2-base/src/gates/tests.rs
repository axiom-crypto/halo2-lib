use super::{
    flex_gate::{FlexGateConfig, GateStrategy},
    range, GateInstructions, RangeInstructions,
};
use crate::{
    Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::*, dev::MockProver, halo2curves::bn256::Fr, plonk::*,
};

#[derive(Default)]
struct MyCircuit<F> {
    a: Value<F>,
    b: Value<F>,
    c: Value<F>,
}

const NUM_ADVICE: usize = 1;

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = FlexGateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        FlexGateConfig::configure(
            meta,
            GateStrategy::PlonkPlus,
            &[NUM_ADVICE],
            1,
            "default".to_string(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let using_simple_floor_planner = true;
        let mut first_pass = true;

        layouter.assign_region(
            || "gate",
            |region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("default".to_string(), NUM_ADVICE)],
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
                    )?;
                    (cells[0].clone(), cells[1].clone(), cells[2].clone())
                };

                // test add
                {
                    config.add(ctx, &Existing(&a_cell), &Existing(&b_cell))?;
                }

                // test sub
                {
                    config.sub(ctx, &Existing(&a_cell), &Existing(&b_cell))?;
                }

                // test multiply
                {
                    config.mul(ctx, &Existing(&c_cell), &Existing(&b_cell))?;
                }

                // test idx_to_indicator
                {
                    config.idx_to_indicator(ctx, &Constant(F::from(3)), 4)?;
                }

                println!(
                    "maximum rows used by an advice column: {}",
                    ctx.advice_rows["default"]
                        .iter()
                        .max()
                        .or(Some(&0))
                        .unwrap(),
                );
                let (const_rows, _) = config.finalize(ctx)?;
                println!("maximum rows used by a fixed column: {}", const_rows);

                Ok(())
            },
        )
    }
}

#[test]
fn test_gates() {
    let k = 6;
    let circuit = MyCircuit::<Fr> {
        a: Value::known(Fr::from(10)),
        b: Value::known(Fr::from(12)),
        c: Value::known(Fr::from(120)),
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
    // assert_eq!(prover.verify(), Ok(()));
}

#[cfg(feature = "dev-graph")]
#[test]
fn plot_gates() {
    let k = 6;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (1024, 1024)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Gates Layout", ("sans-serif", 60)).unwrap();

    let circuit = MyCircuit::<Fr>::default();
    halo2_proofs::dev::CircuitLayout::default()
        .render(k, &circuit, &root)
        .unwrap();
}

#[derive(Default)]
struct RangeTestCircuit<F> {
    range_bits: usize,
    lt_bits: usize,
    a: Value<F>,
    b: Value<F>,
}

impl<F: FieldExt> Circuit<F> for RangeTestCircuit<F> {
    type Config = range::RangeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            range_bits: self.range_bits,
            lt_bits: self.lt_bits,
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        range::RangeConfig::configure(
            meta,
            range::RangeStrategy::PlonkPlus,
            &[NUM_ADVICE],
            &[1],
            1,
            3,
            "default".to_string(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_lookup_table(&mut layouter)?;

        let using_simple_floor_planner = true;
        let mut first_pass = true;

        // let's try a separate layouter for loading private inputs
        let (a, b) = layouter.assign_region(
            || "load private inputs",
            |region| {
                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("default".to_string(), NUM_ADVICE)],
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
        )?;

        layouter.assign_region(
            || "range",
            |region| {
                // If we uncomment out the line below, get_shape will be empty and the layouter will try to assign at row 0, but "load private inputs" has already assigned to row 0, so this will panic and fail
                /*
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }
                */

                let mut aux = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("default".to_string(), NUM_ADVICE)],
                    },
                );
                let ctx = &mut aux;

                {
                    config.range_check(ctx, &a, self.range_bits)?;
                }
                {
                    config.check_less_than(ctx, &Existing(&a), &Existing(&b), self.lt_bits)?;
                }
                {
                    config.is_less_than(ctx, &Existing(&a), &Existing(&b), self.lt_bits)?;
                }
                {
                    config.is_less_than(ctx, &Existing(&b), &Existing(&a), self.lt_bits)?;
                }
                {
                    config.is_equal(ctx, &Existing(&b), &Existing(&a))?;
                }
                {
                    config.is_zero(ctx, &a)?;
                }

                println!(
                    "maximum rows used by an advice column: {}",
                    ctx.advice_rows["default"].iter().max().unwrap()
                );

                let (const_rows, _, _) = config.finalize(ctx)?;
                println!("maximum rows used by a fixed column: {}", const_rows);
                println!("lookup cells used: {}", ctx.cells_to_lookup.len());
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
        a: Value::known(Fr::from(100)),
        b: Value::known(Fr::from(101)),
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
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

    halo2_proofs::dev::CircuitLayout::default()
        .render(7, &circuit, &root)
        .unwrap();
}
