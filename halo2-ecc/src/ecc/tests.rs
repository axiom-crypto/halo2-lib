#![allow(unused_assignments, unused_imports, unused_variables)]
use super::*;
use crate::fields::fp::{FpConfig, FpStrategy};
use crate::fields::fp2::Fp2Chip;
use crate::fields::PrimeField;
use crate::halo2_proofs::{
    circuit::*,
    dev::MockProver,
    halo2curves::bn256::{Fq, Fr, G1Affine, G2Affine, G1, G2},
    plonk::*,
};
use group::Group;
use halo2_base::utils::bigint_to_fe;
use halo2_base::SKIP_FIRST_PASS;
use halo2_base::{gates::range::RangeStrategy, utils::value_to_option, ContextParams};
use num_bigint::{BigInt, RandBigInt};
use std::marker::PhantomData;
use std::ops::Neg;

#[derive(Default)]
pub struct MyCircuit<F> {
    pub P: Option<G1Affine>,
    pub Q: Option<G1Affine>,
    pub _marker: PhantomData<F>,
}

const NUM_ADVICE: usize = 2;
const NUM_FIXED: usize = 2;

impl<F: PrimeField> Circuit<F> for MyCircuit<F> {
    type Config = FpConfig<F, Fq>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { P: None, Q: None, _marker: PhantomData }
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
        let chip = EccChip::construct(config.clone());

        let mut first_pass = SKIP_FIRST_PASS;

        layouter.assign_region(
            || "ecc",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = chip.field_chip().new_context(region);
                let ctx = &mut aux;

                let P_assigned = chip.load_private(
                    ctx,
                    match self.P {
                        Some(P) => (Value::known(P.x), Value::known(P.y)),
                        None => (Value::unknown(), Value::unknown()),
                    },
                );
                let Q_assigned = chip.load_private(
                    ctx,
                    match self.Q {
                        Some(Q) => (Value::known(Q.x), Value::known(Q.y)),
                        None => (Value::unknown(), Value::unknown()),
                    },
                );

                // test add_unequal
                {
                    chip.field_chip.enforce_less_than(ctx, P_assigned.x());
                    chip.field_chip.enforce_less_than(ctx, Q_assigned.x());
                    let sum = chip.add_unequal(ctx, &P_assigned, &Q_assigned, false);
                    assert_eq!(
                        value_to_option(sum.x.truncation.to_bigint(config.limb_bits)),
                        value_to_option(sum.x.value.clone())
                    );
                    assert_eq!(
                        value_to_option(sum.y.truncation.to_bigint(config.limb_bits)),
                        value_to_option(sum.y.value.clone())
                    );
                    if self.P.is_some() {
                        let actual_sum = G1Affine::from(self.P.unwrap() + self.Q.unwrap());
                        sum.x.value.map(|v| assert_eq!(bigint_to_fe::<Fq>(&v), actual_sum.x));
                        sum.y.value.map(|v| assert_eq!(bigint_to_fe::<Fq>(&v), actual_sum.y));
                    }
                    println!("add unequal witness OK");
                }

                // test double
                {
                    let doub = chip.double(ctx, &P_assigned);
                    assert_eq!(
                        value_to_option(doub.x.truncation.to_bigint(config.limb_bits)),
                        value_to_option(doub.x.value.clone())
                    );
                    assert_eq!(
                        value_to_option(doub.y.truncation.to_bigint(config.limb_bits)),
                        value_to_option(doub.y.value.clone())
                    );
                    if self.P.is_some() {
                        let actual_doub = G1Affine::from(self.P.unwrap() * Fr::from(2u64));
                        doub.x.value.map(|v| assert_eq!(bigint_to_fe::<Fq>(&v), actual_doub.x));
                        doub.y.value.map(|v| assert_eq!(bigint_to_fe::<Fq>(&v), actual_doub.y));
                    }
                    println!("double witness OK");
                }

                chip.field_chip.finalize(ctx);

                #[cfg(feature = "display")]
                {
                    println!("Using {NUM_ADVICE} advice columns and {NUM_FIXED} fixed columns");
                    println!("total advice cells: {}", ctx.total_advice);
                    let (const_rows, _) = ctx.fixed_stats();
                    println!("maximum rows used by a fixed column: {const_rows}");
                }

                Ok(())
            },
        )
    }
}

#[cfg(test)]
#[test]
fn test_ecc() {
    let k = 23;
    let mut rng = rand::thread_rng();

    let P = Some(G1Affine::random(&mut rng));
    let Q = Some(G1Affine::random(&mut rng));

    let circuit = MyCircuit::<Fr> { P, Q, _marker: PhantomData };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[cfg(feature = "dev-graph")]
#[cfg(test)]
#[test]
fn plot_ecc() {
    let k = 10;
    use plotters::prelude::*;

    let root = BitMapBackend::new("layout.png", (512, 16384)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled("Ecc Layout", ("sans-serif", 60)).unwrap();

    let circuit = MyCircuit::<Fr>::default();

    halo2_proofs::dev::CircuitLayout::default().render(k, &circuit, &root).unwrap();
}
