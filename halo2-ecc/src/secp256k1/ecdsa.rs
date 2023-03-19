#![allow(non_snake_case)]
use crate::fields::fp::FpConfig;
use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::*,
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::*,
};
use crate::secp256k1::FpChip;
use crate::{
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::{fp::FpStrategy, FieldChip},
};
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};
use halo2_base::{utils::PrimeField, SKIP_FIRST_PASS};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Serialize, Deserialize)]
pub struct CircuitParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

pub struct ECDSACircuit<F> {
    pub r: Option<Fq>,
    pub s: Option<Fq>,
    pub msghash: Option<Fq>,
    pub pk: Option<Secp256k1Affine>,
    pub G: Secp256k1Affine,
    pub _marker: PhantomData<F>,
}
impl<F: PrimeField> Default for ECDSACircuit<F> {
    fn default() -> Self {
        Self {
            r: None,
            s: None,
            msghash: None,
            pk: None,
            G: Secp256k1Affine::generator(),
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField> Circuit<F> for ECDSACircuit<F> {
    type Config = FpChip<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // use std::env::var;
        // use std::fs::File;
        // let path = var("ECDSA_CONFIG")
        //     .unwrap_or_else(|_| "./src/secp256k1/configs/ecdsa_circuit.tmp.config".to_string());
        // let PARAMS: CircuitParams = serde_json::from_reader(
        //     File::open(&path).unwrap_or_else(|_| panic!("{path:?} file should exist")),
        // )
        // .unwrap();

        use super::params::PARAMS;

        FpChip::<F>::configure(
            meta,
            PARAMS.strategy,
            &[PARAMS.num_advice],
            &[PARAMS.num_lookup_advice],
            PARAMS.num_fixed,
            PARAMS.lookup_bits,
            PARAMS.limb_bits,
            PARAMS.num_limbs,
            modulus::<Fp>(),
            0,
            PARAMS.degree as usize,
        )
    }

    fn synthesize(
        &self,
        fp_chip: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        fp_chip.range.load_lookup_table(&mut layouter)?;

        let limb_bits = fp_chip.limb_bits;
        let num_limbs = fp_chip.num_limbs;
        let _num_fixed = fp_chip.range.gate.constants.len();
        let _lookup_bits = fp_chip.range.lookup_bits;
        let _num_advice = fp_chip.range.gate.num_advice;

        let mut first_pass = SKIP_FIRST_PASS;
        // ECDSA verify
        layouter.assign_region(
            || "ECDSA",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let mut aux = fp_chip.new_context(region);
                let ctx = &mut aux;

                let (r_assigned, s_assigned, m_assigned) = {
                    let fq_chip = FpConfig::<F, Fq>::construct(
                        fp_chip.range.clone(),
                        limb_bits,
                        num_limbs,
                        modulus::<Fq>(),
                    );

                    let m_assigned = fq_chip.load_private(
                        ctx,
                        FpConfig::<F, Fq>::fe_to_witness(
                            &self.msghash.map_or(Value::unknown(), Value::known),
                        ),
                    );

                    let r_assigned = fq_chip.load_private(
                        ctx,
                        FpConfig::<F, Fq>::fe_to_witness(
                            &self.r.map_or(Value::unknown(), Value::known),
                        ),
                    );
                    let s_assigned = fq_chip.load_private(
                        ctx,
                        FpConfig::<F, Fq>::fe_to_witness(
                            &self.s.map_or(Value::unknown(), Value::known),
                        ),
                    );
                    (r_assigned, s_assigned, m_assigned)
                };

                let ecc_chip = EccChip::<F, FpChip<F>>::construct(fp_chip.clone());
                let pk_assigned = ecc_chip.load_private(
                    ctx,
                    (
                        self.pk.map_or(Value::unknown(), |pt| Value::known(pt.x)),
                        self.pk.map_or(Value::unknown(), |pt| Value::known(pt.y)),
                    ),
                );
                // test ECDSA
                let ecdsa = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
                    &ecc_chip.field_chip,
                    ctx,
                    &pk_assigned,
                    &r_assigned,
                    &s_assigned,
                    &m_assigned,
                    4,
                    4,
                );

                // IMPORTANT: this copies cells to the lookup advice column to perform range check lookups
                // This is not optional.
                fp_chip.finalize(ctx);

                #[cfg(feature = "display")]
                if self.r.is_some() {
                    println!("ECDSA res {ecdsa:?}");

                    ctx.print_stats(&["Range"]);
                }
                Ok(())
            },
        )
    }
}

pub fn generate_ecdsa_input() -> (Fq, Fq, Fq, Secp256k1Affine, Secp256k1Affine) {
    let G = Secp256k1Affine::generator();
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let pubkey = Secp256k1Affine::from(G * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(G * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&x_bigint);
    let s = k_inv * (msg_hash + (r * sk));

    (r, s, msg_hash, pubkey, G)
}
