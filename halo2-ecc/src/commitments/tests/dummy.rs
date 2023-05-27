// #![allow(warnings, unused)]

use std::{marker::PhantomData};
use halo2_ecc::{bigint::ProperCrtUint, commitments::kzg::KZGChip};
use halo2_ecc::fields::fp::Reduced;
use halo2_ecc::fields::vector::FieldVector;
use halo2_ecc::fields::Selectable;

use halo2_base::{halo2_proofs::{
    dev::MockProver,
    circuit::*,
    halo2curves::{bn256::{Fr, G1Affine, G2Affine, G1, G2}, FieldExt},
    plonk::*,
}, AssignedValue, utils::ScalarField, QuantumCell};
use halo2_base::gates::builder::{GateCircuitBuilder, GateThreadBuilder, RangeCircuitBuilder};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use num_bigint::{BigInt, BigUint};
use halo2_base::gates::GateInstructions;

use halo2_base::{
    Context,
    utils::{fe_to_bigint, modulus},
    SKIP_FIRST_PASS,
};
use halo2_base::gates::range::{RangeChip};
use halo2_ecc::{fields::{FieldChip, PrimeField, fp::BaseFieldChip, FpStrategy}, ecc::EccChip};
use halo2_ecc::{
    bn254::{pairing::PairingChip, FpChip, Fp2Chip},
    fields::fp::{FpConfig},
};
use halo2_ecc::{
    fields::{
        fp12::Fp12Chip,
    },
};

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};

use pprof::criterion::{Output, PProfProfiler};

#[derive(Serialize, Deserialize)]
pub struct CircuitInputs {
    pub p_bar: G1Affine,
    pub open_idxs: Vec<Fr>,
    pub open_vals: Vec<Fr>,
    pub q_bar: G1Affine,
    pub z_coeffs: Vec<Fr>,
    pub r_coeffs: Vec<Fr>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct PP {
    pub ptau_g1: Vec<G1>,
    pub ptau_g2: Vec<G2>,
}

#[derive(Default)]
struct KZGTestCircuit<F> {
    p_bar: G1Affine,
    open_idxs: Vec<Fr>,
    open_vals: Vec<Fr>,
    q_bar: G1Affine,
    z_coeffs: Vec<F>,
    r_coeffs: Vec<F>,
    ptau_g1: Vec<G1Affine>,
    ptau_g2: Vec<G2Affine>,
    _marker: PhantomData<F>,
}

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

const K: u32 = 20;
const XI_0: i64 = 9;
const BLOB_LEN: usize = 4;
const N_OPENINGS: usize = 2;
const INPUT_F: &str = "input/circuit_inputs.json";
const PP_F: &str = "input/pp.json";

const NUM_ADVICE: usize = 8;
const NUM_LOOKUP_ADVICE: usize = 1;
const NUM_FIXED: usize = 1;

#[derive(Clone, Debug)]
struct KZGConfig<F: PrimeField + ScalarField>
where F: From<[u64; 4]> + Into<[u64; 4]>
{
    fp_config: FpConfig<F>,
    columns: Column<Advice>
}

fn g2_add_test<F: PrimeField + ScalarField>(builder: &mut GateThreadBuilder<F>, params: CircuitParams, config: KZGTestCircuit<F>) 
    where for<'a> Fp2Chip<'a, F>: Selectable<F, FieldVector<Reduced<ProperCrtUint<F>, halo2_base::halo2_proofs::halo2curves::bn256::Fq>>>
{

    let ctx = builder.main(0);

    std::env::set_var("LOOKUP_BITS", params.lookup_bits.to_string());
    
    let range = RangeChip::<F>::default(params.lookup_bits);
    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let g1_chip = EccChip::new(&fp_chip);
    let fp2_chip = Fp2Chip::<F>::new(&fp_chip);
    let g2_chip = EccChip::new(&fp2_chip);
    let pairing_chip = PairingChip::new(&fp_chip);

    let assigned_q_bar = g1_chip.assign_point(ctx, config.q_bar);
    let assigned_p_bar = g1_chip.assign_point(ctx, config.p_bar);
    let g2_generator = g2_chip.assign_point(ctx, G2Affine::generator());

    let mut ptau_g1_loaded = vec![];
    let mut ptau_g2_loaded = vec![];
    let mut z_coeffs_loaded = vec![];
    let mut r_coeffs_loaded = vec![];

    for el in config.ptau_g1.iter() {
        ptau_g1_loaded.push(g1_chip.assign_point(ctx, el.clone()));
    }
    for el in config.ptau_g2.iter() {
        ptau_g2_loaded.push(g2_chip.assign_point(ctx, el.clone()));
    }

    for (i, z_coeff) in config.z_coeffs.iter().enumerate() {
        z_coeffs_loaded.push(
            ctx.load_witness(z_coeff.clone())
        );
    }

    for (i, r_coeff) in config.r_coeffs.iter().enumerate() {
        r_coeffs_loaded.push(
            ctx.load_witness(r_coeff.clone())
        );
    }

    let kzg_chip = KZGChip::new(&pairing_chip, &g1_chip, &g2_chip);

    kzg_chip.opening_assert(
        builder,
        &ptau_g1_loaded[..],
        &ptau_g2_loaded[..],
        r_coeffs_loaded.iter().map(|x| vec![x.clone()]).collect::<Vec<_>>(),
        z_coeffs_loaded.iter().map(|x| vec![x.clone()]).collect::<Vec<_>>(),
        assigned_p_bar,
        assigned_q_bar
    );
}

fn main() {
    let circuit_inputs: CircuitInputs =
        serde_json::from_reader(File::open(INPUT_F).unwrap()).unwrap();
    let pp: PP =
        serde_json::from_reader(File::open(PP_F).unwrap()).unwrap();

    // compute actual g1s and g2s
    let mut ptau_g1s = vec![];
    let mut ptau_g2s = vec![];
    for i in 0..(N_OPENINGS){
        ptau_g1s.push(pp.ptau_g1[i].clone().into());
    }
    for i in 0..=N_OPENINGS {
        ptau_g2s.push(pp.ptau_g2[i].clone().into());
    }

    let circuit = KZGTestCircuit::<Fr> {
        p_bar: circuit_inputs.p_bar,
        open_idxs: circuit_inputs.open_idxs,
        open_vals: circuit_inputs.open_vals,
        q_bar: circuit_inputs.q_bar,
        z_coeffs: circuit_inputs.z_coeffs,
        r_coeffs: circuit_inputs.r_coeffs,
        ptau_g1: ptau_g1s,
        ptau_g2: ptau_g2s,
        _marker: PhantomData,
    };

    let circuit_params = CircuitParams {
        strategy: FpStrategy::Simple,
        degree: K as u32,
        num_advice: NUM_ADVICE,
        num_lookup_advice: NUM_LOOKUP_ADVICE,
        num_fixed: NUM_FIXED,
        lookup_bits: 18,
        limb_bits: 91,
        num_limbs: 3,
        batch_size: 0,
    };

    let mut builder = GateThreadBuilder::<Fr>::mock();
    g2_add_test::<Fr>(&mut builder, circuit_params, circuit);

    builder.config(K as usize, Some(20));
    let circuit = RangeCircuitBuilder::mock(builder);
    MockProver::run(K, &circuit, vec![]).unwrap().assert_satisfied();
}
