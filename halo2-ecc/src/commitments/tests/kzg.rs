use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};
use super::*;
use crate::fields::FpStrategy;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct KZGCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

#[test]
fn test_kzg() {
    let path = "configs/commitments/kzg_circuit.config";
    let params: KZGCircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    println!("params: {:?}", params);
}
