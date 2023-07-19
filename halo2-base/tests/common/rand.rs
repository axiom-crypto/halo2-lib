use halo2_base::{QuantumCell, QuantumCell::Witness};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use proptest::prelude::*;

prop_compose! {
    pub fn rand_fr()(val in any::<u64>()) -> Fr {
        Fr::from(val)
    }
}

prop_compose! {
    pub fn rand_witness()(val in any::<u64>()) -> QuantumCell<Fr> {
        Witness(Fr::from(val))
    }
}

prop_compose! {
    pub fn rand_bin_witness()(val in prop::sample::select(vec![Fr::zero(), Fr::one()])) -> QuantumCell<Fr> {
        Witness(val)
    }
}
