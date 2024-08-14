use super::*;
use crate::halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};

use itertools::Itertools;

mod compatibility;
mod hasher;
mod state;

#[test]
fn test_mds() {
    let spec = OptimizedPoseidonSpec::<Fr, 3, 2>::new::<8, 57, 0>();

    let mds = [
        vec![
            "7511745149465107256748700652201246547602992235352608707588321460060273774987",
            "10370080108974718697676803824769673834027675643658433702224577712625900127200",
            "19705173408229649878903981084052839426532978878058043055305024233888854471533",
        ],
        vec![
            "18732019378264290557468133440468564866454307626475683536618613112504878618481",
            "20870176810702568768751421378473869562658540583882454726129544628203806653987",
            "7266061498423634438633389053804536045105766754026813321943009179476902321146",
        ],
        vec![
            "9131299761947733513298312097611845208338517739621853568979632113419485819303",
            "10595341252162738537912664445405114076324478519622938027420701542910180337937",
            "11597556804922396090267472882856054602429588299176362916247939723151043581408",
        ],
    ];
    for (row1, row2) in mds.iter().zip_eq(spec.mds_matrices.mds.0.iter()) {
        for (e1, e2) in row1.iter().zip_eq(row2.iter()) {
            assert_eq!(Fr::from_str_vartime(e1).unwrap(), *e2);
        }
    }
}

// TODO: test clear()/squeeze().
// TODO: test constraints actually work.
