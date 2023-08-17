use super::*;
use crate::{
    gates::{builder::GateThreadBuilder, GateChip},
    halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField},
};

use itertools::Itertools;

mod compatibility;

#[test]
fn test_mds() {
    let spec = OptimizedPoseidonSpec::<Fr, 3, 2>::new::<8, 57, 0>();

    let mds = vec![
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

#[test]
fn test_poseidon_against_test_vectors() {
    let mut builder = GateThreadBuilder::prover();
    let gate = GateChip::<Fr>::default();
    let ctx = builder.main(0);

    // https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
    // poseidonperm_x5_254_3
    {
        const R_F: usize = 8;
        const R_P: usize = 57;
        const T: usize = 3;
        const RATE: usize = 2;

        let mut hasher = PoseidonHasherChip::<Fr, T, RATE>::new::<R_F, R_P, 0>(ctx);

        let state = [0u64, 1, 2];
        hasher.state =
            PoseidonState::<Fr, T, RATE> { s: state.map(|v| ctx.load_constant(Fr::from(v))) };
        let inputs = [Fr::zero(); RATE].iter().map(|f| ctx.load_constant(*f)).collect_vec();
        hasher.permutation(ctx, &gate, inputs); // avoid padding
        let state_0 = hasher.state.s;
        let expected = [
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
            "7142104613055408817911962100316808866448378443474503659992478482890339429929",
            "6549537674122432311777789598043107870002137484850126429160507761192163713804",
        ];
        for (word, expected) in state_0.into_iter().zip(expected.iter()) {
            assert_eq!(word.value(), &Fr::from_str_vartime(expected).unwrap());
        }
    }

    // https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
    // poseidonperm_x5_254_5
    {
        const R_F: usize = 8;
        const R_P: usize = 60;
        const T: usize = 5;
        const RATE: usize = 4;

        let mut hasher = PoseidonHasherChip::<Fr, T, RATE>::new::<R_F, R_P, 0>(ctx);

        let state = [0u64, 1, 2, 3, 4];
        hasher.state =
            PoseidonState::<Fr, T, RATE> { s: state.map(|v| ctx.load_constant(Fr::from(v))) };
        let inputs = [Fr::zero(); RATE].iter().map(|f| ctx.load_constant(*f)).collect_vec();
        hasher.permutation(ctx, &gate, inputs);
        let state_0 = hasher.state.s;
        let expected = [
            "18821383157269793795438455681495246036402687001665670618754263018637548127333",
            "7817711165059374331357136443537800893307845083525445872661165200086166013245",
            "16733335996448830230979566039396561240864200624113062088822991822580465420551",
            "6644334865470350789317807668685953492649391266180911382577082600917830417726",
            "3372108894677221197912083238087960099443657816445944159266857514496320565191",
        ];
        for (word, expected) in state_0.into_iter().zip(expected.iter()) {
            assert_eq!(word.value(), &Fr::from_str_vartime(expected).unwrap());
        }
    }
}

// TODO: test clear()/squeeze().
// TODO: test constraints actually work.
