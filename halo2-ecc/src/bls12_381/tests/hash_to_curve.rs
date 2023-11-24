// use std::{
//     fs::{self, File},
//     io::{BufRead, BufReader},
//     marker::PhantomData,
// };

// use super::*;
// use crate::{
//     ecc::hash_to_curve::HashToCurveChip,
//     ecc::hash_to_curve::{ExpandMsgXmd, HashInstructions},
//     fields::{FieldChip, FpStrategy},
// };
// use halo2_base::{
//     gates::{flex_gate::threads::SinglePhaseCoreManager, RangeChip},
//     halo2_proofs::{halo2curves::CurveAffine, plonk::Error},
//     utils::BigPrimeField,
//     AssignedValue, QuantumCell,
// };
// extern crate pairing;
// use crate::group::Curve;
// use itertools::Itertools;

// #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
// struct HashToCurveCircuitParams {
//     strategy: FpStrategy,
//     degree: u32,
//     num_advice: usize,
//     num_lookup_advice: usize,
//     num_fixed: usize,
//     lookup_bits: usize,
//     limb_bits: usize,
//     num_limbs: usize,
// }

// #[derive(Clone, Copy, Debug, Default)]
// struct Sha256MockChip<F: BigPrimeField>(PhantomData<F>);

// impl<F: BigPrimeField> HashInstructions<F> for Sha256MockChip<F> {
//     const BLOCK_SIZE: usize = 64;
//     const DIGEST_SIZE: usize = 32;

//     type CircuitBuilder = SinglePhaseCoreManager<F>;
//     type Output = Vec<AssignedValue<F>>;

//     fn digest<const MAX_INPUT_SIZE: usize>(
//         &self,
//         thread_pool: &mut Self::CircuitBuilder,
//         input: impl IntoIterator<Item = QuantumCell<F>>,
//         _strict: bool,
//     ) -> Result<Vec<AssignedValue<F>>, Error> {
//         use sha2::{Digest, Sha256};
//         let input_bytes = input
//             .into_iter()
//             .map(|b| match b {
//                 QuantumCell::Witness(b) => b.get_lower_32() as u8,
//                 QuantumCell::Constant(b) => b.get_lower_32() as u8,
//                 QuantumCell::Existing(av) => av.value().get_lower_32() as u8,
//                 _ => unreachable!(),
//             })
//             .collect_vec();

//         let output_bytes = Sha256::digest(&input_bytes)
//             .into_iter()
//             .map(|b| thread_pool.main().load_witness(F::from(b as u64)))
//             .collect_vec();
//         Ok(output_bytes)
//     }
// }

// fn hash_to_g2_test<F: BigPrimeField>(
//     thread_pool: &mut SinglePhaseCoreManager<F>,
//     range: &RangeChip<F>,
//     params: HashToCurveCircuitParams,
//     msg: Vec<u8>,
// ) {
//     #[cfg(feature = "halo2-axiom")]
//     use crate::halo2_base::halo2_proofs::halo2curves::bls12_381::hash_to_curve::ExpandMsgXmd as ExpandMsgXmdNative;
//     #[cfg(feature = "halo2-pse")]
//     use halo2curves::bls12_381::hash_to_curve::ExpandMsgXmd as ExpandMsgXmdNative;

//     const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
//     let fp_chip = FpChip::<F>::new(range, params.limb_bits, params.num_limbs);
//     let fp2_chip = Fp2Chip::new(&fp_chip);

//     let sha256 = Sha256MockChip::<F>::default();

//     let h2c_chip = HashToCurveChip::new(&sha256, &fp2_chip);

//     let assigned_msghash = h2c_chip
//         .hash_to_curve::<ExpandMsgXmd>(
//             thread_pool,
//             msg.iter().copied().map(|b| QuantumCell::Witness(F::from(b as u64))),
//             DST,
//         )
//         .unwrap();

//     let msghash = G2Affine::from_xy(
//         fp2_chip.get_assigned_value(&assigned_msghash.x.into()),
//         fp2_chip.get_assigned_value(&assigned_msghash.y.into()),
//     )
//     .unwrap();

//     // Verify off-circuit
//     let msghash_control =
//         <G2 as HashToCurve<ExpandMsgXmdNative<sha2::Sha256>>>::hash_to_curve(&msg, DST).to_affine();

//     // Compare the 2 results
//     assert_eq!(msghash, msghash_control);
// }

// #[test]
// fn test_hash_to_g2() {
//     let run_path = "configs/bls12_381/hash_to_curve_circuit.config";
//     let path = run_path;
//     let params: HashToCurveCircuitParams = serde_json::from_reader(
//         File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
//     )
//     .unwrap();
//     println!("num_advice: {num_advice}", num_advice = params.num_advice);

//     let test_input = vec![0u8; 32];

//     base_test().k(params.degree).lookup_bits(params.lookup_bits).run_builder(|builder, range| {
//         hash_to_g2_test(builder, range, params, test_input);
//     })
// }

// #[test]
// fn bench_pairing() -> Result<(), Box<dyn std::error::Error>> {
//     let config_path = "configs/bls12_381/bench_hash_to_curve.config";
//     let bench_params_file =
//         File::open(config_path).unwrap_or_else(|e| panic!("{config_path} does not exist: {e:?}"));
//     fs::create_dir_all("results/bls12_381").unwrap();
//     fs::create_dir_all("data").unwrap();

//     let results_path = "results/bls12_381/pairing_bench.csv";
//     let mut fs_results = File::create(results_path).unwrap();
//     writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;

//     let bench_params_reader = BufReader::new(bench_params_file);
//     for line in bench_params_reader.lines() {
//         let bench_params: HashToCurveCircuitParams =
//             serde_json::from_str(line.unwrap().as_str()).unwrap();
//         let k = bench_params.degree;
//         println!("---------------------- degree = {k} ------------------------------",);

//         let test_input = vec![0u8; 32];
//         let stats = base_test().k(k).lookup_bits(bench_params.lookup_bits).bench_builder(
//             test_input.clone(),
//             test_input,
//             |pool, range, test_input| {
//                 hash_to_g2_test(pool, range, bench_params, test_input);
//             },
//         );

//         writeln!(
//             fs_results,
//             "{},{},{},{},{},{},{},{:?},{},{:?}",
//             bench_params.degree,
//             bench_params.num_advice,
//             bench_params.num_lookup_advice,
//             bench_params.num_fixed,
//             bench_params.lookup_bits,
//             bench_params.limb_bits,
//             bench_params.num_limbs,
//             stats.proof_time.time.elapsed(),
//             stats.proof_size,
//             stats.verify_time.time.elapsed()
//         )?;
//     }
//     Ok(())
// }
