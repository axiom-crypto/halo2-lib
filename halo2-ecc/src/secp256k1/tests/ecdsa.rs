#![allow(non_snake_case)]
use ark_std::{end_timer, start_timer};
use halo2_base::utils::PrimeField;
use std::marker::PhantomData;
use std::{
    env::var,
    io::{BufWriter, Write},
};

use crate::halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    halo2curves::secp256k1::{Fq, Secp256k1Affine},
    plonk::*,
    poly::commitment::ParamsProver,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    SerdeFormat,
};
use rand_core::OsRng;

use halo2_base::utils::{biguint_to_fe, fe_to_biguint, modulus};

use crate::secp256k1::ecdsa::{CircuitParams, ECDSACircuit};

#[cfg(test)]
#[test]
fn test_secp256k1_ecdsa() {
    let mut folder = std::path::PathBuf::new();
    folder.push("./src/secp256k1");
    folder.push("configs/ecdsa_circuit.config");
    let params_str = std::fs::read_to_string(folder.as_path())
        .expect("src/secp256k1/configs/ecdsa_circuit.config file should exist");
    let params: CircuitParams = serde_json::from_str(params_str.as_str()).unwrap();
    let K = params.degree;

    // generate random pub key and sign random message
    let G = Secp256k1Affine::generator();
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let pubkey = Secp256k1Affine::from(G * sk);
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(G * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msg_hash + (r * sk));

    let circuit = ECDSACircuit::<Fr> {
        r: Some(r),
        s: Some(s),
        msghash: Some(msg_hash),
        pk: Some(pubkey),
        G,
        _marker: PhantomData,
    };

    let prover = MockProver::run(K, &circuit, vec![]).unwrap();
    //prover.assert_satisfied();
    assert_eq!(prover.verify(), Ok(()));
}

#[cfg(test)]
#[test]
fn bench_secp256k1_ecdsa() -> Result<(), Box<dyn std::error::Error>> {
    use halo2_base::utils::fs::gen_srs;

    use crate::halo2_proofs::{
        poly::kzg::{
            commitment::KZGCommitmentScheme,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    };
    use std::{env::set_var, fs, io::BufRead};

    let _rng = OsRng;

    let mut folder = std::path::PathBuf::new();
    folder.push("./src/secp256k1");

    folder.push("configs/bench_ecdsa.config");
    let bench_params_file = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();
    folder.pop();

    folder.push("results/ecdsa_bench.csv");
    let mut fs_results = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    folder.pop();
    writeln!(fs_results, "degree,num_advice,num_lookup,num_fixed,lookup_bits,limb_bits,num_limbs,proof_time,proof_size,verify_time")?;
    folder.push("data");
    if !folder.is_dir() {
        std::fs::create_dir(folder.as_path())?;
    }

    let bench_params_reader = std::io::BufReader::new(bench_params_file);
    for line in bench_params_reader.lines() {
        let bench_params: CircuitParams = serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!(
            "---------------------- degree = {} ------------------------------",
            bench_params.degree
        );

        {
            folder.pop();
            folder.push("configs/ecdsa_circuit.tmp.config");
            set_var("ECDSA_CONFIG", &folder);
            let mut f = std::fs::File::create(folder.as_path())?;
            write!(f, "{}", serde_json::to_string(&bench_params).unwrap())?;
            folder.pop();
            folder.pop();
            folder.push("keys")
        }
        let params_time = start_timer!(|| "Time elapsed in circuit & params construction");
        let params = gen_srs(bench_params.degree);
        let circuit = ECDSACircuit::<Fr>::default();
        end_timer!(params_time);

        let vk_time = start_timer!(|| "Time elapsed in generating vkey");
        let vk = keygen_vk(&params, &circuit)?;
        end_timer!(vk_time);

        // write the verifying key to a file
        {
            folder.push(format!("ecdsa_{}.vk", bench_params.degree));
            let f = std::fs::File::create(folder.as_path()).unwrap();
            let mut writer = BufWriter::new(f);
            vk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
            writer.flush().unwrap();
            folder.pop();
        }
        folder.pop();
        folder.push("data");

        let pk_time = start_timer!(|| "Time elapsed in generating pkey");
        let pk = keygen_pk(&params, vk, &circuit)?;
        end_timer!(pk_time);

        // write the proving key to a file
        {
            folder.push(format!("ecdsa_{}.pk", bench_params.degree));
            let f = std::fs::File::create(folder.as_path()).unwrap();
            let mut writer = BufWriter::new(f);
            pk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
            writer.flush().unwrap();
            folder.pop();
        }

        // generate random pub key and sign random message
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

        let proof_circuit = ECDSACircuit::<Fr> {
            r: Some(r),
            s: Some(s),
            msghash: Some(msg_hash),
            pk: Some(pubkey),
            G,
            _marker: PhantomData,
        };
        let mut rng = OsRng;

        // create a proof
        let proof_time = start_timer!(|| "Proving time");
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            ECDSACircuit<Fr>,
        >(&params, &pk, &[proof_circuit], &[&[]], &mut rng, &mut transcript)?;
        let proof = transcript.finalize();
        end_timer!(proof_time);

        let proof_size = {
            folder.push(format!(
                "ecdsa_circuit_proof_{}_{}_{}_{}_{}_{}_{}.data",
                bench_params.degree,
                bench_params.num_advice,
                bench_params.num_lookup_advice,
                bench_params.num_fixed,
                bench_params.lookup_bits,
                bench_params.limb_bits,
                bench_params.num_limbs
            ));
            let mut fd = std::fs::File::create(folder.as_path()).unwrap();
            folder.pop();
            fd.write_all(&proof).unwrap();
            fd.metadata().unwrap().len()
        };

        let verify_time = start_timer!(|| "Verify time");
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, pk.get_vk(), strategy, &[&[]], &mut transcript)
        .is_ok());
        end_timer!(verify_time);
        fs::remove_file(var("ECDSA_CONFIG").unwrap())?;

        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{:?},{},{:?}",
            bench_params.degree,
            bench_params.num_advice,
            bench_params.num_lookup_advice,
            bench_params.num_fixed,
            bench_params.lookup_bits,
            bench_params.limb_bits,
            bench_params.num_limbs,
            proof_time.time.elapsed(),
            proof_size,
            verify_time.time.elapsed()
        )?;
    }
    Ok(())
}
