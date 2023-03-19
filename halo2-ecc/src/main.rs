use halo2_base::halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, G1Affine},
        CurveAffine,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::commitment::ParamsKZG,
    },
};
use std::fs::File;
use std::io::BufReader;

fn write_params(k: u32) {
    let dir = "./params".to_string();
    let params = ParamsKZG::<Bn256>::read(&mut BufReader::new(
        File::open(format!("{dir}/kzg_bn254_{k}.srs").as_str())
            .expect("Params file does not exist"),
    ))
    .unwrap();

    let mut params_file = File::create(format!("params_{k}.bin")).unwrap();
    params.write(&mut params_file).unwrap();
}

fn main() {
    let k = 16;
    write_params(k);
}
