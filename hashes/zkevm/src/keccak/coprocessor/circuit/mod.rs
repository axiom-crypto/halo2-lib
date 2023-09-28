pub mod leaf;
#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    error,
    fmt::Debug,
    fs::{File, OpenOptions},
    hash::Hash,
    path::Path,
};

use hex::serde;
use serde::{de::DeserializeOwned, Serialize};

pub trait BenchRecord<P>: Serialize + DeserializeOwned {
    fn get_parameter(&self) -> P;
}

pub fn bench_circuit<P: Eq + Debug + Hash, BR: BenchRecord<P>>(
    name: &str,
    parameter_set: Vec<P>,
    filed_names: &[&'static str],
    bench_impl: fn(P) -> BR,
) -> Result<(), Box<dyn error::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let instance_type = rt.block_on(get_instance_type())?;
    let filepath = format!("bench_{name}_{instance_type}.csv");
    ensure_file_exists(&filepath, filed_names);
    // Read the CSV file.
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_path(&filepath)?;

    let mut saved_parameters = HashSet::<P>::new();

    for result in rdr.deserialize() {
        let rd: BR = result?;
        saved_parameters.insert(rd.get_parameter());
    }
    // Open the CSV file in append mode.
    let file = OpenOptions::new().append(true).open(&filepath)?;

    let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(file);

    for parameter in parameter_set {
        println!("Benchmarking {:?}", parameter);
        let e = saved_parameters.get(&parameter);
        if e.is_some() {
            println!("Already have results. Continue");
            continue;
        }
        let br = bench_impl(parameter);
        wtr.serialize(br)?;
        wtr.flush()?;
    }
    Ok(())
}

pub async fn get_instance_type() -> Result<String, Box<dyn error::Error>> {
    let url = "http://169.254.169.254/latest/meta-data/instance-type";
    let resp = reqwest::get(url).await?.text().await?;
    Ok(resp)
}

fn ensure_file_exists<P: AsRef<Path>>(path: P, filed_names: &[&'static str]) {
    let path_ref = path.as_ref();
    if !path_ref.exists() {
        let f = File::create(path_ref).unwrap();
        let mut wtr = csv::Writer::from_writer(f);
        wtr.write_record(filed_names).unwrap();
    }
}
