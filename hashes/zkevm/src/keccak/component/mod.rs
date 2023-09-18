/// Module of Keccak component circuit(s).
pub mod circuit;
/// Module of encoding raw inputs to component circuit lookup keys.
pub mod encode;
/// Module for Rust native processing of input bytes into resized fixed length format to match vanilla circuit LoadedKeccakF
pub mod ingestion;
/// Module of Keccak component circuit output.
pub mod output;
/// Module of Keccak component circuit constant parameters.
pub mod param;
#[cfg(test)]
mod tests;
