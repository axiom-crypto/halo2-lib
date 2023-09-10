/// Module of Keccak coprocessor circuit.
pub mod circuit;
/// Module of encoding raw inputs to coprocessor circuit lookup keys.
pub mod encode;
/// Module for Rust native processing of input bytes into resized fixed length format to match vanilla circuit LoadedKeccakF
pub mod ingestion;
/// Module of Keccak coprocessor circuit output.
pub mod output;
/// Module of Keccak coprocessor circuit constant parameters.
pub mod param;
#[cfg(test)]
mod tests;
