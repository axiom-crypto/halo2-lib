//! Brecht's SHA-256 circuit implementation, which he modified from the Keccak bit implementation.
//! Note this circuit does **not** use lookup tables, only custom gates.
//! The number of columns are fixed (~130). Unlike keccak, it is not configurable.
//!
//! More details here: https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/756
//!
//! Note: this circuit only supports SHA256 of a byte array of length up to 2^32 - 1, unlike the spec which supports up
//! to 2^64 - 1.

pub mod vanilla;
