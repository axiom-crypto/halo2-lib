//!
//! A control chip provides a table of hashes, that is pairs of input messages to digests.
//!
//! A control chip is responsible for the following tasks:
//!
//! **Table of Hashes**
//! - Convert between the fixed positions of permutations into the desired positions of data in a user circuit. This is done by exposing the hashes as a table, which user circuits can access with lookup arguments.
//! - Indicate to user circuits which entries of the table are valid. This is done by exposing a boolean column "enabled", in sync with valid input/digest pairs.
//!- Prevent confusion between messages that are prefix or suffix of each other.
//!
//! **Data Formats**
//! - Convert the format of input data in user circuits, into initial states.
//! - Convert the format of final states into output digests in user circuits.
//! - Pad variable-length inputs, as per the sponge method.
//!
//! **Control of the Permutations**
//! - Decide where to start a new hash, and where to chain consecutive permutations to hash long messages. This is done by some logic on the message length.
//! - At the start of a hash, set an initial state to the first chunk of a message.
//! - To continue a hash, XOR the previous final state with the next input chunk.
//! - Deduplicate identical inputs.
//! - Fill unused permutations.
//!
//! **The Keccak-RLC control chip**
//!
//! This chip exposes Keccak hashes, where both the input messages and the digests are identified by RLC values.
//!
//! - A hash entries in the exposed table is a tuple on a single row: (input_rlc, input_length, digest_rlc, enabled=true).
//! - Permutations are implemented by the Keccak-f chip.
//! - Convert: RLC of the message <=> vector of bytes <=> chunks of 17 words in fat-bit encoding.
//! - Convert: RLC of the digest <=> 32 bytes <=> 4 words in fat-bit encoding.
//! - The RLC values are computed using the challenge API, in a second phase after the permutations.
//!
