# ZKEVM SHA-256

## Vanilla

SHA-256 circuit in vanilla halo2. This implementation is largely based on [Brechtpd](https://github.com/Brechtpd)'s [PR](https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/756) to the PSE `zkevm-circuits`. His implementation of SHA-256 is in turn based on his implementation of Keccak using the "Bits" approach: one can read more about it [here](https://hackmd.io/NaTuIvmaQCybaOYgd-DG1Q?view#Bit-implementation).

The major difference is that this version directly represent raw inputs and SHA-256 digests as witnesses, while the original version only has RLCs (random linear combination) of raw inputs and outputs. Because this version doesn't need RLCs, it doesn't have the 2nd phase or use challenge APIs.

### Logical Input/Output

Logically the circuit takes a variable length array of variable length bytes as inputs and SHA-256 digests of these bytes as outputs.
While these logical inputs are variable, what is fixed in a given circuit is max number of _total number of SHA-256 input blocks_ that can be processed (see below). We refer to this as the capacity of the circuit.

`sha256::vanilla::witness::generate_witnesses_multi_sha256` generates the witnesses of the circuit for a given input.

### Background Knowledge

- Given a variable length byte array, one first pads as follows (taken from [Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Pseudocode)):

```
begin with the original message of length L bits
append a single '1' bit
append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64-bit integer> , (the number of bits will be a multiple of 512)
```

- The SHA-256 algorithm processes padded input data in _blocks_ of 512 bits or 64 bytes.
- The hashing process comprises a series of `NUM_ROUNDS` (64) rounds.
- The algorithm can be organized so that the 64 bytes are divided into `NUM_WORDS_TO_ABSORB` (16) _words_ of 32 bits each, and one new word is ingested in each of the first `NUM_WORDS_TO_ABSORB` rounds.

### Circuit Overview

- The circuit operates on one 512 bit input block at a time.
- For each block, `SHA256_NUM_ROWS` (72) are used. This consists of `NUM_START_ROWS` (4) + `NUM_ROUNDS` (64) + `NUM_END_ROWS` (4) rows.
  - As described above, the input is "absorbed" in 32 bit words, one in each row of rows `NUM_START_ROWS..NUM_START_ROWS + NUM_WORDS_TO_ABSORB`. These are the rows in which a selector `q_input` is turned on.
- We store inputs and outputs for external use in columns inside the `ShaTable` struct. These are:
  - `is_enabled`: a boolean indicating if it is the last row of the block and also this is the last input block of a full input (i.e., this is the block with the finalized digest).
  - `length`: the running length in bytes of input data "absorbed" so far, including the current block, excluding padding. This is only constrained when `q_input` is true. One recovers the length of the unpadded input by reading this value on the last "absorb" row in a block with `is_enabled` true.
  - `word_value`: 32 bits of the input, as described above. We use the following slightly funny conversion: we consider the 4 byte chunk of the input, replace the padding with 0s, and then convert to a 32-bit integer by considering the 4 bytes _in little endian_. This choice was chosen for consistency with the Keccak circuit, but is arbitrary.
    - Only constrained when `q_input` is true.
  - `output` (2): the hash digest the SHA-256 algorithm on the input bytes (32 bytes). We represent this as two field elements in hi-lo form - we split 32 bytes into two 16 byte chunks, and convert them to `u128` as _big endian_.
    - Only constrained when the last row of a block. Should only be considered meaningful when `is_enabled` is true.
- We conveniently store the relevant cells for the above data, per input block, in the struct `AssignedSha256Block`.
- This circuit has a hard constraint that the input array has length up to `2^32 - 1` bits, whereas the official SHA-256 spec supports up to `2^64 - 1`. (In practice it is likely impossible to create a circuit that can handle `2^32 - 1` bit inputs.)
- Details are provided in inline comments.

### Example

To illustrate, let's consider `inputs = [[], [0x00, 0x01, ..., 0x37]]`. The corresponding table will look like (input idx is not a real column, provided for viewing convenience):

| row | input idx | word_value   | length | is_enabled | hash_lo | hash_hi |
| --- | --------- | ------------ | ------ | ---------- | ------- | ------- |
| 0   | 0         | -            | ...    | false      |         |
| ... | 0         | ...          | ...    | ...        |         |
| 4   | 0         | `0`          | 0      | false      |         |
| ... | 0         | `0`          | 0      | false      |         |
| 71  | 0         | -            | 0      | true       | RESULT  | RESULT  |
| 72  | 1         | -            | ...    | ...        |         |
| ... | 1         | ...          | ...    | false      |         |
| 76  | 1         | `0x03020100` | 4      | false      |         |
| ... | 1         | ...          | ...    | false      |         |
| 91  | 1         | `0x0`        | 56     | false      |         |
| 143 | 1         | -            | -      | false      |         |         |
| 144 | 1         | -            | ...    | ...        |         |
| ... | 1         | ...          | ...    | false      |         |
| 148 | 1         | `0x0`        | 56     | false      |         |
| ... | 1         | ...          | ...    | false      |         |
| 163 | 1         | `0x0`        | 56     | false      |         |
| 215 | 1         | -            | -      | true       | RESULT  | RESULT  |

Here the second input has a length of 56 (in bytes) and requires two blocks due to padding: `56 * 8 + 1 + 64 > 512`.
