# ZKEVM Keccak

## Vanilla

Keccak circuit in vanilla halo2. This implementation starts from [PSE version](https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit), then adopts some changes from [this PR](https://github.com/scroll-tech/zkevm-circuits/pull/216) and later updates in PSE version.

The major difference is that this version directly represent raw inputs and Keccak results as witnesses, while the original version only has RLCs(random linear combination) of raw inputs and Keccak results. Because this version doesn't need RLCs, it doesn't have the 2nd phase or use challenge APIs.

### Logical Input/Output

Logically the circuit takes an array of bytes as inputs and Keccak results of these bytes as outputs.

`keccak::vanilla::witness::multi_keccak` generates the witnesses of the circuit for a given input.

### Background Knowledge

All these items remain consistent across all versions.

- Keccak process a logical input `keccak_f` by `keccak_f`.
- Each `keccak_f` has `NUM_ROUNDS`(24) rounds.
- The number of rows of a round(`rows_per_round`) is configurable. Usually less rows means less wasted cells.
- Each `keccak_f` takes `(NUM_ROUNDS + 1) * rows_per_round` rows. The last `rows_per_round` rows could be considered as a virtual round for "squeeze".
- Every input is padded to be a multiple of RATE (136 bytes). If the length of the logical input already matches a multiple of RATE, an additional RATE bytes are added as padding.
- Each `keccak_f` absorbs `RATE` bytes, which are splitted into `NUM_WORDS_TO_ABSORB`(17) words. Each word has `NUM_BYTES_PER_WORD`(8) bytes.
- Each of the first `NUM_WORDS_TO_ABSORB`(17) rounds of each `keccak_f` absorbs a word.
- `is_final`(anothe name is `is_enabled`) is meaningful only at the first row of the "squeeze" round. It must be true if this is the last `keccak_f` of a logical input.
- The first round of the circuit is a dummy round, which doesn't correspond to any input.

### Raw inputs

- In this version, we added column `word_value`/`bytes_left` to represent raw inputs.
- `word_value` is meaningful only at the first row of the first `NUM_WORDS_TO_ABSORB`(17) rounds.
- `bytes_left` is meaningful only at the first row of each round.
- `word_value` equals to the bytes from the raw input in this round's word in little-endian.
- `bytes_left` equals to the number of bytes, which haven't been absorbed from the raw input before this round.
- More details could be found in comments.

### Keccak Results

- In this version, we added column `hash_lo`/`hash_hi` to represent Keccak results.
- `hash_lo`/`hash_hi` of a logical input could be found at the first row of the virtual round of the last `keccak_f`.
- `hash_lo` is the low 128 bits of Keccak results. `hash_hi` is the high 128 bits of Keccak results.

### Example

In this version, we care more about the first row of each round(`offset = x * rows_per_round`). So we only show the first row of each round in the following example.
Let's say `rows_per_round = 10` and `inputs = [[], [0x89, 0x88, .., 0x01]]`. The corresponding table is:

| row           | input idx | round | word_value           | bytes_left | is_final | hash_lo | hash_hi |
| ------------- | --------- | ----- | -------------------- | ---------- | -------- | ------- | ------- |
| 0 (dummy)     | -         | -     | -                    | -          | false    | -       | -       |
| 10            | 0         | 1     | `0`                  | 0          | -        | -       | -       |
| ...           | 0         | ...   | ...                  | 0          | -        | -       | -       |
| 170           | 0         | 17    | `0`                  | 0          | -        | -       | -       |
| 180           | 0         | 18    | -                    | 0          | -        | -       | -       |
| ...           | 0         | ...   | ...                  | 0          | -        | -       | -       |
| 250 (squeeze) | 0         | 25    | -                    | 0          | true     | RESULT  | RESULT  |
| 260           | 1         | 1     | `0x8283848586878889` | 137        | -        | -       | -       |
| 270           | 1         | 2     | `0x7A7B7C7D7E7F8081` | 129        | -        | -       | -       |
| ...           | 1         | ...   | ...                  | ...        | -        | -       | -       |
| 420           | 1         | 17    | `0x0203040506070809` | 9          | -        | -       | -       |
| 430           | 1         | 18    | -                    | 1          | -        | -       | -       |
| ...           | 1         | ...   | ...                  | 0          | -        | -       | -       |
| 500 (squeeze) | 1         | 25    | -                    | 0          | false    | -       | -       |
| 510           | 1         | 1     | `0x01`               | 1          | -        | -       | -       |
| 520           | 1         | 2     | -                    | 0          | -        | -       | -       |
| ...           | 1         | ...   | ...                  | 0          | -        | -       | -       |
| 750 (squeeze) | 1         | 25    | -                    | 0          | true     | RESULT  | RESULT  |

### Change Details

- Removed column `input_rlc`/`input_len` and related gates.
- Removed column `output_rlc` and related gates.
- Removed challenges.
- Refactored the folder structure to follow [Scroll's repo](https://github.com/scroll-tech/zkevm-circuits/tree/95f82762cfec46140d6866c34a420ee1fc1e27c7/zkevm-circuits/src/keccak_circuit). `mod.rs` and `witness.rs` could be found [here](https://github.com/scroll-tech/zkevm-circuits/blob/develop/zkevm-circuits/src/keccak_circuit.rs). `KeccakTable` could be found [here](https://github.com/scroll-tech/zkevm-circuits/blob/95f82762cfec46140d6866c34a420ee1fc1e27c7/zkevm-circuits/src/table.rs#L1308).
- Imported utilities from [PSE zkevm-circuits repo](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/588b8b8c55bf639fc5cbf7eae575da922ea7f1fd/zkevm-circuits/src/util/word.rs).

## Component

Keccak component circuits and utilities based on halo2-lib.

### Motivation

Move expensive Keccak computation into standalone circuits(**Component Circuits**) and circuits with actual business logic(**App Circuits**) can read Keccak results from component circuits. Then we achieve better scalability - the maximum size of a single circuit could be managed and component/app circuits could be proved in paralle.

### Output

Logically a component circuit outputs 3 columns `lookup_key`, `hash_lo`, `hash_hi` with `capacity` rows, where `capacity` is a configurable parameter and it means the maximum number of keccak_f this circuit can perform.

- `lookup_key` can be cheaply derived from a bytes input. Specs can be found at `keccak::component::encode::encode_native_input`. Also `keccak::component::encode` provides some utilities to encode bytes inputs in halo2-lib.
- `hash_lo`/`hash_hi` are low/high 128 bits of the corresponding Keccak result.

There 2 ways to publish circuit outputs:

- Publish all these 3 columns as 3 public instance columns.
- Publish the commitment of all these 3 columns as a single public instance.

Developers can choose either way according to their needs. Specs of these 2 ways can be found at `keccak::component::circuit::shard::KeccakComponentShardCircuit::publish_outputs`.

`keccak::component::output` provides utilities to compute component circuit outputs for given inputs. App circuits could use these utilities to load Keccak results before witness generation of component circuits.

### Lookup Key Encode

For easier understanding specs at `keccak::component::encode::encode_native_input`, here we provide an example of encoding `[0x89, 0x88, .., 0x01]`(137 bytes):
| keccak_f| round | word | witness | Note |
|---------|-------|------|---------| ---- |
| 0 | 1 | `0x8283848586878889` | - | |
| 0 | 2 | `0x7A7B7C7D7E7F8081` | `0x7A7B7C7D7E7F808182838485868788890000000000000089` | [length, word[0], word[1]] |
| 0 | 3 | `0x7273747576777879` | - | |
| 0 | 4 | `0x6A6B6C6D6E6F7071` | - | |
| 0 | 5 | `0x6263646566676869` | `0x62636465666768696A6B6C6D6E6F70717273747576777879` | [word[2], word[3], word[4]] |
| ... | ... | ... | ... | ... |
| 0 | 15 | `0x1213141516171819` | - | |
| 0 | 16 | `0x0A0B0C0D0E0F1011` | - | |
| 0 | 17 | `0x0203040506070809` | `0x02030405060708090A0B0C0D0E0F10111213141516171819` | [word[15], word[16], word[17]] |
| 1 | 1 | `0x0000000000000001` | - | |
| 1 | 2 | `0x0000000000000000` | `0x000000000000000000000000000000010000000000000000` | [0, word[0], word[1]] |
| 1 | 3 | `0x0000000000000000` | - | |
| 1 | 4 | `0x0000000000000000` | - | |
| 1 | 5 | `0x0000000000000000` | `0x000000000000000000000000000000000000000000000000` | [word[2], word[3], word[4]] |
| ... | ... | ... | ... | ... |
| 1 | 15 | `0x0000000000000000` | - | |
| 1 | 16 | `0x0000000000000000` | - | |
| 1 | 17 | `0x0000000000000000` | `0x000000000000000000000000000000000000000000000000` | [word[15], word[16], word[17]] |

The raw input is transformed into `payload = [0x7A7B7C7D7E7F808182838485868788890000000000000089, 0x62636465666768696A6B6C6D6E6F70717273747576777879, ... , 0x02030405060708090A0B0C0D0E0F10111213141516171819, 0x000000000000000000000000000000010000000000000000, 0x000000000000000000000000000000000000000000000000, ... , 0x000000000000000000000000000000000000000000000000]`. 2 keccak_fs, 6 witnesses each keecak_f, 12 witnesses in total.

Finally the lookup key will be `Poseidon(payload)`.

### Shard Circuit

Implementation: `keccak::component::circuit::shard::KeccakComponentShardCircuit`

- Shard circuits are the circuits that actually perform Keccak computation.
- Logically shard circuits take an array of bytes as inputs.
- Shard circuits follow the component output format above.
- Shard circuits have a configurable parameter `capacity`, which is the maximum number of keccak_f this circuit can perform.
- Shard circuits' outputs have Keccak results of all logical inputs. Outputs are padded into `capacity` rows with Keccak results of "". Paddings might be inserted between Keccak results of logical inputs.

### Aggregation Circuit

Aggregation circuits aggregate Keccak results of shard circuits and smaller aggregation circuits. Aggregation circuits can bring better scalability.

Implementation is TODO.
