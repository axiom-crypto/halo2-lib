# ZKEVM Keccka
## Vanilla
Keccak circuit in vanilla halo2. This implementation starts from Scroll's version then adopts some changes from [this PR](https://github.com/scroll-tech/zkevm-circuits/pull/216) and [PSE version](https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit).

The majoir differences is that this version directly represent raw inputs and Keccak results as witnesses, while the original version only has RLCs(random linear combination) of raw inputs and Keccak results. Becuase this version doesn't need RLCs, it doesn't have the 2nd phase or use challenage APIs.

### Logical Input/Output
Logically the circuit takes an array of bytes and Keccak results of these bytes. 

`keccak::vanilla::witness::multi_keccak` generates the witnesses of the ciruit for a given input.
### Background Knowledge
All these items are same in all versions.
- Keccak process a logical input `keccak_f` by `keccak_f`. 
- Each `keccak_f` has `NUM_ROUNDS`(24) rounds.
- The number of rows of a round(`rows_per_round`) is configurable. Usually less rows means less wasted cells.
- Each `keccak_f` takes `(NUM_ROUNDS + 1) * rows_per_round` rows. The last `rows_per_round` rows could be considered as a virtual round for "squeeze".
- An input is always padded to a multiple of `RATE`(136) bytes. If the length of a logical input is already a multiple of `RATE`, another `RATE` bytes will be padded.
- Each `keccak_f` absorbs `RATE` bytes, which are splitted into `NUM_WORDS_TO_ABSORB`(17) words. Each word has `NUM_BYTES_PER_WORD`(8) bytes.
- Each of the first `NUM_WORDS_TO_ABSORB`(17) rounds of each `keccak_f` absorbs a word.
- `is_final`(anothe name is `is_enabled`) can be true only at the first row of a round. It must be true if at least a padding has been absorbed by this round. It indicates the end of a logical input.
- The first round of the circuit is a dummy round, which doesn't crespond to any input.

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
- `hash_lo` is the low 128 bits of Keccak results. `hash_hi` is the low 128 bits of Keccak results.

### Change Details
- Removed column `input_rlc`/`input_len` and related gates.
- Removed column `output_rlc` and related gates.
- Removed challenges.
- Refactored the folder strcuture to follow [Scroll's repo](https://github.com/scroll-tech/zkevm-circuits/tree/95f82762cfec46140d6866c34a420ee1fc1e27c7/zkevm-circuits/src/keccak_circuit). `mod.rs` and `witness.rs` could be found [here](https://github.com/scroll-tech/zkevm-circuits/blob/develop/zkevm-circuits/src/keccak_circuit.rs). `KeccakTable` could be found [here](https://github.com/scroll-tech/zkevm-circuits/blob/95f82762cfec46140d6866c34a420ee1fc1e27c7/zkevm-circuits/src/table.rs#L1308).
- Imported utilites from [PSE zkevm-circuits repo](https://github.com/privacy-scaling-explorations/zkevm-circuits/blob/588b8b8c55bf639fc5cbf7eae575da922ea7f1fd/zkevm-circuits/src/util/word.rs). 

## Coprocessor
Keccak coprocessor circuits and utilities based on Halo2lib.

### Motivation
Move expensive Keccak computation into standalone circuits(**Coprocessor Circuits**) and circuits with actual business logic(**App Circuits**) can read Keccak results from coprocessor circuits. Then we have better scalability the maximum size of a single circuit could be managed and coprocessor/app circuits could be proved in paralle.

### Output
Logically a coprocessor ciruit outputs 3 columns `lookup_key`, `hash_lo`, `hash_hi` with `capacity` rows, where `capacity` is a configurable parameter and it means the maximum number of keccak_f this circuit can perform.

- `lookup_key` can be cheaply derived from a bytes input. Specs can be found at `keccak::coprocessor::encode::encode_native_input`. Also `keccak::coprocessor::encode` provides some utilities to encode bytes inputs in halo2lib.
- `hash_lo`/`hash_hi` are low/high 128 bits of the corresponding Keccak result.

There 2 ways to publish circuit outputs:

- Publish all these 3 columns as 3 public instance columns.
- Publish the commitment of all these 3 columns as a single public instance.

Developers can choose either way according to their needs. Specs of these 2 ways can be found at `keccak::coprocessor::circuit::leaf::KeccakCoprocessorLeafCircuit::publish_outputs`.

`keccak::coprocessor::output` provides utilities to compute coprocessor circuit outputs for given inputs. App circuits could use these utilities to load Keccak results before witness generation of corpocessor circuits.

### Leaf Circuit
Implementation: `keccak::coprocessor::circuit::leaf::KeccakCoprocessorLeafCircuit`
- Leaf circuits are the circuits that actually perform Keccak computation. 
- Logically leaf circuits take an array of bytes as inputs.
- Leaf circuits follow the coprocessor output format above.
- Leaf circuits have a configurable parameter `capacity`, which is the maximum number of keccak_f this circuit can perform.
- Leaf circuits' outputs have Keccak results of all logical inputs. Outputs are padded into `capacity` rows with Keccak results of "". Paddings might be inserted between Keccak results of logical inputs.

### Aggregation Circuit
Aggregation circuits aggregate Keecak results of leaf circuits and smaller aggregation circuits. Aggregation circuits can bring better scalability.

Implementation is TODO.