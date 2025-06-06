# halo2-lib

> ⚠️ **This branch contains unaudited contributions from the community.** Community contributions in this branch have been reviewed by maintainers of this repository, but they have not undergone an official audit. To use the latest audited version make sure to use the correct commit. The tagged versions that have undergone an official audit and are ready for production use can be found in the [releases](https://github.com/axiom-crypto/halo2-lib/releases).

This repository aims to provide basic primitives for writing zero-knowledge proof circuits using the [Halo 2](https://zcash.github.io/halo2/) proving stack. To discuss or collaborate, join our community on [Telegram](https://t.me/halo2lib).

## Getting Started

For a brief introduction to zero-knowledge proofs (ZK), see this [doc](https://docs.axiom.xyz/zero-knowledge-proofs/introduction-to-zk).

Halo 2 is written in Rust, so you need to [install](https://www.rust-lang.org/tools/install) Rust to use this library:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone this repo and start off in the `halo2-lib` directory.

```bash
git clone https://github.com/axiom-crypto/halo2-lib.git
cd halo2-lib
```

## Projects built with `halo2-lib`

- [Axiom](https://github.com/axiom-crypto/axiom-eth) -- Prove facts about Ethereum on-chain data via aggregate block header, account, and storage proofs.
- [Proof of Email](https://github.com/zkemail/) -- Prove facts about emails with the same trust assumption as the email domain.
  - [halo2-regex](https://github.com/zkemail/halo2-regex)
  - [halo2-zk-email](https://github.com/zkemail/halo2-zk-email)
  - [halo2-base64](https://github.com/zkemail/halo2-base64)
  - [halo2-rsa](https://github.com/zkemail/halo2-rsa/tree/feat/new_bigint)
- [halo2-fri-gadget](https://github.com/maxgillett/halo2-fri-gadget) -- FRI verifier in halo2.
- [eth-voice-recovery](https://github.com/SoraSuegami/voice_recovery_circuit) -- Verify the voice recovery process.
- [PLUME ERC 7524 Signatures](https://github.com/plume-sig/zk-nullifier-sig/pull/83) - Verify deterministic PLUME signatures of Ethereum keys, for private voting nullifiers.
- [zkEVM signature verification circuit](https://github.com/scroll-tech/zkevm-circuits/tree/develop/zkevm-circuits/src/sig_circuit.rs)
- [zkEVM tx-circuit](https://github.com/scroll-tech/zkevm-circuits/tree/develop/zkevm-circuits/src/tx_circuit)
- [webauthn-halo2](https://github.com/zkwebauthn/webauthn-halo2) -- Proving and verifying WebAuthn with halo2.
- [Fixed Point Arithmetic](https://github.com/DCMMC/halo2-scaffold/tree/main/src/gadget) -- Fixed point arithmetic library in halo2.
- [Spectre](https://github.com/ChainSafe/Spectre) -- Verifying Beacon chain headers via Altair light client protocol
- [halo2-nn-wasm](https://github.com/metavind/halo2-nn-wasm) -- Neural network in halo2 for WASM.
- [halo2-cairo](https://github.com/odyssey2077/halo2-cairo) -- Prove Cairo program execution in halo2.
- [indexed-merkle-tree](https://github.com/aerius-labs/indexed-merkle-tree-halo2) -- Indexed Merkle Tree operations in halo2.
- [zkCert](https://github.com/zkCert/halo2-zkcert) -- Verify a chain of x509 certificates in halo2.
- [zk-dcap-verifier](https://github.com/CliqueOfficial/zk-dcap-verifier) -- On-chain DCAP attestation verification.
- [MynaWallet](https://github.com/MynaWallet/monorepo/tree/develop/packages/halo2-circuits) -- Verifies RSA signatures signed by Myna Card (Japan's ID Card).
- [zk-face-circuit](https://github.com/team-byof/zk-face-circuit) -- Face Wallet Verification system for Ethereum wallets.
- [halo2-lib-secp256r1](https://github.com/CliqueOfficial/halo2-lib-secp256r1)

## halo2-base

This crate provides an additional API for writing circuits in Halo 2 using our [simple vertical gate](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2#halo2-lib). It also provides basic functions built using this API. The provided methods can be found in [`GateInstructions`](https://axiom-crypto.github.io/halo2-lib/halo2_base/gates/flex_gate/trait.GateInstructions.html) and [`RangeInstructions`](https://axiom-crypto.github.io/halo2-lib/halo2_base/gates/range/trait.RangeInstructions.html). The latter are operations that require using a lookup table for range checks.

- Read the [Rust docs](https://docs.rs/halo2-base/0.4.1/halo2_base/) for this crate.
- To get started with Halo 2 and to learn how to build using the `halo2-base` API, see the [Getting Started](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2) guide.

To run some basic tests, run the following command:

```bash
cargo test -- --nocapture test_gates
cargo test -- --nocapture test_range
```

(Rust tests by default do not display stdout, so we use `--nocapture` to enable streaming stdout.)
These tests use the `MockProver` to check circuits are properly constrained, however it does not mimic a true production proving setup.

For benchmarks of native field multiplication and inner product where a production proving setup is run, run the following command:

```bash
cargo bench --bench mul
cargo bench --bench inner_product
```

These benchmarks use the `criterion` crate to run `create_proof` 10 times for statistical analysis. Note the benchmark circuits perform more than one multiplication / inner product per circuit.

## halo2-ecc

This crate uses `halo2-base` to provide a library of elliptic curve cryptographic primitives. In particular, we support elliptic curves over base fields that are larger than the scalar field used in the proving system (e.g., `F_r` for bn254 when using Halo 2 with a KZG backend).

- [Rust docs](https://axiom-crypto.github.io/halo2-lib/halo2_ecc/index.html)

### Features

We recommend ignoring this section and using the default features if you are new to Rust.
The default features are: "jemallocator", "halo2-axiom", "display".
You can turn off "display" for a very small performance increase, where certain statistics about the circuit are not
computed and printed.

**Exactly one** of "halo2-axiom" or "halo2-pse" feature should be turned on at all times.

- The "halo2-axiom" feature uses our [`halo2_proofs`](https://github.com/axiom-crypto/halo2) which is a fork of the [PSE one](https://github.com/privacy-scaling-explorations/halo2) which we have slightly optimized for proving speed.
- The "halo2-pse" feature uses the Privacy Scaling Explorations [`halo2_proofs`](https://github.com/privacy-scaling-explorations/halo2) which is the most stable and has the most reviewers.

We guarantee that the proofs generated by the two forks are identical.

#### Memory allocator

The "jemallocator" feature uses the [jemallocator](https://crates.io/crates/jemallocator) crate for memory allocation.
You can turn it off to use the system allocator. Or use feature "mimalloc" to use the [mimalloc](https://crates.io/crates/mimalloc) crate. We have found the performance of these allocators heavily depends on what machine you are running on.

### Modules

- `bigint`: Provides support for optimized big integer arithmetic in ZK.
- `fields`: Provides common functions for prime field arithmetic, optimized for prime fields that are larger than the scalar field used in the proving system.
  - `fp2`: Field operations over certain quadratic extension fields.
  - `fp12`: Field operations over certain degree `12` extension fields (designed with BN254 and BLS12-381 in mind).
- `ecc`: Library of elliptic curve cryptographic primitives, currently for short Weierstrass curves over base fields compatible with `fields` module (in particular field extension are allowed).
  - Elliptic curve addition and doubling.
  - Scalar multiplication and multiscalar multiplication (MSM, multiexp). Implementations are ZK-optimized, using windowed methods and Pippenger's algorithm when appropriate.
  - ECDSA signature verification.
- `secp256k1`: Specialization of the `ecc` module for the secp256k1 curve.
  - `test_secp256k1_ecdsa` and `bench_secp256k1_ecdsa` show how to implement ECDSA signature verification for secp256k1. (More details below.)
- `bn254`: Specialization of the `ecc` module for the BN254 curve.
  - `final_exp` and `pairing` modules together implement the optimal Ate pairing for BN254 in ZK. The implementation has been optimized for the specifics of BN curves, but can be easily adapted to BLS curves (coming soon!).

### Tests with `MockProver`

**Do not run `cargo test` without any filters.**
Some of the tests are actually benchmarks, and will take a long time to run.

#### Setup

All tests should be run in the `halo2-lib/halo2-ecc` directory.
Some tests read files from specific directories, so they will not work if
you are in the `halo2-lib` root directory.

For benchmarks below, you can symlink a `params` folder within `halo2-ecc` directory with previously generated universal trusted setup files. Otherwise, the benchmarks will generate a new random setup and save them in the `params` directory. **Warning:** These trusted setups are generated using a _known_ random seed, so they are not secure. They should NOT be used in production.
For more a production suitable trusted setup, see [KZG Trusted Setup](https://docs.axiom.xyz/docs/transparency-and-security/kzg-trusted-setup).

Tests can be run in the same way as in the previous [section](#halo2-base). The available commands are:

```bash
cargo test -- --nocapture test_fp
cargo test -- --nocapture test_fp12
cargo test -- --nocapture test_ecc
cargo test -- --nocapture test_secp256k1_ecdsa
cargo test -- --nocapture test_ec_add # for BN254
cargo test -- --nocapture test_fixed_base_msm # for BN254
cargo test -- --nocapture test_msm # for BN254
cargo test -- --nocapture test_pairing # for BN254
```

### Configurable Circuits

A special features of circuits written using `halo2-base` is that any such circuit can be configured to have a different number of rows vs. columns, while keeping the total number of cells roughly the same. Different configurations make sense for different circumstances. For example, more rows vs. columns always leads to a cheaper gas cost for on-chain verification, but often at the cost of slower proving speed. For a rough mental model, see [Cost Modeling](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2#cost-modeling).

In some of the tests above, the circuit configuration is read from a file. You can change the configuration by changing the numbers in the file. If some numbers are too small, the test will panic because there are not enough cells to construct the circuit. If you put numbers that are too large, the test will display suggestions for what the optimal numbers should be.
In a future version we will have the circuits auto-configure themselves.

The benchmark config files below also give a list of possible configurations you can put in a test config files.

The test config file locations are (relative to `halo2-ecc` directory):
| Test | Config File |
| --- | --- |
| `test_secp256k1_ecdsa` | `src/secp256k1/configs/ecdsa_circuit.config` |
| `test_ec_add` | `src/bn254/configs/ec_add_circuit.config` |
| `test_fixed_base_msm` | `src/bn254/configs/fixed_msm_circuit.config` |
| `test_msm` | `src/bn254/configs/msm_circuit.config` |
| `test_pairing` | `src/bn254/configs/pairing_circuit.config` |

## Benchmarks

We have tests that are actually benchmarks using the production Halo2 prover.
As mentioned [above](#Configurable-Circuits), there are different configurations for each circuit that lead to _very_ different proving times. The following benchmarks will take a list of possible configurations and benchmark each one. The results are saved in a file in the `results` directory. We currently supply the configuration lists, which should provide optimal configurations for a given circuit degree `k` (however you can check versus the stdout suggestions to see if they really are optimal!).

We run the benchmarks in `--release` mode for maximum speed.

#### Commands

The available benchmark commands are:

```bash
cargo test --release -- --nocapture bench_secp256k1_ecdsa
cargo test --release -- --nocapture bench_ec_add
cargo test --release -- --nocapture bench_fixed_base_msm
cargo test --release -- --nocapture bench_msm
cargo test --release -- --nocapture bench_pairing
```

The locations of the config and result files (relative to `halo2-ecc` directory) are:
| Benchmark | Config File | Results File |
| --- | --- | --- |
| `bench_secp256k1_ecdsa` | `src/secp256k1/configs/bench_ecdsa.config` | `src/secp256k1/results/ecdsa_bench.csv` |
| `bench_ec_add` | `src/bn254/configs/bench_ec_add.config` | `src/bn254/results/ec_add_bench.csv` |
| `bench_fixed_base_msm` | `src/bn254/configs/bench_fixed_msm.config` | `src/bn254/results/fixed_msm_bench.csv` |
| `bench_msm` | `src/bn254/configs/bench_msm.config` | `src/bn254/results/msm_bench.csv` |
| `bench_pairing` | `src/bn254/configs/bench_pairing.config` | `src/bn254/results/pairing_bench.csv` |

To speed up benching time you can remove certain lines from the `.config` file for configurations you don't want to bench.

#### Criterion Benchmarks

To run more accurate benchmarks using the `criterion` crate, you can run the following commands:

```bash
cargo bench --bench msm
cargo bench --bench fixed_base_msm
cargo bench --bench fp_mul
```

This runs the same proof generation over 10 runs and collect the average. Each circuit has a fixed configuration chosen for optimal speed. These benchmarks are mostly for use in performance optimization.

### Secp256k1 ECDSA

We provide benchmarks for ECDSA signature verification for the Secp256k1 curve on several different machines. All machines only use CPUs.

On AWS EC2 instances r6a.8xl (AMD, x86) and r6g.8xl (Graviton, arm64), both with 32 CPU cores, 256 GB RAM, the bench is run using

```
cargo test --release --no-default-features --features "halo2-axiom, jemallocator" -- --nocapture bench_secp256k1_ecdsa
```

To optimize memory allocation to prioritize CPU utilization,
we [tune jemallocator](https://github.com/jemalloc/jemalloc/blob/dev/TUNING.md) with

```bash
export JEMALLOC_SYS_WITH_MALLOC_CONF="background_thread:true,metadata_thp:always,dirty_decay_ms:100000,muzzy_decay_ms:100000,narenas:1,abort_conf:true"
```

(in practice this did not make a big difference).

On a M2 Max Macbook Pro (12 CPU cores, 96 GB RAM) we ran the bench using

```
cargo test --release --no-default-features --features "halo2-axiom, mimalloc" -- --nocapture bench_secp256k1_ecdsa
```

(the performance of "mimalloc" vs "jemallocator" was similar).

The other columns provide information about the [PLONKish arithmetization](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2#plonkish-arithmetization).

| `k` | Num Advice | Num Lookup Advice | Num Fixed | Proof Time (M2 Max) | Proof Time (r6a.8xl) | Proof Time (r6g.8xl) |
| --- | ---------- | ----------------- | --------- | ------------------- | -------------------- | -------------------- |
| 11  | 291        | 53                | 4         | 3.5s                | 7.3s                 | 7.2s                 |
| 12  | 139        | 24                | 2         | 2.6s                | 3.3s                 | 5.3s                 |
| 13  | 68         | 12                | 1         | 2.2s                | 2.6s                 | 4.7s                 |
| 14  | 34         | 6                 | 1         | 2.1s                | 2.4s                 | 4.5s                 |
| 15  | 17         | 3                 | 1         | `1.98s` ⚡          | 2.28s                | 4.5s                 |
| 16  | 8          | 2                 | 1         | 2.3s                | 2.5s                 | 5.2s                 |
| 17  | 4          | 1                 | 1         | 2.7s                | 2.9s                 | 6s                   |
| 18  | 2          | 1                 | 1         | 4.4s                | 4.7s                 | 9.5s                 |
| 19  | 1          | 1                 | 1         | 7.6s                | 7.6s                 | 16s                  |

The r6a has a higher clock speed than the r6g.

### BN254 Pairing

We provide benchmarks of the optimal Ate pairing for BN254 on several different machines. All machines only use CPUs.

On AWS EC2 instances r6a.8xl (AMD, x86) and r6g.8xl (Graviton, arm64), both with 32 CPU cores, 256 GB RAM, the bench is run using

```
cargo test --release --no-default-features --features "halo2-axiom, jemallocator" -- --nocapture bench_pairing
```

To optimize memory allocation to prioritize CPU utilization,
we [tune jemallocator](https://github.com/jemalloc/jemalloc/blob/dev/TUNING.md) with

```bash
export JEMALLOC_SYS_WITH_MALLOC_CONF="background_thread:true,metadata_thp:always,dirty_decay_ms:100000,muzzy_decay_ms:100000,narenas:1,abort_conf:true"
```

(in practice this did not make a big difference).

On a M2 Max Macbook Pro (12 CPU cores, 96 GB RAM) we ran the bench using

```
cargo test --release --no-default-features --features "halo2-axiom, mimalloc" -- --nocapture bench_pairing
```

(the performance of "mimalloc" vs "jemallocator" was similar).

The other columns provide information about the [PLONKish arithmetization](https://docs.axiom.xyz/zero-knowledge-proofs/getting-started-with-halo2#plonkish-arithmetization).

| `k` | Num Advice | Num Lookup Advice | Num Fixed | Proof Time (M2 Max) | Proof Time (r6a.8xl) | Proof Time (r6g.8xl) |
| --- | ---------- | ----------------- | --------- | ------------------- | -------------------- | -------------------- |
| 14  | 211        | 27                | 1         | 11.8s               | 16.9s                | 24.8s                |
| 15  | 105        | 14                | 1         | 10.4s               | 12.7s                | 23.6s                |
| 16  | 50         | 6                 | 1         | `9.5s` ⚡           | 10.96s               | 21.6s                |
| 17  | 25         | 3                 | 1         | 9.7s                | 11.2s                | 22.7s                |
| 18  | 13         | 2                 | 1         | 11.9s               | 13.5s                | 27.3s                |
| 19  | 6          | 1                 | 1         | 14.8s               | 15.3s                | 30.6s                |
| 20  | 3          | 1                 | 1         | 23.7s               | 23.8s                | 48.1s                |
| 21  | 2          | 1                 | 1         | 40.3s               | 40.8s                | 82.5s                |
| 22  | 1          | 1                 | 1         | 69.1s               | 66.9s                | 135s                 |

The r6a has a higher clock speed than the r6g. We hypothesize that the Apple Silicon integrated memory leads to the faster performance on the M2 Max.

### BN254 MSM

We provide benchmarks of multi-scalar multiplication (MSM, multi-exp) with a batch size of `100` for BN254.

On an M2 Max Macbook Pro (12 CPU cores, 96 GB RAM) we ran the bench using

```
cargo test --release --no-default-features --features "halo2-axiom, mimalloc" -- --nocapture bench_msm
```

| `k` | Num Advice | Num Lookup Advice | Num Fixed | Proof Time (M2 Max) |
| --- | ---------- | ----------------- | --------- | ------------------- |
| 17  | 84         | 11                | 1         | `27.8s` ⚡          |
| 18  | 42         | 6                 | 1         | 29.95s              |
| 19  | 20         | 3                 | 1         | 32.6s               |
| 20  | 11         | 2                 | 1         | 41.3s               |
| 21  | 6          | 1                 | 1         | 51.9s               |
