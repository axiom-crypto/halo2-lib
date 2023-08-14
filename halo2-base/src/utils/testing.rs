//! Utilities for testing
use crate::{
    gates::{
        builder::{GateThreadBuilder, RangeCircuitBuilder},
        GateChip,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme, commitment::ParamsKZG, multiopen::ProverSHPLONK,
            multiopen::VerifierSHPLONK, strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    },
    safe_types::RangeChip,
    Context,
};
use halo2_proofs_axiom::dev::MockProver;
use rand::{rngs::StdRng, SeedableRng};

/// helper function to generate a proof with real prover
pub fn gen_proof(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
) -> Vec<u8> {
    let rng = StdRng::seed_from_u64(0);
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<_>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, _>,
        _,
    >(params, pk, &[circuit], &[&[]], rng, &mut transcript)
    .expect("prover should not fail");
    transcript.finalize()
}

/// helper function to verify a proof
pub fn check_proof(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    expect_satisfied: bool,
) {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    let res = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, &[&[]], &mut transcript);

    if expect_satisfied {
        assert!(res.is_ok());
    } else {
        assert!(res.is_err());
    }
}

/// Helper to facilitate easier writing of tests using `RangeChip` and `RangeCircuitBuilder`.
/// By default, the [`MockProver`] is used.
///
/// Currently this tester uses all private inputs.
pub struct BaseTester {
    k: u32,
    lookup_bits: Option<usize>,
    expect_satisfied: bool,
}

impl Default for BaseTester {
    fn default() -> Self {
        Self { k: 10, lookup_bits: Some(9), expect_satisfied: true }
    }
}

/// Creates a [`BaseTester`]
pub fn base_test() -> BaseTester {
    BaseTester::default()
}

impl BaseTester {
    /// Changes the number of rows in the circuit to 2<sup>k</sup>.
    /// By default it will also set lookup bits as large as possible, to `k - 1`.
    pub fn k(mut self, k: u32) -> Self {
        self.k = k;
        self.lookup_bits = Some(k as usize - 1);
        self
    }

    /// Sets the size of the lookup table used for range checks to [0, 2<sup>lookup_bits</sup>)
    pub fn lookup_bits(mut self, lookup_bits: usize) -> Self {
        assert!(lookup_bits < self.k as usize, "lookup_bits must be less than k");
        self.lookup_bits = Some(lookup_bits);
        self
    }

    /// Specify whether you expect this test to pass or fail. Default: pass
    pub fn expect_satisfied(mut self, expect_satisfied: bool) -> Self {
        self.expect_satisfied = expect_satisfied;
        self
    }

    /// Run a mock test by providing a closure that uses a `ctx` and `RangeChip`.
    /// - `expect_satisfied`: flag for whether you expect the test to pass or fail. Failure means a constraint system failure -- the tester does not catch system panics.
    pub fn run<R>(&self, f: impl FnOnce(&mut Context<Fr>, &RangeChip<Fr>) -> R) -> R {
        self.run_builder(|builder, range| f(builder.main(0), range))
    }

    /// Run a mock test by providing a closure that uses a `ctx` and `GateChip`.
    /// - `expect_satisfied`: flag for whether you expect the test to pass or fail. Failure means a constraint system failure -- the tester does not catch system panics.
    pub fn run_gate<R>(&self, f: impl FnOnce(&mut Context<Fr>, &GateChip<Fr>) -> R) -> R {
        self.run(|ctx, range| f(ctx, &range.gate))
    }

    /// Run a mock test by providing a closure that uses a `builder` and `RangeChip`.
    /// - `expect_satisfied`: flag for whether you expect the test to pass or fail. Failure means a constraint system failure -- the tester does not catch system panics.
    pub fn run_builder<R>(
        &self,
        f: impl FnOnce(&mut GateThreadBuilder<Fr>, &RangeChip<Fr>) -> R,
    ) -> R {
        let mut builder = GateThreadBuilder::mock();
        let range = RangeChip::default(self.lookup_bits.unwrap_or(0));
        // run the function, mutating `builder`
        let res = f(&mut builder, &range);

        // helper check: if your function didn't use lookups, turn lookup table "off"
        let t_cells_lookup = builder
            .threads
            .iter()
            .map(|t| t.iter().map(|ctx| ctx.cells_to_lookup.len()).sum::<usize>())
            .sum::<usize>();
        let lookup_bits = if t_cells_lookup == 0 { None } else { self.lookup_bits };

        // configure the circuit shape, 9 blinding rows seems enough
        let config_params = builder.config(self.k as usize, Some(9), lookup_bits);
        // create circuit
        let circuit = RangeCircuitBuilder::mock(builder, config_params);
        if self.expect_satisfied {
            MockProver::run(self.k, &circuit, vec![]).unwrap().assert_satisfied();
        } else {
            assert!(MockProver::run(self.k, &circuit, vec![]).unwrap().verify().is_err());
        }
        res
    }
}
