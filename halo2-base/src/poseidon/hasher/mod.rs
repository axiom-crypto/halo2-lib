use crate::{
    gates::GateInstructions,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, state::PoseidonState},
    safe_types::{RangeInstructions, SafeTypeChip},
    utils::BigPrimeField,
    AssignedValue, Context,
    QuantumCell::Constant,
    ScalarField,
};

use getset::Getters;
use num_bigint::BigUint;
use std::{cell::OnceCell, mem};

#[cfg(test)]
mod tests;

/// Module for maximum distance separable matrix operations.
pub mod mds;
/// Module for poseidon specification.
pub mod spec;
/// Module for poseidon states.
pub mod state;

/// Stateless Poseidon hasher.
pub struct PoseidonHasher<F: ScalarField, const T: usize, const RATE: usize> {
    spec: OptimizedPoseidonSpec<F, T, RATE>,
    consts: OnceCell<PoseidonHasherConsts<F, T, RATE>>,
}
#[derive(Getters)]
struct PoseidonHasherConsts<F: ScalarField, const T: usize, const RATE: usize> {
    #[getset(get = "pub")]
    init_state: PoseidonState<F, T, RATE>,
    // hash of an empty input("").
    #[getset(get = "pub")]
    empty_hash: AssignedValue<F>,
}

impl<F: ScalarField, const T: usize, const RATE: usize> PoseidonHasherConsts<F, T, RATE> {
    pub fn new(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        spec: &OptimizedPoseidonSpec<F, T, RATE>,
    ) -> Self {
        let init_state = PoseidonState::default(ctx);
        let mut state = init_state.clone();
        let empty_hash = fix_len_array_squeeze(ctx, gate, &vec![], &mut state, spec);
        Self { init_state, empty_hash }
    }
}

impl<F: ScalarField, const T: usize, const RATE: usize> PoseidonHasher<F, T, RATE> {
    /// Create a poseidon hasher from an existing spec.
    pub fn new(spec: OptimizedPoseidonSpec<F, T, RATE>) -> Self {
        Self { spec, consts: OnceCell::new() }
    }
    /// Initialize necessary consts of hasher. Must be called before any computation.
    pub fn initialize_consts(&mut self, ctx: &mut Context<F>, gate: &impl GateInstructions<F>) {
        self.consts.get_or_init(|| PoseidonHasherConsts::<F, T, RATE>::new(ctx, gate, &self.spec));
    }

    fn empty_hash(&self) -> &AssignedValue<F> {
        self.consts.get().unwrap().empty_hash()
    }
    fn init_state(&self) -> &PoseidonState<F, T, RATE> {
        self.consts.get().unwrap().init_state()
    }

    /// Constrains and returns hash of a witness array with a variable length.
    ///
    /// Assumes `len` is within [usize] and `len <= inputs.len()`.
    /// * inputs: An right-padded array of [AssignedValue]. Constraints on paddings are not required.
    /// * len: Length of `inputs`.
    /// Return hash of `inputs`.
    pub fn hash_var_len_array(
        &self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
        inputs: &Vec<AssignedValue<F>>,
        len: AssignedValue<F>,
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let max_len = inputs.len();
        if max_len == 0 {
            return *self.empty_hash();
        };

        // len <= max_len --> num_of_bits(len) <= num_of_bits(max_len)
        let num_bits = (usize::BITS - max_len.leading_zeros()) as usize;
        // num_perm = len // RATE + 1, len_last_chunk = len % RATE
        let (mut num_perm, len_last_chunk) = range.div_mod(ctx, len, BigUint::from(RATE), num_bits);
        num_perm = range.gate().inc(ctx, num_perm);

        let mut state = self.init_state().clone();
        let mut result_state = state.clone();
        for (i, chunk) in inputs.chunks(RATE).enumerate() {
            let is_last_perm =
                range.gate().is_equal(ctx, num_perm, Constant(F::from((i + 1) as u64)));
            let len_chunk = range.gate().select(
                ctx,
                len_last_chunk,
                Constant(F::from(RATE as u64)),
                is_last_perm,
            );

            state.permutation(ctx, range.gate(), &chunk.to_vec(), Some(len_chunk), &self.spec);
            result_state.select(
                ctx,
                range.gate(),
                SafeTypeChip::<F>::unsafe_to_bool(is_last_perm),
                &state,
            );
        }
        if max_len % RATE == 0 {
            let is_last_perm = range.gate().is_equal(
                ctx,
                num_perm,
                Constant(F::from((max_len / RATE + 1) as u64)),
            );
            let len_chunk = ctx.load_zero();
            state.permutation(ctx, range.gate(), &vec![], Some(len_chunk), &self.spec);
            result_state.select(
                ctx,
                range.gate(),
                SafeTypeChip::<F>::unsafe_to_bool(is_last_perm),
                &state,
            );
        }
        result_state.s[1]
    }

    /// Constrains and returns hash of a witness array.
    ///
    /// * inputs: An array of [AssignedValue].
    /// Return hash of `inputs`.
    pub fn hash_fix_len_array(
        &self,
        ctx: &mut Context<F>,
        range: &impl RangeInstructions<F>,
        inputs: &Vec<AssignedValue<F>>,
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let mut state = self.init_state().clone();
        fix_len_array_squeeze(ctx, range.gate(), inputs, &mut state, &self.spec)
    }
}

/// Poseidon sponge. This is stateful.
pub struct PoseidonSponge<F: ScalarField, const T: usize, const RATE: usize> {
    init_state: PoseidonState<F, T, RATE>,
    state: PoseidonState<F, T, RATE>,
    spec: OptimizedPoseidonSpec<F, T, RATE>,
    absorbing: Vec<AssignedValue<F>>,
}

impl<F: ScalarField, const T: usize, const RATE: usize> PoseidonSponge<F, T, RATE> {
    /// Create new Poseidon hasher.
    pub fn new<const R_F: usize, const R_P: usize, const SECURE_MDS: usize>(
        ctx: &mut Context<F>,
    ) -> Self {
        let init_state = PoseidonState::default(ctx);
        let state = init_state.clone();
        Self {
            init_state,
            state,
            spec: OptimizedPoseidonSpec::new::<R_F, R_P, SECURE_MDS>(),
            absorbing: Vec::new(),
        }
    }

    /// Initialize a poseidon hasher from an existing spec.
    pub fn from_spec(ctx: &mut Context<F>, spec: OptimizedPoseidonSpec<F, T, RATE>) -> Self {
        let init_state = PoseidonState::default(ctx);
        Self { spec, state: init_state.clone(), init_state, absorbing: Vec::new() }
    }

    /// Reset state to default and clear the buffer.
    pub fn clear(&mut self) {
        self.state = self.init_state.clone();
        self.absorbing.clear();
    }

    /// Store given `elements` into buffer.
    pub fn update(&mut self, elements: &[AssignedValue<F>]) {
        self.absorbing.extend_from_slice(elements);
    }

    /// Consume buffer and perform permutation, then output second element of
    /// state.
    pub fn squeeze(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> AssignedValue<F> {
        let input_elements = mem::take(&mut self.absorbing);
        fix_len_array_squeeze(ctx, gate, &input_elements, &mut self.state, &self.spec)
    }
}

fn fix_len_array_squeeze<F: ScalarField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    gate: &impl GateInstructions<F>,
    input_elements: &Vec<AssignedValue<F>>,
    state: &mut PoseidonState<F, T, RATE>,
    spec: &OptimizedPoseidonSpec<F, T, RATE>,
) -> AssignedValue<F> {
    let exact = input_elements.len() % RATE == 0;

    for chunk in input_elements.chunks(RATE) {
        state.permutation(ctx, gate, &chunk.to_vec(), None, spec);
    }
    if exact {
        state.permutation(ctx, gate, &vec![], None, spec);
    }

    state.s[1]
}
