use crate::{
    gates::GateInstructions,
    poseidon::{spec::OptimizedPoseidonSpec, state::PoseidonState},
    AssignedValue, Context, ScalarField,
};

#[cfg(test)]
mod tests;

/// Module for maximum distance separable matrix operations.
pub mod mds;
/// Module for poseidon specification.
pub mod spec;
/// Module for poseidon states.
pub mod state;

/// Chip for Poseidon hasher. The chip is stateful.
pub struct PoseidonHasherChip<F: ScalarField, const T: usize, const RATE: usize> {
    init_state: PoseidonState<F, T, RATE>,
    state: PoseidonState<F, T, RATE>,
    spec: OptimizedPoseidonSpec<F, T, RATE>,
    absorbing: Vec<AssignedValue<F>>,
}

impl<F: ScalarField, const T: usize, const RATE: usize> PoseidonHasherChip<F, T, RATE> {
    /// Create new Poseidon hasher chip.
    pub fn new<const R_F: usize, const R_P: usize, const SECURE_MDS: usize>(
        ctx: &mut Context<F>,
    ) -> Self {
        let init_state = PoseidonState::<F, T, RATE>::default(ctx);
        let state = init_state.clone();
        Self {
            init_state,
            state,
            spec: OptimizedPoseidonSpec::new::<R_F, R_P, SECURE_MDS>(),
            absorbing: Vec::new(),
        }
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
        let mut input_elements = vec![];
        input_elements.append(&mut self.absorbing);

        let mut padding_offset = 0;

        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, gate, chunk.to_vec());
        }

        if padding_offset == 0 {
            self.permutation(ctx, gate, vec![]);
        }

        self.state.s[1]
    }

    fn permutation(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        inputs: Vec<AssignedValue<F>>,
    ) {
        let r_f = self.spec.r_f / 2;
        let mds = &self.spec.mds_matrices.mds.0;

        let constants = &self.spec.constants.start;
        self.state.absorb_with_pre_constants(ctx, gate, inputs, &constants[0]);
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.state.sbox_full(ctx, gate, constants);
            self.state.apply_mds(ctx, gate, mds);
        }

        let pre_sparse_mds = &self.spec.mds_matrices.pre_sparse_mds.0;
        self.state.sbox_full(ctx, gate, constants.last().unwrap());
        self.state.apply_mds(ctx, gate, pre_sparse_mds);

        let sparse_matrices = &self.spec.mds_matrices.sparse_matrices;
        let constants = &self.spec.constants.partial;
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.state.sbox_part(ctx, gate, constant);
            self.state.apply_sparse_mds(ctx, gate, sparse_mds);
        }

        let constants = &self.spec.constants.end;
        for constants in constants.iter() {
            self.state.sbox_full(ctx, gate, constants);
            self.state.apply_mds(ctx, gate, mds);
        }
        self.state.sbox_full(ctx, gate, &[F::ZERO; T]);
        self.state.apply_mds(ctx, gate, mds);
    }
}
