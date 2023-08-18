use std::iter;

use crate::{
    gates::GateInstructions,
    poseidon::hasher::mds::SparseMDSMatrix,
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};

#[derive(Clone)]
pub(crate) struct PoseidonState<F: ScalarField, const T: usize, const RATE: usize> {
    pub(crate) s: [AssignedValue<F>; T],
}

impl<F: ScalarField, const T: usize, const RATE: usize> PoseidonState<F, T, RATE> {
    pub fn default(ctx: &mut Context<F>) -> Self {
        let mut default_state = [F::ZERO; T];
        // from Section 4.2 of https://eprint.iacr.org/2019/458.pdf
        // • Variable-Input-Length Hashing. The capacity value is 2^64 + (o−1) where o the output length.
        // for our transcript use cases, o = 1
        default_state[0] = F::from_u128(1u128 << 64);
        Self { s: default_state.map(|f| ctx.load_constant(f)) }
    }

    pub fn x_power5_with_constant(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        x: AssignedValue<F>,
        constant: &F,
    ) -> AssignedValue<F> {
        let x2 = gate.mul(ctx, x, x);
        let x4 = gate.mul(ctx, x2, x2);
        gate.mul_add(ctx, x, x4, Constant(*constant))
    }

    pub fn sbox_full(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        constants: &[F; T],
    ) {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(ctx, gate, *x, constant);
        }
    }

    pub fn sbox_part(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        constant: &F,
    ) {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(ctx, gate, *x, constant);
    }

    pub fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        inputs: Vec<AssignedValue<F>>,
        pre_constants: &[F; T],
    ) {
        assert!(inputs.len() < T);

        // Explanation of what's going on: before each round of the poseidon permutation,
        // two things have to be added to the state: inputs (the absorbed elements) and
        // preconstants. Imagine the state as a list of T elements, the first of which is
        // the capacity:  |--cap--|--el1--|--el2--|--elR--|
        // - A preconstant is added to each of all T elements (which is different for each)
        // - The inputs are added to all elements starting from el1 (so, not to the capacity),
        //   to as many elements as inputs are available.
        // - To the first element for which no input is left (if any), an extra 1 is added.

        // adding preconstant to the distinguished capacity element (only one)
        self.s[0] = gate.add(ctx, self.s[0], Constant(pre_constants[0]));

        // adding pre-constants and inputs to the elements for which both are available
        for ((x, constant), input) in
            self.s.iter_mut().zip(pre_constants.iter()).skip(1).zip(inputs.iter())
        {
            *x = gate.sum(ctx, [Existing(*x), Existing(*input), Constant(*constant)]);
        }

        let offset = inputs.len() + 1;
        // adding only pre-constants when no input is left
        for (i, (x, constant)) in
            self.s.iter_mut().zip(pre_constants.iter()).skip(offset).enumerate()
        {
            *x = gate.add(ctx, *x, Constant(if i == 0 { F::ONE + constant } else { *constant }));
            // the if idx == 0 { F::one() } else { F::zero() } is to pad the input with a single 1 and then 0s
            // this is the padding suggested in pg 31 of https://eprint.iacr.org/2019/458.pdf and in Section 4.2 (Variable-Input-Length Hashing. The padding consists of one field element being 1, and the remaining elements being 0.)
        }
    }

    pub fn apply_mds(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        mds: &[[F; T]; T],
    ) {
        let res = mds
            .iter()
            .map(|row| {
                gate.inner_product(ctx, self.s.iter().copied(), row.iter().map(|c| Constant(*c)))
            })
            .collect::<Vec<_>>();

        self.s = res.try_into().unwrap();
    }

    pub fn apply_sparse_mds(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        mds: &SparseMDSMatrix<F, T, RATE>,
    ) {
        self.s = iter::once(gate.inner_product(
            ctx,
            self.s.iter().copied(),
            mds.row.iter().map(|c| Constant(*c)),
        ))
        .chain(
            mds.col_hat
                .iter()
                .zip(self.s.iter().skip(1))
                .map(|(coeff, state)| gate.mul_add(ctx, self.s[0], Constant(*coeff), *state)),
        )
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    }
}
