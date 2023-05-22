use itertools::Itertools;
use rayon::prelude::*;

use crate::{utils::ScalarField, Context};

use super::GateThreadBuilder;

/// Utility function to parallelize an operation involving [`Context`]s in phase `phase`.
pub fn parallelize_in<F, T, R, FR>(
    phase: usize,
    builder: &mut GateThreadBuilder<F>,
    input: Vec<T>,
    f: FR,
) -> Vec<R>
where
    F: ScalarField,
    T: Send,
    R: Send,
    FR: Fn(&mut Context<F>, T) -> R + Send + Sync,
{
    let witness_gen_only = builder.witness_gen_only();
    // to prevent concurrency issues with context id, we generate all the ids first
    let ctx_ids = input.iter().map(|_| builder.get_new_thread_id()).collect_vec();
    let (outputs, mut ctxs): (Vec<_>, Vec<_>) = input
        .into_par_iter()
        .zip(ctx_ids.into_par_iter())
        .map(|(input, ctx_id)| {
            // create new context
            let mut ctx = Context::new(witness_gen_only, ctx_id);
            let output = f(&mut ctx, input);
            (output, ctx)
        })
        .unzip();
    // we collect the new threads to ensure they are a FIXED order, otherwise later `assign_threads_in` will get confused
    builder.threads[phase].append(&mut ctxs);

    outputs
}
