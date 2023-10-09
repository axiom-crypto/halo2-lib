//! Module for managing the virtual region corresponding to [super::FlexGateConfig]
//!
//! In the virtual region we have virtual columns. Each virtual column is referred to as a "thread"
//! because it can be generated in a separate CPU thread. The virtual region manager will collect all
//! threads together, virtually concatenate them all together back into a single virtual column, and
//! then assign this virtual column to multiple physical Halo2 columns according to the provided configuration parameters.
//!
//! Supports multiple phases.

/// Thread builder for multiple phases
mod multi_phase;
mod parallelize;
/// Thread builder for a single phase
pub mod single_phase;

pub use multi_phase::{GateStatistics, MultiPhaseCoreManager};
pub use parallelize::parallelize_core;
pub use single_phase::SinglePhaseCoreManager;

use crate::{utils::BigPrimeField, Context};

/// Abstracts basic context management for custom gate builders.
pub trait ThreadManager<F: BigPrimeField> {
    /// Returns a mutable reference to the [Context] of a gate thread. Spawns a new thread for the given phase, if none exists.
    fn main(&mut self) -> &mut Context<F>;

    /// Returns the number of threads
    fn thread_count(&self) -> usize;

    /// Creates new context but does not append to `self.threads`
    fn new_context(&self, context_id: usize) -> Context<F>;

    /// Spawns a new thread for a new given `phase`. Returns a mutable reference to the [Context] of the new thread.
    /// * `phase`: The phase (index) of the gate thread.
    fn new_thread(&mut self) -> &mut Context<F>;
}

impl<F: BigPrimeField> ThreadManager<F> for SinglePhaseCoreManager<F> {
    fn main(&mut self) -> &mut Context<F> {
        self.main()
    }

    fn thread_count(&self) -> usize {
        self.thread_count()
    }

    fn new_context(&self, context_id: usize) -> Context<F> {
        self.new_context(context_id)
    }

    fn new_thread(&mut self) -> &mut Context<F> {
        self.new_thread()
    }
}
