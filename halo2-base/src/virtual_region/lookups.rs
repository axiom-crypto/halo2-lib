use std::any::TypeId;
use std::mem;
use std::sync::{Arc, Mutex};

use getset::Getters;
use rayon::slice::ParallelSliceMut;

use crate::ff::Field;
use crate::halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column},
};
use crate::utils::halo2::raw_assign_advice;
use crate::AssignedValue;

use super::copy_constraints::SharedCopyConstraintManager;
use super::manager::VirtualRegionManager;

/// If we have a lookup argument that uses `ADVICE_COLS` advice columns and `TABLE_COLS` table columns, where
/// the table is either fixed or dynamic (advice), then we want to dynamically allocate chunks of `ADVICE_COLS` columns
/// that have the lookup into the table **always on** so that:
/// - every time we want to lookup [_; ADVICE_COLS] values, we copy them over to a row in the special
/// lookup-enabled advice columns.
/// - note that just for assignment, we don't need to know anything about the table itself.
///
/// We want this manager to be CPU thread safe, while ensuring that the resulting circuit is
/// deterministic -- the order in which the cells to lookup are added matters.
/// The current solution is to tag the cells to lookup with the context id from the [Context] in which
/// it was called, and then sort them by id. The assumption is that the [Context] is thread-local.
#[derive(Clone, Debug, Getters)]
pub struct LookupAnyManager<F: Field + Ord, const ADVICE_COLS: usize> {
    /// Shared cells to lookup, tagged by context id.
    pub cells_to_lookup: Arc<Mutex<Vec<(usize, [AssignedValue<F>; ADVICE_COLS])>>>,
    /// Global shared copy manager
    pub copy_manager: SharedCopyConstraintManager<F>,
    /// Type id of the cells to lookup, used to tag the copied cells in the special lookup enabled columns.
    type_id: TypeId,
    /// Specify whether constraints should be imposed for additional safety.
    #[getset(get = "pub")]
    witness_gen_only: bool,
}

impl<F: Field + Ord, const ADVICE_COLS: usize> LookupAnyManager<F, ADVICE_COLS> {
    /// Creates a new [LookupAnyManager] with a given copy manager.
    /// * `type_id`: Type id of the cells to lookup, used to tag the copied cells in the special lookup enabled columns.
    ///     * Make sure this is unique for each distinct lookup argument in the circuit!
    pub fn new(
        witness_gen_only: bool,
        type_id: TypeId,
        copy_manager: SharedCopyConstraintManager<F>,
    ) -> Self {
        Self { witness_gen_only, cells_to_lookup: Default::default(), copy_manager, type_id }
    }

    /// Add a lookup argument to the manager.
    pub fn add_lookup(&self, context_id: usize, cells: [AssignedValue<F>; ADVICE_COLS]) {
        self.cells_to_lookup.lock().unwrap().push((context_id, cells));
    }

    /// The total number of virtual rows needed to special lookups
    pub fn total_rows(&self) -> usize {
        self.cells_to_lookup.lock().unwrap().len()
    }

    /// The optimal number of `ADVICE_COLS` chunks of advice columns with lookup enabled for this
    /// particular lookup argument that we should allocate.
    pub fn num_advice_chunks(&self, usable_rows: usize) -> usize {
        let total = self.total_rows();
        (total + usable_rows - 1) / usable_rows
    }
}

impl<F: Field + Ord, const ADVICE_COLS: usize> VirtualRegionManager<F>
    for LookupAnyManager<F, ADVICE_COLS>
{
    type Config = Vec<[Column<Advice>; ADVICE_COLS]>;

    fn assign_raw(&self, config: &Self::Config, region: &mut Region<F>) {
        let mut cells_to_lookup = self.cells_to_lookup.lock().unwrap();
        let mut cells_to_lookup: Vec<_> = mem::take(cells_to_lookup.as_mut());
        cells_to_lookup.par_sort_unstable_by(|(id1, _), (id2, _)| id1.cmp(id2));

        // Copy the cells to the config columns, going left to right, then top to bottom.
        // Will panic if out of rows
        let mut lookup_offset = 0;
        let mut lookup_col = 0;
        for (id, advices) in cells_to_lookup {
            if lookup_col >= config.len() {
                lookup_col = 0;
                lookup_offset += 1;
            }
            for (advice, &column) in advices.into_iter().zip(config[lookup_col].iter()) {
                let bcell =
                    raw_assign_advice(region, column, lookup_offset, Value::known(advice.value));
                if !self.witness_gen_only {
                    let ctx_cell = advice.cell.unwrap();
                    let acell = self
                        .copy_manager
                        .lock()
                        .unwrap()
                        .assigned_advices
                        .get(&ctx_cell)
                        .expect("cell not assigned");
                    region.constrain_equal(*acell, bcell.cell());
                }
            }

            lookup_col += 1;
        }
    }
}
