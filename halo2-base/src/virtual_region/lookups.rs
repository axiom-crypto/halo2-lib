use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use getset::Getters;

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
/// it was called, and add virtual cells sequentially to buckets labelled by id.
/// The virtual cells will be assigned to physical cells sequentially by id.
/// We use a `BTreeMap` for the buckets instead of sorting to cells, to ensure that the order of the cells
/// within a bucket is deterministic.
/// The assumption is that the [Context] is thread-local.
///
/// Cheap to clone across threads because everything is in [Arc].
#[derive(Clone, Debug, Getters)]
pub struct LookupAnyManager<F: Field + Ord, const ADVICE_COLS: usize> {
    /// Shared cells to lookup, tagged by context id.
    #[allow(clippy::type_complexity)]
    pub cells_to_lookup: Arc<Mutex<BTreeMap<usize, Vec<[AssignedValue<F>; ADVICE_COLS]>>>>,
    /// Global shared copy manager
    pub copy_manager: SharedCopyConstraintManager<F>,
    /// Specify whether constraints should be imposed for additional safety.
    #[getset(get = "pub")]
    witness_gen_only: bool,
    /// Flag for whether `assign_raw` has been called, for safety only.
    pub(crate) assigned: Arc<OnceLock<()>>,
}

impl<F: Field + Ord, const ADVICE_COLS: usize> LookupAnyManager<F, ADVICE_COLS> {
    /// Creates a new [LookupAnyManager] with a given copy manager.
    pub fn new(witness_gen_only: bool, copy_manager: SharedCopyConstraintManager<F>) -> Self {
        Self {
            witness_gen_only,
            cells_to_lookup: Default::default(),
            copy_manager,
            assigned: Default::default(),
        }
    }

    /// Add a lookup argument to the manager.
    pub fn add_lookup(&self, context_id: usize, cells: [AssignedValue<F>; ADVICE_COLS]) {
        self.cells_to_lookup
            .lock()
            .unwrap()
            .entry(context_id)
            .and_modify(|thread| thread.push(cells))
            .or_insert(vec![cells]);
    }

    /// The total number of virtual rows needed to special lookups
    pub fn total_rows(&self) -> usize {
        self.cells_to_lookup.lock().unwrap().iter().flat_map(|(_, advices)| advices).count()
    }

    /// The optimal number of `ADVICE_COLS` chunks of advice columns with lookup enabled for this
    /// particular lookup argument that we should allocate.
    pub fn num_advice_chunks(&self, usable_rows: usize) -> usize {
        let total = self.total_rows();
        (total + usable_rows - 1) / usable_rows
    }
}

impl<F: Field + Ord, const ADVICE_COLS: usize> Drop for LookupAnyManager<F, ADVICE_COLS> {
    /// Sanity checks whether the manager has assigned cells to lookup,
    /// to prevent user error.
    fn drop(&mut self) {
        if Arc::strong_count(&self.cells_to_lookup) > 1 {
            return;
        }
        if self.total_rows() > 0 && self.assigned.get().is_none() {
            dbg!("WARNING: LookupAnyManager was not assigned!");
        }
    }
}

impl<F: Field + Ord, const ADVICE_COLS: usize> VirtualRegionManager<F>
    for LookupAnyManager<F, ADVICE_COLS>
{
    type Config = Vec<[Column<Advice>; ADVICE_COLS]>;

    fn assign_raw(&self, config: &Self::Config, region: &mut Region<F>) {
        let cells_to_lookup = self.cells_to_lookup.lock().unwrap();
        // Copy the cells to the config columns, going left to right, then top to bottom.
        // Will panic if out of rows
        let mut lookup_offset = 0;
        let mut lookup_col = 0;
        for advices in cells_to_lookup.iter().flat_map(|(_, advices)| advices) {
            if lookup_col >= config.len() {
                lookup_col = 0;
                lookup_offset += 1;
            }
            for (advice, &column) in advices.iter().zip(config[lookup_col].iter()) {
                let bcell =
                    raw_assign_advice(region, column, lookup_offset, Value::known(advice.value));
                if !self.witness_gen_only {
                    let ctx_cell = advice.cell.unwrap();
                    let copy_manager = self.copy_manager.lock().unwrap();
                    let acell =
                        copy_manager.assigned_advices.get(&ctx_cell).expect("cell not assigned");
                    region.constrain_equal(*acell, bcell.cell());
                }
            }

            lookup_col += 1;
        }
        // We cannot clear `cells_to_lookup` because keygen_vk and keygen_pk both call this function
        let _ = self.assigned.set(());
    }
}
