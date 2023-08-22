use std::any::TypeId;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use halo2_proofs_axiom::plonk::Assigned;
use itertools::Itertools;

use crate::halo2_proofs::{
    circuit::{Cell, Region},
    plonk::{Column, Fixed},
};
use crate::utils::halo2::{raw_assign_fixed, raw_constrain_equal, Halo2AssignedCell};
use crate::AssignedValue;
use crate::{ff::Field, ContextCell};

use super::manager::VirtualRegionManager;

/// Thread-safe shared global manager for all copy constraints.
pub type SharedCopyConstraintManager<F> = Arc<Mutex<CopyConstraintManager<F>>>;

/// Global manager for all copy constraints. Thread-safe.
///
/// This will only be accessed during key generation, not proof generation, so it does not need to be optimized.
///
/// Implements [VirtualRegionManager], which should be assigned only after all cells have been assigned
/// by other managers.
#[derive(Clone, Default, Debug)]
pub struct CopyConstraintManager<F: Field + Ord> {
    /// A [Vec] tracking equality constraints between pairs of virtual advice cells, tagged by [ContextCell].
    /// These can be across different virtual regions.
    pub advice_equalities: Vec<(ContextCell, ContextCell)>,

    /// A [Vec] tracking equality constraints between virtual advice cell and fixed values.
    /// Fixed values will only be added once globally.
    pub constant_equalities: Vec<(F, ContextCell)>,

    external_cell_count: usize,

    // In circuit assignments
    /// Advice assignments, mapping from virtual [ContextCell] to assigned physical [Cell].
    pub assigned_advices: HashMap<ContextCell, Cell>,
    /// Constant assignments, (key = constant, value = [Cell])
    pub assigned_constants: BTreeMap<F, Cell>,
}

impl<F: Field + Ord> CopyConstraintManager<F> {
    /// Returns the number of distinct constants used.
    pub fn num_distinct_constants(&self) -> usize {
        self.constant_equalities.iter().map(|(x, _)| x).sorted().dedup().count()
    }

    /// Adds external raw [Halo2AssignedCell] to `self.assigned_advices` and returns a new virtual [AssignedValue]
    /// that can be used in any virtual region. No copy constraint is imposed, as the virtual cell "points" to the
    /// raw assigned cell. The returned [ContextCell] will have `type_id` the `TypeId::of::<Cell>()`.
    pub fn load_external_assigned(
        &mut self,
        assigned_cell: Halo2AssignedCell<F>,
    ) -> AssignedValue<F> {
        let context_cell = self.load_external_cell(assigned_cell.cell());
        let mut value = Assigned::Trivial(F::ZERO);
        assigned_cell.value().map(|v| {
            #[cfg(feature = "halo2-axiom")]
            {
                value = **v;
            }
            #[cfg(not(feature = "halo2-axiom"))]
            {
                value = Assigned::Trivial(*v);
            }
        });
        AssignedValue { value, cell: Some(context_cell) }
    }

    /// Adds external raw Halo2 cell to `self.assigned_advices` and returns a new virtual cell that can be
    /// used as a tag (but will not be re-assigned). The returned [ContextCell] will have `type_id` the `TypeId::of::<Cell>()`.
    pub fn load_external_cell(&mut self, cell: Cell) -> ContextCell {
        let context_cell = ContextCell::new(TypeId::of::<Cell>(), 0, self.external_cell_count);
        self.external_cell_count += 1;
        self.assigned_advices.insert(context_cell, cell);
        context_cell
    }
}

impl<F: Field + Ord> Drop for CopyConstraintManager<F> {
    fn drop(&mut self) {
        if !self.advice_equalities.is_empty() {
            panic!("advice_equalities not empty");
        }
        if !self.constant_equalities.is_empty() {
            panic!("constant_equalities not empty");
        }
    }
}

impl<F: Field + Ord> VirtualRegionManager<F> for SharedCopyConstraintManager<F> {
    // The fixed columns
    type Config = Vec<Column<Fixed>>;

    fn assign_raw(&self, config: &Self::Config, region: &mut Region<F>) -> Self::Assignment {
        let mut manager = self.lock().unwrap();
        // Assign fixed cells, we go left to right, then top to bottom, to avoid needing to know number of rows here
        let mut fixed_col = 0;
        let mut fixed_offset = 0;
        for (c, _) in manager.constant_equalities.iter() {
            if manager.assigned_constants.get(c).is_none() {
                // this will panic if you run out of rows
                let cell = raw_assign_fixed(region, config[fixed_col], fixed_offset, *c);
                manager.assigned_constants.insert(*c, cell);
                fixed_col += 1;
                if fixed_col >= config.len() {
                    fixed_col = 0;
                    fixed_offset += 1;
                }
            }
        }

        // Impose equality constraints between assigned advice cells
        // At this point we assume all cells have been assigned by other VirtualRegionManagers
        for (left, right) in &manager.advice_equalities {
            let left = manager.assigned_advices.get(left).expect("virtual cell not assigned");
            let right = manager.assigned_advices.get(right).expect("virtual cell not assigned");
            raw_constrain_equal(region, *left, *right);
        }
        for (left, right) in &manager.constant_equalities {
            let left = manager.assigned_constants[left];
            let right = manager.assigned_advices.get(right).expect("virtual cell not assigned");
            raw_constrain_equal(region, left, *right);
        }
        manager.advice_equalities.clear();
        manager.constant_equalities.clear();
    }
}
