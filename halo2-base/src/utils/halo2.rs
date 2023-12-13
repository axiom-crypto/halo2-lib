use std::collections::hash_map::Entry;

use crate::ff::Field;
use crate::halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Assigned, Column, Fixed, Circuit},
};
use crate::virtual_region::copy_constraints::{CopyConstraintManager, EXTERNAL_CELL_TYPE_ID};
use crate::AssignedValue;

/// Raw (physical) assigned cell in Plonkish arithmetization.
#[cfg(any(feature = "halo2-axiom", feature = "halo2-axiom-icicle"))]
pub type Halo2AssignedCell<'v, F> = AssignedCell<&'v Assigned<F>, F>;
/// Raw (physical) assigned cell in Plonkish arithmetization.
#[cfg(any(feature = "halo2-pse", feature = "halo2-icicle"))]
pub type Halo2AssignedCell<'v, F> = AssignedCell<Assigned<F>, F>;

/// Assign advice to physical region.
#[inline(always)]
pub fn raw_assign_advice<'v, F: Field>(
    region: &mut Region<F>,
    column: Column<Advice>,
    offset: usize,
    value: Value<impl Into<Assigned<F>>>,
) -> Halo2AssignedCell<'v, F> {
    #[cfg(any(feature = "halo2-axiom", feature = "halo2-axiom-icicle"))]
    {
        region.assign_advice(column, offset, value)
    }
    #[cfg(any(feature = "halo2-pse", feature = "halo2-icicle"))]
    {
        let value = value.map(|a| Into::<Assigned<F>>::into(a));
        region
            .assign_advice(
                || format!("assign advice {column:?} offset {offset}"),
                column,
                offset,
                || value,
            )
            .unwrap()
    }
}

/// Assign fixed to physical region.
#[inline(always)]
pub fn raw_assign_fixed<F: Field>(
    region: &mut Region<F>,
    column: Column<Fixed>,
    offset: usize,
    value: F,
) -> Cell {
    #[cfg(any(feature = "halo2-axiom", feature = "halo2-axiom-icicle"))]
    {
        region.assign_fixed(column, offset, value)
    }
    #[cfg(any(feature = "halo2-pse", feature = "halo2-icicle"))]
    {
        region
            .assign_fixed(
                || format!("assign fixed {column:?} offset {offset}"),
                column,
                offset,
                || Value::known(value),
            )
            .unwrap()
            .cell()
    }
}

/// Constrain two physical cells to be equal.
#[inline(always)]
pub fn raw_constrain_equal<F: Field>(region: &mut Region<F>, left: Cell, right: Cell) {
    #[cfg(any(feature = "halo2-axiom", feature = "halo2-axiom-icicle"))]
    region.constrain_equal(left, right);
    #[cfg(any(feature = "halo2-pse", feature = "halo2-icicle"))]
    region.constrain_equal(left, right).unwrap();
}

/// Constrains that `virtual_cell` is equal to `external_cell`. The `virtual_cell` must have
/// already been raw assigned with the raw assigned cell stored in `copy_manager`
/// **unless** it is marked an external-only cell with type id [EXTERNAL_CELL_TYPE_ID].
/// * When the virtual cell has already been assigned, the assigned cell is constrained to be equal to the external cell.
/// * When the virtual cell has not been assigned **and** it is marked as an external cell, it is assigned to `external_cell` and the mapping is stored in `copy_manager`.
///
/// This should only be called when `witness_gen_only` is false, otherwise it will panic.
///
/// ## Panics
/// If witness generation only mode is true.
pub fn constrain_virtual_equals_external<F: Field + Ord>(
    region: &mut Region<F>,
    virtual_cell: AssignedValue<F>,
    external_cell: Cell,
    copy_manager: &mut CopyConstraintManager<F>,
) {
    let ctx_cell = virtual_cell.cell.unwrap();
    match copy_manager.assigned_advices.entry(ctx_cell) {
        Entry::Occupied(acell) => {
            // The virtual cell has already been assigned, so we can constrain it to equal the external cell.
            region.constrain_equal(*acell.get(), external_cell);
        }
        Entry::Vacant(assigned) => {
            // The virtual cell **must** be an external cell
            assert_eq!(ctx_cell.type_id, EXTERNAL_CELL_TYPE_ID);
            // We map the virtual cell to point to the raw external cell in `copy_manager`
            assigned.insert(external_cell);
        }
    }
}
