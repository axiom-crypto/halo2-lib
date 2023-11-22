use crate::ff::Field;
use crate::halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Assigned, Column, Fixed},
};
use crate::virtual_region::copy_constraints::{CopyConstraintManager, SharedCopyConstraintManager};
use crate::AssignedValue;

/// Raw (physical) assigned cell in Plonkish arithmetization.
#[cfg(feature = "halo2-axiom")]
pub type Halo2AssignedCell<'v, F> = AssignedCell<&'v Assigned<F>, F>;
/// Raw (physical) assigned cell in Plonkish arithmetization.
#[cfg(not(feature = "halo2-axiom"))]
pub type Halo2AssignedCell<'v, F> = AssignedCell<Assigned<F>, F>;

/// Assign advice to physical region.
#[inline(always)]
pub fn raw_assign_advice<'v, F: Field>(
    region: &mut Region<F>,
    column: Column<Advice>,
    offset: usize,
    value: Value<impl Into<Assigned<F>>>,
) -> Halo2AssignedCell<'v, F> {
    #[cfg(feature = "halo2-axiom")]
    {
        region.assign_advice(column, offset, value)
    }
    #[cfg(feature = "halo2-pse")]
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
    #[cfg(feature = "halo2-axiom")]
    {
        region.assign_fixed(column, offset, value)
    }
    #[cfg(feature = "halo2-pse")]
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
    #[cfg(feature = "halo2-axiom")]
    region.constrain_equal(left, right);
    #[cfg(not(feature = "halo2-axiom"))]
    region.constrain_equal(left, right).unwrap();
}

/// Assign virtual cell to raw halo2 cell in column `column` at row offset `offset` within the `region`.
/// Stores the mapping between `virtual_cell` and the raw assigned cell in `copy_manager`, if provided.
///
/// `copy_manager` **must** be provided unless you are only doing witness generation
/// without constraints.
pub fn assign_virtual_to_raw<'v, F: Field + Ord>(
    region: &mut Region<F>,
    column: Column<Advice>,
    offset: usize,
    virtual_cell: AssignedValue<F>,
    copy_manager: Option<&SharedCopyConstraintManager<F>>,
) -> Halo2AssignedCell<'v, F> {
    let raw = raw_assign_advice(region, column, offset, Value::known(virtual_cell.value));
    if let Some(copy_manager) = copy_manager {
        let mut copy_manager = copy_manager.lock().unwrap();
        let cell = virtual_cell.cell.unwrap();
        copy_manager.assigned_advices.insert(cell, raw.cell());
        drop(copy_manager);
    }
    raw
}

/// Constrains that `virtual` is equal to `external`. The `virtual` cell must have
/// **already** been raw assigned, with the raw assigned cell stored in `copy_manager`.
///
/// This should only be called when `witness_gen_only` is false, otherwise it will panic.
///
/// ## Panics
/// If witness generation only mode is true.
pub fn constrain_virtual_equals_external<F: Field + Ord>(
    region: &mut Region<F>,
    virtual_cell: AssignedValue<F>,
    external_cell: Cell,
    copy_manager: &CopyConstraintManager<F>,
) {
    let ctx_cell = virtual_cell.cell.unwrap();
    let acell = copy_manager.assigned_advices.get(&ctx_cell).expect("cell not assigned");
    region.constrain_equal(*acell, external_cell);
}
