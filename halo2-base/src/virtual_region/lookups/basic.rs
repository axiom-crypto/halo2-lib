use crate::{
    halo2_proofs::{
        circuit::{Layouter, Region, Value},
        halo2curves::ff::Field,
        plonk::{Advice, Column, ConstraintSystem, Fixed, Phase},
        poly::Rotation,
    },
    utils::{
        halo2::{raw_assign_advice, raw_assign_fixed, Halo2AssignedCell},
        ScalarField,
    },
    virtual_region::{
        copy_constraints::SharedCopyConstraintManager, lookups::LookupAnyManager,
        manager::VirtualRegionManager,
    },
    AssignedValue,
};

/// A simple dynamic lookup table for when you want to verify some length `KEY_COL` key
/// is in a provided (dynamic) table of the same format.
///
/// Note that you can also use this to look up (key, out) pairs, where you consider the whole
/// pair as the new key.
///
/// We can have multiple sets of dedicated columns to be looked up: these can be specified
/// when calling `new`, but typically we just need 1 set.
///
/// The `table` consists of advice columns. Since this table may have poisoned rows (blinding factors),
/// we use a fixed column `table_selector` which is default 0 and only 1 on enabled rows of the table.
/// The dynamic lookup will check that a `key` in `to_lookup` matches one of the rows in `table` if
/// that row is enabled, or `[F::ZERO; KEY_COL]` if the row is not enabled.
/// **Therefore `[F::ZERO, KEY_COL]` should never be used as a valid key in `to_lookup`**. This must
/// be checked on a per-implementation basis.
#[derive(Clone, Debug)]
pub struct BasicDynLookupConfig<const KEY_COL: usize> {
    /// Columns for cells to be looked up.
    pub to_lookup: Vec<[Column<Advice>; KEY_COL]>,
    /// Table to look up against.
    pub table: [Column<Advice>; KEY_COL],
    /// Selector to enable a row in `table` to actually be part of the lookup table. This is to prevent
    /// blinding factors in `table` advice columns from being used in the lookup.
    pub table_selector: Column<Fixed>,
}

impl<const KEY_COL: usize> BasicDynLookupConfig<KEY_COL> {
    /// Assumes all columns are in the same phase `P` to make life easier.
    /// We enable equality on all columns because we envision both the columns to lookup
    /// and the table will need to talk to halo2-lib.
    pub fn new<P: Phase, F: Field>(
        meta: &mut ConstraintSystem<F>,
        phase: impl Fn() -> P,
        num_lu_sets: usize,
    ) -> Self {
        let mut make_columns = || {
            [(); KEY_COL].map(|_| {
                let advice = meta.advice_column_in(phase());
                meta.enable_equality(advice);
                advice
            })
        };
        let table = make_columns();
        let to_lookup: Vec<_> = (0..num_lu_sets).map(|_| make_columns()).collect();
        let table_selector = meta.fixed_column();

        for to_lookup in &to_lookup {
            meta.lookup_any("dynamic lookup table", |meta| {
                let table_selector = meta.query_fixed(table_selector, Rotation::cur());
                let table = table.map(|c| meta.query_advice(c, Rotation::cur()));
                let to_lu = to_lookup.map(|c| meta.query_advice(c, Rotation::cur()));
                to_lu
                    .into_iter()
                    .zip(table)
                    .map(|(to_lu, table)| (to_lu, table_selector.clone() * table))
                    .collect()
            });
        }

        Self { table_selector, table, to_lookup }
    }

    /// Assign managed lookups
    pub fn assign_managed_lookups<F: ScalarField>(
        &self,
        mut layouter: impl Layouter<F>,
        lookup_manager: &LookupAnyManager<F, KEY_COL>,
    ) {
        layouter
            .assign_region(
                || "Managed lookup advice",
                |mut region| {
                    lookup_manager.assign_raw(&self.to_lookup, &mut region);
                    Ok(())
                },
            )
            .unwrap();
    }

    /// Assign virtual table to raw
    pub fn assign_virtual_table_to_raw<F: ScalarField>(
        &self,
        mut layouter: impl Layouter<F>,
        rows: impl IntoIterator<Item = [AssignedValue<F>; KEY_COL]>,
        copy_manager: Option<&SharedCopyConstraintManager<F>>,
    ) {
        #[cfg(not(feature = "halo2-axiom"))]
        let rows = rows.into_iter().collect::<Vec<_>>();
        layouter
            .assign_region(
                || "Dynamic Lookup Table",
                |mut region| {
                    self.assign_virtual_table_to_raw_from_offset(
                        &mut region,
                        #[cfg(feature = "halo2-axiom")]
                        rows,
                        #[cfg(not(feature = "halo2-axiom"))]
                        rows.clone(),
                        0,
                        copy_manager,
                    );
                    Ok(())
                },
            )
            .unwrap();
    }

    /// `copy_manager` **must** be provided unless you are only doing witness generation
    /// without constraints.
    pub fn assign_virtual_table_to_raw_from_offset<F: ScalarField>(
        &self,
        region: &mut Region<F>,
        rows: impl IntoIterator<Item = [AssignedValue<F>; KEY_COL]>,
        offset: usize,
        copy_manager: Option<&SharedCopyConstraintManager<F>>,
    ) {
        for (i, row) in rows.into_iter().enumerate() {
            let row_offset = offset + i;
            // Enable this row in the table
            raw_assign_fixed(region, self.table_selector, row_offset, F::ONE);
            for (col, virtual_cell) in self.table.into_iter().zip(row) {
                assign_virtual_to_raw(region, col, row_offset, virtual_cell, copy_manager);
            }
        }
    }
}

/// Assign virtual cell to raw halo2 cell.
/// `copy_manager` **must** be provided unless you are only doing witness generation
/// without constraints.
pub fn assign_virtual_to_raw<'v, F: ScalarField>(
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
