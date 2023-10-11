use crate::{
    halo2_proofs::{
        circuit::{Layouter, Region},
        halo2curves::ff::Field,
        plonk::{Advice, Column, ConstraintSystem, Phase},
        poly::Rotation,
    },
    utils::ScalarField,
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
#[derive(Clone, Debug)]
pub struct BasicDynLookupConfig<const KEY_COL: usize> {
    pub to_lookup: Vec<[Column<Advice>; KEY_COL]>,
    pub table: [Column<Advice>; KEY_COL],
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

        for to_lookup in &to_lookup {
            meta.lookup_any("dynamic lookup table", |meta| {
                let table = table.map(|c| meta.query_advice(c, Rotation::cur()));
                let to_lu = to_lookup.map(|c| meta.query_advice(c, Rotation::cur()));
                to_lu.into_iter().zip(table).collect()
            });
        }

        Self { table, to_lookup }
    }

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

    pub fn assign_virtual_table_to_raw<F: ScalarField>(
        &self,
        mut layouter: impl Layouter<F>,
        rows: impl IntoIterator<Item = [AssignedValue<F>; KEY_COL]>,
        copy_manager: Option<&SharedCopyConstraintManager<F>>,
    ) {
        layouter
            .assign_region(
                || "Dynamic Lookup Table",
                |mut region| {
                    self.assign_virtual_table_to_raw_from_offset(
                        &mut region,
                        rows,
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
            for (col, virtual_cell) in self.table.into_iter().zip(row) {
                assign_virtual_to_raw(region, col, offset + i, virtual_cell, copy_manager);
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
