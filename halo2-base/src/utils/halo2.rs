use crate::ff::Field;
use crate::halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Assigned, Column, Fixed},
};

#[cfg(feature = "halo2-axiom")]
pub type Halo2AssignedCell<'v, F> = AssignedCell<&'v Assigned<F>, F>;
#[cfg(not(feature = "halo2-axiom"))]
pub type Halo2AssignedCell<'v, F> = AssignedCell<F, F>;

#[inline(always)]
pub fn raw_assign_advice<'v, F: Field>(
    region: &mut Region<F>,
    column: Column<Advice>,
    offset: usize,
    value: Value<F>,
) -> Halo2AssignedCell<'v, F> {
    #[cfg(feature = "halo2-axiom")]
    {
        region.assign_advice(column, offset, value)
    }
    #[cfg(feature = "halo2-pse")]
    {
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

#[inline(always)]
pub fn raw_constrain_equal<F: Field>(region: &mut Region<F>, left: Cell, right: Cell) {
    #[cfg(feature = "halo2-axiom")]
    region.constrain_equal(left, right);
    #[cfg(not(feature = "halo2-axiom"))]
    region.constrain_equal(left, right).unwrap();
}
