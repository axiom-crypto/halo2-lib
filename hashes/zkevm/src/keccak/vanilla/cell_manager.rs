use crate::{
    halo2_proofs::{
        halo2curves::ff::PrimeField,
        plonk::{Advice, Column, ConstraintSystem, Expression, VirtualCells},
        poly::Rotation,
    },
    util::expression::Expr,
};

use super::KeccakRegion;

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    pub(crate) expression: Expression<F>,
    pub(crate) column_expression: Expression<F>,
    pub(crate) column: Option<Column<Advice>>,
    pub(crate) column_idx: usize,
    pub(crate) rotation: i32,
}

impl<F: PrimeField> Cell<F> {
    pub(crate) fn new(
        meta: &mut VirtualCells<F>,
        column: Column<Advice>,
        column_idx: usize,
        rotation: i32,
    ) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation(rotation)),
            column_expression: meta.query_advice(column, Rotation::cur()),
            column: Some(column),
            column_idx,
            rotation,
        }
    }

    pub(crate) fn new_value(column_idx: usize, rotation: i32) -> Self {
        Self {
            expression: 0.expr(),
            column_expression: 0.expr(),
            column: None,
            column_idx,
            rotation,
        }
    }

    pub(crate) fn at_offset(&self, meta: &mut ConstraintSystem<F>, offset: i32) -> Self {
        let mut expression = 0.expr();
        meta.create_gate("Query cell", |meta| {
            expression = meta.query_advice(self.column.unwrap(), Rotation(self.rotation + offset));
            vec![0.expr()]
        });

        Self {
            expression,
            column_expression: self.column_expression.clone(),
            column: self.column,
            column_idx: self.column_idx,
            rotation: self.rotation + offset,
        }
    }

    pub(crate) fn assign(&self, region: &mut KeccakRegion<F>, offset: i32, value: F) {
        region.assign(self.column_idx, (offset + self.rotation) as usize, value);
    }
}

impl<F: PrimeField> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

impl<F: PrimeField> Expr<F> for &Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

/// CellColumn
#[derive(Clone, Debug)]
pub(crate) struct CellColumn<F> {
    pub(crate) advice: Column<Advice>,
    pub(crate) expr: Expression<F>,
}

/// CellManager
#[derive(Clone, Debug)]
pub(crate) struct CellManager<F> {
    height: usize,
    width: usize,
    current_row: usize,
    columns: Vec<CellColumn<F>>,
    // rows[i] gives the number of columns already used in row `i`
    rows: Vec<usize>,
    num_unused_cells: usize,
}

impl<F: PrimeField> CellManager<F> {
    pub(crate) fn new(height: usize) -> Self {
        Self {
            height,
            width: 0,
            current_row: 0,
            columns: Vec::new(),
            rows: vec![0; height],
            num_unused_cells: 0,
        }
    }

    pub(crate) fn query_cell(&mut self, meta: &mut ConstraintSystem<F>) -> Cell<F> {
        let (row_idx, column_idx) = self.get_position();
        self.query_cell_at_pos(meta, row_idx as i32, column_idx)
    }

    pub(crate) fn query_cell_at_row(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        row_idx: i32,
    ) -> Cell<F> {
        let column_idx = self.rows[row_idx as usize];
        self.rows[row_idx as usize] += 1;
        self.width = self.width.max(column_idx + 1);
        self.current_row = (row_idx as usize + 1) % self.height;
        self.query_cell_at_pos(meta, row_idx, column_idx)
    }

    pub(crate) fn query_cell_at_pos(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        row_idx: i32,
        column_idx: usize,
    ) -> Cell<F> {
        let column = if column_idx < self.columns.len() {
            self.columns[column_idx].advice
        } else {
            assert!(column_idx == self.columns.len());
            let advice = meta.advice_column();
            let mut expr = 0.expr();
            meta.create_gate("Query column", |meta| {
                expr = meta.query_advice(advice, Rotation::cur());
                vec![0.expr()]
            });
            self.columns.push(CellColumn { advice, expr });
            advice
        };

        let mut cells = Vec::new();
        meta.create_gate("Query cell", |meta| {
            cells.push(Cell::new(meta, column, column_idx, row_idx));
            vec![0.expr()]
        });
        cells[0].clone()
    }

    pub(crate) fn query_cell_value(&mut self) -> Cell<F> {
        let (row_idx, column_idx) = self.get_position();
        self.query_cell_value_at_pos(row_idx as i32, column_idx)
    }

    pub(crate) fn query_cell_value_at_row(&mut self, row_idx: i32) -> Cell<F> {
        let column_idx = self.rows[row_idx as usize];
        self.rows[row_idx as usize] += 1;
        self.width = self.width.max(column_idx + 1);
        self.current_row = (row_idx as usize + 1) % self.height;
        self.query_cell_value_at_pos(row_idx, column_idx)
    }

    pub(crate) fn query_cell_value_at_pos(&mut self, row_idx: i32, column_idx: usize) -> Cell<F> {
        Cell::new_value(column_idx, row_idx)
    }

    fn get_position(&mut self) -> (usize, usize) {
        let best_row_idx = self.current_row;
        let best_row_pos = self.rows[best_row_idx];
        self.rows[best_row_idx] += 1;
        self.width = self.width.max(best_row_pos + 1);
        self.current_row = (best_row_idx + 1) % self.height;
        (best_row_idx, best_row_pos)
    }

    pub(crate) fn get_width(&self) -> usize {
        self.width
    }

    pub(crate) fn start_region(&mut self) -> usize {
        // Make sure all rows start at the same column
        let width = self.get_width();
        #[cfg(debug_assertions)]
        for row in self.rows.iter() {
            self.num_unused_cells += width - *row;
        }
        self.rows = vec![width; self.height];
        width
    }

    pub(crate) fn columns(&self) -> &[CellColumn<F>] {
        &self.columns
    }

    pub(crate) fn get_num_unused_cells(&self) -> usize {
        self.num_unused_cells
    }
}
