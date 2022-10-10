use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Column, Error, Fixed},
};
use num_bigint::BigUint;
use std::{borrow::Borrow, collections::HashMap, rc::Rc};
use utils::fe_to_biguint;

pub mod gates;
pub mod utils;

#[derive(Clone, Debug)]
pub enum QuantumCell<'a, F: FieldExt> {
    Existing(&'a AssignedValue<F>),
    Witness(Value<F>),
    Constant(F),
}

impl<F: FieldExt> QuantumCell<'_, F> {
    pub fn value(&self) -> Value<&F> {
        match self {
            Self::Existing(a) => a.value(),
            Self::Witness(a) => a.as_ref(),
            Self::Constant(a) => Value::known(a),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedValue<F: FieldExt> {
    pub cell: Rc<Cell>,
    pub value: Rc<Value<F>>,
    pub context_id: Rc<String>,
    column_index: usize,
    row_offset: usize,
    // the phase is provided for convenience; a more rigorous way to check the phase is to identify the column the cell is in using `column_index` and `row_offset` and call `column.phase()`
    phase: u8,
}

impl<F: FieldExt> AssignedValue<F> {
    pub fn new(
        cell: Cell,
        value: Value<F>,
        context_id: Rc<String>,
        column_index: usize,
        row_offset: usize,
        phase: u8,
    ) -> Self {
        Self {
            cell: Rc::new(cell),
            value: Rc::new(value),
            context_id,
            column_index,
            row_offset,
            phase,
        }
    }

    pub fn from_assigned(
        assigned: AssignedCell<F, F>,
        context_id: Rc<String>,
        column_index: usize,
        row_offset: usize,
        phase: u8,
    ) -> Self {
        Self {
            cell: Rc::new(assigned.cell()),
            value: Rc::new(assigned.value().copied()),
            context_id,
            column_index,
            row_offset,
            phase,
        }
    }

    pub fn context_id(&self) -> &String {
        self.context_id.borrow()
    }

    pub fn column(&self) -> usize {
        self.column_index
    }

    pub fn row(&self) -> usize {
        self.row_offset
    }

    pub fn phase(&self) -> u8 {
        self.phase
    }

    pub fn cell(&self) -> Cell {
        self.cell.as_ref().clone()
    }

    pub fn value(&self) -> Value<&F> {
        self.value.as_ref().as_ref()
    }

    pub fn copy_advice<A, AR>(
        &self,
        annotation: A,
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let assigned_cell =
            region.assign_advice(annotation, column, offset, || self.value.as_ref().clone())?;
        region.constrain_equal(assigned_cell.cell(), self.cell())?;

        Ok(assigned_cell)
    }
}

// The reason we have a `Context` is that we will need to mutably borrow `advice_rows` (etc.) to update row count
// The `Circuit` trait takes in `Config` as an input that is NOT mutable, so we must pass around &mut Context everywhere for function calls
// We follow halo2wrong's convention of having `Context` also include the `Region` to be passed around, instead of a `Layouter`, so that everything happens within a single `layouter.assign_region` call. This allows us to circumvent the Halo2 layouter and use our own "pseudo-layouter", which is more specialized (and hence faster) for our specific gates
#[derive(Debug)]
pub struct Context<'a, F: FieldExt> {
    pub region: Region<'a, F>,

    // `advice_rows[context_id][column_index]` keeps track of the number of rows used in the `column_index`-th column of the chip/config specified by the string `context_id`
    pub advice_rows: HashMap<String, Vec<usize>>,

    // `constants_to_assign` is a vector keeping track of all constants that we use throughout
    // we load them all in one go using fn `load_constants`
    // if we have (c, Some(cell)) in the vector then we also constrain the loaded cell for `c` to equal `cell`
    pub constants_to_assign: Vec<(F, Option<Cell>)>,
    pub zero_cell: Option<AssignedValue<F>>,

    pub challenge: HashMap<String, Value<F>>,

    // `cells_to_lookup` is a vector keeping track of all cells that we want to enable lookup for. When there is more than 1 advice column we will copy_advice all of these cells to the special lookup enabled columns and do lookups there
    pub cells_to_lookup: Vec<AssignedValue<F>>,

    current_phase: u8,

    #[cfg(feature = "display")]
    pub op_count: HashMap<String, usize>,
}

impl<'a, F: FieldExt> std::fmt::Display for Context<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

// a single struct to package any configuration parameters we will need for constructing a new `Context`
#[derive(Clone, Debug)]
pub struct ContextParams {
    pub num_advice: Vec<(String, usize)>,
}

impl<'a, F: FieldExt> Context<'a, F> {
    pub fn new(region: Region<'a, F>, params: ContextParams) -> Self {
        let mut advice_rows = HashMap::new();
        for (context_id, num_columns) in params.num_advice.into_iter() {
            let dup = advice_rows.insert(context_id, vec![0; num_columns]);
            assert!(dup.is_none());
        }
        Self {
            region,
            advice_rows,
            constants_to_assign: Vec::new(),
            zero_cell: None,
            challenge: HashMap::new(),
            cells_to_lookup: Vec::new(),
            current_phase: 0u8,
            #[cfg(feature = "display")]
            op_count: HashMap::new(),
        }
    }

    pub fn next_phase(&mut self) {
        self.current_phase += 1;
    }

    pub fn current_phase(&self) -> u8 {
        self.current_phase
    }

    pub fn advice_rows_get(&self, id: &String) -> &Vec<usize> {
        self.advice_rows
            .get(id)
            .expect(format!("context_id {} should have advice rows", id).as_str())
    }

    pub fn advice_rows_get_mut(&mut self, id: &String) -> &mut Vec<usize> {
        self.advice_rows
            .get_mut(id)
            .expect(format!("context_id {} should have advice rows", id).as_str())
    }

    pub fn challenge_get(&self, id: &String) -> &Value<F> {
        self.challenge
            .get(id)
            .expect(format!("challenge {} should exist", id).as_str())
    }

    /// returns leftmost `i` where `advice_rows[context_id][i]` is minimum amongst all `i`
    pub fn min_gate_index(&self, context_id: &String) -> usize {
        self.advice_rows
            .get(context_id)
            .unwrap()
            .iter()
            .enumerate()
            .min_by(|(_, x), (_, y)| x.cmp(y))
            .map(|(i, _)| i)
            .unwrap()
    }

    /// Assuming that this is only called if ctx.region is not in shape mode!
    pub fn assign_cell(
        &mut self,
        input: QuantumCell<F>,
        column: Column<Advice>,
        context_id: &Rc<String>,
        column_index: usize,
        row_offset: usize,
        phase: u8,
    ) -> Result<AssignedValue<F>, Error> {
        match input {
            QuantumCell::Existing(acell) => Ok(AssignedValue {
                cell: Rc::new(
                    acell
                        .copy_advice(|| "gate: copy advice", &mut self.region, column, row_offset)?
                        .cell(),
                ),
                value: acell.value.clone(),
                context_id: context_id.clone(),
                column_index,
                row_offset,
                phase,
            }),
            QuantumCell::Witness(val) => Ok(AssignedValue {
                cell: Rc::new(
                    self.region
                        .assign_advice(|| "gate: assign advice", column, row_offset, || val)?
                        .cell(),
                ),
                value: Rc::new(val),
                context_id: context_id.clone(),
                column_index,
                row_offset,
                phase,
            }),
            QuantumCell::Constant(c) => {
                let cell = self
                    .region
                    .assign_advice(
                        || "gate: assign const",
                        column,
                        row_offset,
                        || Value::known(c),
                    )?
                    .cell();
                self.constants_to_assign.push((c, Some(cell)));
                Ok(AssignedValue {
                    cell: Rc::new(cell),
                    value: Rc::new(Value::known(c)),
                    context_id: context_id.clone(),
                    column_index,
                    row_offset,
                    phase,
                })
            }
        }
    }

    /// call this at the very end of synthesize!
    /// assumes self.region is not in shape mode
    pub fn assign_and_constrain_constants(
        &mut self,
        fixed_columns: &Vec<Column<Fixed>>,
    ) -> Result<(usize, usize), Error> {
        // load constants cyclically over `fixed_columns.len()` columns
        let mut assigned: HashMap<BigUint, AssignedCell<F, F>> = HashMap::new();
        let mut col = 0;
        let mut offset = 0;

        for (c, ocell) in &self.constants_to_assign {
            let c_big = fe_to_biguint(c);
            let c_cell = if let Some(c_cell) = assigned.get(&c_big) {
                c_cell.clone()
            } else {
                let c_cell = self.region.assign_fixed(
                    || "load constant",
                    fixed_columns[col],
                    offset,
                    || Value::known(c.clone()),
                )?;
                assigned.insert(c_big, c_cell.clone());
                col += 1;
                if col == fixed_columns.len() {
                    col = 0;
                    offset += 1;
                }
                c_cell
            };
            if let Some(cell) = ocell {
                self.region.constrain_equal(c_cell.cell(), cell.clone())?;
            }
        }
        Ok((offset, assigned.len()))
    }

    /// call this at the very end of synthesize!
    /// assumes self.region is not in shape mode
    pub fn copy_and_lookup_cells(
        &mut self,
        lookup_advice: &[Vec<Column<Advice>>],
    ) -> Result<Vec<usize>, Error> {
        const NUM_PHASE: usize = 3;
        let mut col = [0; NUM_PHASE];
        let mut offset = [0; NUM_PHASE];
        for acell in &self.cells_to_lookup {
            let phase = acell.phase as usize;
            assert!(phase < NUM_PHASE);
            acell.copy_advice(
                || "copy lookup cell",
                &mut self.region,
                lookup_advice[phase][col[phase]],
                offset[phase],
            )?;
            col[phase] += 1;
            if col[phase] == lookup_advice[phase].len() {
                col[phase] = 0;
                offset[phase] += 1;
            }
        }
        Ok(offset.to_vec())
    }
}
