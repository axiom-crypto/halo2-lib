#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![deny(clippy::perf)]
#![allow(clippy::too_many_arguments)]

// different memory allocator options:
// mimalloc is fastest on Mac M2
#[cfg(feature = "jemallocator")]
use jemallocator::Jemalloc;
#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[cfg(all(feature = "halo2-pse", feature = "halo2-axiom"))]
compile_error!(
    "Cannot have both \"halo2-pse\" and \"halo2-axiom\" features enabled at the same time!"
);
#[cfg(not(any(feature = "halo2-pse", feature = "halo2-axiom")))]
compile_error!("Must enable exactly one of \"halo2-pse\" or \"halo2-axiom\" features to choose which halo2_proofs crate to use.");

use gates::flex_gate::MAX_PHASE;
#[cfg(feature = "halo2-pse")]
pub use halo2_proofs;
#[cfg(feature = "halo2-axiom")]
pub use halo2_proofs_axiom as halo2_proofs;

use halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Assigned, Column, Fixed},
};
use rustc_hash::FxHashMap;
#[cfg(feature = "halo2-pse")]
use std::marker::PhantomData;
use std::{cell::RefCell, rc::Rc};
use utils::ScalarField;

pub mod gates;
// pub mod hashes;
pub mod utils;

#[cfg(feature = "halo2-axiom")]
pub const SKIP_FIRST_PASS: bool = false;
#[cfg(feature = "halo2-pse")]
pub const SKIP_FIRST_PASS: bool = true;

#[derive(Clone, Debug)]
pub enum QuantumCell<'a, F: ScalarField> {
    Existing(&'a AssignedValue<F>),
    ExistingOwned(AssignedValue<F>), // this is similar to the Cow enum
    Witness(Value<F>),
    WitnessFraction(Value<Assigned<F>>),
    Constant(F),
}

impl<F: ScalarField> QuantumCell<'_, F> {
    pub fn value(&self) -> Value<&F> {
        match self {
            Self::Existing(a) => a.value(),
            Self::ExistingOwned(a) => a.value(),
            Self::Witness(a) => a.as_ref(),
            Self::WitnessFraction(_) => {
                panic!("Trying to get value of a fraction before batch inversion")
            }
            Self::Constant(a) => Value::known(a),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedValue<F: ScalarField> {
    #[cfg(feature = "halo2-axiom")]
    pub cell: AssignedCell<&'a Assigned<F>, F>,

    #[cfg(feature = "halo2-pse")]
    pub cell: Cell,
    #[cfg(feature = "halo2-pse")]
    pub value: Value<F>,
    #[cfg(feature = "halo2-pse")]
    pub row_offset: usize,

    #[cfg(feature = "display")]
    pub context_id: usize,
}

impl<'a, F: ScalarField> AssignedValue<F> {
    #[cfg(feature = "display")]
    pub fn context_id(&self) -> usize {
        self.context_id
    }

    pub fn row(&self) -> usize {
        #[cfg(feature = "halo2-axiom")]
        {
            self.cell.row_offset()
        }

        #[cfg(feature = "halo2-pse")]
        {
            self.row_offset
        }
    }

    #[cfg(feature = "halo2-axiom")]
    pub fn cell(&self) -> &Cell {
        self.cell.cell()
    }
    #[cfg(feature = "halo2-pse")]
    pub fn cell(&self) -> Cell {
        self.cell
    }

    pub fn value(&self) -> Value<&F> {
        #[cfg(feature = "halo2-axiom")]
        {
            self.cell.value().map(|a| match *a {
                Assigned::Trivial(a) => a,
                _ => unreachable!(),
            })
        }
        #[cfg(feature = "halo2-pse")]
        {
            self.value.as_ref()
        }
    }

    #[cfg(feature = "halo2-axiom")]
    pub fn copy_advice<'v>(
        &'a self,
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        offset: usize,
    ) -> AssignedCell<&'v Assigned<F>, F> {
        let assigned_cell = region
            .assign_advice(column, offset, self.cell.value().map(|v| **v))
            .unwrap_or_else(|err| panic!("{err:?}"));
        region.constrain_equal(assigned_cell.cell(), self.cell());

        assigned_cell
    }

    #[cfg(feature = "halo2-pse")]
    pub fn copy_advice(
        &self,
        region: &mut Region<'_, F>,
        column: Column<Advice>,
        offset: usize,
    ) -> Cell {
        let cell = region
            .assign_advice(|| "", column, offset, || self.value)
            .expect("assign copy advice should not fail")
            .cell();
        region.constrain_equal(cell, self.cell()).expect("constrain equal should not fail");

        cell
    }
}

// The reason we have a `Context` is that we will need to mutably borrow `advice_rows` (etc.) to update row count
// The `Circuit` trait takes in `Config` as an input that is NOT mutable, so we must pass around &mut Context everywhere for function calls
// We follow halo2wrong's convention of having `Context` also include the `Region` to be passed around, instead of a `Layouter`, so that everything happens within a single `layouter.assign_region` call. This allows us to circumvent the Halo2 layouter and use our own "pseudo-layouter", which is more specialized (and hence faster) for our specific gates
#[derive(Debug)]
pub struct Context<'a, F: ScalarField> {
    pub region: Region<'a, F>, // I don't see a reason to use Box<Region<'a, F>> since we will pass mutable reference of `Context` anyways

    pub max_rows: usize,

    // Assigning advice in a "horizontal" first fashion requires getting the column with min rows used each time `assign_region` is called, which takes a toll on witness generation speed, so instead we will just assigned a column all the way down until it reaches `max_rows` and then increment the column index
    //
    /// `advice_alloc[context_id] = (index, offset)` where `index` contains the current column index corresponding to `context_id`, and `offset` contains the current row offset within column `index`
    ///
    /// This assumes the phase is `ctx.current_phase()` to enforce the design pattern that advice should be assigned one phase at a time.
    pub advice_alloc: Vec<(usize, usize)>, // [Vec<(usize, usize)>; MAX_PHASE],

    #[cfg(feature = "display")]
    pub total_advice: usize,

    // To save time from re-allocating new temporary vectors that get quickly dropped (e.g., for some range checks), we keep a vector with high capacity around that we `clear` before use each time
    // Need to use RefCell to avoid borrow rules
    // Need to use Rc to borrow this and mutably borrow self at same time
    preallocated_vec_to_assign: Rc<RefCell<Vec<AssignedValue<F>>>>,

    // `assigned_constants` is a HashMap keeping track of all constants that we use throughout
    // we assign them to fixed columns as we go, re-using a fixed cell if the constant value has been assigned previously
    fixed_columns: Vec<Column<Fixed>>,
    fixed_col: usize,
    fixed_offset: usize,
    // fxhash is faster than normal HashMap: https://nnethercote.github.io/perf-book/hashing.html
    #[cfg(feature = "halo2-axiom")]
    pub assigned_constants: FxHashMap<F, Cell>,
    // PSE's halo2curves does not derive Hash
    #[cfg(feature = "halo2-pse")]
    pub assigned_constants: FxHashMap<Vec<u8>, Cell>,

    pub zero_cell: Option<AssignedValue<F>>,

    // `cells_to_lookup` is a vector keeping track of all cells that we want to enable lookup for. When there is more than 1 advice column we will copy_advice all of these cells to the single lookup enabled column and do lookups there
    pub cells_to_lookup: Vec<AssignedValue<F>>,

    current_phase: usize,

    #[cfg(feature = "display")]
    pub op_count: FxHashMap<String, usize>,
    #[cfg(feature = "display")]
    pub advice_alloc_cache: [Vec<(usize, usize)>; MAX_PHASE],
    #[cfg(feature = "display")]
    pub total_lookup_cells: [usize; MAX_PHASE],
    #[cfg(feature = "display")]
    pub total_fixed: usize,
}

//impl<'a, F: ScalarField> std::ops::Drop for Context<'a, F> {
//    fn drop(&mut self) {
//        assert!(
//            self.cells_to_lookup.is_empty(),
//            "THERE ARE STILL ADVICE CELLS THAT NEED TO BE LOOKED UP"
//        );
//    }
//}

impl<'a, F: ScalarField> std::fmt::Display for Context<'a, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:#?}")
    }
}

// a single struct to package any configuration parameters we will need for constructing a new `Context`
#[derive(Clone, Debug)]
pub struct ContextParams {
    pub max_rows: usize,
    /// `num_advice[context_id][phase]` contains the number of advice columns that context `context_id` keeps track of in phase `phase`
    pub num_context_ids: usize,
    pub fixed_columns: Vec<Column<Fixed>>,
}

impl<'a, F: ScalarField> Context<'a, F> {
    pub fn new(region: Region<'a, F>, params: ContextParams) -> Self {
        let advice_alloc = vec![(0, 0); params.num_context_ids];

        Self {
            region,
            max_rows: params.max_rows,
            advice_alloc,
            #[cfg(feature = "display")]
            total_advice: 0,
            preallocated_vec_to_assign: Rc::new(RefCell::new(Vec::with_capacity(256))),
            fixed_columns: params.fixed_columns,
            fixed_col: 0,
            fixed_offset: 0,
            assigned_constants: FxHashMap::default(),
            zero_cell: None,
            cells_to_lookup: Vec::new(),
            current_phase: 0,
            #[cfg(feature = "display")]
            op_count: FxHashMap::default(),
            #[cfg(feature = "display")]
            advice_alloc_cache: [(); MAX_PHASE].map(|_| vec![]),
            #[cfg(feature = "display")]
            total_lookup_cells: [0; MAX_PHASE],
            #[cfg(feature = "display")]
            total_fixed: 0,
        }
    }

    pub fn preallocated_vec_to_assign(&self) -> Rc<RefCell<Vec<AssignedValue<F>>>> {
        Rc::clone(&self.preallocated_vec_to_assign)
    }

    pub fn next_phase(&mut self) {
        assert!(
            self.cells_to_lookup.is_empty(),
            "THERE ARE STILL ADVICE CELLS THAT NEED TO BE LOOKED UP"
        );
        #[cfg(feature = "display")]
        {
            self.advice_alloc_cache[self.current_phase] = self.advice_alloc.clone();
        }
        #[cfg(feature = "halo2-axiom")]
        self.region.next_phase();
        self.current_phase += 1;
        for advice_alloc in self.advice_alloc.iter_mut() {
            *advice_alloc = (0, 0);
        }
        assert!(self.current_phase < MAX_PHASE);
    }

    pub fn current_phase(&self) -> usize {
        self.current_phase
    }

    #[cfg(feature = "display")]
    /// Returns (number of fixed columns used, total fixed cells used)
    pub fn fixed_stats(&self) -> (usize, usize) {
        // heuristic, fixed cells don't need to worry about blinding factors
        ((self.total_fixed + self.max_rows - 1) / self.max_rows, self.total_fixed)
    }

    #[cfg(feature = "halo2-axiom")]
    pub fn assign_fixed(&mut self, c: F) -> Cell {
        let fixed = self.assigned_constants.get(&c);
        if let Some(cell) = fixed {
            *cell
        } else {
            let cell = self.assign_fixed_without_caching(c);
            self.assigned_constants.insert(c, cell);
            cell
        }
    }
    #[cfg(feature = "halo2-pse")]
    pub fn assign_fixed(&mut self, c: F) -> Cell {
        let fixed = self.assigned_constants.get(c.to_repr().as_ref());
        if let Some(cell) = fixed {
            *cell
        } else {
            let cell = self.assign_fixed_without_caching(c);
            self.assigned_constants.insert(c.to_repr().as_ref().to_vec(), cell);
            cell
        }
    }

    /// Saving the assigned constant to the hashmap takes time.
    ///
    /// In situations where you don't expect to reuse the value, you can assign the fixed value directly using this function.
    pub fn assign_fixed_without_caching(&mut self, c: F) -> Cell {
        #[cfg(feature = "halo2-axiom")]
        let cell = self.region.assign_fixed(
            self.fixed_columns[self.fixed_col],
            self.fixed_offset,
            Assigned::Trivial(c),
        );
        #[cfg(feature = "halo2-pse")]
        let cell = self
            .region
            .assign_fixed(
                || "",
                self.fixed_columns[self.fixed_col],
                self.fixed_offset,
                || Value::known(c),
            )
            .expect("assign fixed should not fail")
            .cell();
        #[cfg(feature = "display")]
        {
            self.total_fixed += 1;
        }
        self.fixed_col += 1;
        if self.fixed_col == self.fixed_columns.len() {
            self.fixed_col = 0;
            self.fixed_offset += 1;
        }
        cell
    }

    /// Assuming that this is only called if ctx.region is not in shape mode!
    #[cfg(feature = "halo2-axiom")]
    pub fn assign_cell<'v>(
        &mut self,
        input: QuantumCell<'_, 'v, F>,
        column: Column<Advice>,
        #[cfg(feature = "display")] context_id: usize,
        row_offset: usize,
    ) -> AssignedValue<F> {
        match input {
            QuantumCell::Existing(acell) => {
                AssignedValue {
                    cell: acell.copy_advice(
                        // || "gate: copy advice",
                        &mut self.region,
                        column,
                        row_offset,
                    ),
                    #[cfg(feature = "display")]
                    context_id,
                }
            }
            QuantumCell::ExistingOwned(acell) => {
                AssignedValue {
                    cell: acell.copy_advice(
                        // || "gate: copy advice",
                        &mut self.region,
                        column,
                        row_offset,
                    ),
                    #[cfg(feature = "display")]
                    context_id,
                }
            }
            QuantumCell::Witness(val) => AssignedValue {
                cell: self
                    .region
                    .assign_advice(column, row_offset, val.map(Assigned::Trivial))
                    .expect("assign advice should not fail"),
                #[cfg(feature = "display")]
                context_id,
            },
            QuantumCell::WitnessFraction(val) => AssignedValue {
                cell: self
                    .region
                    .assign_advice(column, row_offset, val)
                    .expect("assign advice should not fail"),
                #[cfg(feature = "display")]
                context_id,
            },
            QuantumCell::Constant(c) => {
                let acell = self
                    .region
                    .assign_advice(column, row_offset, Value::known(Assigned::Trivial(c)))
                    .expect("assign fixed advice should not fail");
                let c_cell = self.assign_fixed(c);
                self.region.constrain_equal(acell.cell(), &c_cell);
                AssignedValue {
                    cell: acell,
                    #[cfg(feature = "display")]
                    context_id,
                }
            }
        }
    }

    #[cfg(feature = "halo2-pse")]
    pub fn assign_cell<'v>(
        &mut self,
        input: QuantumCell<'_, F>,
        column: Column<Advice>,
        #[cfg(feature = "display")] context_id: usize,
        row_offset: usize,
        phase: u8,
    ) -> AssignedValue<F> {
        match input {
            QuantumCell::Existing(acell) => {
                AssignedValue {
                    cell: acell.copy_advice(
                        // || "gate: copy advice",
                        &mut self.region,
                        column,
                        row_offset,
                    ),
                    value: acell.value,
                    row_offset,
                    #[cfg(feature = "display")]
                    context_id,
                }
            }
            QuantumCell::ExistingOwned(acell) => {
                AssignedValue {
                    cell: acell.copy_advice(
                        // || "gate: copy advice",
                        &mut self.region,
                        column,
                        row_offset,
                    ),
                    value: acell.value,
                    row_offset,
                    #[cfg(feature = "display")]
                    context_id,
                }
            }
            QuantumCell::Witness(value) => AssignedValue {
                cell: self
                    .region
                    .assign_advice(|| "", column, row_offset, || value)
                    .expect("assign advice should not fail")
                    .cell(),
                value,
                row_offset,
                #[cfg(feature = "display")]
                context_id,
            },
            QuantumCell::WitnessFraction(val) => AssignedValue {
                cell: self
                    .region
                    .assign_advice(|| "", column, row_offset, || val)
                    .expect("assign advice should not fail")
                    .cell(),
                value: Value::unknown(),
                row_offset,
                #[cfg(feature = "display")]
                context_id,
            },
            QuantumCell::Constant(c) => {
                let acell = self
                    .region
                    .assign_advice(|| "", column, row_offset, || Value::known(c))
                    .expect("assign fixed advice should not fail")
                    .cell();
                let c_cell = self.assign_fixed(c);
                self.region.constrain_equal(acell, c_cell).unwrap();
                AssignedValue {
                    cell: acell,
                    value: Value::known(c),
                    row_offset,
                    #[cfg(feature = "display")]
                    context_id,
                }
            }
        }
    }

    // convenience function to deal with rust warnings
    pub fn constrain_equal(&mut self, a: &AssignedValue<F>, b: &AssignedValue<F>) {
        #[cfg(feature = "halo2-axiom")]
        self.region.constrain_equal(a.cell(), b.cell());
        #[cfg(not(feature = "halo2-axiom"))]
        self.region.constrain_equal(a.cell(), b.cell()).unwrap();
    }

    /// Call this at the end of a phase
    ///
    /// assumes self.region is not in shape mode
    pub fn copy_and_lookup_cells(&mut self, lookup_advice: Vec<Column<Advice>>) -> usize {
        let total_cells = self.cells_to_lookup.len();
        let mut cells_to_lookup = self.cells_to_lookup.iter().peekable();
        for column in lookup_advice.into_iter() {
            let mut offset = 0;
            while offset < self.max_rows && cells_to_lookup.peek().is_some() {
                let acell = cells_to_lookup.next().unwrap();
                acell.copy_advice(&mut self.region, column, offset);
                offset += 1;
            }
        }
        if cells_to_lookup.peek().is_some() {
            panic!("NOT ENOUGH ADVICE COLUMNS WITH LOOKUP ENABLED");
        }
        self.cells_to_lookup.clear();
        #[cfg(feature = "display")]
        {
            self.total_lookup_cells[self.current_phase] = total_cells;
        }
        total_cells
    }

    #[cfg(feature = "display")]
    pub fn print_stats(&mut self, context_names: &[&str]) {
        let curr_phase = self.current_phase();
        self.advice_alloc_cache[curr_phase] = self.advice_alloc.clone();
        for phase in 0..=curr_phase {
            for (context_name, alloc) in
                context_names.iter().zip(self.advice_alloc_cache[phase].iter())
            {
                println!("Context \"{context_name}\" used {} advice columns and {} total advice cells in phase {phase}", alloc.0 + 1, alloc.0 * self.max_rows + alloc.1);
            }
            let num_lookup_advice_cells = self.total_lookup_cells[phase];
            println!("Special lookup advice cells: optimal columns: {}, total {num_lookup_advice_cells} cells used in phase {phase}.",  (num_lookup_advice_cells + self.max_rows - 1)/self.max_rows);
        }
        let (fixed_cols, total_fixed) = self.fixed_stats();
        println!("Fixed columns: {fixed_cols}, Total fixed cells: {total_fixed}");
    }
}

#[derive(Clone, Debug)]
pub struct AssignedPrimitive<'a, T: Into<u64> + Copy, F: ScalarField> {
    pub value: Value<T>,

    #[cfg(feature = "halo2-axiom")]
    pub cell: AssignedCell<&'a Assigned<F>, F>,

    #[cfg(feature = "halo2-pse")]
    pub cell: Cell,
    #[cfg(feature = "halo2-pse")]
    row_offset: usize,
    #[cfg(feature = "halo2-pse")]
    _marker: PhantomData<&'a F>,
}
