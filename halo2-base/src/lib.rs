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

// use gates::flex_gate::MAX_PHASE;
#[cfg(feature = "halo2-pse")]
pub use halo2_proofs;
#[cfg(feature = "halo2-axiom")]
pub use halo2_proofs_axiom as halo2_proofs;

use halo2_proofs::plonk::Assigned;
use std::collections::HashMap;
use utils::ScalarField;

pub mod gates;
pub mod utils;

#[cfg(feature = "halo2-axiom")]
pub const SKIP_FIRST_PASS: bool = false;
#[cfg(feature = "halo2-pse")]
pub const SKIP_FIRST_PASS: bool = true;

#[derive(Clone, Copy, Debug)]
pub enum QuantumCell<F: ScalarField> {
    Existing(AssignedValue<F>),
    /// This is a guard for witness values assigned after pkey generation. We do not use `Value` api anymore.
    Witness(F),
    WitnessFraction(Assigned<F>),
    Constant(F),
}

impl<F: ScalarField> From<AssignedValue<F>> for QuantumCell<F> {
    fn from(a: AssignedValue<F>) -> Self {
        Self::Existing(a)
    }
}

impl<F: ScalarField> QuantumCell<F> {
    pub fn value(&self) -> &F {
        match self {
            Self::Existing(a) => a.value(),
            Self::Witness(a) => a,
            Self::WitnessFraction(_) => {
                panic!("Trying to get value of a fraction before batch inversion")
            }
            Self::Constant(a) => a,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ContextCell {
    pub context_id: usize,
    pub offset: usize,
}

/// The object that you fetch from a context when you want to reference its value in later computations.
/// This performs a copy of the value, so it should only be used when you are about to assign the value again elsewhere.
#[derive(Clone, Copy, Debug)]
pub struct AssignedValue<F: ScalarField> {
    pub value: Assigned<F>, // we don't use reference to avoid issues with lifetimes (you can't safely borrow from vector and push to it at the same time)
    // only needed during vkey, pkey gen to fetch the actual cell from the relevant context
    pub cell: Option<ContextCell>,
}

impl<F: ScalarField> AssignedValue<F> {
    pub fn value(&self) -> &F {
        match &self.value {
            Assigned::Trivial(a) => a,
            _ => unreachable!(), // if trying to fetch an un-evaluated fraction, you will have to do something manual
        }
    }
}

/// A context should be thought of as a single thread of execution trace.
/// We keep the naming `Context` for historical reasons
#[derive(Clone, Debug)]
pub struct Context<F: ScalarField> {
    /// flag to determine whether we are doing pkey gen or only witness gen.
    /// in the latter case many operations can be skipped for optimization
    witness_gen_only: bool,
    /// identifier to reference cells from this context later
    pub context_id: usize,

    /// this is the single column of advice cells exactly as they should be assigned
    pub advice: Vec<Assigned<F>>,
    /// `cells_to_lookup` is a vector keeping track of all cells that we want to enable lookup for. When there is more than 1 advice column we will copy_advice all of these cells to the single lookup enabled column and do lookups there
    pub cells_to_lookup: Vec<AssignedValue<F>>,

    pub zero_cell: Option<AssignedValue<F>>,

    // To save time from re-allocating new temporary vectors that get quickly dropped (e.g., for some range checks), we keep a vector with high capacity around that we `clear` before use each time
    // This is NOT THREAD SAFE
    // Need to use RefCell to avoid borrow rules
    // Need to use Rc to borrow this and mutably borrow self at same time
    // preallocated_vec_to_assign: Rc<RefCell<Vec<AssignedValue<'a, F>>>>,

    // ========================================
    // General principle: we don't need to optimize anything specific to `witness_gen_only == false` because it is only done during keygen
    // If `witness_gen_only == false`:
    /// the constants used in this context
    pub constants: HashMap<F, usize>,
    /// one selector column accompanying each advice column, should have same length as `advice`
    pub selector: Vec<bool>,
    // TODO: gates that use fixed columns as selectors?
    /// A pair of context cells, both assumed to be `advice`, that must be constrained equal
    pub advice_equality_constraints: Vec<(ContextCell, ContextCell)>,
    /// A pair of context cells, where the first is in `constant` and the second in `advice` that must be constrained equal
    pub constant_equality_constraints: Vec<(ContextCell, ContextCell)>,
}

impl<F: ScalarField> Context<F> {
    pub fn new(witness_gen_only: bool, context_id: usize) -> Self {
        Self {
            witness_gen_only,
            context_id,
            advice: Vec::new(),
            cells_to_lookup: Vec::new(),
            zero_cell: None,
            constants: HashMap::new(),
            selector: Vec::new(),
            advice_equality_constraints: Vec::new(),
            constant_equality_constraints: Vec::new(),
        }
    }

    pub fn witness_gen_only(&self) -> bool {
        self.witness_gen_only
    }

    pub fn assign_fixed(&mut self, c: F) -> usize {
        let index = self.constants.get(&c);
        if let Some(index) = index {
            *index
        } else {
            let index = self.constants.len();
            self.constants.insert(c, index);
            index
        }
    }

    /// Push a `QuantumCell` onto the stack of advice cells to be assigned
    pub fn assign_cell(&mut self, input: impl Into<QuantumCell<F>>) {
        match input.into() {
            QuantumCell::Existing(acell) => {
                self.advice.push(acell.value);
                if !self.witness_gen_only {
                    let new_cell =
                        ContextCell { context_id: self.context_id, offset: self.advice.len() - 1 };
                    self.advice_equality_constraints.push((new_cell, acell.cell.unwrap()));
                }
            }
            QuantumCell::Witness(val) => {
                self.advice.push(Assigned::Trivial(val));
            }
            QuantumCell::WitnessFraction(val) => {
                self.advice.push(val);
            }
            QuantumCell::Constant(c) => {
                self.advice.push(Assigned::Trivial(c));
                if !self.witness_gen_only {
                    let c_cell =
                        ContextCell { context_id: self.context_id, offset: self.assign_fixed(c) };
                    let new_cell =
                        ContextCell { context_id: self.context_id, offset: self.advice.len() - 1 };
                    self.constant_equality_constraints.push((c_cell, new_cell));
                }
            }
        }
    }

    pub fn last(&self) -> Option<AssignedValue<F>> {
        self.advice.last().map(|v| {
            let cell = (!self.witness_gen_only).then_some(ContextCell {
                context_id: self.context_id,
                offset: self.advice.len() - 1,
            });
            AssignedValue { value: *v, cell }
        })
    }

    pub fn get(&self, offset: isize) -> AssignedValue<F> {
        let offset = if offset < 0 {
            self.advice.len().wrapping_add_signed(offset)
        } else {
            offset as usize
        };
        assert!(offset < self.advice.len());
        let cell =
            (!self.witness_gen_only).then_some(ContextCell { context_id: self.context_id, offset });
        AssignedValue { value: self.advice[offset], cell }
    }

    pub fn constrain_equal(&mut self, a: &AssignedValue<F>, b: &AssignedValue<F>) {
        if !self.witness_gen_only {
            self.advice_equality_constraints.push((a.cell.unwrap(), b.cell.unwrap()));
        }
    }

    /// Assigns multiple advice cells and the accompanying selector cells.
    ///
    /// Returns the slice of assigned cells.
    ///
    /// All indices in `gate_offsets` are with respect to `inputs` indices
    /// * `gate_offsets` specifies indices to enable selector for the gate
    /// * allow the index in `gate_offsets` to be negative in case we want to do advanced overlapping
    pub fn assign_region<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        for input in inputs {
            self.assign_cell(input);
        }

        if !self.witness_gen_only {
            let row_offset = self.selector.len();
            self.selector.resize(self.advice.len(), false);
            for offset in gate_offsets {
                *self
                    .selector
                    .get_mut(row_offset.checked_add_signed(offset).expect("Invalid gate offset"))
                    .expect("Gate offset out of bounds") = true;
            }
        }
    }

    /// Calls `assign_region` and returns the last assigned cell
    pub fn assign_region_last<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
    ) -> AssignedValue<F>
    where
        Q: Into<QuantumCell<F>>,
    {
        self.assign_region(inputs, gate_offsets);
        self.last().unwrap()
    }

    /// All indices in `gate_offsets`, `equality_offsets`, `external_equality` are with respect to `inputs` indices
    /// - `gate_offsets` specifies indices to enable selector for the gate; assume `gate_offsets` is sorted in increasing order
    /// - `equality_offsets` specifies pairs of indices to constrain equality
    /// - `external_equality` specifies an existing cell to constrain equality with the cell at a certain index
    pub fn assign_region_smart<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
        equality_offsets: impl IntoIterator<Item = (isize, isize)>,
        external_equality: impl IntoIterator<Item = (Option<ContextCell>, isize)>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        let row_offset = self.advice.len();
        self.assign_region(inputs, gate_offsets);

        if !self.witness_gen_only {
            for (offset1, offset2) in equality_offsets {
                self.advice_equality_constraints.push((
                    ContextCell {
                        context_id: self.context_id,
                        offset: row_offset.wrapping_add_signed(offset1),
                    },
                    ContextCell {
                        context_id: self.context_id,
                        offset: row_offset.wrapping_add_signed(offset2),
                    },
                ));
            }
            for (cell, offset) in external_equality {
                self.advice_equality_constraints.push((
                    cell.unwrap(),
                    ContextCell {
                        context_id: self.context_id,
                        offset: row_offset.wrapping_add_signed(offset),
                    },
                ));
            }
        }
    }

    pub fn assign_witnesses(
        &mut self,
        witnesses: impl IntoIterator<Item = F>,
    ) -> Vec<AssignedValue<F>> {
        let row_offset = self.advice.len();
        self.assign_region(witnesses.into_iter().map(QuantumCell::Witness), []);
        self.advice[row_offset..]
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let cell = (!self.witness_gen_only)
                    .then_some(ContextCell { context_id: self.context_id, offset: row_offset + i });
                AssignedValue { value: *v, cell }
            })
            .collect()
    }

    pub fn load_witness(&mut self, witness: F) -> AssignedValue<F> {
        self.assign_cell(QuantumCell::Witness(witness));
        self.last().unwrap()
    }

    pub fn load_constant(&mut self, c: F) -> AssignedValue<F> {
        self.assign_cell(QuantumCell::Constant(c));
        self.last().unwrap()
    }

    pub fn load_zero(&mut self) -> AssignedValue<F> {
        if let Some(zcell) = &self.zero_cell {
            return *zcell;
        }
        let zero_cell = self.load_constant(F::zero());
        self.zero_cell = Some(zero_cell);
        zero_cell
    }
}
