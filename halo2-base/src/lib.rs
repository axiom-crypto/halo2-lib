//! Base library to build Halo2 circuits.
#![feature(stmt_expr_attributes)]
#![feature(trait_alias)]
#![deny(clippy::perf)]
#![allow(clippy::too_many_arguments)]
#![warn(clippy::default_numeric_fallback)]
#![warn(missing_docs)]

// Different memory allocator options:
#[cfg(feature = "jemallocator")]
use jemallocator::Jemalloc;
#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// mimalloc is fastest on Mac M2
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
use utils::ScalarField;

/// Module that contains the main API for creating and working with circuits.
pub mod gates;
/// Utility functions for converting between different types of field elements.
pub mod utils;

/// Constant representing whether the Layouter calls `synthesize` once just to get region shape.
#[cfg(feature = "halo2-axiom")]
pub const SKIP_FIRST_PASS: bool = false;
#[cfg(feature = "halo2-pse")]
pub const SKIP_FIRST_PASS: bool = true;

/// Convenience Enum which abstracts the scenarios under a value is added to an advice column.
#[derive(Clone, Copy, Debug)]
pub enum QuantumCell<F: ScalarField> {
    /// An [AssignedValue] already existing in the advice column (e.g., a witness value that was already assigned in a previous cell in the column).
    /// * Assigns a new cell into the advice column with value equal to the value of a.
    /// * Imposes an equality constraint between the new cell and the cell of a so the Verifier guarantees that these two cells are always equal.
    Existing(AssignedValue<F>),
    // This is a guard for witness values assigned after pkey generation. We do not use `Value` api anymore.
    /// A non-existing witness [ScalarField] value (e.g. private input) to add to an advice column.
    Witness(F),
    /// A non-existing witness [ScalarField] marked as a fraction for optimization in batch inversion later.
    WitnessFraction(Assigned<F>),
    /// A known constant value added as a witness value to the advice column and added to the "Fixed" column during circuit creation time.
    /// * Visible to both the Prover and the Verifier.
    /// * Imposes an equality constraint between the two corresponding cells in the advice and fixed columns.
    Constant(F),
}

impl<F: ScalarField> From<AssignedValue<F>> for QuantumCell<F> {
    /// Converts an [AssignedValue<F>] into a [QuantumCell<F>] of [type Existing(AssignedValue<F>)]
    fn from(a: AssignedValue<F>) -> Self {
        Self::Existing(a)
    }
}

impl<F: ScalarField> QuantumCell<F> {
    /// Returns an immutable reference to the underlying [ScalarField] value of a QuantumCell<F>.
    ///
    /// Panics if the QuantumCell<F> is of type WitnessFraction.
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

/// Pointer to the position of a cell at `offset` in an advice column within a [Context] of `context_id`.
#[derive(Clone, Copy, Debug)]
pub struct ContextCell {
    /// Identifier of the [Context] that this cell belongs to.
    pub context_id: usize,
    /// Relative offset of the cell within this [Context] advice column.
    pub offset: usize,
}

/// Pointer containing cell value and location within [Context].
///
/// Note: Performs a copy of the value, should only be used when you are about to assign the value again elsewhere.
#[derive(Clone, Copy, Debug)]
pub struct AssignedValue<F: ScalarField> {
    /// Value of the cell.
    pub value: Assigned<F>, // we don't use reference to avoid issues with lifetimes (you can't safely borrow from vector and push to it at the same time).
    // only needed during vkey, pkey gen to fetch the actual cell from the relevant context
    /// [ContextCell] pointer to the cell the value is assigned to within an advice column of a [Context].
    pub cell: Option<ContextCell>,
}

impl<F: ScalarField> AssignedValue<F> {
    /// Returns an immutable reference to the underlying value of an AssignedValue<F>.
    ///
    /// Panics if the AssignedValue<F> is of type WitnessFraction.
    pub fn value(&self) -> &F {
        match &self.value {
            Assigned::Trivial(a) => a,
            _ => unreachable!(), // if trying to fetch an un-evaluated fraction, you will have to do something manual
        }
    }
}

/// Represents a single thread of an execution trace.
/// * We keep the naming [Context] for historical reasons.
#[derive(Clone, Debug)]
pub struct Context<F: ScalarField> {
    /// Flag to determine whether only witness generation or proving and verification key generation is being performed.
    /// * If witness gen is performed many operations can be skipped for optimization.
    witness_gen_only: bool,

    /// Identifier to reference cells from this [Context].
    pub context_id: usize,

    /// Single column of advice cells.
    pub advice: Vec<Assigned<F>>,

    /// [Vec] tracking all cells that lookup is enabled for.
    /// * When there is more than 1 advice column all `advice` cells will be copied to a single lookup enabled column to perform lookups.
    pub cells_to_lookup: Vec<AssignedValue<F>>,

    /// Cell that represents the zero value as AssignedValue<F>
    pub zero_cell: Option<AssignedValue<F>>,

    // To save time from re-allocating new temporary vectors that get quickly dropped (e.g., for some range checks), we keep a vector with high capacity around that we `clear` before use each time
    // This is NOT THREAD SAFE
    // Need to use RefCell to avoid borrow rules
    // Need to use Rc to borrow this and mutably borrow self at same time
    // preallocated_vec_to_assign: Rc<RefCell<Vec<AssignedValue<'a, F>>>>,

    // ========================================
    // General principle: we don't need to optimize anything specific to `witness_gen_only == false` because it is only done during keygen
    // If `witness_gen_only == false`:
    /// [Vec] representing the selector column of this [Context] accompanying each `advice` column
    /// * Assumed to have the same length as `advice`
    pub selector: Vec<bool>,

    // TODO: gates that use fixed columns as selectors?
    /// A [Vec] tracking equality constraints between pairs of [Context] `advice` cells.
    ///
    /// Assumes both `advice` cells are in the same [Context].
    pub advice_equality_constraints: Vec<(ContextCell, ContextCell)>,

    /// A [Vec] tracking pairs equality constraints between Fixed values and [Context] `advice` cells.
    ///
    /// Assumes the constant and `advice` cell are in the same [Context].
    pub constant_equality_constraints: Vec<(F, ContextCell)>,
}

impl<F: ScalarField> Context<F> {
    /// Creates a new [Context] with the given `context_id` and witness generation enabled/disabled by the `witness_gen_only` flag.
    /// * `witness_gen_only`: flag to determine whether public key generation or only witness generation is being performed.
    /// * `context_id`: identifier to reference advice cells from this [Context] later.
    pub fn new(witness_gen_only: bool, context_id: usize) -> Self {
        Self {
            witness_gen_only,
            context_id,
            advice: Vec::new(),
            cells_to_lookup: Vec::new(),
            zero_cell: None,
            selector: Vec::new(),
            advice_equality_constraints: Vec::new(),
            constant_equality_constraints: Vec::new(),
        }
    }

    /// Returns the `witness_gen_only` flag of the [Context]
    pub fn witness_gen_only(&self) -> bool {
        self.witness_gen_only
    }

    /// Pushes a [QuantumCell<F>] to the end of the `advice` column ([Vec] of advice cells) in this [Context].
    /// * `input`: the cell to be assigned.
    pub fn assign_cell(&mut self, input: impl Into<QuantumCell<F>>) {
        // Determine the type of the cell and push it to the relevant vector
        match input.into() {
            QuantumCell::Existing(acell) => {
                self.advice.push(acell.value);
                // If witness generation is not performed, enforce equality constraints between the existing cell and the new cell
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
                // If witness generation is not performed, enforce equality constraints between the existing cell and the new cell
                if !self.witness_gen_only {
                    let new_cell =
                        ContextCell { context_id: self.context_id, offset: self.advice.len() - 1 };
                    self.constant_equality_constraints.push((c, new_cell));
                }
            }
        }
    }

    /// Returns the [AssignedValue] of the last cell in the `advice` column of [Context] or [None] if `advice` is empty
    pub fn last(&self) -> Option<AssignedValue<F>> {
        self.advice.last().map(|v| {
            let cell = (!self.witness_gen_only).then_some(ContextCell {
                context_id: self.context_id,
                offset: self.advice.len() - 1,
            });
            AssignedValue { value: *v, cell }
        })
    }

    /// Returns the [AssignedValue] of the cell at the given `offset` in the `advice` column of [Context]
    /// * `offset`: the offset of the cell to be fetched
    ///     * `offset` may be negative indexing from the end of the column (e.g., `-1` is the last cell)
    /// * Assumes `offset` is a valid index in `advice`;
    ///     * `0` <= `offset` < `advice.len()` (or `advice.len() + offset >= 0` if `offset` is negative)
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

    /// Creates an equality constraint between two `advice` cells.
    /// * `a`: the first `advice` cell to be constrained equal
    /// * `b`: the second `advice` cell to be constrained equal
    /// * Assumes both cells are `advice` cells
    pub fn constrain_equal(&mut self, a: &AssignedValue<F>, b: &AssignedValue<F>) {
        if !self.witness_gen_only {
            self.advice_equality_constraints.push((a.cell.unwrap(), b.cell.unwrap()));
        }
    }

    /// Pushes multiple advice cells to the `advice` column of [Context] and enables them by enabling the corresponding selector specified in `gate_offset`.
    ///
    /// * `inputs`: Iterator that specifies the cells to be assigned
    /// * `gate_offsets`: specifies relative offset from current position to enable selector for the gate (e.g., `0` is inputs[0]).
    ///     * `offset` may be negative indexing from the end of the column (e.g., `-1` is the last previously assigned cell)
    pub fn assign_region<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        if self.witness_gen_only {
            for input in inputs {
                self.assign_cell(input);
            }
        } else {
            let row_offset = self.advice.len();
            // note: row_offset may not equal self.selector.len() at this point if we previously used `load_constant` or `load_witness`
            for input in inputs {
                self.assign_cell(input);
            }
            self.selector.resize(self.advice.len(), false);
            for offset in gate_offsets {
                *self
                    .selector
                    .get_mut(row_offset.checked_add_signed(offset).expect("Invalid gate offset"))
                    .expect("Invalid selector offset") = true;
            }
        }
    }

    /// Pushes multiple advice cells to the `advice` column of [Context] and enables them by enabling the corresponding selector specified in `gate_offset` and returns the last assigned cell.
    ///
    /// Assumes `gate_offsets` is the same length as `inputs`
    ///
    /// Returns the last assigned cell
    /// * `inputs`: Iterator that specifies the cells to be assigned
    /// * `gate_offsets`: specifies indices to enable selector for the gate; assume `gate_offsets` is sorted in increasing order
    ///     * `offset` may be negative indexing from the end of the column (e.g., `-1` is the last cell)
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

    /// Pushes multiple advice cells to the `advice` column of [Context] and enables them by enabling the corresponding selector specified in `gate_offset`.
    ///
    /// Allows for the specification of equality constraints between cells at `equality_offsets` within the `advice` column and external advice cells specified in `external_equality` (e.g, Fixed column).
    /// * `gate_offsets`: specifies indices to enable selector for the gate;
    ///     * `offset` may be negative indexing from the end of the column (e.g., `-1` is the last cell)
    /// * `equality_offsets`: specifies pairs of indices to constrain equality
    /// * `external_equality`: specifies an existing cell to constrain equality with the cell at a certain index
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

        // note: row_offset may not equal self.selector.len() at this point if we previously used `load_constant` or `load_witness`
        // If not in witness generation mode, add equality constraints.
        if !self.witness_gen_only {
            // Add equality constraints between cells in the advice column.
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
            // Add equality constraints between cells in the advice column and external cells (Fixed column).
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

    /// Assigns a region of witness cells in an iterator and returns a [Vec] of assigned cells.
    /// * `witnesses`: Iterator that specifies the cells to be assigned
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

    /// Assigns a witness value and returns the corresponding assigned cell.
    /// * `witness`: the witness value to be assigned
    pub fn load_witness(&mut self, witness: F) -> AssignedValue<F> {
        self.assign_cell(QuantumCell::Witness(witness));
        if !self.witness_gen_only {
            self.selector.resize(self.advice.len(), false);
        }
        self.last().unwrap()
    }

    /// Assigns a constant value and returns the corresponding assigned cell.
    /// * `c`: the constant value to be assigned
    pub fn load_constant(&mut self, c: F) -> AssignedValue<F> {
        self.assign_cell(QuantumCell::Constant(c));
        if !self.witness_gen_only {
            self.selector.resize(self.advice.len(), false);
        }
        self.last().unwrap()
    }

    /// Assigns the 0 value to a new cell or returns a previously assigned zero cell from `zero_cell`.
    pub fn load_zero(&mut self) -> AssignedValue<F> {
        if let Some(zcell) = &self.zero_cell {
            return *zcell;
        }
        let zero_cell = self.load_constant(F::zero());
        self.zero_cell = Some(zero_cell);
        zero_cell
    }
}
