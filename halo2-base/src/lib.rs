//! Base library to build Halo2 circuits.
#![allow(incomplete_features)]
#![deny(clippy::perf)]
#![allow(clippy::too_many_arguments)]
#![warn(clippy::default_numeric_fallback)]
#![warn(missing_docs)]

use getset::CopyGetters;
use halo2_proofs_axiom_gpu::cuda::utils::HALO2_GPU_CTX;

use halo2_proofs_axiom_gpu::cuda::{DeviceBufferExt, DeviceBufferMutSlice};
use halo2_proofs_axiom_gpu::plonk::GpuAssigned;
use halo2_proofs_axiom_gpu::poly::batch_invert_assigned_inplace_device;
use itertools::Itertools;
// Different memory allocator options:
#[cfg(feature = "jemallocator")]
use jemallocator::Jemalloc;
#[cfg(feature = "jemallocator")]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// // mimalloc is fastest on Mac M2
// #[cfg(feature = "mimalloc")]
// use mimalloc::MiMalloc;
// #[cfg(feature = "mimalloc")]
// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;

// use gates::flex_gate::MAX_PHASE;
#[cfg(not(feature = "cuda"))]
pub use halo2_proofs_axiom as halo2_proofs;
#[cfg(feature = "cuda")]
pub use halo2_proofs_axiom_gpu as halo2_proofs;
use openvm_cuda_common::copy::MemCopyH2D;
use openvm_cuda_common::d_buffer::DeviceBuffer;
use openvm_cuda_common::error::MemCopyError;
use openvm_cuda_common::stream::{CudaEvent, GpuDeviceCtx};

use halo2_proofs::halo2curves::ff;
use halo2_proofs::plonk::Assigned;
use utils::ScalarField;
use virtual_region::copy_constraints::SharedCopyConstraintManager;

/// Module that contains the main API for creating and working with circuits.
/// `gates` is misleading because we currently only use one custom gate throughout.
pub mod gates;
/// Module for the Poseidon hash function.
pub mod poseidon;
/// Module for SafeType which enforce value range and realted functions.
pub mod safe_types;
/// Utility functions for converting between different types of field elements.
pub mod utils;
pub mod virtual_region;

/// Constant representing whether the Layouter calls `synthesize` once just to get region shape.
pub const SKIP_FIRST_PASS: bool = false;

use std::ffi::c_void;
use std::ops::{Deref, DerefMut};

use crate::virtual_region::copy_constraints::DummyCopyConstraintManager;

#[link(name = "cudart")]
unsafe extern "C" {
    pub fn cudaMallocHost(ptr: *mut *const c_void, size: u64) -> i32;
    pub fn cudaFreeHost(ptr: *const c_void) -> i32;

}

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
    /// Converts an [`AssignedValue<F>`] into a [`QuantumCell<F>`] of enum variant `Existing`.
    fn from(a: AssignedValue<F>) -> Self {
        Self::Existing(a)
    }
}

impl<F: ScalarField> QuantumCell<F> {
    /// Returns an immutable reference to the underlying [ScalarField] value of a [`QuantumCell<F>`].
    ///
    /// Panics if the [`QuantumCell<F>`] is of type `WitnessFraction`.
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

/// Unique tag for a context across all virtual regions.
/// In the form `(type_id, context_id)` where `type_id` should be a unique identifier
/// for the virtual region this context belongs to, and `context_id` is a counter local to that virtual region.
pub type ContextTag = (&'static str, usize);

/// Pointer to the position of a cell at `offset` in an advice column within a [Context] of `context_id`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextCell {
    /// The unique string identifier of the virtual region that this cell belongs to.
    pub type_id: &'static str,
    /// Identifier of the [Context] that this cell belongs to.
    pub context_id: usize,
    /// Relative offset of the cell within this [Context] advice column.
    pub offset: usize,
}

impl ContextCell {
    /// Creates a new [ContextCell] with the given `type_id`, `context_id`, and `offset`.
    ///
    /// **Warning:** If you create your own `Context` in a new virtual region not provided by our libraries, you must ensure that the `type_id: &str` of the context is a globally unique identifier for the virtual region, distinct from the other `type_id` strings used to identify other virtual regions. We suggest that you either include your crate name as a prefix in the `type_id` or use [`module_path!`](https://doc.rust-lang.org/std/macro.module_path.html) to generate a prefix.
    /// In the future we will introduce a macro to check this uniqueness at compile time.
    pub fn new(type_id: &'static str, context_id: usize, offset: usize) -> Self {
        Self { type_id, context_id, offset }
    }
}

/// Pointer containing cell value and location within [Context].
///
/// Note: Performs a copy of the value, should only be used when you are about to assign the value again elsewhere.
#[derive(Clone, Copy, Debug)]
pub struct AssignedValue<F: crate::ff::Field> {
    /// Value of the cell.
    pub value: Assigned<F>, // we don't use reference to avoid issues with lifetimes (you can't safely borrow from vector and push to it at the same time).
    // only needed during vkey, pkey gen to fetch the actual cell from the relevant context
    /// [ContextCell] pointer to the cell the value is assigned to within an advice column of a [Context].
    pub cell: Option<ContextCell>,
}

impl<F: ScalarField> AssignedValue<F> {
    /// Returns an immutable reference to the underlying value of an [`AssignedValue<F>`].
    ///
    /// Panics if the witness value is of type [Assigned::Rational] or [Assigned::Zero].
    pub fn value(&self) -> &F {
        match &self.value {
            Assigned::Trivial(a) => a,
            _ => unreachable!(), // if trying to fetch an un-evaluated fraction, you will have to do something manual
        }
    }

    /// Debug helper function for writing negative tests. This will change the **witness** value in `ctx` corresponding to `self.offset`.
    /// This assumes that `ctx` is the context that `self` lies in.
    pub fn debug_prank(&self, ctx: &mut Context<F>, prank_value: F) {
        ctx.advice[self.cell.unwrap().offset] = Assigned::Trivial(prank_value);
    }
}

impl<F: ScalarField> AsRef<AssignedValue<F>> for AssignedValue<F> {
    fn as_ref(&self) -> &AssignedValue<F> {
        self
    }
}

#[derive(Clone, Debug)]
pub struct PageLockedVec<T>(Vec<T>);

impl<T> Deref for PageLockedVec<T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for PageLockedVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Copy> PageLockedVec<T> {
    pub fn new_with_size(size: usize) -> Self {
        unsafe {
            let mut ptr = std::ptr::null();

            assert!(
                cudaMallocHost(
                    &mut ptr as *mut *const c_void,
                    (size * std::mem::size_of::<T>()) as u64
                ) == 0
            );

            // otherwise unsafe if T is not copy
            PageLockedVec(Vec::from_raw_parts(ptr as *mut T, size, size))
        }
    }
}

impl<T> Drop for PageLockedVec<T> {
    fn drop(&mut self) {
        let mut v = vec![];
        std::mem::swap(&mut v, &mut self.0);
        let ptr = v.leak().as_ptr();
        unsafe {
            assert!(cudaFreeHost(ptr as *const c_void) == 0);
        }
    }
}

pub trait ContextKind<F: ScalarField> {
    /// Concrete copy-constraint manager backing this context.
    type CopyManager: virtual_region::copy_constraints::CopyConstraintManagerKind<F>;

    fn assign_cell(&mut self, input: impl Into<QuantumCell<F>>);
    fn last(&self) -> Option<AssignedValue<F>>;
    fn constrain_equal(&mut self, a: &AssignedValue<F>, b: &AssignedValue<F>);
    fn assign_region<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
    ) where
        Q: Into<QuantumCell<F>>;

    fn assign_region_last<Q>(
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

    fn assign_region_smart<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
        equality_offsets: impl IntoIterator<Item = (isize, isize)>,
        external_equality: impl IntoIterator<Item = (Option<ContextCell>, isize)>,
    ) where
        Q: Into<QuantumCell<F>>;

    fn get_offset(&self) -> usize;
    fn load_witness(&mut self, witness: F) -> AssignedValue<F>;
    fn load_constant(&mut self, c: F) -> AssignedValue<F>;
    fn load_zero(&mut self) -> AssignedValue<F>;
    fn to_assigned_value(&self, qc: impl Into<QuantumCell<F>>, offset: usize) -> AssignedValue<F>;

    fn witness_gen_only(&self) -> bool;
    fn phase(&self) -> usize;
    fn tag(&self) -> ContextTag;

    /// Provides `&mut` access to the underlying copy-constraint manager. For
    /// contexts that hold the manager behind a lock, this method takes the lock
    /// only for the duration of `f`.
    fn with_copy_manager<R>(&mut self, f: impl FnOnce(&mut Self::CopyManager) -> R) -> R;
}

impl<F: ScalarField> Clone for PagedWitnessContext<F> {
    fn clone(&self) -> Self {
        unreachable!()
    }
}

/// Witness-generation context that writes directly into a flat, column-major advice buffer.
///
/// The buffer holds one physical column of `n = 2^k` rows per advice column, laid out as
/// `[col 0 rows 0..n) | col 1 rows 0..n) | ...]`, matching what
/// [`halo2_proofs::plonk::create_proof_materialized`] and
/// [`crate::gates::circuit::builder::WitnessCircuitBuilder::assign_lookups_to_advice`] expect.
///
/// `break_points[k]` is the `row_offset` of the last cell placed in physical column `k` before
/// switching to column `k + 1`. Its semantics match the `ThreadBreakPoints` returned by
/// [`assign_with_constraints`](crate::gates::flex_gate::threads::single_phase::assign_with_constraints):
/// each entry is column-local, in `[0, max_rows)`, and the value at that row is duplicated into
/// row 0 of the next column to preserve the gate-overlap copy constraint that keygen bakes into
/// the proving key.
#[derive(Debug)]
pub struct PagedWitnessContext<F: ScalarField> {
    break_points: Vec<usize>,
    break_idx: usize,
    /// Rows per physical column (`2^k`).
    n: usize,
    /// Index of the physical column currently being written.
    col: usize,
    /// Row within the current column of the next cell to be written.
    row_offset: usize,
    /// Number of caller-visible cells pushed so far (excludes the duplicates written at
    /// break points). Returned by [`ContextKind::get_offset`] so callers see a linear
    /// index consistent with the base [`Context`] semantics.
    linear_idx: usize,

    zero_cell: Option<AssignedValue<F>>,
    cur_break_point: Option<usize>,

    cur_page_idx: usize,
    cur_page_ptr: *mut GpuAssigned<F>,
    cur_page_stage: usize,
    paged_chunks: Vec<(
        PageLockedVec<GpuAssigned<F>>, // assigned into
        DeviceBuffer<GpuAssigned<F>>,  // copied into
        DeviceBuffer<F>,               // tmp buf
        CudaEvent,
    )>,
    final_advice_values: Vec<DeviceBuffer<F>>,
    last_assigned: Option<Assigned<F>>,
}

const PAGED_WITNESS_PAGE_SIZE: usize = 1024 * 32;
const PAGED_WITNESS_STAGES: usize = 3;
impl<F: ScalarField> PagedWitnessContext<F> {
    pub fn new(break_points: Vec<usize>, n: usize, num_columns: usize) -> Self {
        let cur_break_point = break_points.get(0).copied();
        // TODO: generalize to non divisible case
        assert!(n % PAGED_WITNESS_PAGE_SIZE == 0);

        let mut paged_chunks: Vec<(
            PageLockedVec<GpuAssigned<F>>, // assigned into
            DeviceBuffer<GpuAssigned<F>>,  // copied into
            DeviceBuffer<F>,               // tmp buf
            CudaEvent,
        )> = vec![];

        for _ in 0..PAGED_WITNESS_STAGES {
            paged_chunks.push((
                PageLockedVec::new_with_size(PAGED_WITNESS_PAGE_SIZE),
                DeviceBuffer::with_capacity_on(PAGED_WITNESS_PAGE_SIZE, &HALO2_GPU_CTX),
                DeviceBuffer::with_capacity_on(PAGED_WITNESS_PAGE_SIZE * 2, &HALO2_GPU_CTX),
                CudaEvent::new().unwrap(),
            ));
        }

        PagedWitnessContext {
            break_points,
            break_idx: 1,
            n,
            col: 0,
            row_offset: 0,
            linear_idx: 0,
            zero_cell: None,
            cur_break_point,
            cur_page_idx: 0,
            cur_page_ptr: paged_chunks[0].0.as_mut_ptr(),
            cur_page_stage: 0,
            paged_chunks,
            final_advice_values: (0..num_columns)
                .map(|_| {
                    let mut buf = DeviceBuffer::with_capacity_on(n, &HALO2_GPU_CTX);
                    buf.mut_slice(..).fill(F::ZERO, &HALO2_GPU_CTX).unwrap();
                    buf
                })
                .collect_vec(),
            last_assigned: None,
        }
    }

    fn write_advice(&mut self, val: GpuAssigned<F>) {
        unsafe {
            *self.cur_page_ptr.add(self.cur_page_idx) = val;
        }

        self.cur_page_idx += 1;
        // maintain invariant that upon entry, self.cur_page_ptr and self.cur_page_idx is valid
        if self.cur_page_idx == PAGED_WITNESS_PAGE_SIZE {
            let (host_buf, dev_buf, tmp_buf, event) =
                &mut self.paged_chunks[self.cur_page_stage % PAGED_WITNESS_STAGES];

            host_buf.copy_to_on(dev_buf, &HALO2_GPU_CTX).unwrap();

            // assert!(
            //     self.cur_page_stage * PAGED_WITNESS_PAGE_SIZE <= self.final_advice_values.len()
            // );

            let global_off = self.cur_page_stage * PAGED_WITNESS_PAGE_SIZE;
            let cur_col = global_off / self.n;
            let local_off = global_off % self.n;
            batch_invert_assigned_inplace_device(
                dev_buf,
                tmp_buf,
                &self.final_advice_values[cur_col],
                local_off,
            )
            .unwrap();
            event.record_on(&HALO2_GPU_CTX.stream).unwrap();

            // prepare next stage
            self.cur_page_stage += 1;
            let (host_buf, _, _, event) =
                &mut self.paged_chunks[self.cur_page_stage % PAGED_WITNESS_STAGES];
            event.synchronize().unwrap(); // wait for memcpy and kernels to complete
            self.cur_page_idx = 0;
            self.cur_page_ptr = host_buf.as_mut_ptr();
        }
    }

    /// Writes a witness into the current `(col, row_offset)` slot. If `row_offset` matches the
    /// next entry of `break_points`, advances to `(col + 1, 0)` and writes the same value there
    /// as the gate-overlap duplicate before advancing `row_offset` to 1.
    ///
    /// This mirrors the layout produced by
    /// [`assign_witnesses`](crate::gates::flex_gate::threads::single_phase::assign_witnesses) so
    /// that the flat buffer satisfies the copy constraints in the proving key.
    pub fn push_advice(&mut self, val: Assigned<F>) {
        self.last_assigned = Some(val);
        let val = val.into();
        // unsafe {
        //     let advice_ptr = self.advice.as_mut_ptr();
        //     *advice_ptr.add(self.linear_idx) = val;
        // }

        self.write_advice(val);

        // self.advice[self.col * self.n + self.row_offset] = val;
        if self.cur_break_point == Some(self.row_offset) {
            for _ in (self.row_offset + 1)..self.n {
                self.write_advice(F::ZERO.into());
            }
            self.write_advice(val);
            self.col += 1;
            self.row_offset = 0;
            // self.advice[self.col * self.n] = val;
            self.cur_break_point = self.break_points.get(self.break_idx).copied();
            self.break_idx += 1;
            self.linear_idx = self.col * self.n;
        }
        self.row_offset += 1;
        self.linear_idx += 1;
    }

    // pub fn get_advice(self) -> Vec<GpuAssigned<F>> {
    //     self.advice
    // }

    pub fn get_gpu_advice(mut self) -> Vec<DeviceBuffer<F>> {
        // flush final page to gpu
        if self.cur_page_idx > 0 {
            let (host_buf, dev_buf, tmp_buf, _) =
                &mut self.paged_chunks[self.cur_page_stage % PAGED_WITNESS_STAGES];

            // for i in self.cur_page_idx..PAGED_WITNESS_PAGE_SIZE {
            //     host_buf[i] = GpuAssigned::Zero;
            // }

            host_buf.copy_to_on(dev_buf, &HALO2_GPU_CTX).unwrap();
            dev_buf
                .mut_slice(self.cur_page_idx..PAGED_WITNESS_PAGE_SIZE)
                .fill(GpuAssigned::Zero, &HALO2_GPU_CTX)
                .unwrap();

            let global_off = self.cur_page_stage * PAGED_WITNESS_PAGE_SIZE;
            let cur_col = global_off / self.n;
            let local_off = global_off % self.n;
            batch_invert_assigned_inplace_device(
                dev_buf,
                tmp_buf,
                &self.final_advice_values[cur_col],
                local_off,
            )
            .unwrap();
        }

        let mut dev_val = vec![];
        // need to perform a swap as the Drop is custom
        std::mem::swap(&mut dev_val, &mut self.final_advice_values);
        HALO2_GPU_CTX.stream.synchronize().unwrap();

        dev_val
    }

    pub fn copy_gpu_advice(&mut self, slice: &[GpuAssigned<F>], col: usize, offset: usize) {
        if slice.len() == 0 {
            return;
        }
        let dev_buf = slice.to_device_on(&HALO2_GPU_CTX).unwrap();
        let tmp = DeviceBuffer::with_capacity_on(slice.len() * 2, &HALO2_GPU_CTX);

        batch_invert_assigned_inplace_device(
            &dev_buf,
            &tmp,
            &self.final_advice_values[col],
            offset,
        )
        .unwrap();
    }
}

impl<F: ScalarField> Drop for PagedWitnessContext<F> {
    fn drop(&mut self) {
        for b in self.paged_chunks.iter() {
            b.3.synchronize().unwrap(); // make sure all H2D copies complete before freeing the host buffers
        }
    }
}

/// Static `type_id` returned by [`PagedWitnessContext::tag`]. All paged-witness
/// contexts share the same tag because they operate purely in witness-gen mode
/// where the tag is only used to route lookups to the right per-phase manager.
const PAGED_WITNESS_TYPE_ID: &str = "halo2-base:PagedWitnessContext";

impl<F: ScalarField> ContextKind<F> for PagedWitnessContext<F> {
    type CopyManager = DummyCopyConstraintManager<F>;

    fn assign_cell(&mut self, input: impl Into<QuantumCell<F>>) {
        match input.into() {
            QuantumCell::Existing(acell) => {
                self.push_advice(acell.value);
            }
            QuantumCell::Witness(val) => {
                self.push_advice(Assigned::Trivial(val));
            }
            QuantumCell::WitnessFraction(val) => {
                self.push_advice(val);
            }
            QuantumCell::Constant(c) => {
                self.push_advice(Assigned::Trivial(c));
            }
        }
    }

    fn last(&self) -> Option<AssignedValue<F>> {
        Some(AssignedValue { value: self.last_assigned?, cell: None })
    }

    fn constrain_equal(&mut self, _a: &AssignedValue<F>, _b: &AssignedValue<F>) {
        // witness_gen_only: copy constraints are only relevant during keygen.
    }

    fn assign_region<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        _gate_offsets: impl IntoIterator<Item = isize>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        for input in inputs {
            self.assign_cell(input);
        }
    }

    fn assign_region_smart<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        _gate_offsets: impl IntoIterator<Item = isize>,
        _equality_offsets: impl IntoIterator<Item = (isize, isize)>,
        _external_equality: impl IntoIterator<Item = (Option<ContextCell>, isize)>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        for input in inputs {
            self.assign_cell(input);
        }
    }

    fn get_offset(&self) -> usize {
        self.linear_idx
    }

    fn load_witness(&mut self, witness: F) -> AssignedValue<F> {
        self.push_advice(Assigned::Trivial(witness));
        AssignedValue { value: Assigned::Trivial(witness), cell: None }
    }

    fn load_constant(&mut self, c: F) -> AssignedValue<F> {
        self.push_advice(Assigned::Trivial(c));
        AssignedValue { value: Assigned::Trivial(c), cell: None }
    }

    fn load_zero(&mut self) -> AssignedValue<F> {
        if let Some(v) = &self.zero_cell {
            return *v;
        }
        let v = self.load_constant(F::ZERO);
        self.zero_cell = Some(v);
        v
    }

    fn to_assigned_value(&self, qc: impl Into<QuantumCell<F>>, _offset: usize) -> AssignedValue<F> {
        let value = match qc.into() {
            QuantumCell::Existing(acell) => acell.value,
            QuantumCell::Witness(val) => Assigned::Trivial(val),
            QuantumCell::WitnessFraction(val) => val,
            QuantumCell::Constant(c) => Assigned::Trivial(c),
        };
        AssignedValue { value, cell: None }
    }

    fn witness_gen_only(&self) -> bool {
        true
    }

    fn phase(&self) -> usize {
        0
    }

    fn tag(&self) -> ContextTag {
        (PAGED_WITNESS_TYPE_ID, 0)
    }

    fn with_copy_manager<R>(&mut self, f: impl FnOnce(&mut Self::CopyManager) -> R) -> R {
        let mut dummy = DummyCopyConstraintManager::<F>::default();
        f(&mut dummy)
    }
}

/// Represents a single thread of an execution trace.
/// * We keep the naming [Context] for historical reasons.
///
/// [Context] is CPU thread-local.
#[derive(Clone, Debug, CopyGetters)]
pub struct Context<F: ScalarField> {
    /// Flag to determine whether only witness generation or proving and verification key generation is being performed.
    /// * If witness gen is performed many operations can be skipped for optimization.
    #[getset(get_copy = "pub")]
    witness_gen_only: bool,
    /// The challenge phase that this [Context] will map to.
    #[getset(get_copy = "pub")]
    phase: usize,
    /// Identifier for what virtual region this context is in.
    /// Warning: the circuit writer must ensure that distinct virtual regions have distinct names as strings to prevent possible errors.
    /// We do not use [std::any::TypeId] because it is not stable across rust builds or dependencies.
    #[getset(get_copy = "pub")]
    type_id: &'static str,
    /// Identifier to reference cells from this [Context].
    context_id: usize,

    /// Single column of advice cells.
    pub(crate) advice: Vec<Assigned<F>>,

    /// Slight optimization: since zero is so commonly used, keep a reference to the zero cell.
    zero_cell: Option<AssignedValue<F>>,

    // ========================================
    // General principle: we don't need to optimize anything specific to `witness_gen_only == false` because it is only done during keygen
    // If `witness_gen_only == false`:
    /// [Vec] representing the selector column of this [Context] accompanying each `advice` column
    /// * Assumed to have the same length as `advice`
    pub selector: Vec<bool>,

    /// Global shared thread-safe manager for all copy (equality) constraints between virtual advice, constants, and raw external Halo2 cells.
    pub copy_manager: SharedCopyConstraintManager<F>,
}

impl<F: ScalarField> Context<F> {
    /// Creates a new [Context] with the given `context_id` and witness generation enabled/disabled by the `witness_gen_only` flag.
    /// * `witness_gen_only`: flag to determine whether public key generation or only witness generation is being performed.
    /// * `context_id`: identifier to reference advice cells from this [Context] later.
    ///
    /// **Warning:** If you create your own `Context` in a new virtual region not provided by our libraries, you must ensure that the `type_id: &str` of the context is a globally unique identifier for the virtual region, distinct from the other `type_id` strings used to identify other virtual regions. We suggest that you either include your crate name as a prefix in the `type_id` or use [`module_path!`](https://doc.rust-lang.org/std/macro.module_path.html) to generate a prefix.
    /// In the future we will introduce a macro to check this uniqueness at compile time.
    pub fn new(
        witness_gen_only: bool,
        phase: usize,
        type_id: &'static str,
        context_id: usize,
        copy_manager: SharedCopyConstraintManager<F>,
    ) -> Self {
        Self {
            witness_gen_only,
            phase,
            type_id,
            context_id,
            advice: Vec::new(),
            selector: Vec::new(),
            zero_cell: None,
            copy_manager,
        }
    }

    /// The context id, this can be used as a tag when CPU multi-threading
    pub fn id(&self) -> usize {
        self.context_id
    }

    /// A unique tag that should identify this context across all virtual regions and phases.
    pub fn tag(&self) -> ContextTag {
        (self.type_id, self.context_id)
    }

    /// Returns the current offset in the `advice` column (equivalently, the number of cells
    /// assigned so far). Callers use this after [`Self::assign_region`] together with
    /// [`Self::to_assigned_value`] to reconstruct an [`AssignedValue`] without re-reading `advice`.
    pub fn get_offset(&self) -> usize {
        self.advice.len()
    }

    fn latest_cell(&self) -> ContextCell {
        ContextCell::new(self.type_id, self.context_id, self.advice.len() - 1)
    }

    /// Virtually assigns the `input` within the current [Context], with different handling depending on the [QuantumCell] variant.
    pub fn assign_cell(&mut self, input: impl Into<QuantumCell<F>>) {
        // Determine the type of the cell and push it to the relevant vector
        match input.into() {
            QuantumCell::Existing(acell) => {
                self.advice.push(acell.value);
                // If witness generation is not performed, enforce equality constraints between the existing cell and the new cell
                if !self.witness_gen_only {
                    let new_cell = self.latest_cell();
                    self.copy_manager
                        .lock()
                        .unwrap()
                        .advice_equalities
                        .push((new_cell, acell.cell.unwrap()));
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
                    let new_cell = self.latest_cell();
                    self.copy_manager.lock().unwrap().constant_equalities.push((c, new_cell));
                }
            }
        }
    }

    /// Returns the [AssignedValue] of the last cell in the `advice` column of [Context] or [None] if `advice` is empty
    pub fn last(&self) -> Option<AssignedValue<F>> {
        self.advice.last().map(|v| {
            let cell = (!self.witness_gen_only).then_some(self.latest_cell());
            AssignedValue { value: *v, cell }
        })
    }

    /// Constructs an [AssignedValue] locally from a [QuantumCell] and an absolute `offset`,
    /// without reading `advice`. Callers use this after [`Self::assign_region`] when they
    /// already know the value being assigned and its position in the region, avoiding
    /// the `advice`-index dereference done by [`Self::get`].
    ///
    /// * `qc`: the [QuantumCell] variant that was pushed at `offset`.
    /// * `offset`: the absolute index within the `advice` column of this [Context].
    pub fn to_assigned_value(
        &self,
        qc: impl Into<QuantumCell<F>>,
        offset: usize,
    ) -> AssignedValue<F> {
        let value = match qc.into() {
            QuantumCell::Existing(acell) => acell.value,
            QuantumCell::Witness(val) => Assigned::Trivial(val),
            QuantumCell::WitnessFraction(val) => val,
            QuantumCell::Constant(c) => Assigned::Trivial(c),
        };
        let cell = (!self.witness_gen_only).then_some(ContextCell::new(
            self.type_id,
            self.context_id,
            offset,
        ));
        AssignedValue { value, cell }
    }

    // Returns the [AssignedValue] of the cell at the given `offset` in the `advice` column of [Context]
    // * `offset`: the offset of the cell to be fetched
    //     * `offset` may be negative indexing from the end of the column (e.g., `-1` is the last cell)
    // * Assumes `offset` is a valid index in `advice`;
    //     * `0` <= `offset` < `advice.len()` (or `advice.len() + offset >= 0` if `offset` is negative)
    // pub fn get(&self, offset: isize) -> AssignedValue<F> {
    //     let offset = if offset < 0 {
    //         self.advice.len().wrapping_add_signed(offset)
    //     } else {
    //         offset as usize
    //     };
    //     assert!(offset < self.advice.len());
    //     let cell = (!self.witness_gen_only).then_some(ContextCell::new(
    //         self.type_id,
    //         self.context_id,
    //         offset,
    //     ));
    //     AssignedValue { value: self.advice[offset], cell }
    // }

    /// Creates an equality constraint between two `advice` cells.
    /// * `a`: the first `advice` cell to be constrained equal
    /// * `b`: the second `advice` cell to be constrained equal
    /// * Assumes both cells are `advice` cells
    pub fn constrain_equal(&mut self, a: &AssignedValue<F>, b: &AssignedValue<F>) {
        if !self.witness_gen_only {
            self.copy_manager
                .lock()
                .unwrap()
                .advice_equalities
                .push((a.cell.unwrap(), b.cell.unwrap()));
        }
    }

    /// Pushes multiple advice cells to the `advice` column of [Context] and enables them by enabling the corresponding selector specified in `gate_offset`.
    ///
    /// * `inputs`: Iterator that specifies the cells to be assigned
    /// * `gate_offsets`: specifies relative offset from current position to enable selector for the gate (e.g., `0` is `inputs[0]`).
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
                self.copy_manager.lock().unwrap().advice_equalities.push((
                    ContextCell::new(
                        self.type_id,
                        self.context_id,
                        row_offset.wrapping_add_signed(offset1),
                    ),
                    ContextCell::new(
                        self.type_id,
                        self.context_id,
                        row_offset.wrapping_add_signed(offset2),
                    ),
                ));
            }
            // Add equality constraints between cells in the advice column and external cells (Fixed column).
            for (cell, offset) in external_equality {
                self.copy_manager.lock().unwrap().advice_equalities.push((
                    cell.unwrap(),
                    ContextCell::new(
                        self.type_id,
                        self.context_id,
                        row_offset.wrapping_add_signed(offset),
                    ),
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
                let cell = (!self.witness_gen_only).then_some(ContextCell::new(
                    self.type_id,
                    self.context_id,
                    row_offset + i,
                ));
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

    /// Assigns a list of constant values and returns the corresponding assigned cells.
    /// * `c`: the list of constant values to be assigned
    pub fn load_constants(&mut self, c: &[F]) -> Vec<AssignedValue<F>> {
        c.iter().map(|v| self.load_constant(*v)).collect_vec()
    }

    /// Assigns the 0 value to a new cell or returns a previously assigned zero cell from `zero_cell`.
    pub fn load_zero(&mut self) -> AssignedValue<F> {
        if let Some(zcell) = &self.zero_cell {
            return *zcell;
        }
        let zero_cell = self.load_constant(F::ZERO);
        self.zero_cell = Some(zero_cell);
        zero_cell
    }

    /// Helper function for debugging using `MockProver`. This adds a constraint that always fails.
    /// The `MockProver` will print out the row, column where it fails, so it serves as a debugging "break point"
    /// so you can add to your code to search for where the actual constraint failure occurs.
    pub fn debug_assert_false(&mut self) {
        use rand_chacha::rand_core::OsRng;
        let rand1 = self.load_witness(F::random(OsRng));
        let rand2 = self.load_witness(F::random(OsRng));
        self.constrain_equal(&rand1, &rand2);
    }
}

impl<F: ScalarField> ContextKind<F> for Context<F> {
    type CopyManager = virtual_region::copy_constraints::CopyConstraintManager<F>;

    fn assign_cell(&mut self, input: impl Into<QuantumCell<F>>) {
        <Self>::assign_cell(self, input)
    }

    fn last(&self) -> Option<AssignedValue<F>> {
        <Self>::last(self)
    }

    fn constrain_equal(&mut self, a: &AssignedValue<F>, b: &AssignedValue<F>) {
        <Self>::constrain_equal(self, a, b)
    }

    fn assign_region<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        <Self>::assign_region(self, inputs, gate_offsets)
    }

    fn assign_region_smart<Q>(
        &mut self,
        inputs: impl IntoIterator<Item = Q>,
        gate_offsets: impl IntoIterator<Item = isize>,
        equality_offsets: impl IntoIterator<Item = (isize, isize)>,
        external_equality: impl IntoIterator<Item = (Option<ContextCell>, isize)>,
    ) where
        Q: Into<QuantumCell<F>>,
    {
        <Self>::assign_region_smart(self, inputs, gate_offsets, equality_offsets, external_equality)
    }

    fn get_offset(&self) -> usize {
        <Self>::get_offset(self)
    }

    fn load_witness(&mut self, witness: F) -> AssignedValue<F> {
        <Self>::load_witness(self, witness)
    }

    fn load_constant(&mut self, c: F) -> AssignedValue<F> {
        <Self>::load_constant(self, c)
    }

    fn load_zero(&mut self) -> AssignedValue<F> {
        <Self>::load_zero(self)
    }

    fn to_assigned_value(&self, qc: impl Into<QuantumCell<F>>, offset: usize) -> AssignedValue<F> {
        <Self>::to_assigned_value(self, qc, offset)
    }

    fn witness_gen_only(&self) -> bool {
        <Self>::witness_gen_only(self)
    }

    fn phase(&self) -> usize {
        <Self>::phase(self)
    }

    fn tag(&self) -> ContextTag {
        <Self>::tag(self)
    }

    fn with_copy_manager<R>(&mut self, f: impl FnOnce(&mut Self::CopyManager) -> R) -> R {
        f(&mut self.copy_manager.lock().unwrap())
    }
}
