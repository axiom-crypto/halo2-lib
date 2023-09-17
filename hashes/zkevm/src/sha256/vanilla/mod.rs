//! Brecht's SHA-256 circuit implementation, which he modified from the Keccak bit implementation.
//! Note this circuit does **not** use lookup tables, only custom gates.
//! The number of columns are fixed (~130). Unlike keccak, it is not configurable.
//!
//! More details here: https://github.com/privacy-scaling-explorations/zkevm-circuits/pull/756
//!
use std::{marker::PhantomData, vec};

use crate::{
    halo2_proofs::{
        circuit::{Region, Value},
        plonk::{Advice, Challenge, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
        poly::Rotation,
    },
    keccak_packed_multi::{assign_advice_custom, assign_fixed_custom},
    util::{
        constraint_builder::BaseConstraintBuilder,
        eth_types::Field,
        expression::{and, not, select, sum, xor, Expr},
    },
    Halo2AssignedCell,
};
use log::{debug, info};

mod constraints;
#[cfg(test)]
mod tests;
pub mod util;
mod witness_gen;

pub use constraints::*;
pub use util::*;
pub use witness_gen::*;

pub type ShaTable = crate::keccak_packed_multi::KeccakTable;
pub type ShaAssignedValue<'v, F> = Halo2AssignedCell<'v, F>;

#[derive(Clone, Debug, PartialEq)]
pub struct ShaRowFirstPhase {
    w: [bool; NUM_BITS_PER_WORD_W],
    a: [bool; NUM_BITS_PER_WORD_EXT],
    e: [bool; NUM_BITS_PER_WORD_EXT],
    pub is_final: bool,
    pub length: usize,
    pub is_paddings: [bool; ABSORB_WIDTH_PER_ROW_BYTES],
}

#[derive(Clone, Debug, PartialEq)]
pub struct ShaRowSecondPhase<F> {
    pub data_rlc: F,
    pub hash_rlc: F,
    data_rlcs: [F; ABSORB_WIDTH_PER_ROW_BYTES],
}
