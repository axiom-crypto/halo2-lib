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
    util::{
        constraint_builder::BaseConstraintBuilder,
        eth_types::Field,
        expression::{and, not, select, sum, xor, Expr},
    },
};
use log::{debug, info};

pub mod columns;
pub mod constraints;
pub mod param;
#[cfg(test)]
mod tests;
pub mod util;
pub mod witness;
