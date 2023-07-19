/// Module that helps auto-build circuits
pub mod builder;
/// Module implementing our simple custom gate and common functions using it
pub mod flex_gate;
/// Module using a single lookup table for range checks
pub mod range;

pub use flex_gate::{GateChip, GateInstructions};
pub use range::{RangeChip, RangeInstructions};
