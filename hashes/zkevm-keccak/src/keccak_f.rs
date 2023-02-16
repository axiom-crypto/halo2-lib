//!
//! The Keccak-f Chip provides a sequence of initial/final states connected by the Keccak-f permutation (1600 bits).
//!
//! This chip creates a fixed layout containing a sequence of regions that implement Keccak-f. As many regions as possible are fitted given target height parameters.
//!
//! The chip *config* exposes the positions of initial/final states within a region (column, offset), and the positions of all initial/final states within a circuit (rows). Regions are separated by a minimum number of rows, predictable based on the height parameters.
//!
//! The states are encoded in the native efficient format of the chip. A state is 25 cells, each holding a word of 64 bits. Words use a fat encoding where each bit takes up 3 bits worth of space:
//!
//!     word = ∑( bits[i] * (1 << 3*i) )
//!
//! The chip produces this format in final states. However, the constraints on, and the content of the initial states are the responsibility of a control chip. The Keccak-f synthesis receives initial state values from a control chip.
//!
//! If some regions are not used, they should be filled by applying the permutation on the zero initial state. The chip provides a function to do this efficiently.
//!
