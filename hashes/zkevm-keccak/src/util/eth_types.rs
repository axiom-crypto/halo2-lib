//! Ethereum and Evm types used to deserialize responses from web3 / geth.

use crate::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::utils::BigPrimeField;

use ethers_core::types;
pub use ethers_core::types::{
    transaction::{eip2930::AccessList, response::Transaction},
    Address, Block, Bytes, Signature, H160, H256, H64, U256, U64,
};

/// Trait used to reduce verbosity with the declaration of the [`FieldExt`]
/// trait and its repr.
pub trait Field: BigPrimeField + PrimeField<Repr = [u8; 32]> {}

// Impl custom `Field` trait
impl<F> Field for F where F: BigPrimeField + PrimeField<Repr = [u8; 32]> {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

/// Trait used to convert a type to a [`Word`].
pub trait ToWord {
    /// Convert the type to a [`Word`].
    fn to_word(&self) -> Word;
}

/// Trait used to convert a type to a [`Address`].
pub trait ToAddress {
    /// Convert the type to a [`Address`].
    fn to_address(&self) -> Address;
}

/// Trait uset do convert a scalar value to a 32 byte array in big endian.
pub trait ToBigEndian {
    /// Convert the value to a 32 byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32];
}

/// Trait used to convert a scalar value to a 32 byte array in little endian.
pub trait ToLittleEndian {
    /// Convert the value to a 32 byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32];
}

/// Ethereum Word (256 bits).
pub type Word = U256;

impl ToBigEndian for U256 {
    /// Encode the value as byte array in big endian.
    fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes
    }
}

impl ToLittleEndian for U256 {
    /// Encode the value as byte array in little endian.
    fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        bytes
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl ToAddress for U256 {
    fn to_address(&self) -> Address {
        Address::from_slice(&self.to_be_bytes()[12..])
    }
}

/// Ethereum Hash (256 bits).
pub type Hash = types::H256;

impl ToWord for Hash {
    fn to_word(&self) -> Word {
        Word::from(self.as_bytes())
    }
}

impl ToWord for Address {
    fn to_word(&self) -> Word {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        Word::from(bytes)
    }
}

impl ToWord for bool {
    fn to_word(&self) -> Word {
        if *self {
            Word::one()
        } else {
            Word::zero()
        }
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

#[macro_export]
/// Create an [`Address`] from a hex string.  Panics on invalid input.
macro_rules! address {
    ($addr_hex:expr) => {{
        use std::str::FromStr;
        $crate::Address::from_str(&$addr_hex).expect("invalid hex Address")
    }};
}

#[macro_export]
/// Create a [`Word`] from a hex string.  Panics on invalid input.
macro_rules! word {
    ($word_hex:expr) => {
        $crate::Word::from_str_radix(&$word_hex, 16).expect("invalid hex Word")
    };
}

#[macro_export]
/// Create a [`Word`] to [`Word`] HashMap from pairs of hex strings.  Panics on
/// invalid input.
macro_rules! word_map {
    () => {
        std::collections::HashMap::new()
    };
    ($($key_hex:expr => $value_hex:expr),*) => {
        {
            std::collections::HashMap::from_iter([(
                    $(word!($key_hex), word!($value_hex)),*
            )])
        }
    }
}
