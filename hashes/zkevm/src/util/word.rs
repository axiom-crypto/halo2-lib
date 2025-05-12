//! Define generic Word type with utility functions
// Naming conversion
// - Limbs: An EVM word is 256 bits **big-endian**. Limbs N means split 256 into N limb. For example, N = 4, each
//   limb is 256/4 = 64 bits

use super::{
    eth_types::{self, Field, ToLittleEndian, H160, H256},
    expression::{from_bytes, not, or, Expr},
};
use crate::halo2_proofs::{
    circuit::Value,
    plonk::{Advice, Column, Expression, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;

/// evm word 32 bytes, half word 16 bytes
const N_BYTES_HALF_WORD: usize = 16;

/// The EVM word for witness
#[derive(Clone, Debug, Copy)]
pub struct WordLimbs<T, const N: usize> {
    /// The limbs of this word. Little-endian.
    pub limbs: [T; N],
}

pub(crate) type Word2<T> = WordLimbs<T, 2>;

#[allow(dead_code)]
pub(crate) type Word4<T> = WordLimbs<T, 4>;

#[allow(dead_code)]
pub(crate) type Word32<T> = WordLimbs<T, 32>;

impl<T, const N: usize> WordLimbs<T, N> {
    /// Constructor
    pub fn new(limbs: [T; N]) -> Self {
        Self { limbs }
    }
    /// The number of limbs
    pub fn n() -> usize {
        N
    }
}

impl<const N: usize> WordLimbs<Column<Advice>, N> {
    /// Query advice of WordLibs of columns advice
    pub fn query_advice<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        at: Rotation,
    ) -> WordLimbs<Expression<F>, N> {
        WordLimbs::new(self.limbs.map(|column| meta.query_advice(column, at)))
    }
}

impl<const N: usize> WordLimbs<u8, N> {
    /// Convert WordLimbs of u8 to WordLimbs of expressions
    pub fn to_expr<F: Field>(&self) -> WordLimbs<Expression<F>, N> {
        WordLimbs::new(self.limbs.map(|v| Expression::Constant(F::from(v as u64))))
    }
}

impl<T: Default, const N: usize> Default for WordLimbs<T, N> {
    fn default() -> Self {
        Self { limbs: [(); N].map(|_| T::default()) }
    }
}

impl<F: Field, const N: usize> WordLimbs<F, N> {
    /// Check if zero
    pub fn is_zero_vartime(&self) -> bool {
        self.limbs.iter().all(|limb| limb.is_zero_vartime())
    }
}

/// Get the word expression
pub trait WordExpr<F> {
    /// Get the word expression
    fn to_word(&self) -> Word<Expression<F>>;
}

/// `Word`, special alias for Word2.
#[derive(Clone, Debug, Copy, Default)]
pub struct Word<T>(Word2<T>);

impl<T: Clone> Word<T> {
    /// Construct the word from 2 limbs [lo, hi]
    pub fn new(limbs: [T; 2]) -> Self {
        Self(WordLimbs::<T, 2>::new(limbs))
    }
    /// The high 128 bits limb
    pub fn hi(&self) -> T {
        self.0.limbs[1].clone()
    }
    /// the low 128 bits limb
    pub fn lo(&self) -> T {
        self.0.limbs[0].clone()
    }
    /// number of limbs
    pub fn n() -> usize {
        2
    }
    /// word to low and high 128 bits
    pub fn to_lo_hi(&self) -> (T, T) {
        (self.0.limbs[0].clone(), self.0.limbs[1].clone())
    }

    /// Extract (move) lo and hi values
    pub fn into_lo_hi(self) -> (T, T) {
        let [lo, hi] = self.0.limbs;
        (lo, hi)
    }

    /// Wrap `Word` into `Word<Value>`
    pub fn into_value(self) -> Word<Value<T>> {
        let [lo, hi] = self.0.limbs;
        Word::new([Value::known(lo), Value::known(hi)])
    }

    /// Map the word to other types
    pub fn map<T2: Clone>(&self, mut func: impl FnMut(T) -> T2) -> Word<T2> {
        Word(WordLimbs::<T2, 2>::new([func(self.lo()), func(self.hi())]))
    }
}

impl<T> std::ops::Deref for Word<T> {
    type Target = WordLimbs<T, 2>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone + PartialEq> PartialEq for Word<T> {
    fn eq(&self, other: &Self) -> bool {
        self.lo() == other.lo() && self.hi() == other.hi()
    }
}

impl<F: Field> From<eth_types::Word> for Word<F> {
    /// Construct the word from u256
    fn from(value: eth_types::Word) -> Self {
        let bytes = value.to_le_bytes();
        Word::new([
            from_bytes::value(&bytes[..N_BYTES_HALF_WORD]),
            from_bytes::value(&bytes[N_BYTES_HALF_WORD..]),
        ])
    }
}

impl<F: Field> From<H256> for Word<F> {
    /// Construct the word from H256
    fn from(h: H256) -> Self {
        let le_bytes = {
            let mut b = h.to_fixed_bytes();
            b.reverse();
            b
        };
        Word::new([
            from_bytes::value(&le_bytes[..N_BYTES_HALF_WORD]),
            from_bytes::value(&le_bytes[N_BYTES_HALF_WORD..]),
        ])
    }
}

impl<F: Field> From<u64> for Word<F> {
    /// Construct the word from u64
    fn from(value: u64) -> Self {
        let bytes = value.to_le_bytes();
        Word::new([from_bytes::value(&bytes), F::from(0)])
    }
}

impl<F: Field> From<u8> for Word<F> {
    /// Construct the word from u8
    fn from(value: u8) -> Self {
        Word::new([F::from(value as u64), F::from(0)])
    }
}

impl<F: Field> From<bool> for Word<F> {
    fn from(value: bool) -> Self {
        Word::new([F::from(value as u64), F::from(0)])
    }
}

impl<F: Field> From<H160> for Word<F> {
    /// Construct the word from h160
    fn from(value: H160) -> Self {
        let mut bytes = *value.as_fixed_bytes();
        bytes.reverse();
        Word::new([
            from_bytes::value(&bytes[..N_BYTES_HALF_WORD]),
            from_bytes::value(&bytes[N_BYTES_HALF_WORD..]),
        ])
    }
}

// impl<F: Field> Word<Value<F>> {
//     /// Assign advice
//     pub fn assign_advice<A, AR>(
//         &self,
//         region: &mut Region<'_, F>,
//         annotation: A,
//         column: Word<Column<Advice>>,
//         offset: usize,
//     ) -> Result<Word<AssignedCell<F, F>>, Error>
//     where
//         A: Fn() -> AR,
//         AR: Into<String>,
//     {
//         let annotation: String = annotation().into();
//         let lo = region.assign_advice(|| &annotation, column.lo(), offset, || self.lo())?;
//         let hi = region.assign_advice(|| &annotation, column.hi(), offset, || self.hi())?;

//         Ok(Word::new([lo, hi]))
//     }
// }

impl Word<Column<Advice>> {
    /// Query advice of Word of columns advice
    pub fn query_advice<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        at: Rotation,
    ) -> Word<Expression<F>> {
        self.0.query_advice(meta, at).to_word()
    }
}

impl<F: Field> Word<Expression<F>> {
    /// create word from lo limb with hi limb as 0. caller need to guaranteed to be 128 bits.
    pub fn from_lo_unchecked(lo: Expression<F>) -> Self {
        Self(WordLimbs::<Expression<F>, 2>::new([lo, 0.expr()]))
    }
    /// zero word
    pub fn zero() -> Self {
        Self(WordLimbs::<Expression<F>, 2>::new([0.expr(), 0.expr()]))
    }

    /// one word
    pub fn one() -> Self {
        Self(WordLimbs::<Expression<F>, 2>::new([1.expr(), 0.expr()]))
    }

    /// select based on selector. Here assume selector is 1/0 therefore no overflow check
    pub fn select<T: Expr<F> + Clone>(
        selector: T,
        when_true: Word<T>,
        when_false: Word<T>,
    ) -> Word<Expression<F>> {
        let (true_lo, true_hi) = when_true.to_lo_hi();

        let (false_lo, false_hi) = when_false.to_lo_hi();
        Word::new([
            selector.expr() * true_lo.expr() + (1.expr() - selector.expr()) * false_lo.expr(),
            selector.expr() * true_hi.expr() + (1.expr() - selector.expr()) * false_hi.expr(),
        ])
    }

    /// Assume selector is 1/0 therefore no overflow check
    pub fn mul_selector(&self, selector: Expression<F>) -> Self {
        Word::new([self.lo() * selector.clone(), self.hi() * selector])
    }

    /// No overflow check on lo/hi limbs
    pub fn add_unchecked(self, rhs: Self) -> Self {
        Word::new([self.lo() + rhs.lo(), self.hi() + rhs.hi()])
    }

    /// No underflow check on lo/hi limbs
    pub fn sub_unchecked(self, rhs: Self) -> Self {
        Word::new([self.lo() - rhs.lo(), self.hi() - rhs.hi()])
    }

    /// No overflow check on lo/hi limbs
    pub fn mul_unchecked(self, rhs: Self) -> Self {
        Word::new([self.lo() * rhs.lo(), self.hi() * rhs.hi()])
    }
}

impl<F: Field> WordExpr<F> for Word<Expression<F>> {
    fn to_word(&self) -> Word<Expression<F>> {
        self.clone()
    }
}

impl<F: Field, const N1: usize> WordLimbs<Expression<F>, N1> {
    /// to_wordlimbs will aggregate nested expressions, which implies during expression evaluation
    /// it need more recursive call. if the converted limbs word will be used in many places,
    /// consider create new low limbs word, have equality constrain, then finally use low limbs
    /// elsewhere.
    // TODO static assertion. workaround https://github.com/nvzqz/static-assertions-rs/issues/40
    pub fn to_word_n<const N2: usize>(&self) -> WordLimbs<Expression<F>, N2> {
        assert_eq!(N1 % N2, 0);
        let limbs = self
            .limbs
            .chunks(N1 / N2)
            .map(|chunk| from_bytes::expr(chunk))
            .collect_vec()
            .try_into()
            .unwrap();
        WordLimbs::<Expression<F>, N2>::new(limbs)
    }

    /// Equality expression
    // TODO static assertion. workaround https://github.com/nvzqz/static-assertions-rs/issues/40
    pub fn eq<const N2: usize>(&self, others: &WordLimbs<Expression<F>, N2>) -> Expression<F> {
        assert_eq!(N1 % N2, 0);
        not::expr(or::expr(
            self.limbs
                .chunks(N1 / N2)
                .map(|chunk| from_bytes::expr(chunk))
                .zip(others.limbs.clone())
                .map(|(expr1, expr2)| expr1 - expr2)
                .collect_vec(),
        ))
    }
}

impl<F: Field, const N1: usize> WordExpr<F> for WordLimbs<Expression<F>, N1> {
    fn to_word(&self) -> Word<Expression<F>> {
        Word(self.to_word_n())
    }
}

// TODO unittest
