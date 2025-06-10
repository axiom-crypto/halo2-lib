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
    // TODO static assertion. wordaround https://github.com/nvzqz/static-assertions-rs/issues/40
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
    // TODO static assertion. wordaround https://github.com/nvzqz/static-assertions-rs/issues/40
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::halo2_proofs::halo2curves::bn256::Fr as F;
    use crate::util::expression::Expr;
    use eth_types::{H160, H256, Word as EthWord};

    #[test]
    fn test_word_basic_operations() {
        let word = Word::<F>::new([F::from(10), F::from(20)]);
        assert_eq!(word.lo(), F::from(10));
        assert_eq!(word.hi(), F::from(20));
        assert_eq!(word.n(), 2);
        
        let (lo, hi) = word.to_lo_hi();
        assert_eq!(lo, F::from(10));
        assert_eq!(hi, F::from(20));
        
        let (lo_moved, hi_moved) = word.into_lo_hi();
        assert_eq!(lo_moved, F::from(10));
        assert_eq!(hi_moved, F::from(20));
    }

    #[test]
    fn test_word_equality() {
        let word1 = Word::<F>::new([F::from(10), F::from(20)]);
        let word2 = Word::<F>::new([F::from(10), F::from(20)]);
        let word3 = Word::<F>::new([F::from(10), F::from(21)]);
        
        assert_eq!(word1, word2);
        assert_ne!(word1, word3);
    }

    #[test]
    fn test_word_from_u64() {
        let value: u64 = 0x123456789ABCDEF0;
        let word = Word::<F>::from(value);
        
        // For u64, high limb should be 0
        assert_eq!(word.hi(), F::from(0));
        // Low limb should contain the value constructed from bytes
        let bytes = value.to_le_bytes();
        let expected_lo = from_bytes::value(&bytes);
        assert_eq!(word.lo(), expected_lo);
    }

    #[test]
    fn test_word_from_u8() {
        let value: u8 = 0xFF;
        let word = Word::<F>::from(value);
        
        assert_eq!(word.lo(), F::from(255));
        assert_eq!(word.hi(), F::from(0));
    }

    #[test]
    fn test_word_from_bool() {
        let word_true = Word::<F>::from(true);
        let word_false = Word::<F>::from(false);
        
        assert_eq!(word_true.lo(), F::from(1));
        assert_eq!(word_true.hi(), F::from(0));
        
        assert_eq!(word_false.lo(), F::from(0));
        assert_eq!(word_false.hi(), F::from(0));
    }

    #[test]
    fn test_word_from_h256() {
        let h256 = H256::from([0xFF; 32]);
        let word = Word::<F>::from(h256);
        
        // Check that conversion produces expected values
        let le_bytes = {
            let mut b = h256.to_fixed_bytes();
            b.reverse();
            b
        };
        let expected_lo = from_bytes::value(&le_bytes[..N_BYTES_HALF_WORD]);
        let expected_hi = from_bytes::value(&le_bytes[N_BYTES_HALF_WORD..]);
        
        assert_eq!(word.lo(), expected_lo);
        assert_eq!(word.hi(), expected_hi);
    }

    #[test]
    fn test_word_from_h160() {
        let h160 = H160::from([0xFF; 20]);
        let word = Word::<F>::from(h160);
        
        let mut bytes = *h160.as_fixed_bytes();
        bytes.reverse();
        let expected_lo = from_bytes::value(&bytes[..N_BYTES_HALF_WORD]);
        let expected_hi = from_bytes::value(&bytes[N_BYTES_HALF_WORD..]);
        
        assert_eq!(word.lo(), expected_lo);
        assert_eq!(word.hi(), expected_hi);
    }

    #[test]
    fn test_word_from_eth_word() {
        let eth_word = EthWord::from(0x123456789ABCDEF0u64);
        let word = Word::<F>::from(eth_word);
        
        let bytes = eth_word.to_le_bytes();
        let expected_lo = from_bytes::value(&bytes[..N_BYTES_HALF_WORD]);
        let expected_hi = from_bytes::value(&bytes[N_BYTES_HALF_WORD..]);
        
        assert_eq!(word.lo(), expected_lo);
        assert_eq!(word.hi(), expected_hi);
    }

    #[test]
    fn test_word_expression_zero_one() {
        let zero_word = Word::<Expression<F>>::zero();
        let one_word = Word::<Expression<F>>::one();
        
        // We can't directly compare expressions, but we can verify structure
        assert_eq!(zero_word.n(), 2);
        assert_eq!(one_word.n(), 2);
    }

    #[test]
    fn test_word_expression_from_lo_unchecked() {
        let lo_expr = F::from(42).expr();
        let word = Word::<Expression<F>>::from_lo_unchecked(lo_expr);
        
        assert_eq!(word.n(), 2);
    }

    #[test]
    fn test_word_expression_arithmetic() {
        let word1 = Word::<Expression<F>>::one();
        let word2 = Word::<Expression<F>>::one();
        
        let sum = word1.clone().add_unchecked(word2.clone());
        let diff = word1.clone().sub_unchecked(word2.clone());
        let product = word1.mul_unchecked(word2);
        
        // Verify operations return words with correct structure
        assert_eq!(sum.n(), 2);
        assert_eq!(diff.n(), 2);
        assert_eq!(product.n(), 2);
    }

    #[test]
    fn test_word_expression_select() {
        let selector = F::from(1).expr();
        let word_true = Word::<Expression<F>>::one();
        let word_false = Word::<Expression<F>>::zero();
        
        let selected = Word::<Expression<F>>::select(selector, word_true, word_false);
        assert_eq!(selected.n(), 2);
    }

    #[test]
    fn test_word_expression_mul_selector() {
        let word = Word::<Expression<F>>::one();
        let selector = F::from(5).expr();
        
        let result = word.mul_selector(selector);
        assert_eq!(result.n(), 2);
    }

    #[test]
    fn test_word_limbs_basic() {
        let limbs = WordLimbs::<F, 4>::new([F::from(1), F::from(2), F::from(3), F::from(4)]);
        assert_eq!(limbs.n(), 4);
        assert_eq!(limbs.limbs[0], F::from(1));
        assert_eq!(limbs.limbs[3], F::from(4));
    }

    #[test]
    fn test_word_limbs_default() {
        let limbs = WordLimbs::<F, 4>::default();
        assert_eq!(limbs.n(), 4);
        for limb in &limbs.limbs {
            assert_eq!(*limb, F::ZERO);
        }
    }

    #[test]
    fn test_word_limbs_is_zero_vartime() {
        let zero_limbs = WordLimbs::<F, 4>::new([F::ZERO; 4]);
        let non_zero_limbs = WordLimbs::<F, 4>::new([F::from(1), F::ZERO, F::ZERO, F::ZERO]);
        
        assert!(zero_limbs.is_zero_vartime());
        assert!(!non_zero_limbs.is_zero_vartime());
    }

    #[test]
    fn test_word_limbs_u8_to_expr() {
        let limbs_u8 = WordLimbs::<u8, 4>::new([1, 2, 3, 4]);
        let limbs_expr = limbs_u8.to_expr::<F>();
        
        // Can't directly compare expressions, but verify structure
        assert_eq!(limbs_expr.n(), 4);
    }

    #[test]
    fn test_word_limbs_expression_to_word_n() {
        // Test conversion from 4 limbs to 2 limbs
        let limbs_4 = WordLimbs::<Expression<F>, 4>::new([
            F::from(1).expr(),
            F::from(2).expr(), 
            F::from(3).expr(),
            F::from(4).expr()
        ]);
        
        let limbs_2 = limbs_4.to_word_n::<2>();
        assert_eq!(limbs_2.n(), 2);
    }

    #[test]
    fn test_word_limbs_expression_eq() {
        let limbs1 = WordLimbs::<Expression<F>, 2>::new([
            F::from(1).expr(),
            F::from(2).expr()
        ]);
        let limbs2 = WordLimbs::<Expression<F>, 2>::new([
            F::from(1).expr(),
            F::from(2).expr()
        ]);
        
        let eq_expr = limbs1.eq(&limbs2);
        // Verify that eq returns an expression (structure test)
        // The actual equality testing would need circuit evaluation
    }

    #[test]
    fn test_word_into_value() {
        let word = Word::<F>::new([F::from(10), F::from(20)]);
        let value_word = word.into_value();
        
        // Test structure of Value wrapper
        assert_eq!(value_word.n(), 2);
    }

    #[test]
    fn test_word_map() {
        let word = Word::<u64>::new([10, 20]);
        let mapped_word = word.map(|x| x * 2);
        
        assert_eq!(mapped_word.lo(), 20);
        assert_eq!(mapped_word.hi(), 40);
    }

    #[test]
    fn test_word_expr_trait() {
        let word = Word::<Expression<F>>::one();
        let word_expr = word.to_word();
        
        assert_eq!(word_expr.n(), 2);
    }

    #[test]
    fn test_word_limbs_expr_trait() {
        let limbs = WordLimbs::<Expression<F>, 4>::new([
            F::from(1).expr(),
            F::from(2).expr(),
            F::from(3).expr(), 
            F::from(4).expr()
        ]);
        
        let word = limbs.to_word();
        assert_eq!(word.n(), 2);
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_word_limbs_to_word_n_invalid_ratio() {
        // Test that invalid conversions panic
        let limbs_3 = WordLimbs::<Expression<F>, 3>::new([
            F::from(1).expr(),
            F::from(2).expr(),
            F::from(3).expr()
        ]);
        
        // This should panic because 3 % 2 != 0
        let _ = limbs_3.to_word_n::<2>();
    }
}
