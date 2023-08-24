use crate::halo2_proofs::{halo2curves::ff::PrimeField, plonk::Expression};

/// Returns the sum of the passed in cells
pub mod sum {
    use super::{Expr, Expression, PrimeField};

    /// Returns an expression for the sum of the list of expressions.
    pub fn expr<F: PrimeField, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs.into_iter().fold(0.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: PrimeField>(values: &[u8]) -> F {
        values.iter().fold(F::ZERO, |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use super::{Expr, Expression, PrimeField};

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    pub fn expr<F: PrimeField, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs.into_iter().fold(1.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: PrimeField>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::ONE, |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use super::{Expr, Expression, PrimeField};

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    pub fn expr<F: PrimeField, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: PrimeField>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use super::{Expr, Expression, PrimeField};

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: PrimeField, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: PrimeField>(b: F) -> F {
        F::ONE - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use super::{Expr, Expression, PrimeField};

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: PrimeField, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: PrimeField>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use super::{Expr, Expression, PrimeField};

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: PrimeField>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: PrimeField>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::ONE - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: PrimeField>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::ONE {
            when_true
        } else {
            when_false
        }
    }
}

/// Decodes a field element from its byte representation in little endian order
pub mod from_bytes {
    use super::{Expr, Expression, PrimeField};

    pub fn expr<F: PrimeField, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub fn value<F: PrimeField>(bytes: &[u8]) -> F {
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: PrimeField> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: PrimeField> Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: PrimeField> Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);

impl<F: PrimeField> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: PrimeField> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: PrimeField> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            F::from(self.unsigned_abs() as u64) * if self.is_negative() { -F::ONE } else { F::ONE },
        )
    }
}

/// Returns 2**by as PrimeField
pub fn pow_of_two<F: PrimeField>(by: usize) -> F {
    F::from(2).pow([by as u64])
}
