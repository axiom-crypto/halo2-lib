#[cfg(feature = "halo2-pse")]
use crate::halo2_proofs::arithmetic::CurveAffine;
use crate::halo2_proofs::{arithmetic::FieldExt, circuit::Value};
use core::hash::Hash;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::Sign;
use num_traits::Signed;
use num_traits::{One, Zero};

#[cfg(feature = "halo2-axiom")]
pub trait BigPrimeField: ScalarField {
    fn from_u64_digits(val: &[u64]) -> Self;
}
#[cfg(feature = "halo2-axiom")]
impl<F> BigPrimeField for F
where
    F: FieldExt + Hash + Into<[u64; 4]> + From<[u64; 4]>,
{
    #[inline(always)]
    fn from_u64_digits(val: &[u64]) -> Self {
        debug_assert!(val.len() <= 4);
        let mut raw = [0u64; 4];
        raw[..val.len()].copy_from_slice(val);
        Self::from(raw)
    }
}

#[cfg(feature = "halo2-axiom")]
pub trait ScalarField: FieldExt + Hash {
    /// Returns the base `2^bit_len` little endian representation of the prime field element
    /// up to `num_limbs` number of limbs (truncates any extra limbs)
    ///
    /// Basically same as `to_repr` but does not go further into bytes
    ///
    /// Undefined behavior if `bit_len > 64`
    fn to_u64_limbs(self, num_limbs: usize, bit_len: usize) -> Vec<u64>;
}
#[cfg(feature = "halo2-axiom")]
impl<F> ScalarField for F
where
    F: FieldExt + Hash + Into<[u64; 4]>,
{
    #[inline(always)]
    fn to_u64_limbs(self, num_limbs: usize, bit_len: usize) -> Vec<u64> {
        let tmp: [u64; 4] = self.into();
        decompose_u64_digits_to_limbs(tmp, num_limbs, bit_len)
    }
}

// Later: will need to separate BigPrimeField from ScalarField when Goldilocks is introduced

#[cfg(feature = "halo2-pse")]
pub trait BigPrimeField = FieldExt<Repr = [u8; 32]> + Hash;

#[cfg(feature = "halo2-pse")]
pub trait ScalarField = FieldExt + Hash;

#[inline(always)]
pub(crate) fn decompose_u64_digits_to_limbs(
    e: impl IntoIterator<Item = u64>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<u64> {
    debug_assert!(bit_len <= 64);

    let mut e = e.into_iter();
    let mask: u64 = (1u64 << bit_len) - 1u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                limb
            }
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                limb
            }
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem;
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                limb
            }
        })
        .collect()
}

pub fn bit_length(x: u64) -> usize {
    (u64::BITS - x.leading_zeros()) as usize
}

pub fn log2_ceil(x: u64) -> usize {
    (u64::BITS - x.leading_zeros() - (x & (x - 1) == 0) as u32) as usize
}

pub fn modulus<F: BigPrimeField>() -> BigUint {
    fe_to_biguint(&-F::one()) + 1u64
}

pub fn power_of_two<F: BigPrimeField>(n: usize) -> F {
    biguint_to_fe(&(BigUint::one() << n))
}

/// assume `e` less than modulus of F
pub fn biguint_to_fe<F: BigPrimeField>(e: &BigUint) -> F {
    #[cfg(feature = "halo2-axiom")]
    {
        F::from_u64_digits(&e.to_u64_digits())
    }

    #[cfg(feature = "halo2-pse")]
    {
        let mut repr = F::Repr::default();
        let bytes = e.to_bytes_le();
        repr.as_mut()[..bytes.len()].copy_from_slice(&bytes);
        F::from_repr(repr).unwrap()
    }
}

/// assume `|e|` less than modulus of F
pub fn bigint_to_fe<F: BigPrimeField>(e: &BigInt) -> F {
    #[cfg(feature = "halo2-axiom")]
    {
        let (sign, digits) = e.to_u64_digits();
        if sign == Sign::Minus {
            -F::from_u64_digits(&digits)
        } else {
            F::from_u64_digits(&digits)
        }
    }
    #[cfg(feature = "halo2-pse")]
    {
        let (sign, bytes) = e.to_bytes_le();
        let mut repr = F::Repr::default();
        repr.as_mut()[..bytes.len()].copy_from_slice(&bytes);
        let f_abs = F::from_repr(repr).unwrap();
        if sign == Sign::Minus {
            -f_abs
        } else {
            f_abs
        }
    }
}

pub fn fe_to_biguint<F: ff::PrimeField>(fe: &F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}

pub fn fe_to_bigint<F: BigPrimeField>(fe: &F) -> BigInt {
    // TODO: `F` should just have modulus as lazy_static or something
    let modulus = modulus::<F>();
    let e = fe_to_biguint(fe);
    if e <= &modulus / 2u32 {
        BigInt::from_biguint(Sign::Plus, e)
    } else {
        BigInt::from_biguint(Sign::Minus, modulus - e)
    }
}

pub fn decompose<F: BigPrimeField>(e: &F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    if bit_len > 64 {
        decompose_biguint(&fe_to_biguint(e), number_of_limbs, bit_len)
    } else {
        decompose_fe_to_u64_limbs(e, number_of_limbs, bit_len).into_iter().map(F::from).collect()
    }
}

/// Assumes `bit_len` <= 64
pub fn decompose_fe_to_u64_limbs<F: ScalarField>(
    e: &F,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<u64> {
    #[cfg(feature = "halo2-axiom")]
    {
        e.to_u64_limbs(number_of_limbs, bit_len)
    }

    #[cfg(feature = "halo2-pse")]
    {
        decompose_u64_digits_to_limbs(fe_to_biguint(e).iter_u64_digits(), number_of_limbs, bit_len)
    }
}

pub fn decompose_biguint<F: BigPrimeField>(
    e: &BigUint,
    num_limbs: usize,
    bit_len: usize,
) -> Vec<F> {
    debug_assert!(bit_len > 64 && bit_len <= 128);
    let mut e = e.iter_u64_digits();

    let mut limb0 = e.next().unwrap_or(0) as u128;
    let mut rem = bit_len - 64;
    let mut u64_digit = e.next().unwrap_or(0);
    limb0 |= ((u64_digit & ((1 << rem) - 1)) as u128) << 64;
    u64_digit >>= rem;
    rem = 64 - rem;

    core::iter::once(F::from_u128(limb0))
        .chain((1..num_limbs).map(|_| {
            let mut limb: u128 = u64_digit.into();
            let mut bits = rem;
            u64_digit = e.next().unwrap_or(0);
            if bit_len - bits >= 64 {
                limb |= (u64_digit as u128) << bits;
                u64_digit = e.next().unwrap_or(0);
                bits += 64;
            }
            rem = bit_len - bits;
            limb |= ((u64_digit & ((1 << rem) - 1)) as u128) << bits;
            u64_digit >>= rem;
            rem = 64 - rem;
            F::from_u128(limb)
        }))
        .collect()
}

pub fn decompose_bigint<F: BigPrimeField>(e: &BigInt, num_limbs: usize, bit_len: usize) -> Vec<F> {
    if e.is_negative() {
        decompose_biguint::<F>(e.magnitude(), num_limbs, bit_len).into_iter().map(|x| -x).collect()
    } else {
        decompose_biguint(e.magnitude(), num_limbs, bit_len)
    }
}

pub fn decompose_bigint_option<F: BigPrimeField>(
    value: Value<&BigInt>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<Value<F>> {
    value.map(|e| decompose_bigint(e, number_of_limbs, bit_len)).transpose_vec(number_of_limbs)
}

pub fn value_to_option<V>(value: Value<V>) -> Option<V> {
    let mut v = None;
    value.map(|val| {
        v = Some(val);
    });
    v
}

/// Compute the represented value by a vector of values and a bit length.
///
/// This function is used to compute the value of an integer
/// passing as input its limb values and the bit length used.
/// Returns the sum of all limbs scaled by 2^(bit_len * i)
pub fn compose(input: Vec<BigUint>, bit_len: usize) -> BigUint {
    input.iter().rev().fold(BigUint::zero(), |acc, val| (acc << bit_len) + val)
}

#[cfg(test)]
#[test]
fn test_signed_roundtrip() {
    use crate::halo2_proofs::halo2curves::bn256::Fr;
    assert_eq!(fe_to_bigint(&bigint_to_fe::<Fr>(&-BigInt::one())), -BigInt::one());
}

#[cfg(feature = "halo2-axiom")]
pub use halo2_proofs_axiom::halo2curves::CurveAffineExt;

#[cfg(feature = "halo2-pse")]
pub trait CurveAffineExt: CurveAffine {
    /// Unlike the `Coordinates` trait, this just returns the raw affine coordinantes without checking `is_on_curve`
    fn into_coordinates(self) -> (Self::Base, Self::Base) {
        let coordinates = self.coordinates().unwrap();
        (*coordinates.x(), *coordinates.y())
    }
}
#[cfg(feature = "halo2-pse")]
impl<C: CurveAffine> CurveAffineExt for C {}

pub mod fs {
    use std::{
        env::var,
        fs::{self, File},
        io::{BufReader, BufWriter},
    };

    use crate::halo2_proofs::{
        halo2curves::{
            bn256::{Bn256, G1Affine},
            CurveAffine,
        },
        poly::{
            commitment::{Params, ParamsProver},
            kzg::commitment::ParamsKZG,
        },
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    pub fn read_params(k: u32) -> ParamsKZG<Bn256> {
        let dir = var("PARAMS_DIR").unwrap_or_else(|_| "./params".to_string());
        ParamsKZG::<Bn256>::read(&mut BufReader::new(
            File::open(format!("{dir}/kzg_bn254_{k}.srs").as_str())
                .expect("Params file does not exist"),
        ))
        .unwrap()
    }

    pub fn read_or_create_srs<'a, C: CurveAffine, P: ParamsProver<'a, C>>(
        k: u32,
        setup: impl Fn(u32) -> P,
    ) -> P {
        let dir = var("PARAMS_DIR").unwrap_or_else(|_| "./params".to_string());
        let path = format!("{dir}/kzg_bn254_{k}.srs");
        match File::open(path.as_str()) {
            Ok(f) => {
                #[cfg(feature = "display")]
                println!("read params from {path}");
                let mut reader = BufReader::new(f);
                P::read(&mut reader).unwrap()
            }
            Err(_) => {
                #[cfg(feature = "display")]
                println!("creating params for {k}");
                fs::create_dir_all(dir).unwrap();
                let params = setup(k);
                params.write(&mut BufWriter::new(File::create(path).unwrap())).unwrap();
                params
            }
        }
    }

    pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
        read_or_create_srs::<G1Affine, _>(k, |k| {
            ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()))
        })
    }
}
