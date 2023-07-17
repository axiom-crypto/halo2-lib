#[cfg(feature = "halo2-pse")]
use crate::halo2_proofs::arithmetic::CurveAffine;
use crate::halo2_proofs::{arithmetic::FieldExt, circuit::Value};
use crate::{Context};
use core::hash::Hash;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::Sign;
use num_traits::Signed;
use num_traits::{One, Zero};
use z3::ast::{Array, Ast, Bool, Int, BV, Real};
use z3::*;
use std::env::var;
/// Helper trait to represent a field element that can be converted into [u64] limbs.
///
/// Note: Since the number of bits necessary to represent a field element is larger than the number of bits in a u64, we decompose the integer representation of the field element into multiple [u64] values e.g. `limbs`.
pub trait ScalarField: FieldExt + Hash {
    /// Returns the base `2<sup>bit_len</sup>` little endian representation of the [ScalarField] element up to `num_limbs` number of limbs (truncates any extra limbs).
    ///
    /// Assumes `bit_len < 64`.
    /// * `num_limbs`: number of limbs to return
    /// * `bit_len`: number of bits in each limb
    fn to_u64_limbs(self, num_limbs: usize, bit_len: usize) -> Vec<u64>;

    /// Returns the little endian byte representation of the element.
    fn to_bytes_le(&self) -> Vec<u8>;

    /// Creates a field element from a little endian byte representation.
    ///
    /// The default implementation assumes that `PrimeField::from_repr` is implemented for little-endian.
    /// It should be overriden if this is not the case.
    fn from_bytes_le(bytes: &[u8]) -> Self {
        let mut repr = Self::Repr::default();
        repr.as_mut()[..bytes.len()].copy_from_slice(bytes);
        Self::from_repr(repr).unwrap()
    }
}
// See below for implementations

// Later: will need to separate BigPrimeField from ScalarField when Goldilocks is introduced
pub trait BigPrimeField = ScalarField;

/// Converts an [Iterator] of u64 digits into `number_of_limbs` limbs of `bit_len` bits returned as a [Vec].
///
/// Assumes: `bit_len < 64`.
/// * `e`: Iterator of [u64] digits
/// * `number_of_limbs`: number of limbs to return
/// * `bit_len`: number of bits in each limb
#[inline(always)]

pub(crate) fn z3_formally_verify<F: BigPrimeField>(
    ctx: &mut Context<F>,
    num_bits: usize,
    a: usize,
    b: usize,
){
    let circuit = ctx;
    {
        let cfg = Config::new();
        let ctx = z3::Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let mut constraints = Vec::new();

        let mut advice = Vec::new();


        let p = Int::from_str(&ctx, "21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();
        for i in 0..circuit.advice.len() {
            advice.push(Int::new_const(&ctx, format!("advice_{}", i)));

            constraints.push(advice[i]._eq(&(&advice[i] + &p).modulo(&p)));


        }
        let lookup_bits: usize = var("LOOKUP_BITS").unwrap().parse().unwrap();

        for a in circuit.cells_to_lookup.iter() {
            assert!(a.cell.unwrap().context_id == 0);
            let i = a.cell.unwrap().offset;
            constraints.push(advice[i].ge(&Int::from_u64(&ctx, 0)));
            constraints.push(advice[i].lt(&Int::from_u64(&ctx, 1 << lookup_bits)));
        }

        for (a, b) in circuit.advice_equality_constraints.iter() {
            constraints.push(advice[a.offset]._eq(&advice[b.offset]));
        }

        for (a, b) in circuit.constant_equality_constraints.iter() {
            assert!(b.context_id == 0);
            let val_temp = F::from_bytes_le(a.to_repr().as_ref());
            let val =  BigUint::from_bytes_le(val_temp.to_bytes_le().as_ref());
            println!("VAL: {:?}", val);
            println!("VAL TEMP: {:?}", val_temp.to_bytes_le().as_slice());
            constraints.push(advice[b.offset]._eq(&Int::from_str(&ctx, &format!("{}", val)).unwrap()));

        }

        for i in 0..circuit.advice.len() {
            if circuit.selector[i] {
                let lhs = Int::add(
                    &ctx, &[&advice[i],&Int::mul(&ctx,&[&advice[i + 1],&advice[i + 2],])]);
                //constraints.push(lhs.modulo(&p)._eq(&advice[i + 3]));
                constraints.push(lhs._eq(&advice[i + 3]));

            }
        }

        let refs_par = constraints.iter().collect::<Vec<&Bool>>();
        let all_constraints = Bool::and(&ctx, &refs_par);
        println!("ALL CONSTRAINTS: {:?}", all_constraints);

        let goal = Bool::and(&ctx, &[&advice[a].le(&advice[b])]);
        solver.assert(&all_constraints);
        solver.assert(&goal.not());
        solver.check();
        //assert_eq!(solver.check(), SatResult::Sat);

        println!("Model: {:?}", solver.get_model());

    }
}
pub(crate) fn decompose_u64_digits_to_limbs(
    e: impl IntoIterator<Item = u64>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<u64> {
    debug_assert!(bit_len < 64);

    let mut e = e.into_iter();
    // Mask to extract the bits from each digit
    let mask: u64 = (1u64 << bit_len) - 1u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;

    // For each digit, we extract its individual limbs by repeatedly masking and shifting the digit based on how many bits we have left to extract.
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            // If `rem` > `bit_len`, we mask the bits from the `u64_digit` to return the first limb.
            // We shift the digit to the right by `bit_len` bits and subtract `bit_len` from `rem`
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                limb
            }
            // If `rem` == `bit_len`, then we mask the bits from the `u64_digit` to return the first limb
            // We retrieve the next digit and reset `rem` to 64
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                limb
            }
            // If `rem` < `bit_len`, we retrieve the next digit, mask it, and shift left `rem` bits from the `u64_digit` to return the first limb.
            // we shift the digit to the right by `bit_len` - `rem` bits to retrieve the start of the next limb and add 64 - bit_len to `rem` to get the remainder.
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1u64 << (bit_len - rem)) - 1u64)) << rem;
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                limb
            }
        })
        .collect()
}

/// Returns the number of bits needed to represent the value of `x`.
pub fn bit_length(x: u64) -> usize {
    (u64::BITS - x.leading_zeros()) as usize
}

/// Returns the ceiling of the base 2 logarithm of `x`.
///
/// `log2_ceil(0)` returns 0.
pub fn log2_ceil(x: u64) -> usize {
    (u64::BITS - x.leading_zeros()) as usize - usize::from(x.is_power_of_two())
}

/// Returns the modulus of [BigPrimeField].
pub fn modulus<F: BigPrimeField>() -> BigUint {
    fe_to_biguint(&-F::one()) + 1u64
}

/// Returns the [BigPrimeField] element of 2<sup>n</sup>.
/// * `n`: the desired power of 2.
pub fn power_of_two<F: BigPrimeField>(n: usize) -> F {
    biguint_to_fe(&(BigUint::one() << n))
}

/// Converts an immutable reference to [BigUint] to a [BigPrimeField].
/// * `e`: immutable reference to [BigUint]
///
/// # Assumptions:
/// * `e` is less than the modulus of `F`
pub fn biguint_to_fe<F: BigPrimeField>(e: &BigUint) -> F {
    let bytes = e.to_bytes_le();
    F::from_bytes_le(&bytes)
}

/// Converts an immutable reference to [BigInt] to a [BigPrimeField].
/// * `e`: immutable reference to [BigInt]
///
/// # Assumptions:
/// * The absolute value of `e` is less than the modulus of `F`
pub fn bigint_to_fe<F: BigPrimeField>(e: &BigInt) -> F {
    let (sign, bytes) = e.to_bytes_le();
    let f_abs = F::from_bytes_le(&bytes);
    if sign == Sign::Minus {
        -f_abs
    } else {
        f_abs
    }
}

/// Converts an immutable reference to an PrimeField element into a [BigUint] element.
/// * `fe`: immutable reference to PrimeField element to convert
pub fn fe_to_biguint<F: ScalarField>(fe: &F) -> BigUint {
    BigUint::from_bytes_le(fe.to_bytes_le().as_ref())
}

/// Converts a [BigPrimeField] element into a [BigInt] element by sending `fe` in `[0, F::modulus())` to
/// ```ignore
/// fe,                 if fe < F::modulus() / 2
/// fe - F::modulus(),  otherwise
/// ```
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

/// Decomposes an immutable reference to a [BigPrimeField] element into `number_of_limbs` limbs of `bit_len` bits each and returns a [Vec] of [BigPrimeField] represented by those limbs.
///
/// Assumes `bit_len < 128`.
/// * `e`: immutable reference to [BigPrimeField] element to decompose
/// * `number_of_limbs`: number of limbs to decompose `e` into
/// * `bit_len`: number of bits in each limb
pub fn decompose<F: BigPrimeField>(e: &F, number_of_limbs: usize, bit_len: usize) -> Vec<F> {
    if bit_len > 64 {
        decompose_biguint(&fe_to_biguint(e), number_of_limbs, bit_len)
    } else {
        decompose_fe_to_u64_limbs(e, number_of_limbs, bit_len).into_iter().map(F::from).collect()
    }
}

/// Decomposes an immutable reference to a [ScalarField] element into `number_of_limbs` limbs of `bit_len` bits each and returns a [Vec] of [u64] represented by those limbs.
///
/// Assumes `bit_len` < 64
/// * `e`: immutable reference to [ScalarField] element to decompose
/// * `number_of_limbs`: number of limbs to decompose `e` into
/// * `bit_len`: number of bits in each limb
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

/// Decomposes an immutable reference to a [BigUint] into `num_limbs` limbs of `bit_len` bits each and returns a [Vec] of [BigPrimeField] represented by those limbs.
///
/// Assumes 64 <= `bit_len` < 128.
/// * `e`: immutable reference to [BigInt] to decompose
/// * `num_limbs`: number of limbs to decompose `e` into
/// * `bit_len`: number of bits in each limb
///
/// Truncates to `num_limbs` limbs if `e` is too large.
pub fn decompose_biguint<F: BigPrimeField>(
    e: &BigUint,
    num_limbs: usize,
    bit_len: usize,
) -> Vec<F> {
    // bit_len must be between 64` and 128
    debug_assert!((64..128).contains(&bit_len));
    let mut e = e.iter_u64_digits();

    // Grab first 128-bit limb from iterator
    let mut limb0 = e.next().unwrap_or(0) as u128;
    let mut rem = bit_len - 64;
    let mut u64_digit = e.next().unwrap_or(0);
    // Extract second limb (bit length 64) from e
    limb0 |= ((u64_digit & ((1u64 << rem) - 1u64)) as u128) << 64u32;
    u64_digit >>= rem;
    rem = 64 - rem;

    // Convert `limb0` into field element `F` and create an iterator by chaining `limb0` with the computing the remaining limbs
    core::iter::once(F::from_u128(limb0))
        .chain((1..num_limbs).map(|_| {
            let mut limb = u64_digit as u128;
            let mut bits = rem;
            u64_digit = e.next().unwrap_or(0);
            if bit_len >= 64 + bits {
                limb |= (u64_digit as u128) << bits;
                u64_digit = e.next().unwrap_or(0);
                bits += 64;
            }
            rem = bit_len - bits;
            limb |= ((u64_digit & ((1u64 << rem) - 1u64)) as u128) << bits;
            u64_digit >>= rem;
            rem = 64 - rem;
            F::from_u128(limb)
        }))
        .collect()
}

/// Decomposes an immutable reference to a [BigInt] into `num_limbs` limbs of `bit_len` bits each and returns a [Vec] of [BigPrimeField] represented by those limbs.
///
/// Assumes `bit_len < 128`.
/// * `e`: immutable reference to `BigInt` to decompose
/// * `num_limbs`: number of limbs to decompose `e` into
/// * `bit_len`: number of bits in each limb
pub fn decompose_bigint<F: BigPrimeField>(e: &BigInt, num_limbs: usize, bit_len: usize) -> Vec<F> {
    if e.is_negative() {
        decompose_biguint::<F>(e.magnitude(), num_limbs, bit_len).into_iter().map(|x| -x).collect()
    } else {
        decompose_biguint(e.magnitude(), num_limbs, bit_len)
    }
}

/// Decomposes an immutable reference to a [BigInt] into `num_limbs` limbs of `bit_len` bits each and returns a [Vec] of [BigPrimeField] represented by those limbs wrapped in [Value].
///
/// Assumes `bit_len` < 128.
/// * `e`: immutable reference to `BigInt` to decompose
/// * `num_limbs`: number of limbs to decompose `e` into
/// * `bit_len`: number of bits in each limb
pub fn decompose_bigint_option<F: BigPrimeField>(
    value: Value<&BigInt>,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<Value<F>> {
    value.map(|e| decompose_bigint(e, number_of_limbs, bit_len)).transpose_vec(number_of_limbs)
}



/// Wraps the internal value of `value` in an [Option].
/// If the value is [None], then the function returns [None].
/// * `value`: Value to convert.
pub fn value_to_option<V>(value: Value<V>) -> Option<V> {
    let mut v = None;
    value.map(|val| {
        v = Some(val);
    });
    v
}

/// Computes the value of an integer by passing as `input` a [Vec] of its limb values and the `bit_len` (bit length) used.
///
/// Returns the sum of all limbs scaled by 2<sup>(bit_len * i)</sup> where i is the index of the limb.
/// * `input`: Limb values of the integer.
/// * `bit_len`: Length of limb in bits
pub fn compose(input: Vec<BigUint>, bit_len: usize) -> BigUint {
    input.iter().rev().fold(BigUint::zero(), |acc, val| (acc << bit_len) + val)
}

#[cfg(feature = "halo2-axiom")]
pub use halo2_proofs_axiom::halo2curves::CurveAffineExt;

/// Helper trait
#[cfg(feature = "halo2-pse")]
pub trait CurveAffineExt: CurveAffine {
    /// Unlike the `Coordinates` trait, this just returns the raw affine (X, Y) coordinantes without checking `is_on_curve`
    fn into_coordinates(self) -> (Self::Base, Self::Base) {
        let coordinates = self.coordinates().unwrap();
        (*coordinates.x(), *coordinates.y())
    }
}
#[cfg(feature = "halo2-pse")]
impl<C: CurveAffine> CurveAffineExt for C {}

mod scalar_field_impls {
    use num_bigint::BigUint;

    use super::{decompose_u64_digits_to_limbs, ScalarField};
    use crate::halo2_proofs::halo2curves::FieldExt;
    use std::hash::Hash;

    /// We do a blanket implementation in 'community-edition' to make it easier to integrate with other crates.
    ///
    /// ASSUMING F::Repr is little-endian
    impl<F> ScalarField for F
    where
        F: FieldExt + Hash,
    {
        #[inline(always)]
        fn to_u64_limbs(self, num_limbs: usize, bit_len: usize) -> Vec<u64> {
            let bytes = self.to_repr();
            let uint = BigUint::from_bytes_le(bytes.as_ref());
            let digits = uint.iter_u64_digits();
            decompose_u64_digits_to_limbs(digits, num_limbs, bit_len)
        }

        #[inline(always)]
        fn to_bytes_le(&self) -> Vec<u8> {
            self.to_repr().as_ref().to_vec()
        }
    }
}

/// Module for reading parameters for Halo2 proving system from the file system.
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

    /// Reads the srs from a file found in `./params/kzg_bn254_{k}.srs` or `{dir}/kzg_bn254_{k}.srs` if `PARAMS_DIR` env var is specified.
    /// * `k`: degree that expresses the size of circuit (i.e., 2^<sup>k</sup> is the number of rows in the circuit)
    pub fn read_params(k: u32) -> ParamsKZG<Bn256> {
        let dir = var("PARAMS_DIR").unwrap_or_else(|_| "./params".to_string());
        ParamsKZG::<Bn256>::read(&mut BufReader::new(
            File::open(format!("{dir}/kzg_bn254_{k}.srs").as_str())
                .expect("Params file does not exist"),
        ))
        .unwrap()
    }

    /// Attempts to read the srs from a file found in `./params/kzg_bn254_{k}.srs` or `{dir}/kzg_bn254_{k}.srs` if `PARAMS_DIR` env var is specified, creates a file it if it does not exist.
    /// * `k`: degree that expresses the size of circuit (i.e., 2^<sup>k</sup> is the number of rows in the circuit)
    /// * `setup`: a function that creates the srs
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

    /// Generates the SRS for the KZG scheme and writes it to a file found in "./params/kzg_bn2_{k}.srs` or `{dir}/kzg_bn254_{k}.srs` if `PARAMS_DIR` env var is specified, creates a file it if it does not exist"
    /// * `k`: degree that expresses the size of circuit (i.e., 2^<sup>k</sup> is the number of rows in the circuit)
    pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
        read_or_create_srs::<G1Affine, _>(k, |k| {
            ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()))
        })
    }
}

/// Utilities for testing
#[cfg(any(test, feature = "test-utils"))]
pub mod testing {
    use crate::halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
        poly::commitment::ParamsProver,
        poly::kzg::{
            commitment::KZGCommitmentScheme, commitment::ParamsKZG, multiopen::ProverSHPLONK,
            multiopen::VerifierSHPLONK, strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use rand::rngs::OsRng;

    /// helper function to generate a proof with real prover
    pub fn gen_proof(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        circuit: impl Circuit<Fr>,
    ) -> Vec<u8> {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<_>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, _>,
            _,
        >(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("prover should not fail");
        transcript.finalize()
    }

    /// helper function to verify a proof
    pub fn check_proof(
        params: &ParamsKZG<Bn256>,
        vk: &VerifyingKey<G1Affine>,
        proof: &[u8],
        expect_satisfied: bool,
    ) {
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        let res = verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(verifier_params, vk, strategy, &[&[]], &mut transcript);

        if expect_satisfied {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::halo2_proofs::halo2curves::bn256::Fr;
    use num_bigint::RandomBits;
    use rand::{rngs::OsRng, Rng};
    use std::ops::Shl;

    use super::*;

    #[test]
    fn test_signed_roundtrip() {
        use crate::halo2_proofs::halo2curves::bn256::Fr;
        assert_eq!(fe_to_bigint(&bigint_to_fe::<Fr>(&-BigInt::one())), -BigInt::one());
    }

    #[test]
    fn test_decompose_biguint() {
        let mut rng = OsRng;
        const MAX_LIMBS: u64 = 5;
        for bit_len in 64..128usize {
            for num_limbs in 1..=MAX_LIMBS {
                for _ in 0..10_000usize {
                    let mut e: BigUint = rng.sample(RandomBits::new(num_limbs * bit_len as u64));
                    let limbs = decompose_biguint::<Fr>(&e, num_limbs as usize, bit_len);

                    let limbs2 = {
                        let mut limbs = vec![];
                        let mask = BigUint::one().shl(bit_len) - 1usize;
                        for _ in 0..num_limbs {
                            let limb = &e & &mask;
                            let mut bytes_le = limb.to_bytes_le();
                            bytes_le.resize(32, 0u8);
                            limbs.push(Fr::from_bytes(&bytes_le.try_into().unwrap()).unwrap());
                            e >>= bit_len;
                        }
                        limbs
                    };
                    assert_eq!(limbs, limbs2);
                }
            }
        }
    }

    #[test]
    fn test_decompose_u64_digits_to_limbs() {
        let mut rng = OsRng;
        const MAX_LIMBS: u64 = 5;
        for bit_len in 0..64usize {
            for num_limbs in 1..=MAX_LIMBS {
                for _ in 0..10_000usize {
                    let mut e: BigUint = rng.sample(RandomBits::new(num_limbs * bit_len as u64));
                    let limbs = decompose_u64_digits_to_limbs(
                        e.to_u64_digits(),
                        num_limbs as usize,
                        bit_len,
                    );
                    let limbs2 = {
                        let mut limbs = vec![];
                        let mask = BigUint::one().shl(bit_len) - 1usize;
                        for _ in 0..num_limbs {
                            let limb = &e & &mask;
                            limbs.push(u64::try_from(limb).unwrap());
                            e >>= bit_len;
                        }
                        limbs
                    };
                    assert_eq!(limbs, limbs2);
                }
            }
        }
    }

    #[test]
    fn test_log2_ceil_zero() {
        assert_eq!(log2_ceil(0), 0);
    }
}
