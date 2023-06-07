/*
 * Test utilities for committing to data blobs with KZG
 */
use ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::{bn256::{Fr, G1Affine, G2, G1}, FieldExt};
use serde::{Deserialize, Serialize};
use super::polynomial::Polynomial;

#[derive(Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct pp {
    pub ptau_g1: Vec<G1>,
    pub ptau_g2: Vec<G2>,
}

///
/// Provides an easy interface to commit and open to data blobs
/// ```
/// use rand::rngs::OsRng;
/// 
/// let pp = Blob::mock_trusted_setup(Fr::random(&mut OsRng));
/// let k = 4;
/// let data = vec![Fr::random(OsRng); 2u64.pow(k) as usize];
/// let blob = Blob::new(&data, pp, k);
/// let cm = blob.commit_vector();
/// let open_points = vec![1, 2];
/// let quotient = blob.open_prf(&open_points);
/// ```
/// 
pub struct Blob {
    pub k: u32,
    pub pp: pp,
    pub data: Vec<Fr>,
    p: Polynomial<Fr>,
}

pub fn root_of_unity(k: u32) -> Fr {
    Fr::root_of_unity().pow(&[2u64.pow(Fr::S - k) as u64, 0, 0, 0])
}

impl Blob {
    /*
     * Returns ω - the generator for the roots of unity of order 2^k
     */
    pub fn root_of_unity(&self) -> Fr {
        root_of_unity(self.k)
    }

    /*
     * Instantiates Blob struct w/ public parameters, blob data, and
     * polynomial p(X) that interpolates the blob data.
     */
    pub fn new(data: Vec<Fr>, pp: pp, k: u32) -> Self {
        let w = root_of_unity(k);
        let mut idxs = vec![Fr::one()];
        for _ in 1..2u32.pow(k) as usize {
            idxs.push(idxs.last().unwrap() * w);
        }
        let p = Polynomial::from_points(&idxs, &data);
        Blob { k, pp, data, p }
    }

    /*
    * Convenience function for running a mock setup() for the commitment
    * scheme. This is not secure.
    */
    pub fn mock_trusted_setup(tau: Fr, blob_len: usize, n_openings: usize) -> pp {
        let tau_fr: Fr = Fr::from(tau);

        // Powers of tau in G1 to commit to polynomials p(X) and q(X)
        let mut ptau_g1: Vec<G1> = vec![G1::generator()];
        for _ in 1..blob_len {
            ptau_g1.push(ptau_g1.last().unwrap() * tau_fr);
        }

        // Powers of tau in G2 to commit to polynomials z(X) and r(X)
        let mut ptau_g2: Vec<G2> = vec![G2::generator()];
        for _ in 1..=n_openings {
            ptau_g2.push(ptau_g2.last().unwrap() * tau_fr);
        }

        pp { ptau_g1, ptau_g2 }
    }

    /*
    * Creates vector commitment by interpolating a polynomial p(X) and evaluating
    * at p(τ).
    */
    pub fn commit_vector(&self) -> G1Affine {
        let selected_root = self.root_of_unity();
        let mut idxs = vec![Fr::one()];
        for _ in 1..self.data.len() {
            idxs.push(idxs.last().unwrap() * selected_root);
        }
        let p = Polynomial::from_points(&idxs, &self.data);
        let p_bar = G1Affine::from(p.eval_ptau(&self.pp.ptau_g1));
        p_bar
    }

    /*
    * Computes multi-open proof. Done by computing a quotient polynomial
    * q(X) = [p(X) - r(X)]/z(X). Opening proof is q(τ).
    */
    pub fn open_prf(
        &self,
        idxs: &Vec<u64>,
    ) -> G1Affine {

        let selected_root = self.root_of_unity();
        let idxs_fr: Vec<Fr> = idxs.iter().map(|idx| selected_root.pow(&[*idx as u64, 0, 0, 0])).collect();
        let vals: Vec<Fr> = idxs.iter().map(|idx| self.data[*idx as usize]).collect();

        let r: Polynomial<Fr> = Polynomial::from_points(&idxs_fr, &vals);
        let z: Polynomial<Fr> = Polynomial::vanishing(&idxs_fr);

        let (q, rem) = Polynomial::div_euclid(&(self.p.clone() - r.clone()), &z);
        if !rem.is_zero() {
            panic!("p(X) - r(X) is not divisible by z(X). Cannot compute q(X)");
        }

        G1Affine::from(q.eval_ptau(&self.pp.ptau_g1))
    }
}