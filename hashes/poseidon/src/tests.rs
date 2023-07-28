#[cfg(test)]
mod tests {
    use std::{cmp::max, iter::zip};

    use halo2_base::{
        gates::{builder::GateThreadBuilder, GateChip},
        halo2_proofs::halo2curves::bn256::Fr,
        utils::ScalarField,
    };
    use poseidon::Poseidon;
    use rand::Rng;

    use crate::PoseidonChip;

    // make interleaved calls to absorb and squeeze elements and
    // check that the result is the same in-circuit and natively
    fn poseidon_compatiblity_verification<F: ScalarField, const T: usize, const RATE: usize>(
        // elements of F to absorb; one sublist = one absorption
        mut absorptions: Vec<Vec<F>>,
        // list of amounts of elements of F that should be squeezed every time
        mut squeezings: Vec<usize>,
        rounds_full: usize,
        rounts_partial: usize,
    ) {
        let mut builder = GateThreadBuilder::prover();
        let gate = GateChip::default();

        let mut ctx = builder.main(0);

        // constructing native and in-circuit Poseidon sponges
        let mut native_sponge = Poseidon::<F, T, RATE>::new(rounds_full, rounts_partial);
        let mut circuit_sponge =
            PoseidonChip::<F, T, RATE>::new(&mut ctx, rounds_full, rounts_partial)
                .expect("Failed to construct Poseidon circuit");

        // preparing to interleave absorptions and squeezings
        let n_iterations = max(absorptions.len(), squeezings.len());
        absorptions.resize(n_iterations, Vec::new());
        squeezings.resize(n_iterations, 0);

        for (absorption, squeezing) in zip(absorptions, squeezings) {
            // absorb (if any elements were provided)
            native_sponge.update(&absorption);
            circuit_sponge.update(&ctx.assign_witnesses(absorption));

            // squeeze (if any elements were requested)
            for _ in 0..squeezing {
                let native_squeezed = native_sponge.squeeze();
                let circuit_squeezed =
                    circuit_sponge.squeeze(&mut ctx, &gate).expect("Failed to squeeze");

                assert_eq!(native_squeezed, *circuit_squeezed.value());
            }
        }

        // even if no squeezings were requested, we squeeze to verify the
        // states are the same after all absorptions
        let native_squeezed = native_sponge.squeeze();
        let circuit_squeezed = circuit_sponge.squeeze(&mut ctx, &gate).expect("Failed to squeeze");

        assert_eq!(native_squeezed, *circuit_squeezed.value());
    }

    fn random_nested_list_f<F: ScalarField>(len: usize, max_sub_len: usize) -> Vec<Vec<F>> {
        let mut rng = rand::thread_rng();
        let mut list = Vec::new();
        for _ in 0..len {
            let len = rng.gen_range(0..=max_sub_len);
            let mut sublist = Vec::new();

            for _ in 0..len {
                sublist.push(F::random(&mut rng));
            }
            list.push(sublist);
        }
        list
    }

    fn random_list_usize(len: usize, max: usize) -> Vec<usize> {
        let mut rng = rand::thread_rng();
        let mut list = Vec::new();
        for _ in 0..len {
            list.push(rng.gen_range(0..=max));
        }
        list
    }

    #[test]
    fn test_poseidon_compatibility_squeezing_only() {
        let absorptions = Vec::new();
        let squeezings = random_list_usize(10, 7);

        poseidon_compatiblity_verification::<Fr, 3, 2>(absorptions, squeezings, 8, 57);
    }

    #[test]
    fn test_poseidon_compatibility_absorbing_only() {
        let absorptions = random_nested_list_f(8, 5);
        let squeezings = Vec::new();

        poseidon_compatiblity_verification::<Fr, 3, 2>(absorptions, squeezings, 8, 57);
    }

    #[test]
    fn test_poseidon_compatibility_interleaved() {
        let absorptions = random_nested_list_f(10, 5);
        let squeezings = random_list_usize(7, 10);

        poseidon_compatiblity_verification::<Fr, 3, 2>(absorptions, squeezings, 8, 57);
    }

    #[test]
    fn test_poseidon_compatibility_other_params() {
        let absorptions = random_nested_list_f(10, 10);
        let squeezings = random_list_usize(10, 10);

        poseidon_compatiblity_verification::<Fr, 5, 4>(absorptions, squeezings, 8, 120);
    }
}
