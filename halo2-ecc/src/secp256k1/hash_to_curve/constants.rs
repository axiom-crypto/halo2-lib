use halo2_base::{utils::BigPrimeField, AssignedValue, Context};

pub(crate) fn get_z_pad<F: BigPrimeField>(ctx: &mut Context<F>) -> Vec<AssignedValue<F>> {
    let zero = ctx.load_zero();
    vec![zero; 64]
}

pub(crate) fn get_lib_str<F: BigPrimeField>(ctx: &mut Context<F>) -> Vec<AssignedValue<F>> {
    let zero = ctx.load_zero();
    let ninety_six = ctx.load_constant(F::from(96));
    vec![zero, ninety_six]
}

pub(crate) fn get_dst_prime<F: BigPrimeField>(ctx: &mut Context<F>) -> Vec<AssignedValue<F>> {
    let dst_prime = [
        81, 85, 85, 88, 45, 86, 48, 49, 45, 67, 83, 48, 50, 45, 119, 105, 116, 104, 45, 115, 101,
        99, 112, 50, 53, 54, 107, 49, 95, 88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83,
        87, 85, 95, 82, 79, 95, 49,
    ];
    dst_prime.into_iter().map(F::from).map(|v| ctx.load_constant(v)).collect::<Vec<_>>()
}
