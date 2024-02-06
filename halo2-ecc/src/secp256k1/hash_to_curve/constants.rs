use halo2_base::{ utils::BigPrimeField, AssignedValue, Context };

use crate::bigint::ProperCrtUint;

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
        81, 85, 85, 88, 45, 86, 48, 49, 45, 67, 83, 48, 50, 45, 119, 105, 116, 104, 45, 115, 101, 99,
        112, 50, 53, 54, 107, 49, 95, 88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87,
        85, 95, 82, 79, 95, 49,
    ];
    dst_prime
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>()
}

pub(crate) fn get_Z<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let z = [
        18446744069414583332, 18446744073709551615, 18446744073709551615, 18446744073709551615,
    ];
    let z = z
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_A<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let a = [4635408806871057715, 16813014259472469597, 11568152433342665330, 4577682160469023452];
    let a = a
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_B<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let a = [1771, 0, 0, 0];
    let a = a
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_C1<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let c2 = [12250307269654431171, 7923238676646950141, 11532678464006552332, 848203876191778994];
    let c2 = c2
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_C2<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let c2 = [1676976732802240618, 15092790605762360413, 6707906935894382405, 5030930201920786804];
    let c2 = c2
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_1_0<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_1_0 = [
        10248191149674768583, 4099276460824344803, 16397105843297379214, 10248191152060862008,
    ];
    let k_1_0 = k_1_0
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_1_1<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_1_1 = [
        16140637477814429057, 15390439281582816146, 13399077293683197125, 564028334007329237,
    ];
    let k_1_1 = k_1_1
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_1_2<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_1_2 = [
        5677861232072053346, 16451756383528566833, 16331199996347402988, 6002227985152881894,
    ];
    let k_1_2 = k_1_2
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_1_3<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_1_3 = [
        10248191149674768524, 4099276460824344803, 16397105843297379214, 10248191152060862008,
    ];
    let k_1_3 = k_1_3
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_2_0<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_2_0 = [
        11522098205669897371, 9713490981125900413, 11286949528964841693, 15228765018197889418,
    ];
    let k_2_0 = k_2_0
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_2_1<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_2_1 = [
        14207262949819313428, 491854862080688571, 17853591451159765588, 17126563718956833821,
    ];
    let k_2_1 = k_2_1
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_3_0<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_3_0 = [
        11614616637729727036, 3416063717353620669, 7515340178177965473, 5465701947765793071,
    ];
    let k_3_0 = k_3_0
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_3_1<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_3_1 = [
        16139934577133973923, 7240293169244854895, 12236461929419286229, 14365933273833241615,
    ];
    let k_3_1 = k_3_1
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_3_2<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_3_2 = [
        12062302652890802481, 8225878191764283416, 8165599998173701494, 3001113992576440947,
    ];
    let k_3_2 = k_3_2
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_3_3<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_3_3 = [
        9564978407794773380, 13664254869414482678, 11614616639002310276, 3416063717353620669,
    ];
    let k_3_3 = k_3_3
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_4_0<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_4_0 = [
        18446744069414582587, 18446744073709551615, 18446744073709551615, 18446744073709551615,
    ];
    let k_4_0 = k_4_0
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_4_1<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_4_1 = [
        16119550551890077043, 10693728869668149624, 15414104513184973464, 8792806907174565023,
    ];
    let k_4_1 = k_4_1
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}

pub(crate) fn get_k_4_2<F: BigPrimeField>(ctx: &mut Context<F>) -> ProperCrtUint<F> {
    let k_4_2 = [
        12087522392169162607, 737782293121032857, 17557015139884872574, 7243101504725699116,
    ];
    let k_4_2 = k_4_2
        .into_iter()
        .map(F::from)
        .map(|v| ctx.load_constant(v))
        .collect::<Vec<_>>();
}
