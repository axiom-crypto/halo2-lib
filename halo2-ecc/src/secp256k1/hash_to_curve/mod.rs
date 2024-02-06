use halo2_base::{ gates::RangeChip, utils::BigPrimeField, AssignedValue, Context };

use crate::{ bigint::ProperCrtUint, ecc::EcPoint, fields::FieldChip };

use self::hash_to_field::hash_to_field;

use super::sha256::Sha256Chip;

pub mod util;
pub mod constants;
pub mod expand_message_xmd;
pub mod hash_to_field;
pub mod map_to_curve;
pub mod iso_map;

pub fn hash_to_curve<F: BigPrimeField, FC: FieldChip<F>>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    ecc_chip: &FC,
    sha256_chip: &Sha256Chip<F>,
    msg_bytes: &[AssignedValue<F>],
    q0_gx1_sqrt: ProperCrtUint<F>,
    q0_gx2_sqrt: ProperCrtUint<F>,
    q0_y_pos: ProperCrtUint<F>,
    q0_x_mapped: ProperCrtUint<F>,
    q0_y_mapped: ProperCrtUint<F>,
    q1_gx1_sqrt: ProperCrtUint<F>,
    q1_gx2_sqrt: ProperCrtUint<F>,
    q1_y_pos: ProperCrtUint<F>,
    q1_x_mapped: ProperCrtUint<F>,
    q1_y_mapped: ProperCrtUint<F>
) -> EcPoint<F, ProperCrtUint<F>> {
    // Step 1: u = hash_to_field(msg)
    let (u0, u1) = hash_to_field(ctx, range, sha256_chip, msg_bytes);

    // Step 2: Q0 = map_to_curve(u[0])
    let (q0_x, q0_y2) = map_to_curve::map_to_curve(
        ctx,
        range,
        u0,
        q0_gx1_sqrt,
        q0_gx2_sqrt,
        q0_y_pos,
        q0_x_mapped,
        q0_y_mapped
    );

    // Step 3: Q1 = map_to_curve(u[1])
    let (q1_x, q1_y2) = map_to_curve::map_to_curve(
        ctx,
        range,
        u1,
        q0_gx1_sqrt,
        q0_gx2_sqrt,
        q0_y_pos,
        q0_x_mapped,
        q0_y_mapped
    );

    // Step 4: return A + B
    let q0 = EcPoint::<F, ProperCrtUint<F>>::new(q0_x_mapped, q0_y_mapped);
    let q1 = EcPoint::<F, ProperCrtUint<F>>::new(q1_x_mapped, q1_y_mapped);

    let point_add = ecc_chip.add_no_carry(ctx, q0, q1);

    point_add
}
