//! The constraints of the Sha256 circuit

use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Expression, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use log::info;

use crate::{
    sha256::vanilla::{
        columns::ShaTable,
        util::{decode, rotate, shift, to_be_bytes},
    },
    util::{
        constraint_builder::BaseConstraintBuilder,
        eth_types::Field,
        expression::{and, from_bytes, not, select, sum, xor, Expr},
        word::{self, WordExpr},
    },
};

use super::columns::Sha256CircuitConfig;
use super::param::*;

impl<F: Field> Sha256CircuitConfig<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let q_first = meta.fixed_column();
        let q_extend = meta.fixed_column();
        let q_start = meta.fixed_column();
        let q_compression = meta.fixed_column();
        let q_end = meta.fixed_column();
        let q_input = meta.fixed_column();
        let q_input_last = meta.fixed_column();
        let q_squeeze = meta.fixed_column();
        let word_w = array_init::array_init(|_| meta.advice_column());
        let word_a = array_init::array_init(|_| meta.advice_column());
        let word_e = array_init::array_init(|_| meta.advice_column());
        let is_final = meta.advice_column();
        let is_paddings = array_init::array_init(|_| meta.advice_column());
        let round_cst = meta.fixed_column();
        let h_a = meta.fixed_column();
        let h_e = meta.fixed_column();
        let hash_table = ShaTable::construct(meta);
        let is_enabled = hash_table.is_enabled;
        let length = hash_table.length;
        let q_enable = hash_table.q_enable;

        // State bits
        let mut w_ext = vec![0u64.expr(); NUM_BITS_PER_WORD_W];
        let mut w_2 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut w_7 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut w_15 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut w_16 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut a = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut b = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut c = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut d = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut e = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut f = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut g = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut h = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut d_68 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut h_68 = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut new_a_ext = vec![0u64.expr(); NUM_BITS_PER_WORD_EXT];
        let mut new_e_ext = vec![0u64.expr(); NUM_BITS_PER_WORD_EXT];
        meta.create_gate("Query state bits", |meta| {
            for k in 0..NUM_BITS_PER_WORD_W {
                w_ext[k] = meta.query_advice(word_w[k], Rotation(-0));
            }
            for i in 0..NUM_BITS_PER_WORD {
                let k = i + NUM_BITS_PER_WORD_W - NUM_BITS_PER_WORD;
                w_2[i] = meta.query_advice(word_w[k], Rotation(-2));
                w_7[i] = meta.query_advice(word_w[k], Rotation(-7));
                w_15[i] = meta.query_advice(word_w[k], Rotation(-15));
                w_16[i] = meta.query_advice(word_w[k], Rotation(-16));
                let k = i + NUM_BITS_PER_WORD_EXT - NUM_BITS_PER_WORD;
                a[i] = meta.query_advice(word_a[k], Rotation(-1));
                b[i] = meta.query_advice(word_a[k], Rotation(-2));
                c[i] = meta.query_advice(word_a[k], Rotation(-3));
                d[i] = meta.query_advice(word_a[k], Rotation(-4));
                e[i] = meta.query_advice(word_e[k], Rotation(-1));
                f[i] = meta.query_advice(word_e[k], Rotation(-2));
                g[i] = meta.query_advice(word_e[k], Rotation(-3));
                h[i] = meta.query_advice(word_e[k], Rotation(-4));
                d_68[i] = meta.query_advice(word_a[k], Rotation(-((NUM_ROUNDS + 4) as i32)));
                h_68[i] = meta.query_advice(word_e[k], Rotation(-((NUM_ROUNDS + 4) as i32)));
            }
            for k in 0..NUM_BITS_PER_WORD_EXT {
                new_a_ext[k] = meta.query_advice(word_a[k], Rotation(0));
                new_e_ext[k] = meta.query_advice(word_e[k], Rotation(0));
            }
            vec![0u64.expr()]
        });
        let w = &w_ext[NUM_BITS_PER_WORD_W - NUM_BITS_PER_WORD..NUM_BITS_PER_WORD_W];
        let new_a = &new_a_ext[NUM_BITS_PER_WORD_EXT - NUM_BITS_PER_WORD..NUM_BITS_PER_WORD_EXT];
        let new_e = &new_e_ext[NUM_BITS_PER_WORD_EXT - NUM_BITS_PER_WORD..NUM_BITS_PER_WORD_EXT];

        let xor = |a: &[Expression<F>], b: &[Expression<F>]| {
            debug_assert_eq!(a.len(), b.len(), "invalid length");
            let mut c = vec![0.expr(); a.len()];
            for (idx, (a, b)) in a.iter().zip(b.iter()).enumerate() {
                c[idx] = xor::expr(a, b);
            }
            c
        };

        let select =
            |c: &[Expression<F>], when_true: &[Expression<F>], when_false: &[Expression<F>]| {
                debug_assert_eq!(c.len(), when_true.len(), "invalid length");
                debug_assert_eq!(c.len(), when_false.len(), "invalid length");
                let mut r = vec![0.expr(); c.len()];
                for (idx, (c, (when_true, when_false))) in
                    c.iter().zip(when_true.iter().zip(when_false.iter())).enumerate()
                {
                    r[idx] = select::expr(c.clone(), when_true.clone(), when_false.clone());
                }
                r
            };

        meta.create_gate("input checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            for w in w_ext.iter() {
                cb.require_boolean("w bit boolean", w.clone());
            }
            for a in new_a_ext.iter() {
                cb.require_boolean("a bit boolean", a.clone());
            }
            for e in new_e_ext.iter() {
                cb.require_boolean("e bit boolean", e.clone());
            }
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("w extend", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let s0 = xor(
                &rotate::expr(&w_15, 7),
                &xor(&rotate::expr(&w_15, 18), &shift::expr(&w_15, 3)),
            );
            let s1 =
                xor(&rotate::expr(&w_2, 17), &xor(&rotate::expr(&w_2, 19), &shift::expr(&w_2, 10)));
            let new_w =
                decode::expr(&w_16) + decode::expr(&s0) + decode::expr(&w_7) + decode::expr(&s1);
            cb.require_equal("w", new_w, decode::expr(&w_ext));
            cb.gate(meta.query_fixed(q_extend, Rotation::cur()))
        });

        meta.create_gate("compression", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let s1 = xor(&rotate::expr(&e, 6), &xor(&rotate::expr(&e, 11), &rotate::expr(&e, 25)));
            let ch = select(&e, &f, &g);
            let temp1 = decode::expr(&h)
                + decode::expr(&s1)
                + decode::expr(&ch)
                + meta.query_fixed(round_cst, Rotation::cur())
                + decode::expr(w);

            let s0 = xor(&rotate::expr(&a, 2), &xor(&rotate::expr(&a, 13), &rotate::expr(&a, 22)));
            let maj = select(&xor(&b, &c), &a, &b);
            let temp2 = decode::expr(&s0) + decode::expr(&maj);
            cb.require_equal("compress a", decode::expr(&new_a_ext), temp1.clone() + temp2);
            cb.require_equal("compress e", decode::expr(&new_e_ext), decode::expr(&d) + temp1);
            cb.gate(meta.query_fixed(q_compression, Rotation::cur()))
        });

        meta.create_gate("start", |meta| {
            let is_final = meta.query_advice(is_final, Rotation::cur());
            let h_a = meta.query_fixed(h_a, Rotation::cur());
            let h_e = meta.query_fixed(h_e, Rotation::cur());
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_equal(
                "start a",
                decode::expr(&new_a_ext),
                select::expr(is_final.expr(), h_a, decode::expr(&d)),
            );
            cb.require_equal(
                "start e",
                decode::expr(&new_e_ext),
                select::expr(is_final.expr(), h_e, decode::expr(&h)),
            );
            cb.gate(meta.query_fixed(q_start, Rotation::cur()))
        });

        meta.create_gate("end", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_equal(
                "end a",
                decode::expr(&new_a_ext),
                decode::expr(&d) + decode::expr(&d_68),
            );
            cb.require_equal(
                "end e",
                decode::expr(&new_e_ext),
                decode::expr(&h) + decode::expr(&h_68),
            );
            cb.gate(meta.query_fixed(q_end, Rotation::cur()))
        });

        // Enforce logic for when this block is the last block for a hash
        meta.create_gate("is final", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let is_padding = meta.query_advice(
                *is_paddings.last().unwrap(),
                Rotation(-((NUM_END_ROWS + NUM_ROUNDS - NUM_WORDS_TO_ABSORB) as i32) - 2),
            );
            let is_final_prev = meta.query_advice(is_final, Rotation::prev());
            let is_final = meta.query_advice(is_final, Rotation::cur());
            // On the first row is_final needs to be enabled
            cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
                cb.require_equal("is_final needs to remain the same", is_final.expr(), 1.expr());
            });
            // Get the correct is_final state from the padding selector
            cb.condition(meta.query_fixed(q_squeeze, Rotation::cur()), |cb| {
                cb.require_equal(
                    "is_final needs to match the padding selector",
                    is_final.expr(),
                    is_padding,
                );
            });
            // Copy the is_final state to the q_start rows
            cb.condition(
                meta.query_fixed(q_start, Rotation::cur())
                    - meta.query_fixed(q_first, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "is_final needs to remain the same",
                        is_final.expr(),
                        is_final_prev,
                    );
                },
            );
            cb.gate(1.expr())
        });

        meta.create_gate("is enabled", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_squeeze = meta.query_fixed(q_squeeze, Rotation::cur());
            let is_final = meta.query_advice(is_final, Rotation::cur());
            let is_enabled = meta.query_advice(is_enabled, Rotation::cur());
            // Only set is_enabled to true when is_final is true and it's a squeeze row
            cb.require_equal(
                "is_enabled := q_squeeze && is_final",
                is_enabled.expr(),
                and::expr(&[q_squeeze.expr(), is_final.expr()]),
            );
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        let start_new_hash = |meta: &mut VirtualCells<F>| {
            // A new hash is started when the previous hash is done or on the first row
            meta.query_advice(is_final, Rotation::cur())
        };

        // Create bytes from input bits
        let input_bytes = to_be_bytes::expr(w);

        // Padding
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let prev_is_padding = meta.query_advice(*is_paddings.last().unwrap(), Rotation::prev());
            let q_input = meta.query_fixed(q_input, Rotation::cur());
            let q_input_last = meta.query_fixed(q_input_last, Rotation::cur());
            let length = meta.query_advice(length, Rotation::cur());
            let is_final_padding_row =
                meta.query_advice(*is_paddings.last().unwrap(), Rotation(-2));
            // All padding selectors need to be boolean
            let is_paddings_expr = is_paddings.iter().map(|is_padding| meta.query_advice(*is_padding, Rotation::cur())).collect::<Vec<_>>();
            for is_padding in is_paddings_expr.iter() {
                cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
                    cb.require_boolean("is_padding boolean", is_padding.clone());
                });
            }
            // Now for each padding selector
            for idx in 0..is_paddings.len() {
                // Previous padding selector can be on the previous row
                let is_padding_prev = if idx == 0 {
                    prev_is_padding.expr()
                } else {
                    is_paddings_expr[idx-1].clone()
                };
                let is_padding = is_paddings_expr[idx].clone();
                let is_first_padding = is_padding.clone() - is_padding_prev.clone();
                // Check padding transition 0 -> 1 done only once
                cb.condition(q_input.expr(), |cb| {
                    cb.require_boolean("padding step boolean", is_first_padding.clone());
                });
                // Padding start/intermediate byte, all padding rows except the last one
                cb.condition(
                    and::expr([(q_input.expr() - q_input_last.expr()), is_padding.expr()]),
                    |cb| {
                        // Input bytes need to be zero, or 128 if this is the first padding byte
                        cb.require_equal(
                            "padding start/intermediate byte, all padding rows except the last one",
                            input_bytes[idx].clone(),
                            is_first_padding.expr() * 128.expr(),
                        );
                    },
                );
                // Padding start/intermediate byte, last padding row but not in the final block
                cb.condition(
                    and::expr([
                        q_input_last.expr(),
                        is_padding.expr(),
                        not::expr(is_final_padding_row.expr()),
                    ]),
                    |cb| {
                        // Input bytes need to be zero, or 128 if this is the first padding byte
                        cb.require_equal(
                            "padding start/intermediate byte, last padding row but not in the final block",
                            input_bytes[idx].clone(),
                            is_first_padding.expr() * 128.expr(),
                        );
                    },
                );
            }
            // The padding spec: begin with the original message of length L bits
            // append a single '1' bit
            // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
            // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
            // such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)
            //
            // The last row containing input/padding data in the final block needs to
            // contain the length in bits (Only input lengths up to 2**32 - 1
            // bits are supported, which is lower than the spec of 2**64 - 1 bits)
            cb.condition(and::expr([q_input_last.expr(), is_final_padding_row.expr()]), |cb| {
                cb.require_equal("padding length", decode::expr(w), length.expr() * 8.expr());
            });
            cb.gate(1.expr())
        });

        // Each round gets access to up to 32 bits of input data.
        // We store that as a little-endian word.
        meta.create_gate("word_value", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let masked_input_bytes = input_bytes
                .iter()
                .zip_eq(is_paddings)
                .map(|(input_byte, is_padding)| {
                    input_byte.clone() * not::expr(meta.query_advice(is_padding, Rotation::cur()))
                })
                .collect_vec();
            // Convert to u32 as little-endian bytes. Choice of LE is arbitrary, but consistent with Keccak impl.
            let input_word = from_bytes::expr(&masked_input_bytes);
            cb.require_equal(
                "word value",
                input_word,
                meta.query_advice(hash_table.word_value, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_input, Rotation::cur()))
        });
        // Update the length on rows where we absorb data
        meta.create_gate("length", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let length_prev = meta.query_advice(length, Rotation::prev());
            let length = meta.query_advice(length, Rotation::cur());
            // Length increases by the number of bytes that aren't padding
            // In a new block we have to start from 0 if the previous block was the final one
            cb.require_equal(
                "update length",
                length.clone(),
                length_prev.clone()
                    + sum::expr(is_paddings.map(|is_padding| {
                        not::expr(meta.query_advice(is_padding, Rotation::cur()))
                    })),
            );
            cb.gate(meta.query_fixed(q_input, Rotation::cur()))
        });

        // Make sure data is consistent between blocks
        meta.create_gate("cross block data consistency", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let start_new_hash = start_new_hash(meta);
            let mut add = |_name: &'static str, column: Column<Advice>| {
                let last_rot =
                    Rotation(-((NUM_END_ROWS + NUM_ROUNDS - NUM_WORDS_TO_ABSORB) as i32));
                let value_to_copy = meta.query_advice(column, last_rot);
                let prev_value = meta.query_advice(column, Rotation::prev());
                let cur_value = meta.query_advice(column, Rotation::cur());
                // On squeeze rows fetch the last used value
                cb.condition(meta.query_fixed(q_squeeze, Rotation::cur()), |cb| {
                    cb.require_equal("copy check", cur_value.expr(), value_to_copy.expr());
                });
                // On first rows keep the length the same, or reset the length when starting a
                // new hash
                cb.condition(
                    meta.query_fixed(q_start, Rotation::cur())
                        - meta.query_fixed(q_first, Rotation::cur()),
                    |cb| {
                        cb.require_equal(
                            "equality check",
                            cur_value.expr(),
                            prev_value.expr() * not::expr(start_new_hash.expr()),
                        );
                    },
                );
                // Set the value to zero on the first row
                cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
                    cb.require_equal("initialized to 0", cur_value.clone(), 0.expr());
                });
            };
            add("length", length);
            add("last padding", *is_paddings.last().unwrap());
            cb.gate(1.expr())
        });

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // Squeeze out the hash
            // Last 4 rows assigned in weird order; this translates to hs[0], hs[1], ..., hs[7]
            let hash_parts = [new_a, &a, &b, &c, new_e, &e, &f, &g];
            let hash_bytes_be = hash_parts.iter().flat_map(|part| to_be_bytes::expr(part));
            let hash_bytes_le = hash_bytes_be.rev().collect::<Vec<_>>();
            cb.condition(start_new_hash(meta), |cb| {
                cb.require_equal_word(
                    "hash check",
                    word::Word32::new(hash_bytes_le.try_into().expect("32 bytes")).to_word(),
                    hash_table.output.map(|col| meta.query_advice(col, Rotation::cur())),
                );
            });
            cb.gate(meta.query_fixed(q_squeeze, Rotation::cur()))
        });

        info!("degree: {}", meta.degree());

        Sha256CircuitConfig {
            q_first,
            q_extend,
            q_start,
            q_compression,
            q_end,
            q_input,
            q_input_last,
            q_squeeze,
            hash_table,
            word_w,
            word_a,
            word_e,
            is_final,
            is_paddings,
            round_cst,
            h_a,
            h_e,
            _marker: PhantomData,
        }
    }
}
