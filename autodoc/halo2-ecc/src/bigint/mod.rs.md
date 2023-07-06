This code is part of a Halo 2 proving library, which is a cryptographic library for Zero-Knowledge proof systems. It defines data structures and functions for arithmetic operations with integers in a modular arithmetic context, specifically using the Chinese Remainder Theorem (CRT).

There are several structs defined:

1. OverflowInteger - Represents an integer using a series of limbs (AssignedValue), each with a certain number of bits (max_limb_bits).
2. FixedOverflowInteger - Represents an integer using a series of limbs (Field elements), similar to OverflowInteger but with fixed limbs.
3. CRTInteger - Represents an integer using CRT as `a mod 2^t` and `a mod n`, where `t` is related to the OverflowInteger's truncation and `n` is the modulus of the scalar field.
4. FixedCRTInteger - A fixed version of CRTInteger.
5. FixedAssignedCRTInteger - A fixed version of CRTInteger with limb_fixed_cells to store fixed cells.

The module includes several arithmetic operations and utility functions:

1. construct() - A function to create an instance of the respective structs.
2. to_bigint() - Converts the OverflowInteger or FixedOverflowInteger instances back into BigInt or BigUint.
3. evaluate() - Evaluates an OverflowInteger using the provided gate and context.
4. from_native() - Converts a BigUint into a FixedOverflowInteger or FixedCRTInteger.
5. assign() - Assigns an instance of FixedOverflowInteger or FixedCRTInteger to an OverflowInteger or CRTInteger.
6. select_by_indicator() - Selects an OverflowInteger using an indicator from a list of FixedOverflowIntegers.

In addition to the structs and functions mentioned above, the module also includes several submodules for different arithmetic operations, such as add_no_carry, big_is_equal, big_is_zero, big_less_than, carry_mod, check_carry_mod_to_zero, check_carry_to_zero, mul_no_carry, negative, scalar_mul_and_add_no_carry, scalar_mul_no_carry, select, select_by_indicator, sub, and sub_no_carry.

The BigIntStrategy enum is also defined, which specifies the strategy used for BigInt operations, either Simple or CustomVerticalShort.
