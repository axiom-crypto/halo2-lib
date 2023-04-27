This code defines two functions, `assign` and `crt`, in a Rust library file named `select_by_indicator.rs`. Both functions are based on the Halo 2 proving library and perform arithmetic operations on large integers, represented as `OverflowInteger` and `CRTInteger` types.

1. `assign` function:
   - Takes in four arguments:
     * `gate`: A type implementing `GateInstructions<F>` trait where `F` is a scalar field.
     * `ctx`: A mutable reference to a `Context<F>` where `F` is a scalar field.
     * `a`: A slice of `OverflowInteger<F>` values.
     * `coeffs`: A slice of `AssignedValue<F>` values.
   - The function computes the output limbs of the `OverflowInteger` by mapping over the range of limbs, selecting the appropriate limb by the indicator coefficients.
   - It then calculates the maximum number of bits in each limb of the output integer.
   - Finally, it constructs and returns an `OverflowInteger` with the calculated limbs and max limb bits.

2. `crt` function:
   - Takes in five arguments:
     * `gate`: A type implementing `GateInstructions<F>` trait where `F` is a scalar field.
     * `ctx`: A mutable reference to a `Context<F>` where `F` is a scalar field.
     * `a`: A slice of `CRTInteger<F>` values.
     * `coeffs`: A slice of `AssignedValue<F>` values.
     * `limb_bases`: A slice of `F` values, representing the bases for each limb.
   - The function computes the output limbs of the `OverflowInteger` truncation by mapping over the range of limbs, selecting the appropriate limb by the indicator coefficients.
   - It then calculates the maximum number of bits in each limb of the output integer truncation.
   - The function evaluates the native representation of the `OverflowInteger` using the truncation and the provided limb bases.
   - It also calculates the output value by accumulating the native values of the input `CRTInteger`s based on the coefficients.
   - Finally, it constructs and returns a `CRTInteger` with the calculated truncation, native representation, and output value.
