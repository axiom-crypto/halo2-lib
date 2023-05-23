# Tests

For tests that use `GateCircuitBuilder` or `RangeCircuitBuilder`, we currently must use environmental variables `FLEX_GATE_CONFIG` and `LOOKUP_BITS` to pass circuit configuration parameters to the `Circuit::configure` function. This is troublesome when Rust executes tests in parallel, so we to make sure all tests pass, run

```
cargo test -- --test-threads=1
```

to force serial execution.
