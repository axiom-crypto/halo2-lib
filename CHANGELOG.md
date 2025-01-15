# v0.3.0

- Remove `PlonkPlus` strategy for `GateInstructions` to reduce code complexity.
  - Because this strategy involved 1 selector AND 1 fixed column per advice column, it seems hard to justify it will lead to better performance for the prover or verifier.
