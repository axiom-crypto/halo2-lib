## Contributing to halo2-lib

Thanks for your interest in improving halo2-lib!

The [discussion Telegram][dev-tg] is available for any questions you may have that are not covered in this guide.

### Code of Conduct

This project adheres to the [Rust Code of Conduct][rust-coc].

### Ways to contribute

There are fundamentally four ways an individual can contribute:

1. **By opening an issue:** For example, if you believe that you have uncovered a bug,
   creating a new issue in the issue tracker is the way to report it.
2. **By adding context:** Providing additional context to existing issues,
   such as screenshots, code snippets and helps resolve issues.
3. **By resolving issues:** Typically this is done in the form of either
   demonstrating that the issue reported is not a problem after all, or more often,
   by opening a pull request that fixes the underlying problem, in a concrete and
   reviewable manner.

### Submitting a bug report

When filing a new bug report in the issue tracker, you will be presented with a basic form to fill out.

The most important pieces of information we need in a bug report are:

- The branch you are on (and that it is up to date)
- The platform you are on (Windows, macOS, an M1 Mac or Linux)
- Code snippets if this is happening in relation to testing or building code
- Concrete steps to reproduce the bug

In order to rule out the possibility of the bug being in your project, the code snippets should be as minimal
as possible. It is better if you can reproduce the bug with a small snippet as opposed to an entire project!

### Pull request guidelines

Please file a pull request to resolve an issue.

#### Adding tests

If the change being proposed alters code, the pull request should include one or more tests to ensure that halo2-lib does not regress in the future.

Types of tests include:

- **Positive unit tests**: Checking your ZK circuit produces the expected answer, compared to a native Rust implementation of the same function. This can use either `MockProver` or the real `Prover` and `Verifier`.
- **Negative unit tests**: Checking that your ZK circuit is not under-constrained: the circuit should _not_ verify/pass if given witness values that are deemed incorrect. This can use either `MockProver` (for test execution speed) or the real `Prover` and `Verifier` (for ultimate security).

The easiest way to get started with tests is to look at existing examples and replicate them.

#### Opening the pull request

Before opening a pull request, please make sure all code in the repo compiles, and clippy warnings are resolved.

From within GitHub, opening a new pull request will present you with a template that should be filled out. **Please make pull requests to the [community-edition](https://github.com/axiom-crypto/halo2-lib/tree/community-edition) branch.**

A maintainer will review your pull request and provide feedback and possibly request changes.

[rust-coc]: https://github.com/rust-lang/rust/blob/master/CODE_OF_CONDUCT.md
[dev-tg]: https://t.me/halo2lib
