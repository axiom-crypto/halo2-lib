To benchmark with flamegraph:

```
cargo bench --bench <BENCH NAME> --profile=flamegraph --no-default-features --features "halo2-axiom, jemallocator" -- --profile-time <TIME IN SECONDS>
```

We will now find a file called `flamegraph.svg` in `target/criterion/<name-of-benchmark>/profile/flamegraph.svg`.

---

For deeper benchmarking, on Mac:

```
cargo instruments --bench <BENCH NAME> -t <TEMPLATE> --no-default-features --features "jemallocator"
```

where `<TEMPLATE>` can be `time`, `alloc`, or anything in `cargo instruments -l`.

---

For deeper benchmarking, on Linux:

```
cargo bench --bench <BENCH NAME> --no-run --no-default-features --features "jemallocator"
perf record --call-graph dwarf,16384 -e cpu-clock -F 997 target/release/deps/<BEGINS WITH BENCH NAME>
perf script | inferno-collapse-perf > stacks.folded
grep create_proof stacks.folded | grep synthesize > perf_synthesize.out
```

In order to run `inferno-collapse-perf` you need to install

```
cargo install inferno
```

This is a compiled version of the flamegraph script `stackcollapse-perf.pl`, which was originally a perl script and hence probably slower.
The last command will grep for only functions in `synthesize` called from within `create_proof` because we only want to profile witness generation. You can put `create_proof` or something else for more general profiling. Use `perf script` instead of `perf report` because `perf report` seems to truncate the call chain of stack traces.

```
inferno-flamegraph perf_synthesize.out > flamegraph.svg
```

To convert `perf` output into Flamegraph the old-fashioned way: https://gist.github.com/dlaehnemann/df31787c41bd50c0fe223df07cf6eb89

In linux-5.15 there were some issues with slow `perf`. I fixed it by following https://michcioperz.com/post/slow-perf-script/ and downloading the entire linux-5.19 source. When building `perf` from source, make sure to follow https://www.brendangregg.com/perf.html#Building and install dependencies so dwarf support is on. Make sure you are using the correct version by checking `perf -v`.
