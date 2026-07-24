# Benchmark baseline

`rtc_bench_test.mbt` fixes the workloads used by the native performance gate.
The gate checks the benchmark source hash, so workload changes require a
reviewed baseline update.

The current manifest was recorded from clean commit
`29f4ff26dcb507715a0bfdacd58a0a3b48f3c776` with five warmups and twenty
samples. It retains the runner fingerprint (machine, CPU model, and optional
runner ID), aggregates, and complete raw benchmark output.

Record a baseline only from a clean commit:

```sh
scripts/bench-gate.mjs record
```

This performs five warmups and twenty samples, then writes the commit SHA,
runner fingerprint, aggregate metrics, and complete raw output to
`benchmarks/baseline.json`.

Compare a committed candidate on the same dedicated runner:

```sh
scripts/bench-gate.mjs compare
```

The comparison creates an isolated worktree at the baseline commit, warms both
trees five times, and alternates baseline/candidate order for twenty sample
pairs. It fails when median latency rises by more than 20%, or median
fixed-workload throughput falls by more than 20%. Set
`RTC_BENCH_RUNNER_ID` to a stable dedicated-runner identifier before both
recording and comparing.

Both worktrees use the MoonBit toolchain installed in the current environment.
The manifest intentionally does not record or require a specific MoonBit
version.

Use `scripts/bench-gate.mjs self-test` to validate parsing and threshold logic
without running benchmarks.
