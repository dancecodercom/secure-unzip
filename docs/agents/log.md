# Directory Update Log

## 2026-08-06

* **Creation**: [Verbose Output](cli/verbose-output.md) — `--verbose` reports resolved parameter
  values, peak memory, CPU, file count and MB/s to stderr; records the `Maxrss` unit and
  Windows/`getrusage` traps.
* **Update**: [Command Line Interface](cli/command-line-interface.md) — added `--verbose` and `-q`
  to the flags table.
* **Update**: [Performance Benchmarking](testing/performance-benchmarking.md) — cross-linked, with
  a warning not to quote `--verbose` figures as benchmark results.
* **Creation**: [A --secure master switch, on by default](decisions/2026-08-06-secure-master-switch.md)
  — `--secure=yes` (default) applies the precaution profile, `--secure=no` clears it; explicitly set
  limits always win.
* **Update**: [Command Line Interface](cli/command-line-interface.md) — flags table now carries real
  defaults (`-max-size` 10 GiB, `-max-mode` 0755, new `--secure` and `-max-ratio`); open-questions
  list reduced to two.
* **Update**: [unzip-compatible CLI surface](decisions/2026-08-06-unzip-compatible-cli.md) — noted
  that its deferred escape hatch was delivered as `--secure=no`.
* **Creation**: [Cross-platform binaries in an untracked bin/](decisions/2026-08-06-cross-platform-binaries-in-bin.md)
  — all three platforms built into `bin/` on every build, excluded from version control, published
  as release assets.
* **Update**: [Module Layout](architecture/module-layout.md) — added `bin/` and `.gitignore` to the
  root files table.

* **Creation**: Established the bundle from the specification in `CLAUDE.md` (no source code
  exists yet) with [Architecture](architecture/index.md), [CLI](cli/index.md),
  [Testing](testing/index.md) and [Decisions](decisions/index.md).
* **Creation**: [Module Layout](architecture/module-layout.md),
  [Extraction Pipeline](architecture/extraction-pipeline.md),
  [Threat Model](architecture/threat-model.md),
  [Command Line Interface](cli/command-line-interface.md),
  [Security Test Suite](testing/security-test-suite.md),
  [Performance Benchmarking](testing/performance-benchmarking.md).
* **Creation**: Decision records
  [Go as implementation language](decisions/2026-08-06-go-single-static-binary.md),
  [MIT license](decisions/2026-08-06-mit-license.md),
  [unzip-compatible CLI surface](decisions/2026-08-06-unzip-compatible-cli.md),
  [Fail closed on constraint breach](decisions/2026-08-06-fail-closed-on-breach.md),
  [Write-then-lock for read-only extraction](decisions/2026-08-06-write-then-lock-readonly.md),
  [Benchmark with hyperfine instead of a custom timer](decisions/2026-08-06-hyperfine-for-benchmarks.md).
