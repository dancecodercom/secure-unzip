# Directory Update Log

## 2026-08-06

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
