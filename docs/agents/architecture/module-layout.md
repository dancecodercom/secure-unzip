---
type: Architecture Guide
title: Module Layout
description: The Go packages secure-unzip is specified to have and what each one owns.
tags: [architecture, go, packages, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Module Layout

**Status: implemented** (2026-08-06), as mandated by `CLAUDE.md` §5.

| Path           | Kind            | Owns                                                                                  |
|----------------|-----------------|---------------------------------------------------------------------------------------|
| `main.go`      | package main    | Flag parsing, argument validation, wiring, process exit codes, error printing         |
| `extractor/`   | library package | Opening the archive, iterating entries, streaming decompression, writing to disk      |
| `security/`    | library package | The checks: path canonicalisation, size/ratio accounting, file counting, mode masking |
| `testutils/`   | library package | Malicious fixture generation (zip slip, zip bomb, inode exhaustion, 0777 entries)     |

## Boundary rules

* `security/` must not write files. It decides; `extractor/` acts. This keeps every control
  unit-testable without a filesystem.
* `extractor/` must consult `security/` **before** creating any file or directory — see
  [Extraction Pipeline](extraction-pipeline.md).
* `testutils/` is imported only by `_test.go` files and the fixture generator; it must never be
  reachable from `main.go`.
* Module path `github.com/pforret/secure-unzip`, Go directive `1.23` (`go.mod`). Standard library
  only — no third-party dependencies.

## Other root files

| Path                                  | Status      | Purpose                                                          |
|---------------------------------------|-------------|------------------------------------------------------------------|
| `LICENSE`                             | exists      | MIT text, required by `CLAUDE.md` §5 — see the decision record    |
| `CLAUDE.md`                           | exists      | Product specification; the source of every claim in this bundle   |
| `docs/benchmark/security_report.md`   | generated   | Written by `security_test.go` (`make report`)                     |
| `docs/benchmark/performance_report.md`| generated   | Written by `scripts/benchmark.sh` (`make bench`)                  |
| `bin/`                                | build output| macOS, Linux and Windows binaries; gitignored                     |
| `.gitignore`                          | exists      | Excludes `bin/`, `.idea/`, `testdata/tmp/`, `*.zip`               |
| `Makefile`                            | exists      | `build` (5 targets), `build-host`, `test`, `lint`, `bench`, `report` |
| `cmd/genfixtures/`                    | exists      | CLI wrapper so the bash benchmark can generate the Go fixtures    |
| `scripts/benchmark.sh`                | exists      | hyperfine + GNU time harness                                      |
| `.github/workflows/`                  | exists      | `ci.yml` (test on 3 OSes), `release.yml` (assets on tag)          |


`bin/` holds every platform's binary on every build and is never committed — see
[Cross-platform binaries in an untracked bin/](../decisions/2026-08-06-cross-platform-binaries-in-bin.md).
Nothing in the repo may depend on `bin/` existing.

## Error messages

`CLAUDE.md` §5 requires every error to name the security constraint that triggered it (e.g. which
of `-max-size`, `-max-files`, `-max-mode`, or the zip-slip check aborted the run). Treat the
constraint name as part of the error's contract — the security tests assert on it.
