---
type: Decision Record
title: Go, shipped as a single static binary
description: Implement secure-unzip in Go for cross-platform single-binary distribution and a memory-safe stdlib zip reader.
tags: [go, language, distribution]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# Go, shipped as a single static binary

**Date:** 2026-08-06 (reconstructed from `CLAUDE.md`; the choice predates this record)

## Decision

Implement the tool in Go, as a cross-platform CLI. Packages: `main.go`, `extractor/`, `security/`,
`testutils/`.

## Motivation

* A security tool that replaces `unzip` must be trivially installable on machines that already have
  `unzip`. Go produces one dependency-free binary per platform.
* Memory safety matters more than usual here: the input is hostile by definition. C-family
  implementations of archive handling have a long CVE record for exactly this input class.
* `archive/zip` in the standard library gives a streaming reader, which is what makes live
  size/ratio accounting possible (see [Extraction Pipeline](../architecture/extraction-pipeline.md)).
* Cross-compilation covers the "cross-platform" requirement in `CLAUDE.md` §Overview without a
  build matrix per OS.

## Consequences

* `go.mod` and the minimum Go version must be pinned — currently **not on record**, no `go.mod`
  exists.
* Test suite and fixture generator are Go (`_test.go` + `testutils/`), but the *benchmark* harness
  deliberately is not — see [hyperfine for benchmarks](2026-08-06-hyperfine-for-benchmarks.md).
* Permission handling (`-max-mode`, `-read-only`) goes through Go's `os.FileMode`, whose semantics
  on Windows differ sharply from POSIX. Cross-platform behaviour of the permission controls is
  undecided.

## Drawbacks / Alternatives considered

* **Rust**: comparable safety and single-binary story; rejected implicitly by the spec. No recorded
  comparison.
* **A wrapper around system `unzip`**: cheaper, but cannot enforce limits mid-stream — by the time
  `unzip` reports, the bomb has already expanded. Fundamentally incompatible with the threat model.
* Accepted cost: Go's `archive/zip` requires the full central directory, so pure-stream (pipe)
  input is not supported.

# Citations

[1] `CLAUDE.md` §Overview and §5 — "cross-platform command-line utility in Go", module list
