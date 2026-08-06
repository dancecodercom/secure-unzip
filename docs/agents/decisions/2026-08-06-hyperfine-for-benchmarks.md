---
type: Decision Record
title: Benchmark with hyperfine, not a custom timer
description: Use hyperfine and /usr/bin/time in an external script rather than Go benchmarks, to get credible statistics and a fair comparison against system unzip.
tags: [benchmark, tooling, testing]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# Benchmark with hyperfine, not a custom timer

**Date:** 2026-08-06 (reconstructed from `CLAUDE.md`)

## Decision

Performance measurement lives in an **external** script (Bash or PHP) that drives `hyperfine
--warmup 3 --export-markdown` and `/usr/bin/time -v`, comparing secure-unzip side-by-side with
system `unzip`. It is not a Go benchmark.

## Motivation

* The headline claim is *relative*: "how much does hardening cost versus plain `unzip`". Go's
  `testing.B` cannot benchmark a foreign binary, so a Go benchmark could only measure one side.
* `hyperfine` supplies warmup, repetition, mean, standard deviation, and speed ratios — the exact
  statistics `CLAUDE.md` §4 asks for — without hand-rolled timing code that nobody will trust.
* `/usr/bin/time -v` supplies Max RSS and CPU percentage, which matter more than wall-clock for a
  tool whose whole point is bounding resource use.
* Markdown export drops straight into the generated report.

## Consequences

* Two external dependencies for benchmarking (`hyperfine`, GNU time). Neither is verified as
  installed in this environment; the script must check and fail with a clear message.
* **macOS ships BSD `time`, which has no `-v`.** The primary working platform here is darwin, so
  the script needs a `gtime` fallback — see
  [Performance Benchmarking](../testing/performance-benchmarking.md).
* Benchmarks cannot run in a minimal CI container without installing these tools; the security
  suite (pure Go) can. Keeping the two harnesses separate is what makes that split possible.

## Drawbacks / Alternatives considered

* **Go `testing.B` benchmarks**: zero extra dependencies, runs anywhere — but cannot measure system
  `unzip`, so it answers the wrong question. Rejected as the primary harness; still fine to add
  later for internal hot-path work.
* Accepted cost: benchmark numbers are not reproducible across machines and must be regenerated,
  not trusted from the committed report.

# Citations

[1] `CLAUDE.md` §4 — "leverages hyperfine and GNU /usr/bin/time", "hyperfine --warmup 3 --export-markdown"
