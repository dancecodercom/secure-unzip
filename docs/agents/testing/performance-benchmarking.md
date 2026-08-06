---
type: Testing Guide
title: Performance Benchmarking
description: The external benchmark harness, the exact tools and flags, and the report it writes.
tags: [testing, benchmark, hyperfine, implemented]
timestamp: 2026-08-06T00:00:00Z
---

# Performance Benchmarking

**Status: implemented** (2026-08-06). Harness in `benchmark/performance/benchmark.sh`, run via
`make bench`; corpus from `benchmark/performance/generate_examples.py` (`make fixtures`).
Source: `CLAUDE.md` §4.

An **external** script (Bash or PHP), not a Go benchmark — see
[the decision record](../decisions/2026-08-06-hyperfine-for-benchmarks.md).

## Tools and invocations

| Tool            | Invocation                                             | Captures                                                   |
|-----------------|--------------------------------------------------------|------------------------------------------------------------|
| `hyperfine`     | `--warmup 3 --runs 10 --time-unit millisecond`         | execution duration, mean, standard deviation, speed ratios |
| GNU `time`      | `gtime -v` (or `/usr/bin/time -v` where GNU is native) | Peak Resident Set Size (Max RSS), CPU usage percentage     |

Both are run side-by-side against standard `unzip` on the same archives.

`--time-unit millisecond` is not optional: without it hyperfine switches to seconds for the
slower archives, and the merged table silently mixes units.

## Corpus

Every archive in `benchmark/performance/examples/` is benchmarked, not one representative file —
the extractors' relative standing swings from ~1.5x to ~7.8x depending on whether the work is
inflate-bound, write-bound or syscall-bound. See `benchmark/performance/README.md`. The `.zip`
files are gitignored; the script regenerates them if the directory is empty.

secure-unzip is measured with its hardening **on** — `--secure=no` would answer the wrong
question. The one exception is `-max-ratio`, disabled because the benign `compressible-text`
fixture is legitimately ~290:1 and would otherwise abort. Every other default (path validation,
max-size, max-files, mode masking) stands.

## Platform caveat

`time -v` is GNU time; **macOS ships BSD time, which has no `-v`**, and darwin is the primary
working platform. Install it with `brew install gnu-time` — note that is *not* `coreutils`,
which ships `gdate` and `gtimeout` but no `time(1)`. Verified present on the reference machine
as `/opt/homebrew/bin/gtime`.

When GNU time is absent the script falls back to BSD `time -l`, which reports Max RSS in bytes
and no CPU percentage — the percentage is derived as `(user + sys) / real`. `CLAUDE.md` §4 allows
"or process profiling" for exactly this reason. The report records which tool produced its
numbers, since the two are not interchangeable across machines.

## Output

Report path: `docs/benchmark/performance_report.md` (generated). It combines the exported
hyperfine markdown table with the resource metrics into one structured summary, plus the host,
CPU, and both extractor versions — the figures are machine-specific and must be regenerated on
the machine you care about rather than read from a committed report.

Distinct from the tool's own `--verbose` statistics ([Verbose Output](../cli/verbose-output.md)):
those are single-run, self-reported, and unwarmed. Never quote them as benchmark results.

Keep it separate from `security_report.md` — different harness, different audience, different
regeneration cadence.
