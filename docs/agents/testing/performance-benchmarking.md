---
type: Testing Guide
title: Performance Benchmarking
description: The external benchmark harness, the exact tools and flags, and the report it writes.
tags: [testing, benchmark, hyperfine, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Performance Benchmarking

**Status: planned** — no benchmark script exists as of 2026-08-06. Source: `CLAUDE.md` §4.

An **external** script (Bash or PHP), not a Go benchmark — see
[the decision record](../decisions/2026-08-06-hyperfine-for-benchmarks.md).

## Tools and invocations

| Tool             | Invocation                                    | Captures                                                     |
|------------------|-----------------------------------------------|--------------------------------------------------------------|
| `hyperfine`      | `hyperfine --warmup 3 --export-markdown <out>` | execution duration, mean, standard deviation, speed ratios   |
| `/usr/bin/time`  | `/usr/bin/time -v`                             | Peak Resident Set Size (Max RSS), CPU usage percentage       |

Both are run side-by-side against standard `unzip` on the same archives.

## Platform caveat

`/usr/bin/time -v` is GNU time. **macOS ships BSD time, which has no `-v`** — the repo's primary
working platform is darwin, so the script must detect `gtime` (Homebrew `coreutils`) or fall back
to another profiling path. `CLAUDE.md` §4 allows "or process profiling" for exactly this reason.
Neither tool is currently verified as installed here.

## Output

Report path: `docs/benchmark/performance_report.md` (generated; does not exist yet). It combines
the exported hyperfine markdown table with the resource metrics into one structured summary.

Distinct from the tool's own `--verbose` statistics ([Verbose Output](../cli/verbose-output.md)):
those are single-run, self-reported, and unwarmed. Never quote them as benchmark results.

Keep it separate from `security_report.md` — different harness, different audience, different
regeneration cadence.
