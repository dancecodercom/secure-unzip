---
type: CLI Guide
title: Verbose Output
description: What --verbose prints — resolved parameter values up front, resource and throughput stats at the end — and the platform traps in measuring them.
tags: [cli, verbose, metrics, observability, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Verbose Output

**Status: implemented** (2026-08-06). Output formatting in `stats.go`; resource sampling in
`rusage_unix.go` and `rusage_windows.go`.

`--verbose` (`-v`) makes the run self-reporting: every effective parameter before extraction, and
resource plus throughput figures after. It changes no behaviour, only output.

## What it prints

### Before extraction — resolved parameters

**Resolved**, not defaults: after the `--secure` profile is applied and explicitly-set flags
override it (see [A --secure master switch](../decisions/2026-08-06-secure-master-switch.md)).
This is the point of printing them — it answers "what limits am I actually running under" when a
profile and explicit flags interact.

Mark the origin of each value, since that is the thing users get wrong:

```
secure-unzip 1.0.0
  archive     fixtures/benign.zip
  destination /tmp/out
  --secure    yes
  -max-size   10737418240   (10.0 GiB)   [profile]
  -max-files  1000000                    [explicit]
  -max-ratio  100                        [profile]
  -max-mode   0755                       [profile]
  -read-only  false                      [profile]
  -cpu-limit  0  (reserved, not implemented)
```

### After extraction — statistics

| Metric | Source | Notes |
|--------|--------|-------|
| Files generated | the `Budget` counter already kept for `-max-files` | Split files vs directories |
| Bytes written | the streaming counter already kept for `-max-size` | Print uncompressed total |
| Throughput (MB/s) | uncompressed bytes ÷ wall-clock seconds | Define MB as 1e6 for a rate; state the unit in the output |
| Peak memory | `getrusage(RUSAGE_SELF).Maxrss` | **Unit differs per OS — see below** |
| CPU | `getrusage` `Utime + Stime` | See the "max cpu" caveat below |

## Platform traps

* **`Maxrss` units are not portable.** Linux reports **kilobytes**; macOS/BSD report **bytes**. A
  naive shared code path is wrong by a factor of 1024 on one of them. Guard per `runtime.GOOS` and
  unit-test the conversion.
* **`getrusage` does not exist on Windows.** Use `GetProcessMemoryInfo`/`GetProcessTimes`, or print
  `n/a` for the resource lines. Do not fail the run.
* **"max cpu" is ambiguous.** `getrusage` yields *cumulative* CPU time, from which only an
  **average** percentage over the run can be derived (`cpuTime / wallTime`). A true *peak* requires
  sampling on a ticker. Plan: print the average, labelled `avg cpu`, and treat peak sampling as
  optional. Do not label an average as a maximum.

## Conventions

* Verbose output goes to **stderr**, keeping stdout clean for the extracted file listing.
* `-q` (quiet) and `--verbose` conflict; the last one specified wins.
* Statistics are printed **even when the run aborts** on a constraint breach — the numbers at the
  moment of abort are exactly what a user debugging a limit needs.
* Not a benchmark. These are self-reported, single-run figures with no warmup or statistics; the
  credible comparison against system `unzip` lives in
  [Performance Benchmarking](../testing/performance-benchmarking.md).
