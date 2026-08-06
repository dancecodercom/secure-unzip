---
type: CLI Guide
title: Command Line Interface
description: Every secure-unzip flag, its default, and what it constrains.
tags: [cli, flags, defaults, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Command Line Interface

**Status: planned** — no flag-parsing code exists as of 2026-08-06. Source: `CLAUDE.md` §1.

## Syntax

```
secure-unzip [options] archive.zip [-d extract_dir]
```

The shape mirrors standard `unzip` deliberately — see
[unzip-compatible CLI](../decisions/2026-08-06-unzip-compatible-cli.md).

## Flags

| Flag                  | Type            | Default        | Constrains                                                          |
|-----------------------|-----------------|----------------|---------------------------------------------------------------------|
| `-d <dir>`            | path            | cwd            | Destination directory; also the zip-slip containment root           |
| `-max-size <bytes>`   | bytes           | **unresolved** | Absolute cap on total uncompressed output                           |
| `-max-files <count>`  | integer         | `10000`        | Max extracted files + directories (inode exhaustion)                |
| `-cpu-limit <percent>`| percent         | not on record  | Throttles extraction to stay under a CPU usage threshold            |
| `-max-mode <octal>`   | octal mode      | not on record  | Permission ceiling mask for extracted files, e.g. `0644`            |
| `-read-only`          | boolean         | off            | After writing, strips write bits (`0444`, or `0400`) from all files |

## Open questions — resolve before implementing

* **`-max-size` default is unspecified.** `CLAUDE.md` line 12 reads "default: the size that was
  returned by " — the sentence is truncated in the spec. Intent was likely free space on the
  destination filesystem, but that is an inference, not a fact. Ask the user; do not guess in code.
* **`-max-mode` default.** The spec gives `0644` only as an example. Whether masking is on by
  default or opt-in is undecided.
* **`-cpu-limit` default and units.** Percent of one core or of all cores is unstated.
* **Flag syntax style.** Go's `flag` package accepts `-max-size`; standard `unzip` uses single-letter
  clustered flags (`-o`, `-q`). How far "compatibility" extends beyond the invocation shape is
  undecided.
* **Exit codes.** `unzip` uses a documented set (0 ok, 1 warning, 2 error, 9 no such file, …).
  Whether secure-unzip mirrors them, and what code a security abort returns, is **not on record**.

## Error output contract

Every failure message must name the constraint that triggered it (`CLAUDE.md` §5). The
[security test suite](../testing/security-test-suite.md) asserts on these strings, so treat them as
API: changing wording is a test-visible change.
