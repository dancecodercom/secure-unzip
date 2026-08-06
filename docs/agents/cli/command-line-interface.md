---
type: CLI Guide
title: Command Line Interface
description: Every secure-unzip flag, its default, and what it constrains.
tags: [cli, flags, defaults, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Command Line Interface

**Status: implemented** (2026-08-06). Flag parsing lives in `main.go`; the resolution rule is
tested in `main_test.go`. Source: `CLAUDE.md` §1.

## Syntax

```
secure-unzip [options] archive.zip [-d extract_dir]
```

The shape mirrors standard `unzip` deliberately — see
[unzip-compatible CLI](../decisions/2026-08-06-unzip-compatible-cli.md).

## Flags

| Flag                  | Type            | Default        | Constrains                                                          |
|-----------------------|-----------------|----------------|---------------------------------------------------------------------|
| `--secure[=yes\|no]`  | boolean         | `yes`          | Master switch selecting the whole precaution profile                |
| `-d <dir>`            | path            | cwd            | Destination directory; also the zip-slip containment root           |
| `-max-size <bytes>`   | bytes           | `10737418240`  | Absolute cap on total uncompressed output (10 GiB)                  |
| `-max-files <count>`  | integer         | `10000`        | Max extracted files + directories (inode exhaustion)                |
| `-max-ratio <n>`      | integer         | `100`          | Compressed→uncompressed expansion ceiling                           |
| `-max-mode <octal>`   | octal mode      | `0755`         | Permission ceiling mask for extracted files                         |
| `-read-only`          | boolean         | off            | After writing, strips write bits (`0444`, or `0400`) from all files |
| `-cpu-limit <percent>`| percent         | `0` (no-op)    | Reserved; throttling is not yet implemented                         |
| `--verbose`, `-v`     | boolean         | off            | Reports resolved parameters, resource use and throughput to stderr  |
| `-q`                  | boolean         | off            | Quiet; conflicts with `--verbose` (last one specified wins)         |

Defaults in this table are the `--secure=yes` profile. `--secure=no` clears all of them; any flag
the user sets **explicitly** wins in either mode (`--secure=no --max-files=1000000`). See
[A --secure master switch](../decisions/2026-08-06-secure-master-switch.md) for the resolution rule
and why it is not positional. `--verbose` prints the *resolved* values — see
[Verbose Output](verbose-output.md).

## Open questions — resolve before implementing

* **Flag syntax style.** Go's `flag` package accepts `-max-size`; standard `unzip` uses single-letter
  clustered flags (`-o`, `-q`). How far "compatibility" extends beyond the invocation shape is
  undecided.
* **`10GB` unit ambiguity.** Recorded as 10 GiB; see the decision record's Open section.

Resolved on 2026-08-06 but **not yet carrying their own decision records** — they live in
`docs/todo/20260806.secure-unzip-implementation.md` (D1–D8) until implementation back-fills them:
exit codes (`0`/`1`/`2`/`3` security abort/`9`), `-max-mode` default `0755`, `-cpu-limit` deferred,
`-max-files` breach aborts, temp-dir staging, symlink containment.

## Error output contract

Every failure message must name the constraint that triggered it (`CLAUDE.md` §5). The
[security test suite](../testing/security-test-suite.md) asserts on these strings, so treat them as
API: changing wording is a test-visible change.
