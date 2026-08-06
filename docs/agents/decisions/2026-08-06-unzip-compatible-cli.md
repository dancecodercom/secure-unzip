---
type: Decision Record
title: unzip-compatible CLI surface
description: Mimic standard unzip's syntax so secure-unzip can be dropped into existing scripts unchanged.
tags: [cli, compatibility, adoption]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# unzip-compatible CLI surface

**Date:** 2026-08-06 (reconstructed from `CLAUDE.md`)

## Decision

The invocation shape mirrors standard `unzip`: `secure-unzip [options] archive.zip [-d extract_dir]`.
Security controls are added as *new* long flags (`-max-size`, `-max-files`, `-cpu-limit`,
`-max-mode`, `-read-only`) rather than by changing existing ones.

## Motivation

The tool's value is realised only when it replaces `unzip` in a pipeline that is already written.
Every syntax difference is a migration cost, and a migration cost is a reason to keep running the
unsafe tool. Aliasing `unzip=secure-unzip` should be a viable adoption path.

## Consequences

* Defaults must be safe *without* any new flag being passed, because the drop-in case passes none.
  This is why `-max-files` has a concrete default of 10,000.
* New flags must not collide with `unzip`'s existing single-letter flags.
* The unresolved default for `-max-size` is a blocker for the drop-in promise — see
  [Command Line Interface](../cli/command-line-interface.md) open questions.

## Drawbacks / Alternatives considered

* **A subcommand CLI** (`secure-unzip extract --archive=…`): cleaner, self-documenting, and
  rejected — it forbids aliasing and forces every caller to be rewritten.
* Accepted cost: compatibility is only claimed for the *core* syntax. Exit codes and the full
  `unzip` flag set are unresolved, so "drop-in" is currently aspirational, not tested.
* Deferred: a compatibility test that runs a corpus of real-world `unzip` invocations against both
  binaries.

# Citations

[1] `CLAUDE.md` §1 — "Compatibility: Mimic the core syntax and flags of standard unzip"
