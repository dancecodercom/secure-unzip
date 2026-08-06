---
type: Decision Record
title: Fail closed on constraint breach
description: Abort the whole extraction immediately when a security constraint is breached, rather than skipping the offending entry.
tags: [security, error-handling, extraction]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# Fail closed on constraint breach

**Date:** 2026-08-06 (reconstructed from `CLAUDE.md`)

## Decision

When any security constraint is breached — zip slip, `-max-size`, expansion ratio, `-max-files` —
the run **aborts immediately** with an error naming the constraint. It does not skip the entry and
continue.

## Motivation

An archive containing one malicious entry is a malicious archive. Skipping the bad entry and
extracting the rest yields a partial, silently-incomplete tree that the caller believes is
complete — a worse outcome than a loud failure, because downstream steps proceed on bad data.
Aborting also bounds the damage from a bomb: detection is only useful if it stops the expansion.

`CLAUDE.md` §2 states it three times: "Abort if any file attempts directory traversal", "Abort
immediately if -max-size or … ratio limits are breached".

## Consequences

* Partially written files may remain on disk when the abort happens mid-stream. Whether the
  destination is cleaned up on abort is **not on record** — decide before v1.
* Error messages are a tested contract: each must name its constraint (`CLAUDE.md` §5), and the
  security suite asserts on them.
* The `-max-files` case is stated slightly differently in `CLAUDE.md` §3 — "stopping at 1,000
  files" reads as *stop-and-succeed* rather than *abort*. This tension is unresolved; the assertion
  in the security suite will pin it down.

## Drawbacks / Alternatives considered

* **Skip-and-continue with a warning** (closer to `unzip`'s behaviour): better compatibility, worse
  safety. Rejected — silent partial extraction is the failure mode this tool exists to prevent.
* **A `--force`/`--best-effort` escape hatch**: not specified. Deferred rather than rejected; if
  added it must be off by default and loud.

# Citations

[1] `CLAUDE.md` §2 "Zip Slip Prevention" and "Zip Bomb & Memory Defense"
[2] `CLAUDE.md` §5 "Ensure all error messages clearly describe which security constraint was triggered"
