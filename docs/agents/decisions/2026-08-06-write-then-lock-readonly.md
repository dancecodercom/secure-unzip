---
type: Decision Record
title: Write-then-lock for read-only extraction
description: Under -read-only, write file data first and strip write permissions afterwards, because the reverse order cannot work.
tags: [permissions, extraction, read-only]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# Write-then-lock for read-only extraction

**Date:** 2026-08-06 (reconstructed from `CLAUDE.md`)

## Decision

`-read-only` is a **post-extraction** operation: write the file data with normal (masked)
permissions, then explicitly remove the write bits, landing at `0444` or `0400`.

## Motivation

Creating the file at `0444` and then writing to it fails, or requires the writer to hold a
descriptor opened before the mode change — fragile and platform-dependent. Ordering the operations
write-then-chmod is the only version that works simply. This is the kind of thing that looks like
a harmless refactor later ("why not just create it read-only?"), so it is recorded here.

## Consequences

* `-read-only` is step 9, the last step of the per-entry pipeline — see
  [Extraction Pipeline](../architecture/extraction-pipeline.md).
* It composes with `-max-mode`: the mask applies at write time (step 7), the lock applies after.
  `-read-only` can only remove bits, never add them.
* There is a window between write and chmod during which the file is writable. Accepted: the
  threat model targets the archive's contents, not a concurrent local attacker.
* Whether `0444` or `0400` is chosen — and on what basis — is **not on record**; `CLAUDE.md` §2
  lists both.
* If the run aborts mid-extraction (see [fail closed](2026-08-06-fail-closed-on-breach.md)),
  already-written files may never get locked.

## Drawbacks / Alternatives considered

* **Create read-only, write via a pre-opened descriptor**: works on POSIX, awkward on Windows,
  and buys nothing given the accepted window. Rejected.
* **A separate `chmod -R` pass at the end**: simpler to read, but it walks the tree twice and
  cannot distinguish files this run created from pre-existing ones in the destination. Rejected.

# Citations

[1] `CLAUDE.md` §1 — "-read-only: Post-extraction flag"
[2] `CLAUDE.md` §2 — "write the file data first, then explicitly remove write permissions (0444 or 0400)"
