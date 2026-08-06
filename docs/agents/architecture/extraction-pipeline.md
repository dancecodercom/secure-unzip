---
type: Architecture Guide
title: Extraction Pipeline
description: The order in which each archive entry is validated, streamed, and permission-locked.
tags: [architecture, pipeline, extraction, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Extraction Pipeline

**Status: implemented** (2026-08-06) in `extractor/extract.go`. Order matters: several controls are
only sound in this sequence.

## Per-archive

1. Open the archive; read the central directory.
2. Resolve the destination directory (`-d`, default: current working directory) to an absolute,
   symlink-resolved path. This resolved path is the containment root for every later check.
3. Initialise counters: files written = 0, total uncompressed bytes = 0.

## Per-entry

| # | Step                  | Rejects                                       | Owner        |
|---|-----------------------|-----------------------------------------------|--------------|
| 1 | Canonicalise target   | Zip Slip / absolute paths / `..` traversal    | `security/`  |
| 2 | Containment assert    | Target not under the resolved destination     | `security/`  |
| 3 | File-count check      | `-max-files` exceeded (inode exhaustion)      | `security/`  |
| 4 | Declared-size check   | Header total already over `-max-size`         | `security/`  |
| 5 | Stream decompress     | —                                             | `extractor/` |
| 6 | Live size/ratio check | `-max-size` or expansion-ratio breach mid-read| `security/`  |
| 7 | Mode mask             | Permission bits above `-max-mode`             | `security/`  |
| 8 | Write file            | —                                             | `extractor/` |
| 9 | Read-only lock        | —                                             | `extractor/` |

## Non-obvious requirements

* **Step 1 must not trust the header size.** A zip header can under-report the uncompressed size,
  so step 4 is an early-out only; step 6 is the control that actually holds. Counting must happen
  on the decompressed byte stream as it is read, not after.
* **Step 6 aborts mid-write.** The run stops immediately on breach (see the
  [fail-closed decision](../decisions/2026-08-06-fail-closed-on-breach.md)); partially written
  files may remain on disk.
* **Step 9 runs after step 8, never before.** Setting `0444` before writing makes the write fail —
  see [Write-then-lock](../decisions/2026-08-06-write-then-lock-readonly.md).
* **CPU throttling** (`-cpu-limit`) is applied as pausing/rate-limiting around step 5. Sampling
  interval and pause algorithm: **not on record** — `CLAUDE.md` §2 specifies the goal, not the
  mechanism.

See [Threat Model](threat-model.md) for which attack each numbered step defends against, and
[Command Line Interface](../cli/command-line-interface.md) for the flag defaults.
