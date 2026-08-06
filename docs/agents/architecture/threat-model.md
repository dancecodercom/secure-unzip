---
type: Architecture Guide
title: Threat Model
description: The attack classes secure-unzip is built to stop, and the control that stops each.
tags: [security, threat-model, zip-slip, zip-bomb]
timestamp: 2026-08-06T00:00:00Z
---

# Threat Model

The whole reason this tool exists. Sourced from `CLAUDE.md` §2. Every row must have a
corresponding fixture in [the security test suite](../testing/security-test-suite.md).

| Attack               | Mechanism                                                        | Control                                                   | Pipeline step |
|----------------------|------------------------------------------------------------------|-----------------------------------------------------------|---------------|
| Zip Slip             | Entry name contains `../` or an absolute path, writing outside `-d` | Canonicalise then assert containment; abort on any escape  | 1–2           |
| Zip Bomb (size)      | Small archive decompresses to huge output, filling the disk        | Live byte accounting against `-max-size`                   | 4, 6          |
| Zip Bomb (ratio)     | Extreme compressed→uncompressed expansion                          | Expansion-ratio ceiling checked during the stream          | 6             |
| Inode exhaustion     | Thousands of tiny entries exhausting inodes/dentries               | `-max-files` counter, default 10,000                       | 3             |
| Permission exploit   | Entry carries `0777` or unexpected executable bits                 | Mask down to `-max-mode`                                   | 7             |
| Post-extract tamper  | Extracted files left writable and later modified                   | `-read-only`: strip write bits after writing (`0444`/`0400`) | 9           |
| CPU exhaustion       | Decompression pegging the CPU                                      | `-cpu-limit` throttling/pausing                            | 5             |

## Explicitly out of scope

`CLAUDE.md` does not mention these; do not silently add them, and do not claim them in the README:

* Malware scanning of extracted content.
* Symlink entries pointing outside the destination — **not on record**. The spec covers path
  traversal by name; whether symlink *targets* are validated is undecided. Resolve before v1.
* Encrypted archives, multi-volume archives, non-zip formats.

## Comparison baseline

The security suite asserts secure-unzip catches each payload **while standard system `unzip`
demonstrates unsafe behaviour** (`CLAUDE.md` §3). The comparison is part of the deliverable, not a
nicety — the report is meant to show the delta.
