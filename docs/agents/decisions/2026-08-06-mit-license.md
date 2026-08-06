---
type: Decision Record
title: MIT license
description: Release secure-unzip under MIT so it can be vendored into any build pipeline without legal review.
tags: [license, distribution]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# MIT license

**Date:** 2026-08-06 (reconstructed from `CLAUDE.md`)

## Decision

Release under the MIT License, with the license text in a `LICENSE` file in the repository root.

## Motivation

A hardened `unzip` is most useful inside CI pipelines, container builds, and vendor toolchains —
exactly the places where a copyleft license triggers legal review and gets the tool dropped.
Permissive licensing maximises the odds that someone replaces an unsafe extraction step.

## Consequences

* `LICENSE` must exist in the root — **it does not yet** (2026-08-06). Creating it is outstanding
  work, explicitly required by `CLAUDE.md` §5.
* Any dependency added must be MIT-compatible. Sticking to the Go standard library, as currently
  planned, keeps this trivially true.

## Drawbacks / Alternatives considered

* **GPL/AGPL**: would guarantee that hardening improvements flow back, but blocks the vendoring
  use case that motivates the tool. Rejected.
* Accepted cost: a downstream vendor can ship a modified, weakened fork under the same name-adjacent
  branding without publishing changes.

# Citations

[1] `CLAUDE.md` §Overview ("under the MIT License") and §5 ("Include an MIT License file in the root directory")
