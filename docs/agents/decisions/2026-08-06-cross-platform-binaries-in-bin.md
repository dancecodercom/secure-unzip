---
type: Decision Record
title: Build macOS, Linux and Windows binaries into an untracked bin/
description: Every build produces all three platform binaries under bin/, which is gitignored because those artifacts are published as binary releases instead.
tags: [build, release, distribution, cross-compilation]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# Build macOS, Linux and Windows binaries into an untracked `bin/`

**Date:** 2026-08-06

## Decision

The build always cross-compiles **all three** target platforms — macOS, Linux, Windows — into
`bin/`. `bin/` is excluded from version control; the binaries it holds are what gets attached to
binary releases.

## Motivation

* Cross-platform support is a stated requirement (`CLAUDE.md` §Overview), and a target that is only
  built at release time is a target that breaks silently between releases. Building all three every
  time turns "does it still compile on Windows?" into a build-time answer rather than a
  release-day surprise.
* Windows is where this project is most likely to break: the permission controls (`-max-mode`,
  `-read-only`) rely on POSIX mode bits — see
  [Write-then-lock](2026-08-06-write-then-lock-readonly.md).
* Committing binaries would bloat the repository permanently and make it unclear which build any
  given file came from. A release asset is versioned, checksummable, and deletable; a committed
  binary is none of those.
* Go's cross-compilation makes building all three cheap from one machine — a direct benefit of
  [choosing Go](2026-08-06-go-single-static-binary.md).

## Consequences

* `bin/` is the conventional output path. The Windows artifact needs a `.exe` suffix. Exact
  filenames and whether they encode GOOS/GOARCH: **not on record** — settle this before the first
  release, since release asset names are hard to change later.
* **Outstanding work as of 2026-08-06**: no `.gitignore` exists in this repository and no `bin/`
  directory has been created. The ignore rule must land before the first build, or the artifacts
  get committed by accident.
* Nothing in the repo may read from `bin/` at test or run time — a clean checkout has no such
  directory. Tests build what they need.
* The build tool (Makefile, `go build` loop, goreleaser, CI workflow) is **not on record**; no build
  configuration exists yet.
* Linux/macOS architectures (amd64 vs arm64) are undecided. arm64 macOS is the primary development
  platform here, so an amd64-only macOS build would not be locally runnable.

## Drawbacks / Alternatives considered

* **Build only the host platform, cross-compile at release**: faster inner loop, but lets the other
  two platforms rot between releases. Rejected — that is exactly the failure this decision prevents.
* **Commit the binaries**: makes `git clone` a distribution channel. Rejected; repository bloat is
  permanent and provenance is unclear.
* Accepted cost: every build is roughly three times the work of a host-only build. If the inner
  loop becomes painful, the escape hatch is a separate host-only target for development — not
  dropping platforms from the release build.

# Citations

[1] User instruction, 2026-08-06: "always build Macos Linux and Windows versions under bin/, but keep those out of version control, we will use them as binary releases"
[2] `CLAUDE.md` §Overview — "cross-platform command-line utility in Go"
