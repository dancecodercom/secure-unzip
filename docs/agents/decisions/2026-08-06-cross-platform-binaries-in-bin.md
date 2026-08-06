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

* Release asset names encode both the platform and the version:
  `secure-unzip-<goos>-<goarch>-v<version>`, with `.exe` appended for Windows —
  e.g. `secure-unzip-darwin-amd64-v0.1.1`. Downloaded assets from different releases therefore
  never collide in a downloads folder, and the version is readable without running the binary.
* The version comes from **`VERSION.md`**, managed by [setver](https://github.com/pforret/setver);
  the file holds bare semver (`0.1.1`) and the `v` prefix is added wherever it is displayed. The
  Makefile reads it, stamps it into `main.version` via `-ldflags`, and errors out if the file is
  missing or empty rather than shipping something labelled `dev`. Never hand-edit the version in
  the Makefile — `setver patch|minor|major` moves the file and the git tag together.
* The release workflow refuses to publish when the pushed tag and `VERSION.md` disagree, so a
  mislabelled release fails at the check rather than reaching users.
* `make build-host` writes the unversioned `bin/secure-unzip` for local use; the benchmark harness
  depends on that stable path. Only `make build` produces the versioned release assets.
* Nothing in the repo may read from `bin/` at test or run time — a clean checkout has no such
  directory. Tests build what they need.
* Build tooling is a plain Makefile plus a `go build` loop over `PLATFORMS`, driven by
  `.github/workflows/release.yml` on `v*` tags. No goreleaser.
* Both amd64 and arm64 are built for macOS and Linux; Windows is amd64 only. arm64 macOS is the
  primary development platform, so an amd64-only macOS build would not be locally runnable.

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
