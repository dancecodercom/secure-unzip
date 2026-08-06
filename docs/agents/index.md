---
okf_version: "0.1"
---

# secure-unzip Agent Knowledge Base

Documentation bundle for coding agents (OKF v0.1). Concept docs carry YAML frontmatter
(`type` required); every folder has an `index.md`. These docs go one level deeper than
CLAUDE.md — exact values, exact file paths, and the reasoning behind non-obvious choices.
When a doc and the code disagree, the code wins: fix the doc.

**Status as of 2026-08-06: this repository contains no source code.** `CLAUDE.md` holds the
product specification; git has no commits. Every technical fact below is therefore *specified*,
not *verified against code*. Docs marked **planned** must be re-verified and rewritten the moment
the corresponding code lands.

# Sections

* [Architecture](architecture/index.md) - planned module layout and the extraction pipeline
* [CLI](cli/index.md) - command syntax, flags, defaults, exit behaviour
* [Testing](testing/index.md) - security fixture suite and the benchmark harness
* [Decisions](decisions/index.md) - decision records with motivation, consequences, drawbacks

# Log

* [Update log](log.md)
