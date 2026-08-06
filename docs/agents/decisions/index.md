# Decisions

Decision records, newest first. Each states what was decided, why, what follows, and what was
rejected. Decisions are history — never rewrite a record; supersede it.

These six were reconstructed on 2026-08-06 from the specification in `CLAUDE.md`, since the
repository has no git history (zero commits) and no ADR archive. They record choices the spec
makes without stating its reasoning; the *Motivation* sections are reconstructed rationale, not
quoted from the author.

* [A --secure master switch, on by default](2026-08-06-secure-master-switch.md) - one flag for the whole precaution profile; explicit limits always win
* [Cross-platform binaries in an untracked bin/](2026-08-06-cross-platform-binaries-in-bin.md) - build all three platforms every time, ship them as release assets
* [Fail closed on constraint breach](2026-08-06-fail-closed-on-breach.md) - abort rather than skip-and-continue
* [Write-then-lock for read-only extraction](2026-08-06-write-then-lock-readonly.md) - ordering that makes `-read-only` work
* [Benchmark with hyperfine, not a custom timer](2026-08-06-hyperfine-for-benchmarks.md) - external script over Go benchmarks
* [unzip-compatible CLI surface](2026-08-06-unzip-compatible-cli.md) - drop-in replacement as the adoption path
* [MIT license](2026-08-06-mit-license.md) - permissive licensing for a security utility
* [Go, shipped as a single static binary](2026-08-06-go-single-static-binary.md) - language choice
