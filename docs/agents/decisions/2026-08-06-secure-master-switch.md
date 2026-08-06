---
type: Decision Record
title: A --secure master switch, on by default
description: One flag turns the whole hardening profile on (default) or off, with individually specified limits always overriding the profile.
tags: [cli, security, defaults, flags]
timestamp: 2026-08-06T00:00:00Z
status: accepted
---

# A `--secure` master switch, on by default

**Date:** 2026-08-06

## Decision

`--secure` is a boolean flag, **default `yes`**, that selects a whole profile of precautions rather
than requiring each limit to be set individually.

| Mode | Behaviour |
|------|-----------|
| `--secure=yes` (default) | All precautions active with the profile defaults below |
| `--secure=no` | All precautions off — behaves approximately like standard `unzip` |

Profile defaults under `--secure=yes`:

| Limit | Value |
|-------|-------|
| `-max-size` | **10 GiB** (`10737418240`) |
| `-max-files` | `10000` |
| `-max-ratio` | `100` (expansion ratio ceiling) |
| `-max-mode` | `0755` |
| zip-slip and symlink containment | enforced |

**Individually specified limits always win over the profile**, in either mode. The documented
example is `--secure=no --max-files=1000000`: precautions off, except a file ceiling of one million.

## Motivation

* The set of individual limits is large enough that "make this safe" and "get out of my way" both
  become multi-flag incantations. One switch expresses the actual user intent.
* It preserves the drop-in promise from
  [unzip-compatible CLI](2026-08-06-unzip-compatible-cli.md): safe with zero flags, because the
  default is `yes`.
* It supplies the escape hatch that record deferred ("if added it must be off by default and
  loud") — a user with a legitimately huge or unusual archive needs a way through that is not
  "go back to `unzip`", which would lose zip-slip protection too.

## Consequences

* **Resolution rule:** apply the profile first, then overwrite with any flag the user *explicitly
  set*. In Go this is `flag.Visit` (which reports only explicitly-set flags), not `flag.VisitAll`.
  Deliberately **not** positional: `--max-files=1000000 --secure=no` and
  `--secure=no --max-files=1000000` give the same result. The user's example reads as positional,
  but explicit-wins covers it and is far less surprising.
* `--secure=no` must be **loud**: print a warning to stderr naming the precautions that were
  disabled, unless `-q`. Silently unsafe is the failure mode to avoid.
* Zip-slip path containment is disabled by `--secure=no` — this is what "approximately like
  standard `unzip`" means, and it is the most dangerous part of the switch. The warning must say so
  explicitly.
* `--secure=no` does **not** change the fail-closed rule
  ([Fail closed](2026-08-06-fail-closed-on-breach.md)): if a limit is still in force because it was
  set explicitly, breaching it still aborts.
* Supersedes the earlier working assumption of a 1 GiB `-max-size` default (recorded in
  `docs/todo/20260806.secure-unzip-implementation.md` as D1, never implemented in code).
* Both spellings `--secure` and `-secure` work: Go's `flag` package treats them identically.

## Drawbacks / Alternatives considered

* **No master switch, individual flags only**: honest and explicit, but makes the common "just let
  it through" case a five-flag command, which people solve by using `unzip` instead — losing all
  protection rather than some.
* **`--insecure` as a bare boolean** (no `=yes|no` form): shorter, but cannot express "secure
  profile, explicitly on" in a script, and reads worse in the ordering rule.
* **Positional override semantics** as literally described: rejected: surprising, hard to test, and
  awkward with Go's `flag` package.
* Accepted cost: `--secure=no` is a real foot-gun, mitigated only by a warning.

## Open

* **`10GB` unit ambiguity**: recorded here as 10 **GiB** (`10737418240`), consistent with the binary
  units used elsewhere. If decimal 10 GB (`10000000000`) was meant, correct this record.

# Citations

[1] User instruction, 2026-08-06: "make a --secure(=yes) flag (default on) … --secure=no will switch all precautions off … unless other limits are specified afterwards (--secure=no --max-files=1000000)"
