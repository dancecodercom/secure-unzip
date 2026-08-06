---
type: Testing Guide
title: Security Test Suite
description: The malicious fixtures, what each must prove, and where the report is written.
tags: [testing, security, fixtures, planned]
timestamp: 2026-08-06T00:00:00Z
---

# Security Test Suite

**Status: planned** — no `_test.go` files exist as of 2026-08-06. Source: `CLAUDE.md` §3.

Go tests (`_test.go`) plus a fixture generator living in `testutils/`.

## Fixtures

| Fixture           | Payload                             | secure-unzip must                             | system `unzip` expected to |
|-------------------|-------------------------------------|-----------------------------------------------|----------------------------|
| Zip Slip          | entry named `../../etc/passwd`      | abort, naming the traversal constraint        | write outside the dest dir |
| Zip Bomb          | highly compressed zero-filled files | abort on `-max-size` or ratio breach          | expand unbounded           |
| Inode exhaustion  | thousands of tiny empty files       | stop at the `-max-files` ceiling (e.g. 1,000) | extract all of them        |
| Overly permissive | entry with `0777` mode              | mask down to `-max-mode`                      | preserve `0777`            |

Fixtures are **generated**, not committed — a zip bomb in git is its own problem. The generator is
part of `testutils/`.

## Validation engine

Each case runs both binaries and asserts the *difference*: secure-unzip catches, safely aborts, or
modifies the payload, while system `unzip` demonstrates the unsafe behaviour. A test that only
checks secure-unzip's own behaviour does not satisfy `CLAUDE.md` §3.

**Every test must run in a disposable temp dir.** The zip-slip fixture targets `../../etc/passwd`
by name; the system-`unzip` comparison arm is expected to write outside its destination. Sandbox it
— containment is the test harness's job, not the OS's.

## Output

Report path: `docs/benchmark/security_report.md` (generated; does not exist yet). Contents:
security test outcomes, pass/fail statuses, and the behaviour comparison per fixture.

Related: [Threat Model](../architecture/threat-model.md) — every row there needs a fixture here.
