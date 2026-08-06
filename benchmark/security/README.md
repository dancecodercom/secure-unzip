# Security fixtures

Malicious-but-harmless `.zip` archives used to prove that `secure-unzip` refuses what
system `unzip` happily does.

## Generating

```bash
python3 benchmark/security/generate_examples.py
```

Writes the archives into `benchmark/security/examples/` plus an `examples/README.md` table
with the exact byte sizes of the current run. The `.zip` files themselves are gitignored —
regenerate at will; the manifest is tracked so the fixture set is reviewable in a diff.
Nothing here needs network access or third-party packages — stdlib Python 3 only.

Every payload is deliberately tiny. The largest thing any of them can produce is 1 MiB,
so an accidental `unzip` of the whole folder cannot fill a disk or hang a machine. The
attack *shape* is what matters, not the magnitude.

## What is generated

| archive | attack | expected `secure-unzip` behaviour |
| --- | --- | --- |
| `benign-control.zip` | none — ordinary small archive | extracts cleanly in both modes; the baseline |
| `bomb-ratio-1000x.zip` | ~1 KiB compressed → 1 MiB out | abort on expansion-ratio limit, or on `--max-size` below 1 MiB |
| `liar-declared-1kb-real-1mb.zip` | headers hand-patched to declare 1024 B; the stream really yields 1 MiB | count **actual** bytes written, never the declared size |
| `bomb-nested-3-levels.zip` | zip inside zip inside zip | do not recurse into nested archives; write the outer entry only |
| `slip-relative-traversal.zip` | entry named `../../../tmp/…` | abort: target escapes the destination |
| `slip-absolute-path.zip` | entry named `/tmp/…` | abort: absolute paths rejected, never honoured |
| `slip-symlink-escape.zip` | symlink `out -> /tmp`, then a write through it | abort: symlinks not followed outside the destination |
| `inodes-1000-files.zip` | 1000 tiny files | with `--max-files=100`, abort after 100 entries |
| `deep-directory-nesting.zip` | file 256 directories deep | handle or reject gracefully, no uncontrolled path-limit blowup |
| `perms-0777-setuid.zip` | entries stored 0777 and setuid 4755 | with `--max-mode=0644`, write 0644 and strip setuid/setgid |
| `names-control-chars.zip` | names with newline, backslash, `-rf`, tabs | sanitise or reject; never let a name break shell or log output |
| `duplicate-entries.zip` | same filename stored twice | deterministic: last-wins or reject, never a partial merge |

## Using them

The differential check is the point — run both extractors into throwaway directories and
compare. Sketch:

```bash
for z in benchmark/security/examples/*.zip; do
  out=$(mktemp -d)
  unzip -q -o "$z" -d "$out"          # may misbehave — that is the control
  bin/secure-unzip -q "$z" -d "$out"  # must abort with a named constraint
  rm -rf "$out"
done
```

Two cautions when running these by hand:

- The Zip Slip and symlink fixtures target `/tmp/secure-unzip-pwned*.txt`. If system
  `unzip` succeeds, those files land outside the extraction directory — check for and
  delete them between runs, or they mask a later failure.
- Run in a container or a scratch VM if you extend the fixtures to more aggressive paths.

Each abort must name the constraint that fired (per the project's error-message rule), so
the assertion in the Go suite can match on the constraint, not on an exit code alone.
Results land in `docs/benchmark/security_report.md`.
