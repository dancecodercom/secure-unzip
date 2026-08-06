# secure-unzip

A security-hardened drop-in alternative to standard `unzip`, in Go.

Standard `unzip` will happily write outside its destination directory, expand a
few-KB archive into gigabytes, and preserve `0777` and setuid bits. `secure-unzip`
refuses, by default, and tells you which constraint stopped it.

```sh
secure-unzip [options] archive.zip [-d extract_dir]
```

## Protections

| Attack | Control | Default |
|--------|---------|---------|
| Zip Slip (`../../etc/passwd`) | canonicalise + assert containment | always on |
| Symlink escape | link target must resolve inside the destination | always on |
| Zip bomb (size) | live byte accounting while decompressing | `-max-size 10 GiB` |
| Zip bomb (ratio) | expansion-ratio ceiling | `-max-ratio 100` |
| Inode exhaustion | entry counter | `-max-files 10000` |
| Permission exploit | mode mask; setuid/setgid/sticky always stripped | `-max-mode 0755` |
| Post-extraction tampering | strip write bits after writing | `-read-only` (opt-in) |

A breach **aborts the run** with exit code `3`. Nothing is written to the
destination unless the whole archive extracts cleanly: entries are staged in a
sibling temp directory and moved into place at the end.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--secure[=yes\|no]` | `yes` | Master switch for the whole profile |
| `-d <dir>` | `.` | Destination directory |
| `-max-size <bytes>` | `10737418240` | Total uncompressed output cap (`0` = unlimited) |
| `-max-files <n>` | `10000` | Entry cap (`0` = unlimited) |
| `-max-ratio <n>` | `100` | Expansion ratio ceiling (`0` = unlimited) |
| `-max-mode <octal>` | `0755` | Permission ceiling (`0` = no masking) |
| `-read-only` | off | Strip write bits after writing |
| `-verbose`, `-v` | off | Report resolved parameters and run statistics |
| `-q` / `-o` | off | Quiet / overwrite |
| `-cpu-limit <pct>` | `0` | Reserved — not yet implemented |

`--secure=no` turns **everything** off, including path containment, and prints a
warning saying so. Individually specified limits always win, in either mode and
regardless of position:

```sh
secure-unzip --secure=no -max-files 1000000 archive.zip
```

## Exit codes

`0` success · `1` warnings · `2` error · **`3` security constraint violated** · `9` archive not found

## Development

```sh
make test          # go test ./...
make build-host    # bin/secure-unzip for this machine
make build         # all 5 release targets into bin/ (gitignored)
make fixtures      # regenerate the benchmark/*/examples corpora (needs python3)
make report        # regenerate docs/benchmark/security_report.md
make bench         # regenerate docs/benchmark/performance_report.md (needs hyperfine)
```

Deeper documentation for coding agents lives in `docs/agents/` — architecture,
CLI reference, testing conventions, and decision records explaining the
non-obvious choices. Start at `docs/agents/index.md`.

## License

MIT — see `LICENSE`.
