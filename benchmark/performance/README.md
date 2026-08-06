# Performance fixtures

Benign `.zip` archives that extract normally, chosen to isolate the different bottlenecks
an extractor hits: inflate CPU, disk write throughput, and per-entry syscall overhead.

## Generating

```bash
python3 benchmark/performance/generate_examples.py            # ~32 MiB base unit
SCALE=4 python3 benchmark/performance/generate_examples.py    # 4x bigger corpora
```

Writes the archives into `benchmark/performance/examples/` plus an `examples/README.md`
table carrying the actual sizes and compression ratios of the current run. The `.zip`
files themselves are gitignored; the manifest is tracked. `SCALE` multiplies both the
corpus size and the small-file count.

Stdlib Python 3 only, with one optional extra: if `ffmpeg` is on `PATH`, the
hard-to-compress corpus is a real H.264 clip (`testsrc2`, 720p30, CRF 23) tiled to size.
Without `ffmpeg` it falls back to synthetic data of similar entropy, so ratios shift
slightly between machines — regenerate rather than compare numbers across hosts.

## What is generated

At the default `SCALE=1` this is roughly 145 MiB on disk and takes about 10 s to build.

| archive | corpus | bottleneck it exposes |
| --- | --- | --- |
| `compressible-text.zip` | 32 MiB repetitive log lines, ~290:1 | inflate-bound: a ~113 KiB archive expands to 32 MiB. Also the worst case for expansion-ratio limits — a legitimate archive that looks bomb-shaped |
| `moderate-prose.zip` | 32 MiB pseudo-English, ~6:1 | realistic mixed text, the common case |
| `hard-to-compress-video.zip` | ~32 MiB H.264 | already compressed: CPU spent for near-zero gain |
| `incompressible-random.zip` | 32 MiB CSPRNG noise | write-bound: archive size ≈ output size, measures pure I/O throughput |
| `many-small-files.zip` | 5000 files over a 3-level tree | syscall-bound: per-entry create/write/close dominates, and the path-validation cost per entry shows up here and nowhere else |
| `levels-{0,1,6,9}-mixed.zip` | identical 32 MiB mixed corpus, four compression levels | store (0) vs. fastest (1) vs. default (6) vs. max (9). Same bytes in every variant, so decompression cost is the only variable |

The `levels-*` set is the one to watch for regressions: level 0 is a pure copy path and
level 9 is the heaviest inflate, and both must extract byte-identical output.

## Using them

```bash
for z in benchmark/performance/examples/*.zip; do
  hyperfine --warmup 3 --prepare "rm -rf /tmp/bench-out" \
    "bin/secure-unzip -q $z -d /tmp/bench-out" \
    "unzip -q -o $z -d /tmp/bench-out" \
    --export-markdown "docs/benchmark/$(basename "$z" .zip).md"
done
```

For peak RSS and CPU percentage, wrap a single run in GNU `time -v`. On macOS the system
`/usr/bin/time` is BSD time and does **not** support `-v`; install `gnu-time` via Homebrew
and call `gtime -v`, otherwise the memory column silently goes missing.

Extract to a directory on a local SSD, never a network mount or a RAM disk, or the
write-bound cases measure the filesystem instead of the extractor. Aggregated results go
to `docs/benchmark/performance_report.md`.
