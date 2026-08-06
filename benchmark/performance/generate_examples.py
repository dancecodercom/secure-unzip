#!/usr/bin/env python3
"""Generate benchmark .zip fixtures for secure-unzip vs. unzip timing runs.

Every archive here is safe and extracts normally — the point is to cover the
performance corners: inflate-bound vs. write-bound vs. syscall-bound work, and
the whole store..deflate-9 spectrum. Output goes to ./examples/ — the .zip files
there are gitignored, the generated manifest is tracked.

Usage:
    python3 benchmark/performance/generate_examples.py            # ~32 MiB base unit
    SCALE=4 python3 benchmark/performance/generate_examples.py    # 4x bigger corpora

If ffmpeg is on PATH, the "hard to compress" corpus is a real H.264 clip;
otherwise a synthetic stand-in with similar entropy is used.
"""

import os
import random
import shutil
import subprocess
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "examples")
SCALE = float(os.environ.get("SCALE", "1"))
MIB = 1024 * 1024
BASE = int(32 * MIB * SCALE)  # nominal uncompressed size per single-corpus archive

MANIFEST = []


def register(name, content, level, note):
    MANIFEST.append({"name": name, "content": content, "level": level, "note": note})
    return os.path.join(OUT, name)


def write_zip(path, entries, level):
    method = zipfile.ZIP_STORED if level == 0 else zipfile.ZIP_DEFLATED
    kwargs = {} if level == 0 else {"compresslevel": level}
    with zipfile.ZipFile(path, "w", method, **kwargs) as z:
        for name, data in entries:
            z.writestr(name, data)


# ---------------------------------------------------------------- corpora

def text_corpus(size):
    """Highly repetitive log-like text: deflate eats this alive (>50:1)."""
    line = ("2026-08-06T12:00:00Z INFO  worker[42] processed request id=0000000000 "
            "status=200 duration=13ms upstream=cache\n")
    chunk = line * 512
    out = bytearray()
    while len(out) < size:
        out += chunk.encode()
    return bytes(out[:size])


def prose_corpus(size):
    """More realistic mixed English-ish text: compresses ~3:1, not 50:1."""
    words = ("the quick brown fox jumps over lazy dogs while parsing archives and "
             "validating canonical paths against a destination directory boundary "
             "before writing any bytes to disk").split()
    rnd = random.Random(1234)
    out = bytearray()
    while len(out) < size:
        sentence = " ".join(rnd.choice(words) for _ in range(rnd.randint(6, 20)))
        out += (sentence + ".\n").encode()
    return bytes(out[:size])


def random_corpus(size):
    """Cryptographic-quality noise: deflate cannot shrink it at all."""
    return os.urandom(size)


def media_corpus(size):
    """Already-compressed media. Real H.264 via ffmpeg when available."""
    tmp = os.path.join(OUT, ".clip.mp4")
    if shutil.which("ffmpeg"):
        seconds = max(4, int(size / (2 * MIB)))
        cmd = [
            "ffmpeg", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30:duration=%d" % seconds,
            "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
            "-pix_fmt", "yuv420p", tmp,
        ]
        try:
            subprocess.run(cmd, check=True)
            with open(tmp, "rb") as fh:
                data = fh.read()
            os.remove(tmp)
            # tile the clip up to the requested size so archives stay comparable
            reps = max(1, size // len(data))
            return [("clip-%02d.mp4" % i, data) for i in range(reps)]
        except (subprocess.CalledProcessError, OSError):
            if os.path.exists(tmp):
                os.remove(tmp)
    # Fallback: JPEG-ish entropy — noise with a small repeating header pattern.
    rnd = random.Random(99)
    blocks = []
    for i in range(max(1, size // (4 * MIB))):
        body = bytes(rnd.getrandbits(8) for _ in range(64 * 1024)) * 64
        blocks.append(("clip-%02d.bin" % i, b"\xff\xd8\xff\xe0" + body[:4 * MIB - 4]))
    return blocks


# ---------------------------------------------------------------- archives

def a_text():
    path = register("compressible-text.zip", "%d MiB repetitive log text" % (BASE // MIB),
                    6, "inflate-bound: tiny archive, large output; worst case for ratio limits")
    write_zip(path, [("logs/app-%02d.log" % i, text_corpus(BASE // 8)) for i in range(8)], 6)


def a_prose():
    path = register("moderate-prose.zip", "%d MiB pseudo-English prose" % (BASE // MIB),
                    6, "realistic mixed text, ~3:1 ratio")
    write_zip(path, [("docs/chapter-%02d.txt" % i, prose_corpus(BASE // 8)) for i in range(8)], 6)


def a_media():
    entries = media_corpus(BASE)
    total = sum(len(d) for _, d in entries)
    path = register("hard-to-compress-video.zip", "%.1f MiB H.264/media" % (total / MIB),
                    6, "already compressed: deflate spends CPU for ~0 gain")
    write_zip(path, [("media/" + n, d) for n, d in entries], 6)


def a_random():
    path = register("incompressible-random.zip", "%d MiB CSPRNG noise" % (BASE // MIB),
                    6, "write-bound: archive size ≈ output size, pure I/O throughput")
    write_zip(path, [("random/blob-%02d.bin" % i, random_corpus(BASE // 8)) for i in range(8)], 6)


def a_many_files():
    """5000 small files across a 3-level tree: syscall/inode bound, not I/O bound."""
    count = int(5000 * SCALE)
    entries = []
    rnd = random.Random(7)
    for i in range(count):
        name = "tree/d%02d/s%02d/file-%05d.txt" % (i % 50, (i // 50) % 20, i)
        entries.append((name, prose_corpus(rnd.randint(200, 2000))))
    path = register("many-small-files.zip", "%d files in a 3-level tree" % count,
                    6, "syscall-bound: per-entry create/write/close dominates")
    write_zip(path, entries, 6)


def a_levels():
    """The same mixed corpus at store / fast / default / max compression."""
    unit = BASE // 4
    corpus = [
        ("mixed/logs.txt", text_corpus(unit)),
        ("mixed/prose.txt", prose_corpus(unit)),
        ("mixed/noise.bin", random_corpus(unit)),
        ("mixed/tail.txt", prose_corpus(unit)),
    ]
    labels = {0: "store only", 1: "fastest deflate", 6: "default deflate", 9: "max deflate"}
    for level in (0, 1, 6, 9):
        path = register("levels-%d-mixed.zip" % level, "%d MiB mixed corpus" % (BASE // MIB),
                        level, "compression level %d (%s); same bytes in every variant"
                        % (level, labels[level]))
        write_zip(path, corpus, level)


GENERATORS = [a_text, a_prose, a_media, a_random, a_many_files, a_levels]


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    for gen in GENERATORS:
        gen()

    lines = [
        "# Benchmark archives",
        "",
        "Generated by `benchmark/performance/generate_examples.py` (SCALE=%g)." % SCALE,
        "The archives are gitignored — regenerate at will; this manifest is tracked.",
        "All archives are benign and extract normally.",
        "",
        "| archive | zip size | uncompressed | ratio | level | content | why it matters |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for m in MANIFEST:
        p = os.path.join(OUT, m["name"])
        zsize = os.path.getsize(p)
        with zipfile.ZipFile(p) as z:
            usize = sum(i.file_size for i in z.infolist())
        ratio = (usize / zsize) if zsize else 0
        lines.append("| `%s` | %.1f MiB | %.1f MiB | %.1fx | %d | %s | %s |" % (
            m["name"], zsize / MIB, usize / MIB, ratio, m["level"], m["content"], m["note"]))
    lines += [
        "",
        "## Suggested hyperfine run",
        "",
        "```bash",
        "for z in benchmark/performance/examples/*.zip; do",
        '  hyperfine --warmup 3 --prepare "rm -rf /tmp/bench-out" \\',
        '    "bin/secure-unzip -q $z -d /tmp/bench-out" \\',
        '    "unzip -q -o $z -d /tmp/bench-out" \\',
        '    --export-markdown "docs/benchmark/$(basename "$z" .zip).md"',
        "done",
        "```",
        "",
    ]
    with open(os.path.join(OUT, "README.md"), "w") as fh:
        fh.write("\n".join(lines))

    for m in MANIFEST:
        print("%10d  %s" % (os.path.getsize(os.path.join(OUT, m["name"])), m["name"]))


if __name__ == "__main__":
    main()
