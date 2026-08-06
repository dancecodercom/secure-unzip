#!/usr/bin/env python3
"""Generate malicious-but-harmless .zip fixtures for secure-unzip testing.

All payloads are deliberately small: they demonstrate the attack pattern
without being able to fill a disk or hang a machine if accidentally extracted
with a normal unzip. Output goes to ./examples/ — the .zip files there are
gitignored, the generated manifest is tracked.

Usage: python3 benchmark/security/generate_examples.py
"""

import os
import shutil
import struct
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "examples")

MANIFEST = []


def register(name, attack, expect):
    MANIFEST.append((name, attack, expect))
    return os.path.join(OUT, name)


def zeros(n):
    return b"\0" * n


# ---------------------------------------------------------------- payloads

def bomb_ratio():
    """1 MiB of zeros compressing to ~1 KiB: expansion ratio ~1000:1."""
    path = register(
        "bomb-ratio-1000x.zip",
        "1 MiB uncompressed from ~1 KiB compressed (ratio ~1000:1)",
        "abort on expansion-ratio limit, or on --max-size below 1 MiB",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("payload.bin", zeros(1024 * 1024))


def bomb_nested():
    """A zip inside a zip inside a zip — recursive-extraction bait."""
    inner_path = os.path.join(OUT, ".nested-tmp.zip")
    data = zeros(512 * 1024)
    with zipfile.ZipFile(inner_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("payload.bin", data)
    with open(inner_path, "rb") as fh:
        level1 = fh.read()
    os.remove(inner_path)

    path = register(
        "bomb-nested-3-levels.zip",
        "zip nested 3 deep, innermost holds 512 KiB of zeros",
        "must NOT recurse into nested archives; only the outer entry is written",
    )
    payload = level1
    for depth in (2, 3):
        buf = os.path.join(OUT, ".nested-tmp%d.zip" % depth)
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            z.writestr("level.zip", payload)
        with open(buf, "rb") as fh:
            payload = fh.read()
        os.remove(buf)
    with open(path, "wb") as fh:
        fh.write(payload)


def lying_sizes():
    """Central directory claims 1 KiB; the actual stream inflates to 1 MiB.

    Written by hand-patching the uncompressed-size fields after the fact, so a
    naive extractor that trusts the header allocates/accounts 1 KiB and then
    keeps writing.
    """
    path = register(
        "liar-declared-1kb-real-1mb.zip",
        "headers declare 1024 bytes uncompressed; stream really yields 1 MiB",
        "must count ACTUAL bytes written, not the declared size, and abort",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("honest-looking.txt", zeros(1024 * 1024))

    with open(path, "rb") as fh:
        raw = bytearray(fh.read())

    real = struct.pack("<I", 1024 * 1024)
    fake = struct.pack("<I", 1024)
    # local file header: uncompressed size at offset +22; central dir: +24
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        i = raw.find(sig)
        while i != -1:
            if raw[i + off:i + off + 4] == real:
                raw[i + off:i + off + 4] = fake
            i = raw.find(sig, i + 1)
    with open(path, "wb") as fh:
        fh.write(raw)


def slip_relative():
    path = register(
        "slip-relative-traversal.zip",
        "entry named ../../../tmp/secure-unzip-pwned.txt",
        "abort: target escapes the destination directory",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("innocent.txt", "harmless\n")
        z.writestr("../../../tmp/secure-unzip-pwned.txt", "zip slip (relative)\n")


def slip_absolute():
    path = register(
        "slip-absolute-path.zip",
        "entry named /tmp/secure-unzip-pwned-abs.txt",
        "abort: absolute paths must be rejected (or stripped, never honoured)",
    )
    zf = zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED)
    # zipfile.writestr strips leading slashes, so write the entry by hand.
    info = zipfile.ZipInfo("/tmp/secure-unzip-pwned-abs.txt")
    info.filename = "/tmp/secure-unzip-pwned-abs.txt"
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, "zip slip (absolute)\n")
    zf.close()


def slip_symlink():
    path = register(
        "slip-symlink-escape.zip",
        "symlink out -> /tmp, then out/pwned.txt written through it",
        "abort: symlinks must not be followed outside the destination",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        link = zipfile.ZipInfo("out")
        link.create_system = 3  # unix
        link.external_attr = (0o120777 << 16)  # S_IFLNK | 0777
        z.writestr(link, "/tmp")
        z.writestr("out/secure-unzip-pwned-link.txt", "written through symlink\n")


def inode_exhaustion():
    path = register(
        "inodes-1000-files.zip",
        "1000 tiny files in one archive",
        "with --max-files=100: abort after 100 entries",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(1000):
            z.writestr("many/file-%04d.txt" % i, "x")


def deep_nesting():
    path = register(
        "deep-directory-nesting.zip",
        "a file 256 directories deep",
        "handle or reject gracefully; must not blow the path limit uncontrolled",
    )
    deep = "/".join("d%03d" % i for i in range(256))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(deep + "/deep.txt", "bottom\n")


def permissive_modes():
    path = register(
        "perms-0777-setuid.zip",
        "files stored with 0777 and with the setuid bit set",
        "with --max-mode=0644: written as 0644, setuid/setgid stripped",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, mode in (("world-writable.sh", 0o777), ("setuid-binary", 0o4755)):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = ((0o100000 | mode) << 16)
            z.writestr(info, "#!/bin/sh\necho harmless\n")


def weird_names():
    path = register(
        "names-control-chars.zip",
        "entries with newline, backslash, dotdot-lookalike and non-UTF8-ish names",
        "sanitise or reject; never let names break shell/log output",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name in (
            "line\nbreak.txt",
            "back\\slash.txt",
            "..dotdot.txt",
            "spaces   and\ttabs.txt",
            "-rf.txt",
        ):
            z.writestr(name, "weird name\n")


def overwrite_same_target():
    path = register(
        "duplicate-entries.zip",
        "the same filename stored twice with different content",
        "deterministic behaviour: last-wins or reject, never a partial merge",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("dup.txt", "first\n")
        z.writestr("dup.txt", "second\n")


def benign_control():
    path = register(
        "benign-control.zip",
        "ordinary small archive, no attack",
        "extracts cleanly in both secure and --secure=no modes",
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "nothing to see here\n")
        z.writestr("sub/data.bin", os.urandom(4096))


GENERATORS = [
    benign_control,
    bomb_ratio,
    bomb_nested,
    lying_sizes,
    slip_relative,
    slip_absolute,
    slip_symlink,
    inode_exhaustion,
    deep_nesting,
    permissive_modes,
    weird_names,
    overwrite_same_target,
]


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    for gen in GENERATORS:
        gen()

    lines = [
        "# Malicious example archives",
        "",
        "Generated by `benchmark/security/generate_examples.py`. The archives are gitignored —",
        "regenerate at will; this manifest is tracked.",
        "Every payload is intentionally small and harmless if accidentally extracted.",
        "",
        "| archive | size | attack | expected secure-unzip behaviour |",
        "| --- | ---: | --- | --- |",
    ]
    for name, attack, expect in MANIFEST:
        size = os.path.getsize(os.path.join(OUT, name))
        lines.append("| `%s` | %d B | %s | %s |" % (name, size, attack, expect))
    lines.append("")
    with open(os.path.join(OUT, "README.md"), "w") as fh:
        fh.write("\n".join(lines))

    for name, _, _ in MANIFEST:
        print("%8d  %s" % (os.path.getsize(os.path.join(OUT, name)), name))


if __name__ == "__main__":
    main()
