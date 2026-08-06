// Package testutils generates the malicious archives the security suite runs
// against. Fixtures are generated, never committed: a working zip bomb checked
// into git is its own problem.
package testutils

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Fixture describes one generated archive.
type Fixture struct {
	Name        string
	Description string
	Generate    func(path string) error
}

// All returns every fixture, in report order.
func All() []Fixture {
	return []Fixture{
		{"benign", "a small, well-formed archive (control case)", Benign},
		{"zipslip", "entry named ../../etc/passwd (directory traversal)", ZipSlip},
		{"zipbomb", "highly compressed zero-filled file (expansion attack)", ZipBomb},
		{"inodes", "20,000 tiny entries (inode exhaustion)", InodeExhaustion},
		{"perms", "entry with 0777 permissions", OverlyPermissive},
		{"symlink", "symlink pointing at /etc/passwd", SymlinkEscape},
	}
}

// Generate writes every fixture into dir and returns their paths by name.
func Generate(dir string) (map[string]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	paths := make(map[string]string)
	for _, f := range All() {
		p := filepath.Join(dir, f.Name+".zip")
		if err := f.Generate(p); err != nil {
			return nil, fmt.Errorf("generating fixture %s: %w", f.Name, err)
		}
		paths[f.Name] = p
	}
	return paths, nil
}

func createZip(path string, build func(*zip.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	if err := build(zw); err != nil {
		zw.Close()
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// addFile writes one entry with an explicit mode. Deflate is used so the
// compressed size is meaningful for the ratio check.
func addFile(zw *zip.Writer, name string, mode fs.FileMode, data []byte) error {
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Benign is the control case: a normal small tree. Also the benchmark input.
func Benign(path string) error {
	return createZip(path, func(zw *zip.Writer) error {
		files := map[string]string{
			"README.md":       "# benign fixture\n",
			"src/main.go":     "package main\n\nfunc main() {}\n",
			"src/lib/util.go": "package lib\n",
			"docs/guide.txt":  "nothing to see here\n",
		}
		for name, body := range files {
			if err := addFile(zw, name, 0o644, []byte(body)); err != nil {
				return err
			}
		}
		return addFile(zw, "run.sh", 0o755, []byte("#!/bin/sh\necho hello\n"))
	})
}

// LargeBenign writes a well-formed archive of roughly totalBytes uncompressed,
// spread over many files. This is the benchmark input: big enough to measure,
// realistic enough that the compression ratio stays sane.
func LargeBenign(path string, totalBytes int64) error {
	const fileSize = 256 << 10 // 256 KiB per file
	count := int(totalBytes / fileSize)
	if count < 1 {
		count = 1
	}

	// Pseudo-random but deterministic content: incompressible enough to be a
	// fair I/O test, unlike a run of zeros.
	blob := make([]byte, fileSize)
	seed := uint32(2463534242)
	for i := range blob {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		blob[i] = byte(seed)
	}

	return createZip(path, func(zw *zip.Writer) error {
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("data/%03d/file-%05d.bin", i/100, i)
			if err := addFile(zw, name, 0o644, blob); err != nil {
				return err
			}
		}
		return nil
	})
}

// ZipSlip carries an entry whose name escapes the destination directory.
func ZipSlip(path string) error {
	return createZip(path, func(zw *zip.Writer) error {
		if err := addFile(zw, "harmless.txt", 0o644, []byte("decoy\n")); err != nil {
			return err
		}
		return addFile(zw, "../../etc/passwd", 0o644,
			[]byte("root:x:0:0:PWNED BY ZIP SLIP:/root:/bin/sh\n"))
	})
}

// zipBombUncompressed is large enough to clear the ratio check's 1 MiB floor
// and to breach a modest -max-size in the tests.
const zipBombUncompressed = 64 << 20 // 64 MiB of zeros

// ZipBomb compresses a large run of zeros into a tiny archive. Zeros deflate
// at roughly 1000:1, well past the 100:1 default ceiling.
func ZipBomb(path string) error {
	return createZip(path, func(zw *zip.Writer) error {
		h := &zip.FileHeader{Name: "bomb.bin", Method: zip.Deflate}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		chunk := make([]byte, 1<<20) // 1 MiB of zeros
		for written := 0; written < zipBombUncompressed; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
		return nil
	})
}

// InodeExhaustionCount is the number of entries in the inodes fixture.
const InodeExhaustionCount = 20000

// InodeExhaustion packs many tiny entries to exhaust inodes rather than space.
func InodeExhaustion(path string) error {
	return createZip(path, func(zw *zip.Writer) error {
		for i := 0; i < InodeExhaustionCount; i++ {
			name := fmt.Sprintf("flood/%05d.txt", i)
			if err := addFile(zw, name, 0o644, []byte("x")); err != nil {
				return err
			}
		}
		return nil
	})
}

// OverlyPermissive carries world-writable and setuid entries.
func OverlyPermissive(path string) error {
	return createZip(path, func(zw *zip.Writer) error {
		if err := addFile(zw, "wide-open.sh", 0o777, []byte("#!/bin/sh\necho pwned\n")); err != nil {
			return err
		}
		return addFile(zw, "suid-binary", 0o777|fs.ModeSetuid, []byte("fake binary\n"))
	})
}

// SymlinkEscape carries a symlink pointing outside the destination — the
// deferred-escape variant of Zip Slip that a name-only check would miss.
func SymlinkEscape(path string) error {
	return createZip(path, func(zw *zip.Writer) error {
		if err := addFile(zw, "innocent.txt", 0o644, []byte("nothing\n")); err != nil {
			return err
		}
		// A symlink entry stores its target as the file body.
		return addFile(zw, "escape-link", 0o777|fs.ModeSymlink, []byte("/etc/passwd"))
	})
}
