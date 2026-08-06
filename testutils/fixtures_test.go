package testutils

import (
	"archive/zip"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// The fixtures are the ground truth of the whole security suite. A generator
// that silently degrades — a bomb that no longer compresses, a slip entry that
// lost its ../ — would make every downstream test pass vacuously. These tests
// check the payloads are really what they claim to be.

func TestGenerateAll(t *testing.T) {
	paths, err := Generate(t.TempDir())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, f := range All() {
		if _, ok := paths[f.Name]; !ok {
			t.Errorf("fixture %q missing from Generate output", f.Name)
		}
	}
}

func openFixture(t *testing.T, gen func(string) error, name string) *zip.ReadCloser {
	t.Helper()
	path := t.TempDir() + "/" + name + ".zip"
	if err := gen(path); err != nil {
		t.Fatalf("generating %s: %v", name, err)
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("opening %s: %v", name, err)
	}
	t.Cleanup(func() { zr.Close() })
	return zr
}

func TestZipSlipHasTraversalEntry(t *testing.T) {
	zr := openFixture(t, ZipSlip, "zipslip")
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") {
			return
		}
	}
	t.Fatal("zipslip fixture contains no traversal entry — the payload is gone")
}

func TestZipBombActuallyCompresses(t *testing.T) {
	path := t.TempDir() + "/bomb.zip"
	if err := ZipBomb(path); err != nil {
		t.Fatalf("ZipBomb: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	var uncompressed, compressed int64
	for _, f := range zr.File {
		uncompressed += int64(f.UncompressedSize64)
		compressed += int64(f.CompressedSize64)
	}

	if uncompressed < 1<<20 {
		t.Fatalf("bomb expands to only %d bytes — below the ratio check's 1 MiB floor", uncompressed)
	}
	// The default ceiling is 100:1. If zlib ever stops compressing zeros this
	// hard, the bomb tests would pass vacuously — fail loudly here instead.
	if ratio := uncompressed / compressed; ratio <= 100 {
		t.Fatalf("bomb ratio is only %d:1, not above the 100:1 default ceiling", ratio)
	}
	if st.Size() > 1<<20 {
		t.Errorf("bomb archive is %d bytes; expected a small file", st.Size())
	}
}

func TestInodeFixtureEntryCount(t *testing.T) {
	zr := openFixture(t, InodeExhaustion, "inodes")
	if len(zr.File) != InodeExhaustionCount {
		t.Fatalf("inode fixture has %d entries, want %d", len(zr.File), InodeExhaustionCount)
	}
}

func TestOverlyPermissiveModes(t *testing.T) {
	zr := openFixture(t, OverlyPermissive, "perms")

	var sawWorldWritable, sawSetuid bool
	for _, f := range zr.File {
		mode := f.Mode()
		if mode.Perm() == 0o777 {
			sawWorldWritable = true
		}
		if mode&fs.ModeSetuid != 0 {
			sawSetuid = true
		}
	}
	if !sawWorldWritable {
		t.Error("perms fixture has no 0777 entry")
	}
	if !sawSetuid {
		t.Error("perms fixture has no setuid entry")
	}
}

func TestSymlinkFixtureIsASymlink(t *testing.T) {
	zr := openFixture(t, SymlinkEscape, "symlink")
	for _, f := range zr.File {
		if f.Mode()&fs.ModeSymlink != 0 {
			return
		}
	}
	t.Fatal("symlink fixture contains no symlink entry")
}

func TestBenignIsClean(t *testing.T) {
	zr := openFixture(t, Benign, "benign")
	if len(zr.File) == 0 {
		t.Fatal("benign fixture is empty")
	}
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			t.Errorf("benign fixture must contain no traversal entries, found %q", f.Name)
		}
		if f.Mode()&fs.ModeSymlink != 0 {
			t.Errorf("benign fixture must contain no symlinks, found %q", f.Name)
		}
	}
}
