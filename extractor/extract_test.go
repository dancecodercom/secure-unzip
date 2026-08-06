package extractor

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/pforret/secure-unzip/security"
	"github.com/pforret/secure-unzip/testutils"
)

// secureOpts is the --secure=yes profile, with the limits the tests tighten.
func secureOpts(dest string) Options {
	return Options{
		Dest:      dest,
		Limits:    security.SecureLimits(),
		MaxMode:   security.DefaultMaxMode,
		Overwrite: true,
	}
}

func fixture(t *testing.T, gen func(string) error, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".zip")
	if err := gen(path); err != nil {
		t.Fatalf("generating %s fixture: %v", name, err)
	}
	return path
}

func wantConstraint(t *testing.T, err error, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s constraint error, got nil", constraint)
	}
	ce, ok := security.AsConstraintError(err)
	if !ok {
		t.Fatalf("expected a *ConstraintError, got %T: %v", err, err)
	}
	if ce.Constraint != constraint {
		t.Fatalf("constraint = %q, want %q (%v)", ce.Constraint, constraint, err)
	}
}

func TestExtractBenign(t *testing.T) {
	archive := fixture(t, testutils.Benign, "benign")
	dest := filepath.Join(t.TempDir(), "out")

	res, err := Extract(archive, secureOpts(dest))
	if err != nil {
		t.Fatalf("benign archive must extract cleanly: %v", err)
	}
	if res.Files != 5 {
		t.Errorf("extracted %d files, want 5", res.Files)
	}
	if _, err := os.Stat(filepath.Join(dest, "src", "lib", "util.go")); err != nil {
		t.Errorf("nested file missing: %v", err)
	}
}

func TestZipSlipIsBlocked(t *testing.T) {
	archive := fixture(t, testutils.ZipSlip, "zipslip")
	root := t.TempDir()
	dest := filepath.Join(root, "a", "b", "out")

	_, err := Extract(archive, secureOpts(dest))
	wantConstraint(t, err, security.ConstraintZipSlip)

	// Nothing may have escaped, anywhere under the sandbox root.
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "passwd" {
			t.Errorf("zip slip payload escaped to %s", p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestZipBombIsBlockedBySize(t *testing.T) {
	archive := fixture(t, testutils.ZipBomb, "bomb")
	dest := filepath.Join(t.TempDir(), "out")

	opts := secureOpts(dest)
	opts.Limits.MaxSize = 1 << 20 // 1 MiB: far below the 64 MiB payload

	_, err := Extract(archive, opts)
	wantConstraint(t, err, security.ConstraintMaxSize)
}

func TestZipBombIsBlockedByRatio(t *testing.T) {
	archive := fixture(t, testutils.ZipBomb, "bomb")
	dest := filepath.Join(t.TempDir(), "out")

	// Size ceiling lifted, so only the ratio check can catch it.
	opts := secureOpts(dest)
	opts.Limits.MaxSize = 0

	_, err := Extract(archive, opts)
	wantConstraint(t, err, security.ConstraintMaxRatio)
}

func TestInodeExhaustionIsBlocked(t *testing.T) {
	archive := fixture(t, testutils.InodeExhaustion, "inodes")
	dest := filepath.Join(t.TempDir(), "out")

	opts := secureOpts(dest)
	opts.Limits.MaxFiles = 1000

	_, err := Extract(archive, opts)
	wantConstraint(t, err, security.ConstraintMaxFiles)
}

func TestPermissionsAreMasked(t *testing.T) {
	archive := fixture(t, testutils.OverlyPermissive, "perms")
	dest := filepath.Join(t.TempDir(), "out")

	if _, err := Extract(archive, secureOpts(dest)); err != nil {
		t.Fatalf("permissive archive should extract with masked modes: %v", err)
	}

	info, err := os.Stat(filepath.Join(dest, "wide-open.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("0777 entry extracted as %o, want 0755", info.Mode().Perm())
	}

	suid, err := os.Stat(filepath.Join(dest, "suid-binary"))
	if err != nil {
		t.Fatal(err)
	}
	if suid.Mode()&fs.ModeSetuid != 0 {
		t.Error("setuid bit survived extraction")
	}
}

func TestSymlinkEscapeIsBlocked(t *testing.T) {
	archive := fixture(t, testutils.SymlinkEscape, "symlink")
	dest := filepath.Join(t.TempDir(), "out")

	_, err := Extract(archive, secureOpts(dest))
	wantConstraint(t, err, security.ConstraintSymlinkEscape)
}

// The whole point of staging: a run that aborts must leave the destination
// untouched, not half-populated.
func TestAbortLeavesDestinationClean(t *testing.T) {
	archive := fixture(t, testutils.InodeExhaustion, "inodes")
	dest := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dest, "pre-existing.txt")
	if err := os.WriteFile(existing, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := secureOpts(dest)
	opts.Limits.MaxFiles = 500
	if _, err := Extract(archive, opts); err == nil {
		t.Fatal("expected the run to abort")
	}

	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "pre-existing.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("destination should contain only the pre-existing file, got %v", names)
	}

	// The staging directory must not survive either.
	siblings, err := os.ReadDir(filepath.Dir(dest))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range siblings {
		if len(s.Name()) > 0 && s.Name()[0] == '.' {
			t.Errorf("staging directory %s was left behind", s.Name())
		}
	}
}

func TestReadOnlyLocksFilesAfterWriting(t *testing.T) {
	archive := fixture(t, testutils.Benign, "benign")
	dest := filepath.Join(t.TempDir(), "out")

	// The lock works well enough to defeat t.TempDir's own cleanup, so undo it
	// afterwards. Needing this is itself evidence the feature does its job.
	t.Cleanup(func() {
		filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
			if err == nil {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})

	opts := secureOpts(dest)
	opts.ReadOnly = true

	if _, err := Extract(archive, opts); err != nil {
		t.Fatalf("read-only extraction must still write the data: %v", err)
	}

	// Data written first, permissions stripped after: content must be intact.
	body, err := os.ReadFile(filepath.Join(dest, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "# benign fixture\n" {
		t.Errorf("content = %q, want the fixture body", string(body))
	}

	info, err := os.Stat(filepath.Join(dest, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("mode %o still has a write bit set", info.Mode().Perm())
	}
}

// --secure=no genuinely lifts path containment too. This test asserts the
// tool is unsafe on purpose in that mode, so the warning printed by the CLI is
// truthful rather than decorative. It runs entirely inside a sandbox root: the
// escaping entry lands under the temp dir, never on the real /etc.
func TestUnsecureAllowsTraversal(t *testing.T) {
	archive := fixture(t, testutils.ZipSlip, "zipslip")
	sandbox := t.TempDir()
	dest := filepath.Join(sandbox, "a", "b", "out")

	opts := Options{
		Dest:             dest,
		Limits:           security.UnsecureLimits(),
		Overwrite:        true,
		AllowUnsafePaths: true,
	}
	if _, err := Extract(archive, opts); err != nil {
		t.Fatalf("--secure=no must not block traversal: %v", err)
	}

	// ../../etc/passwd relative to <sandbox>/a/b/out lands in <sandbox>/a/etc.
	escaped := filepath.Join(sandbox, "a", "etc", "passwd")
	if _, err := os.Stat(escaped); err != nil {
		t.Fatalf("expected the payload to escape to %s in unsafe mode: %v", escaped, err)
	}
}

// --secure=no lifts the resource ceilings.
func TestUnsecureLiftsLimits(t *testing.T) {
	archive := fixture(t, testutils.InodeExhaustion, "inodes")
	dest := filepath.Join(t.TempDir(), "out")

	opts := Options{Dest: dest, Limits: security.UnsecureLimits(), Overwrite: true}
	res, err := Extract(archive, opts)
	if err != nil {
		t.Fatalf("--secure=no must not enforce -max-files: %v", err)
	}
	if res.Files != testutils.InodeExhaustionCount {
		t.Errorf("extracted %d entries, want %d", res.Files, testutils.InodeExhaustionCount)
	}
}
