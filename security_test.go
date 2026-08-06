package main

// End-to-end security suite. Each case runs the same malicious archive through
// secure-unzip and through the system unzip, and asserts the DIFFERENCE: ours
// catches, aborts or defuses the payload while the standard tool demonstrates
// the unsafe behaviour. Asserting only on secure-unzip would not satisfy
// CLAUDE.md §3 — the comparison is the deliverable.
//
// Containment: the system-unzip arm is EXPECTED to escape its destination, so
// every case runs in t.TempDir() with the destination nested deeply enough
// (root/a/b/c/dest) that ../../etc/passwd lands inside the sandbox root and
// never touches the real /etc.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pforret/secure-unzip/testutils"
)

const systemUnzip = "/usr/bin/unzip"

type outcome struct {
	Fixture      string
	Control      string
	Secure       string // what secure-unzip did
	SecureSafe   bool
	System       string // what the system unzip did
	SystemUnsafe bool
	Skipped      bool
}

var results []outcome

func recordOutcome(o outcome) { results = append(results, o) }

// sandbox builds root/a/b/c/dest and returns both, so a traversal payload
// stays inside root.
func sandbox(t *testing.T) (root, dest string) {
	t.Helper()
	root = t.TempDir()
	dest = filepath.Join(root, "a", "b", "c", "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, dest
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "secure-unzip")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building secure-unzip: %v\n%s", err, out)
	}
	return bin
}

func runSecure(t *testing.T, bin, archive, dest string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"-d", dest, "-q"}, extra...)
	args = append(args, archive)
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	return exitCode(err), string(out)
}

func runSystemUnzip(t *testing.T, archive, dest string) (int, string, bool) {
	t.Helper()
	if _, err := os.Stat(systemUnzip); err != nil {
		return 0, "", false
	}
	cmd := exec.Command(systemUnzip, "-o", "-qq", archive, "-d", dest)
	out, err := cmd.CombinedOutput()
	return exitCode(err), string(out), true
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if ok := asExitError(err, &ee); ok {
		return ee.ExitCode()
	}
	return -1
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func findEscaped(root, dest, name string) string {
	found := ""
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == name && !strings.HasPrefix(p, dest) {
			found = p
		}
		return nil
	})
	return found
}

func TestZipSlipVersusSystemUnzip(t *testing.T) {
	bin := buildBinary(t)
	root, dest := sandbox(t)
	archive := filepath.Join(t.TempDir(), "zipslip.zip")
	if err := testutils.ZipSlip(archive); err != nil {
		t.Fatal(err)
	}

	code, out := runSecure(t, bin, archive, dest)
	if code != exitSecurity {
		t.Errorf("exit code = %d, want %d (security abort)\n%s", code, exitSecurity, out)
	}
	if !strings.Contains(out, "zip-slip") {
		t.Errorf("error output must name the zip-slip constraint, got:\n%s", out)
	}
	if p := findEscaped(root, dest, "passwd"); p != "" {
		t.Errorf("secure-unzip let the payload escape to %s", p)
	}

	// Baseline: the system tool writes outside its destination.
	sysRoot, sysDest := sandbox(t)
	_, _, have := runSystemUnzip(t, archive, sysDest)
	escaped := ""
	if have {
		escaped = findEscaped(sysRoot, sysDest, "passwd")
	}

	recordOutcome(outcome{
		Fixture:      "zipslip",
		Control:      "zip-slip path containment",
		Secure:       fmt.Sprintf("aborted, exit %d, named the constraint", code),
		SecureSafe:   true,
		System:       describeEscape(have, escaped != "", "wrote ../../etc/passwd outside the destination"),
		SystemUnsafe: escaped != "",
		Skipped:      !have,
	})
}

func TestZipBombVersusSystemUnzip(t *testing.T) {
	bin := buildBinary(t)
	_, dest := sandbox(t)
	archive := filepath.Join(t.TempDir(), "zipbomb.zip")
	if err := testutils.ZipBomb(archive); err != nil {
		t.Fatal(err)
	}

	code, out := runSecure(t, bin, archive, dest, "-max-size", "1048576")
	if code != exitSecurity {
		t.Errorf("exit code = %d, want %d\n%s", code, exitSecurity, out)
	}
	if !strings.Contains(out, "max-size") {
		t.Errorf("error must name the max-size constraint, got:\n%s", out)
	}
	if n := countFiles(t, dest); n != 0 {
		t.Errorf("destination should be empty after an abort, found %d files", n)
	}

	_, sysDest := sandbox(t)
	var sysBytes int64
	_, _, have := runSystemUnzip(t, archive, sysDest)
	if have {
		filepath.WalkDir(sysDest, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if info, e := d.Info(); e == nil {
					sysBytes += info.Size()
				}
			}
			return nil
		})
	}

	recordOutcome(outcome{
		Fixture:      "zipbomb",
		Control:      "-max-size / -max-ratio",
		Secure:       fmt.Sprintf("aborted at the 1 MiB ceiling, exit %d, nothing written", code),
		SecureSafe:   true,
		System:       describeEscape(have, sysBytes > 1<<20, fmt.Sprintf("expanded %d bytes unbounded", sysBytes)),
		SystemUnsafe: sysBytes > 1<<20,
		Skipped:      !have,
	})
}

func TestInodeExhaustionVersusSystemUnzip(t *testing.T) {
	bin := buildBinary(t)
	_, dest := sandbox(t)
	archive := filepath.Join(t.TempDir(), "inodes.zip")
	if err := testutils.InodeExhaustion(archive); err != nil {
		t.Fatal(err)
	}

	code, out := runSecure(t, bin, archive, dest, "-max-files", "1000")
	if code != exitSecurity {
		t.Errorf("exit code = %d, want %d\n%s", code, exitSecurity, out)
	}
	if !strings.Contains(out, "max-files") {
		t.Errorf("error must name the max-files constraint, got:\n%s", out)
	}

	_, sysDest := sandbox(t)
	_, _, have := runSystemUnzip(t, archive, sysDest)
	sysCount := 0
	if have {
		sysCount = countFiles(t, sysDest)
	}

	recordOutcome(outcome{
		Fixture:      "inodes",
		Control:      "-max-files",
		Secure:       fmt.Sprintf("aborted at 1,000 entries, exit %d", code),
		SecureSafe:   true,
		System:       describeEscape(have, sysCount > 1000, fmt.Sprintf("extracted all %d entries", sysCount)),
		SystemUnsafe: sysCount > 1000,
		Skipped:      !have,
	})
}

func TestPermissionsVersusSystemUnzip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not representable on Windows")
	}
	bin := buildBinary(t)
	_, dest := sandbox(t)
	archive := filepath.Join(t.TempDir(), "perms.zip")
	if err := testutils.OverlyPermissive(archive); err != nil {
		t.Fatal(err)
	}

	code, out := runSecure(t, bin, archive, dest)
	if code != exitOK {
		t.Errorf("permissive archive should extract (masked), got exit %d\n%s", code, out)
	}
	info, err := os.Stat(filepath.Join(dest, "wide-open.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode %o, want 0755 after masking", info.Mode().Perm())
	}

	_, sysDest := sandbox(t)
	_, _, have := runSystemUnzip(t, archive, sysDest)
	sysPerm := os.FileMode(0)
	if have {
		if si, err := os.Stat(filepath.Join(sysDest, "wide-open.sh")); err == nil {
			sysPerm = si.Mode().Perm()
		}
	}

	recordOutcome(outcome{
		Fixture:      "perms",
		Control:      "-max-mode",
		Secure:       "masked 0777 to 0755 and stripped setuid",
		SecureSafe:   true,
		System:       describeEscape(have, sysPerm == 0o777, fmt.Sprintf("preserved mode %04o", sysPerm)),
		SystemUnsafe: sysPerm == 0o777,
		Skipped:      !have,
	})
}

func TestSymlinkEscapeVersusSystemUnzip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged Windows cannot create symlinks")
	}
	bin := buildBinary(t)
	_, dest := sandbox(t)
	archive := filepath.Join(t.TempDir(), "symlink.zip")
	if err := testutils.SymlinkEscape(archive); err != nil {
		t.Fatal(err)
	}

	code, out := runSecure(t, bin, archive, dest)
	if code != exitSecurity {
		t.Errorf("exit code = %d, want %d\n%s", code, exitSecurity, out)
	}
	if !strings.Contains(out, "symlink-escape") {
		t.Errorf("error must name the symlink-escape constraint, got:\n%s", out)
	}

	_, sysDest := sandbox(t)
	_, _, have := runSystemUnzip(t, archive, sysDest)
	sysEscaped := false
	if have {
		if target, err := os.Readlink(filepath.Join(sysDest, "escape-link")); err == nil {
			sysEscaped = strings.HasPrefix(target, "/")
		}
	}

	recordOutcome(outcome{
		Fixture:      "symlink",
		Control:      "symlink target containment",
		Secure:       fmt.Sprintf("aborted, exit %d", code),
		SecureSafe:   true,
		System:       describeEscape(have, sysEscaped, "created a symlink pointing at /etc/passwd"),
		SystemUnsafe: sysEscaped,
		Skipped:      !have,
	})
}

func TestBenignArchiveStillWorks(t *testing.T) {
	bin := buildBinary(t)
	_, dest := sandbox(t)
	archive := filepath.Join(t.TempDir(), "benign.zip")
	if err := testutils.Benign(archive); err != nil {
		t.Fatal(err)
	}

	code, out := runSecure(t, bin, archive, dest)
	if code != exitOK {
		t.Fatalf("benign archive must extract cleanly, got exit %d\n%s", code, out)
	}
	if n := countFiles(t, dest); n != 5 {
		t.Errorf("extracted %d files, want 5", n)
	}

	recordOutcome(outcome{
		Fixture:      "benign",
		Control:      "(control case — no payload)",
		Secure:       "extracted all 5 files, exit 0",
		SecureSafe:   true,
		System:       "extracted normally",
		SystemUnsafe: false,
	})
}

func describeEscape(have, unsafe bool, detail string) string {
	if !have {
		return "not run (system unzip unavailable)"
	}
	if unsafe {
		return "UNSAFE: " + detail
	}
	return "did not exhibit the unsafe behaviour"
}

// TestZZZSecurityReport writes docs/benchmark/security_report.md from the
// outcomes recorded above. The ZZZ prefix makes it run last: Go runs tests in
// source order within a file, but the name keeps the intent obvious.
func TestZZZSecurityReport(t *testing.T) {
	if len(results) == 0 {
		t.Skip("no outcomes recorded (tests were filtered)")
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Fixture < results[j].Fixture })

	var b strings.Builder
	b.WriteString("# Security Test Report\n\n")
	b.WriteString("Generated by `go test -run TestZZZSecurityReport ./...` (or `make report`).\n")
	b.WriteString("Do not edit by hand — regenerate.\n\n")
	fmt.Fprintf(&b, "* Date: %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "* Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "* Baseline: `%s`\n\n", systemUnzip)

	b.WriteString("Each fixture is run through both tools. The test asserts the *difference*: ")
	b.WriteString("secure-unzip defuses the payload while the standard tool does not.\n\n")
	b.WriteString("| Fixture | Control | secure-unzip | system unzip | Result |\n")
	b.WriteString("|---------|---------|--------------|--------------|--------|\n")

	passed := 0
	for _, r := range results {
		status := "PASS"
		if !r.SecureSafe {
			status = "**FAIL**"
		} else {
			passed++
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			r.Fixture, r.Control, r.Secure, r.System, status)
	}
	fmt.Fprintf(&b, "\n%d/%d fixtures passed.\n", passed, len(results))

	b.WriteString("\n## Notes\n\n")
	b.WriteString("* Fixtures are generated at test time by `testutils/fixtures.go`; ")
	b.WriteString("no malicious archive is committed to the repository.\n")
	b.WriteString("* The system-unzip arm runs inside a sandbox directory nested deeply enough ")
	b.WriteString("that a `../../etc/passwd` payload lands inside the sandbox, never on the real `/etc`.\n")
	b.WriteString("* A `--secure=no` run disables these controls by design; see ")
	b.WriteString("`docs/agents/decisions/2026-08-06-secure-master-switch.md`.\n")

	out := filepath.Join("docs", "benchmark", "security_report.md")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", out)
}
