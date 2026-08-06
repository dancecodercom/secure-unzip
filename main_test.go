package main

import (
	"io"
	"io/fs"
	"testing"

	"github.com/pforret/secure-unzip/security"
)

// resolveForTest runs the flag resolution with a dummy archive argument.
func resolveForTest(t *testing.T, args []string) *config {
	t.Helper()
	cfg, _, err := parseArgs(append(append([]string{}, args...), "archive.zip"), io.Discard)
	if err != nil {
		t.Fatalf("parseArgs(%v): %v", args, err)
	}
	return cfg
}

// The usage line advertises `secure-unzip [options] archive.zip [-d dir]`, but
// flag.Parse stops at the first non-flag argument. Before the repeated-parse
// fix, a trailing -d was silently dropped and extraction went to the current
// directory — the destination was ignored without any error.
func TestFlagsAreAcceptedOnEitherSideOfTheArchive(t *testing.T) {
	cases := map[string][]string{
		"before":   {"-q", "-d", "/tmp/dest", "archive.zip"},
		"after":    {"-q", "archive.zip", "-d", "/tmp/dest"},
		"straddle": {"-q", "archive.zip", "-o", "-d", "/tmp/dest"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, archive, err := parseArgs(args, io.Discard)
			if err != nil {
				t.Fatalf("parseArgs(%v): %v", args, err)
			}
			if archive != "archive.zip" {
				t.Errorf("archive = %q, want archive.zip", archive)
			}
			if cfg.dest != "/tmp/dest" {
				t.Errorf("dest = %q, want /tmp/dest", cfg.dest)
			}
		})
	}
}

// Member selection (`unzip archive.zip some/file`) is not implemented. Ignoring
// the extra operand would extract everything while the user asked for one file.
func TestExtraOperandIsRejected(t *testing.T) {
	_, _, err := parseArgs([]string{"archive.zip", "wanted/file.txt"}, io.Discard)
	if err == nil {
		t.Fatal("parseArgs accepted a member-selection argument, want error")
	}
}

func TestParseMode(t *testing.T) {
	ok := map[string]fs.FileMode{
		"0755":  0o755,
		"755":   0o755,
		"0o644": 0o644,
		"0644":  0o644,
		"0":     0, // masking off
		"":      0,
	}
	for in, want := range ok {
		got, err := parseMode(in)
		if err != nil {
			t.Errorf("parseMode(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseMode(%q) = %o, want %o", in, got, want)
		}
	}

	for _, bad := range []string{"999", "rwxr-xr-x", "0x1ff", "-1"} {
		if _, err := parseMode(bad); err == nil {
			t.Errorf("parseMode(%q) should fail", bad)
		}
	}
}

func TestParseYesNo(t *testing.T) {
	yes := []string{"yes", "true", "y", "1", "on"}
	no := []string{"no", "false", "n", "0", "off"}

	for _, s := range yes {
		if v, err := parseYesNo(s); err != nil || !v {
			t.Errorf("parseYesNo(%q) = %v, %v; want true", s, v, err)
		}
	}
	for _, s := range no {
		if v, err := parseYesNo(s); err != nil || v {
			t.Errorf("parseYesNo(%q) = %v, %v; want false", s, v, err)
		}
	}
	if _, err := parseYesNo("maybe"); err == nil {
		t.Error("parseYesNo(\"maybe\") should fail")
	}
}

// The resolution rule is non-positional: an explicitly set flag wins wherever
// it appears relative to --secure. Both orderings must agree.
func TestSecureOverrideIsNotPositional(t *testing.T) {
	orders := [][]string{
		{"--secure=no", "-max-files", "1000000"},
		{"-max-files", "1000000", "--secure=no"},
	}
	for _, args := range orders {
		cfg := resolveForTest(t, args)
		if cfg.secure {
			t.Errorf("%v: secure should be off", args)
		}
		if cfg.maxFiles != 1000000 {
			t.Errorf("%v: maxFiles = %d, want 1000000", args, cfg.maxFiles)
		}
		// Everything not named stays lifted by --secure=no.
		if cfg.maxSize != 0 || cfg.maxRatio != 0 || cfg.maxMode != 0 {
			t.Errorf("%v: unnamed limits should be unlimited, got %+v", args, cfg)
		}
	}
}

func TestSecureProfileDefaults(t *testing.T) {
	cfg := resolveForTest(t, nil)
	if !cfg.secure {
		t.Error("--secure defaults to yes")
	}
	if cfg.maxSize != 10737418240 {
		t.Errorf("maxSize = %d, want 10 GiB", cfg.maxSize)
	}
	if cfg.maxFiles != 10000 {
		t.Errorf("maxFiles = %d, want 10000", cfg.maxFiles)
	}
	if cfg.maxMode != 0o755 {
		t.Errorf("maxMode = %o, want 0755", cfg.maxMode)
	}
	if cfg.origin("max-files") != "[profile]" {
		t.Error("an untouched flag must report [profile]")
	}
}

func TestExplicitOriginIsReported(t *testing.T) {
	cfg := resolveForTest(t, []string{"-max-size", "123"})
	if cfg.origin("max-size") != "[explicit]" {
		t.Error("a flag the user typed must report [explicit]")
	}
	if cfg.maxSize != 123 {
		t.Errorf("maxSize = %d, want 123", cfg.maxSize)
	}
}

func TestLastOfResolvesQuietVerboseConflict(t *testing.T) {
	if got := lastOf([]string{"-verbose", "-q"}, "q", "v", "verbose"); got != "q" {
		t.Errorf("got %q, want q (given last)", got)
	}
	if got := lastOf([]string{"-q", "-verbose"}, "q", "v", "verbose"); got != "verbose" {
		t.Errorf("got %q, want verbose (given last)", got)
	}
	if got := lastOf([]string{"-q", "-v"}, "q", "v", "verbose"); got != "verbose" {
		t.Errorf("-v is an alias for -verbose, got %q", got)
	}
}

func TestExitCodeFor(t *testing.T) {
	constraint := &security.ConstraintError{
		Constraint: security.ConstraintZipSlip,
		Entry:      "../../etc/passwd",
		Detail:     "traversal",
	}
	if got := exitCodeFor(constraint); got != exitSecurity {
		t.Errorf("exitCodeFor(constraint) = %d, want %d", got, exitSecurity)
	}

	if got := exitCodeFor(fs.ErrNotExist); got != exitNoSuchFile {
		t.Errorf("exitCodeFor(not-exist) = %d, want %d", got, exitNoSuchFile)
	}

	if got := exitCodeFor(io.ErrUnexpectedEOF); got != exitError {
		t.Errorf("exitCodeFor(other) = %d, want %d", got, exitError)
	}
}

// --secure=no must not silently keep enforcing containment: the CLI warns that
// it is off, so the option passed to the extractor has to match the warning.
func TestUnsecureDisablesContainment(t *testing.T) {
	if cfg := resolveForTest(t, []string{"--secure=no"}); cfg.secure {
		t.Fatal("--secure=no must resolve to secure=false, which sets AllowUnsafePaths")
	}
	if cfg := resolveForTest(t, nil); !cfg.secure {
		t.Fatal("the default must resolve to secure=true")
	}
}
