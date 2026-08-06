package main

import (
	"io/fs"
	"testing"
)

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

func TestExitCodeForConstraint(t *testing.T) {
	err := (&stubConstraint{}).err()
	if got := exitCodeFor(err); got != exitSecurity {
		t.Errorf("exitCodeFor(constraint) = %d, want %d", got, exitSecurity)
	}
}
