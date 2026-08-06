package main

import (
	"bytes"
	"strings"
	"testing"
)

// A non-*os.File writer is never a terminal, so styling must be off. This is
// the case that matters: piped and redirected output must stay byte-for-byte
// plain, because these lines get logged, grepped and diffed.
func TestStylingIsOffForNonTerminals(t *testing.T) {
	var buf bytes.Buffer
	s := newStyler(&buf)
	if s.on {
		t.Fatal("styling must be disabled for a non-terminal writer")
	}
	for _, got := range []string{s.bold("x"), s.red("x"), s.dim("x"), s.cyan("x"), s.amber("x")} {
		if got != "x" {
			t.Errorf("styled %q, want the plain string", got)
		}
	}
}

func TestNoColorBeatsForceColor(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	if colorEnabled(&buf) {
		t.Error("NO_COLOR must win over FORCE_COLOR")
	}
}

func TestForceColorEnablesStylingOffTerminal(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	var buf bytes.Buffer
	if !colorEnabled(&buf) {
		t.Error("FORCE_COLOR should enable styling for a non-terminal writer")
	}
}

// Escape sequences occupy no columns. If pad measured raw length, every styled
// column in --verbose would sit a few characters short of its neighbours.
func TestPadUsesVisibleWidth(t *testing.T) {
	styled := &styler{on: true}
	got := styled.pad(styled.cyan("--max-size"), 14)
	if visibleLen(got) != 14 {
		t.Errorf("visible width = %d, want 14 (raw len %d)", visibleLen(got), len(got))
	}
	if !strings.HasSuffix(got, strings.Repeat(" ", 4)) {
		t.Error("padding should be appended after the reset sequence")
	}
}

func TestVisibleLenIgnoresEscapes(t *testing.T) {
	cases := map[string]int{
		"plain":                    5,
		"\033[1mbold\033[0m":       4,
		"\033[36m\033[1mab\033[0m": 2,
		"":                         0,
	}
	for in, want := range cases {
		if got := visibleLen(in); got != want {
			t.Errorf("visibleLen(%q) = %d, want %d", in, got, want)
		}
	}
}

// The convention: single-letter options take one dash, multi-letter two.
func TestDashedConvention(t *testing.T) {
	cases := map[string]string{
		"d":         "-d",
		"q":         "-q",
		"o":         "-o",
		"v":         "-v",
		"verbose":   "--verbose",
		"secure":    "--secure",
		"max-size":  "--max-size",
		"read-only": "--read-only",
	}
	for in, want := range cases {
		if got := dashed(in); got != want {
			t.Errorf("dashed(%q) = %q, want %q", in, got, want)
		}
	}
}
