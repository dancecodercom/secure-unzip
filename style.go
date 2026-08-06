package main

import (
	"io"
	"os"
	"strings"
)

// Styling is deliberately hand-rolled ANSI rather than a TUI library. This is a
// drop-in unzip replacement: it runs in CI, pipelines and scripts far more often
// than in a terminal, its output goes to stderr where it gets logged and grepped,
// and it is a security tool whose dependency surface is worth keeping at zero.
// See docs/agents/decisions/2026-08-06-go-single-static-binary.md.
const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
	ansiRed   = "\033[31m"
	ansiGreen = "\033[32m"
	ansiAmber = "\033[33m"
	ansiCyan  = "\033[36m"
)

// styler emits escape codes only when the destination is an interactive
// terminal. Everywhere else every method is the identity function, so piped and
// redirected output stays byte-for-byte plain.
type styler struct{ on bool }

func newStyler(w io.Writer) *styler { return &styler{on: colorEnabled(w)} }

// colorEnabled follows the conventions users already expect: NO_COLOR wins over
// everything (https://no-color.org), FORCE_COLOR overrides TTY detection for
// CI logs that do render escapes, TERM=dumb opts out, and otherwise the writer
// must be a character device.
func colorEnabled(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if _, set := os.LookupEnv("FORCE_COLOR"); set {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (s *styler) wrap(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return code + text + ansiReset
}

func (s *styler) bold(t string) string  { return s.wrap(ansiBold, t) }
func (s *styler) dim(t string) string   { return s.wrap(ansiDim, t) }
func (s *styler) red(t string) string   { return s.wrap(ansiRed+ansiBold, t) }
func (s *styler) green(t string) string { return s.wrap(ansiGreen, t) }
func (s *styler) amber(t string) string { return s.wrap(ansiAmber, t) }
func (s *styler) cyan(t string) string  { return s.wrap(ansiCyan, t) }

// pad right-aligns to width using the VISIBLE length. Escape codes occupy no
// columns, so %-*s over an already-styled string would misalign every row.
func (s *styler) pad(text string, width int) string {
	if n := visibleLen(text); n < width {
		return text + strings.Repeat(" ", width-n)
	}
	return text
}

// visibleLen counts runes outside ANSI escape sequences.
func visibleLen(s string) int {
	n, inEscape := 0, false
	for _, r := range s {
		switch {
		case inEscape:
			if r == 'm' {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			n++
		}
	}
	return n
}
