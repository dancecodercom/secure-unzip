// secure-unzip is a security-hardened drop-in alternative to standard unzip.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"

	"github.com/pforret/secure-unzip/extractor"
	"github.com/pforret/secure-unzip/security"
)

var version = "dev"

// Exit codes. 0/1/2/9 mirror standard unzip; 3 is ours, so a script can tell a
// malicious archive from a missing file.
const (
	exitOK         = 0
	exitWarning    = 1
	exitError      = 2
	exitSecurity   = 3
	exitNoSuchFile = 9
)

type param struct{ name, value, origin string }

// config is the resolved run configuration: the --secure profile with any
// explicitly-set flag layered on top.
type config struct {
	secure    bool
	dest      string
	maxSize   int64
	maxFiles  int64
	maxRatio  int64
	maxMode   fs.FileMode
	readOnly  bool
	verbose   bool
	quiet     bool
	overwrite bool

	// explicit records which flags the user actually typed, so the origin can
	// be reported and so profile values never clobber a deliberate choice.
	explicit map[string]bool
}

func (c *config) origin(flagName string) string {
	if c.explicit[flagName] {
		return "[explicit]"
	}
	return "[profile]"
}

func (c *config) resolved() []param {
	maxMode := "off"
	if c.maxMode != 0 {
		maxMode = fmt.Sprintf("%04o", c.maxMode.Perm())
	}
	return []param{
		{"--max-size", limitValue(c.maxSize, security.HumanBytes(c.maxSize)), c.origin("max-size")},
		{"--max-files", limitValue(c.maxFiles, strconv.FormatInt(c.maxFiles, 10)), c.origin("max-files")},
		{"--max-ratio", limitValue(c.maxRatio, fmt.Sprintf("%d:1", c.maxRatio)), c.origin("max-ratio")},
		{"--max-mode", maxMode, c.origin("max-mode")},
		{"--read-only", yesNo(c.readOnly), c.origin("read-only")},
		{"--cpu-limit", "0 (reserved, not implemented)", c.origin("cpu-limit")},
	}
}

func limitValue(n int64, formatted string) string {
	if n <= 0 {
		return "unlimited"
	}
	return formatted
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// errVersion and errUsage are control-flow sentinels from parseArgs, not
// failures the user needs an error message for.
var (
	errVersion = errors.New("version requested")
	errUsage   = errors.New("usage requested")
)

// parseArgs turns argv into a resolved config. It is separate from run so the
// resolution rule — profile first, explicit flags second — can be tested
// without touching the filesystem.
func parseArgs(args []string, out io.Writer) (*config, string, error) {
	fs_ := flag.NewFlagSet("secure-unzip", flag.ContinueOnError)
	fs_.SetOutput(out)
	fs_.Usage = func() { usage(out, fs_) }

	var (
		secure    = fs_.String("secure", "yes", "enable the precaution profile (yes|no)")
		dest      = fs_.String("d", ".", "destination directory")
		maxSize   = fs_.Int64("max-size", security.DefaultMaxSize, "max total uncompressed bytes (0 = unlimited)")
		maxFiles  = fs_.Int64("max-files", security.DefaultMaxFiles, "max extracted entries (0 = unlimited)")
		maxRatio  = fs_.Int64("max-ratio", security.DefaultMaxRatio, "max compression expansion ratio (0 = unlimited)")
		maxModeS  = fs_.String("max-mode", "0755", "permission ceiling in octal (0 = no masking)")
		readOnly  = fs_.Bool("read-only", false, "strip write permissions after extraction")
		cpuLimit  = fs_.Int("cpu-limit", 0, "reserved; CPU throttling is not yet implemented")
		verbose   = fs_.Bool("verbose", false, "report resolved parameters and run statistics")
		verboseV  = fs_.Bool("v", false, "alias for --verbose")
		quiet     = fs_.Bool("q", false, "suppress per-entry output")
		overwrite = fs_.Bool("o", false, "overwrite existing files without prompting")
		showVer   = fs_.Bool("version", false, "print version and exit")
	)
	_ = cpuLimit // parsed and documented, deliberately inert (v2)

	// unzip's documented form puts -d AFTER the archive
	// (`secure-unzip [options] archive.zip [-d extract_dir]`), but flag.Parse
	// stops at the first non-flag argument. Parse repeatedly, peeling off one
	// operand each round, so flags on either side of the archive are seen.
	var operands []string
	rest := args
	for {
		if err := fs_.Parse(rest); err != nil {
			return nil, "", err
		}
		if fs_.NArg() == 0 {
			break
		}
		operands = append(operands, fs_.Arg(0))
		rest = fs_.Args()[1:]
	}
	if *showVer {
		return nil, "", errVersion
	}
	if len(operands) < 1 {
		usage(out, fs_)
		return nil, "", errUsage
	}
	archive := operands[0]
	if len(operands) > 1 {
		return nil, "", fmt.Errorf("unexpected argument %q: selecting individual members is not supported", operands[1])
	}

	secureOn, err := parseYesNo(*secure)
	if err != nil {
		return nil, "", err
	}

	explicit := map[string]bool{}
	fs_.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	maxMode, err := parseMode(*maxModeS)
	if err != nil {
		return nil, "", err
	}

	cfg := &config{
		secure:    secureOn,
		dest:      *dest,
		readOnly:  *readOnly,
		verbose:   *verbose || *verboseV,
		quiet:     *quiet,
		overwrite: *overwrite,
		explicit:  explicit,
	}

	// Resolution rule: start from the profile, then let explicitly-set flags
	// win. Deliberately NOT positional — the order of flags on the command
	// line does not change the result.
	if secureOn {
		cfg.maxSize, cfg.maxFiles, cfg.maxRatio, cfg.maxMode =
			security.DefaultMaxSize, security.DefaultMaxFiles, security.DefaultMaxRatio, security.DefaultMaxMode
	} else {
		cfg.maxSize, cfg.maxFiles, cfg.maxRatio, cfg.maxMode = 0, 0, 0, 0
	}
	if explicit["max-size"] {
		cfg.maxSize = *maxSize
	}
	if explicit["max-files"] {
		cfg.maxFiles = *maxFiles
	}
	if explicit["max-ratio"] {
		cfg.maxRatio = *maxRatio
	}
	if explicit["max-mode"] {
		cfg.maxMode = maxMode
	}

	// -q and --verbose conflict; whichever was given last wins.
	if cfg.verbose && cfg.quiet {
		cfg.quiet = lastOf(args, "q", "v", "verbose") == "q"
		cfg.verbose = !cfg.quiet
	}
	return cfg, archive, nil
}

func run(args []string, stdout, stderr *os.File) int {
	cfg, archive, err := parseArgs(args, stderr)
	switch {
	case errors.Is(err, errVersion):
		fmt.Fprintf(stdout, "secure-unzip %s\n", version)
		return exitOK
	case errors.Is(err, errUsage):
		return exitError
	case err != nil:
		fmt.Fprintf(stderr, "secure-unzip: %v\n", err)
		return exitError
	}

	if !cfg.secure && !cfg.quiet {
		warnInsecure(stderr, cfg)
	}
	if cfg.verbose {
		printResolved(stderr, cfg, archive)
	}

	opts := extractor.Options{
		Dest:      cfg.dest,
		Limits:    security.Limits{MaxSize: cfg.maxSize, MaxFiles: cfg.maxFiles, MaxRatio: cfg.maxRatio},
		MaxMode:   cfg.maxMode,
		ReadOnly:  cfg.readOnly,
		Overwrite: cfg.overwrite,
		Quiet:     cfg.quiet,
		// Path containment is part of the profile: --secure=no turns it off
		// along with everything else. This is the switch's sharpest edge, which
		// is why warnInsecure names it explicitly.
		AllowUnsafePaths: !cfg.secure,
	}
	if !cfg.quiet {
		fmt.Fprintf(stdout, "Archive:  %s\n", archive)
		opts.Log = func(format string, args ...any) {
			fmt.Fprintf(stdout, format+"\n", args...)
		}
	}

	// getrusage is cumulative over the whole process, but Result.Duration
	// covers extraction only. Diffing brackets the CPU figure to the same
	// window, otherwise startup time inflates it into nonsense percentages.
	before := currentUsage()
	res, err := extractor.Extract(archive, opts)

	if cfg.verbose {
		printStats(stderr, res, currentUsage().since(before))
	}

	if err != nil {
		fmt.Fprintf(stderr, "secure-unzip: %v\n", err)
		return exitCodeFor(err)
	}
	if res != nil && len(res.Warnings) > 0 {
		return exitWarning
	}
	return exitOK
}

// exitCodeFor maps an error to an exit code. A security constraint gets its
// own code so callers can distinguish "malicious archive" from "bad path".
func exitCodeFor(err error) int {
	if security.IsConstraintError(err) {
		return exitSecurity
	}
	if errors.Is(err, os.ErrNotExist) {
		return exitNoSuchFile
	}
	return exitError
}

// warnInsecure makes --secure=no loud. Silently unsafe is the failure mode
// worth avoiding: the switch disables path containment, not merely the
// resource ceilings.
func warnInsecure(w io.Writer, cfg *config) {
	s := newStyler(w)
	fmt.Fprintf(w, "%s %s — safety checks are disabled:\n",
		s.red("secure-unzip: WARNING"), s.bold("--secure=no"))
	fmt.Fprintf(w, "  %s zip-slip path containment is %s enforced\n", s.red("*"), s.bold("NOT"))
	fmt.Fprintf(w, "  %s symlink targets are %s checked\n", s.red("*"), s.bold("NOT"))
	for _, p := range cfg.resolved() {
		if p.value == "unlimited" || p.value == "off" {
			fmt.Fprintf(w, "  %s %s is %s\n", s.red("*"), s.cyan(p.name), s.bold(p.value))
		}
	}
}

func parseYesNo(s string) (bool, error) {
	switch s {
	case "yes", "true", "y", "1", "on":
		return true, nil
	case "no", "false", "n", "0", "off":
		return false, nil
	}
	return false, fmt.Errorf("invalid --secure value %q: want yes or no", s)
}

// parseMode accepts octal with or without a leading zero: 0644, 644, 0o644.
func parseMode(s string) (fs.FileMode, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	n, err := strconv.ParseUint(trimOctalPrefix(s), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid --max-mode %q: want an octal mode such as 0755", s)
	}
	return fs.FileMode(n).Perm(), nil
}

func trimOctalPrefix(s string) string {
	if len(s) > 2 && (s[0:2] == "0o" || s[0:2] == "0O") {
		return s[2:]
	}
	return s
}

// lastOf reports which of the named flags appeared last in argv, so that -q
// and --verbose resolve by position rather than by precedence.
func lastOf(args []string, names ...string) string {
	found := ""
	for _, a := range args {
		for _, n := range names {
			if a == "-"+n || a == "--"+n {
				found = n
			}
		}
	}
	if found == "v" || found == "verbose" {
		return "verbose"
	}
	return found
}

// dashed renders a flag name in the project's convention: single-letter
// options take one dash (-q), multi-letter options take two (--max-size).
// Go's flag package accepts either spelling for either kind, so this governs
// what we print and document, not what we parse.
func dashed(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

func usage(w io.Writer, fs_ *flag.FlagSet) {
	s := newStyler(w)

	fmt.Fprintf(w, "%s %s — a security-hardened alternative to unzip\n\n",
		s.bold("secure-unzip"), s.dim(version))

	fmt.Fprintf(w, "%s\n  secure-unzip [options] archive.zip [-d extract_dir]\n\n", s.bold("Usage:"))

	fmt.Fprintf(w, "Safety is on by default (%s): archives are checked for path\n",
		s.green("--secure=yes"))
	fmt.Fprintf(w, "traversal, expansion attacks, inode exhaustion and unsafe permissions.\n")
	fmt.Fprintf(w, "Use %s to disable every check, or override individual limits.\n\n",
		s.red("--secure=no"))

	fmt.Fprintf(w, "%s\n", s.bold("Exit codes:"))
	fmt.Fprintf(w, "  0  success                 2  error (bad archive, I/O)\n")
	fmt.Fprintf(w, "  1  completed with warnings %s  %s\n",
		s.red("3"), s.red("SECURITY: a constraint was violated"))
	fmt.Fprintf(w, "  9  archive not found\n\n")

	fmt.Fprintf(w, "%s\n", s.bold("Options:"))
	printDefaults(w, fs_)
}

// printDefaults replaces flag.PrintDefaults so option names follow the
// one-dash/two-dash convention and each flag occupies a single line.
func printDefaults(w io.Writer, fs_ *flag.FlagSet) {
	type row struct{ name, desc string }
	var rows []row
	width := 0

	s := newStyler(w)

	fs_.VisitAll(func(f *flag.Flag) {
		name := dashed(f.Name)
		if kind, _ := flag.UnquoteUsage(f); kind != "" {
			name += " " + kind
		}
		desc := f.Usage
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			desc += s.dim(fmt.Sprintf(" (default %s)", f.DefValue))
		}
		if len(name) > width {
			width = len(name)
		}
		rows = append(rows, row{s.cyan(name), desc})
	})

	for _, r := range rows {
		fmt.Fprintf(w, "  %s  %s\n", s.pad(r.name, width), r.desc)
	}
}
