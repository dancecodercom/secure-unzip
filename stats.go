package main

import (
	"fmt"
	"io"
	"time"

	"github.com/pforret/secure-unzip/extractor"
)

// resourceUsage is what the platform can tell us about this process. Unset
// fields are reported as "n/a" rather than as zero — see peakRSS.
type resourceUsage struct {
	PeakRSSBytes uint64
	PeakRSSOK    bool
	CPUTime      time.Duration
	CPUTimeOK    bool
}

// since returns usage attributable to the window between the two samples.
// CPU time is cumulative, so it is differenced; peak RSS is a high-water mark,
// so the later (larger) value is kept as-is.
func (u resourceUsage) since(start resourceUsage) resourceUsage {
	out := u
	if u.CPUTimeOK && start.CPUTimeOK {
		out.CPUTime = u.CPUTime - start.CPUTime
		if out.CPUTime < 0 {
			out.CPUTime = 0
		}
	}
	return out
}

// printResolved reports every effective parameter before extraction starts.
// The [profile]/[explicit] origin is the point of the output: it answers
// "which limits am I actually running under" when --secure and individual
// flags interact.
func printResolved(w io.Writer, cfg *config, archive string) {
	s := newStyler(w)

	fmt.Fprintf(w, "%s %s\n", s.bold("secure-unzip"), s.dim(version))
	fmt.Fprintf(w, "  %s  %s\n", s.pad(s.dim("archive"), 12), archive)
	fmt.Fprintf(w, "  %s  %s\n", s.pad(s.dim("destination"), 12), cfg.dest)

	secure := s.green("yes")
	if !cfg.secure {
		secure = s.red("no")
	}
	fmt.Fprintf(w, "  %s  %s\n", s.pad(s.cyan("--secure"), 12), secure)

	for _, p := range cfg.resolved() {
		// An explicit value is the one worth spotting: it is what the user
		// changed, and the reason the run may behave unlike the default.
		origin := s.dim(p.origin)
		value := p.value
		if p.origin == "[explicit]" {
			origin = s.amber("[explicit]")
			value = s.bold(value)
		}
		if p.value == "unlimited" || p.value == "off" {
			value = s.red(p.value)
		}
		fmt.Fprintf(w, "  %s  %s %s\n",
			s.pad(s.cyan(p.name), 12), s.pad(value, 14), origin)
	}
}

// printStats reports what the run did. It is called even when extraction
// aborts: the numbers at the point of failure are exactly what someone
// debugging a limit needs to see.
func printStats(w io.Writer, res *extractor.Result, usage resourceUsage) {
	if res == nil {
		return
	}
	secs := res.Duration.Seconds()
	st := newStyler(w)

	// row keeps label/value alignment in one place so a styled value never
	// throws the column off — escape codes are zero-width.
	row := func(label, value string) {
		fmt.Fprintf(w, "  %s  %s\n", st.pad(st.dim(label), 12), value)
	}
	na := func(why string) string { return st.dim("n/a " + why) }

	fmt.Fprintf(w, "\n%s\n", st.bold("statistics"))
	row("files", fmt.Sprintf("%d", res.Files))
	row("directories", fmt.Sprintf("%d", res.Directories))
	if res.Symlinks > 0 {
		row("symlinks", fmt.Sprintf("%d", res.Symlinks))
	}
	row("written", humanBytes(int64(res.Bytes)))
	row("elapsed", res.Duration.Round(time.Millisecond).String())

	// MB here is 10^6, the conventional unit for a throughput rate.
	if secs > 0 {
		row("throughput", fmt.Sprintf("%.1f MB/s", float64(res.Bytes)/1e6/secs))
	} else {
		row("throughput", na("(run too short to measure)"))
	}

	if usage.PeakRSSOK {
		row("peak memory", humanBytes(int64(usage.PeakRSSBytes)))
	} else {
		row("peak memory", na("(not available on this platform)"))
	}

	// getrusage yields CUMULATIVE cpu time, so only an average over the run can
	// be derived. A true peak would need sampling on a ticker; do not label
	// this figure as a maximum.
	if usage.CPUTimeOK {
		row("cpu time", usage.CPUTime.Round(time.Millisecond).String())
		if secs > 0 {
			row("avg cpu", fmt.Sprintf("%.1f%% %s",
				usage.CPUTime.Seconds()/secs*100, st.dim("of one core")))
		}
	} else {
		row("cpu time", na("(not available on this platform)"))
	}

	for _, warn := range res.Warnings {
		fmt.Fprintf(w, "  %s %s\n", st.amber("warning:"), warn)
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
