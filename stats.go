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
	fmt.Fprintf(w, "secure-unzip %s\n", version)
	fmt.Fprintf(w, "  archive     %s\n", archive)
	fmt.Fprintf(w, "  destination %s\n", cfg.dest)
	fmt.Fprintf(w, "  --secure    %s\n", yesNo(cfg.secure))

	for _, p := range cfg.resolved() {
		fmt.Fprintf(w, "  %-11s %-14s %s\n", p.name, p.value, p.origin)
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

	fmt.Fprintf(w, "\nstatistics\n")
	fmt.Fprintf(w, "  files       %d\n", res.Files)
	fmt.Fprintf(w, "  directories %d\n", res.Directories)
	if res.Symlinks > 0 {
		fmt.Fprintf(w, "  symlinks    %d\n", res.Symlinks)
	}
	fmt.Fprintf(w, "  written     %s\n", humanBytes(int64(res.Bytes)))
	fmt.Fprintf(w, "  elapsed     %s\n", res.Duration.Round(time.Millisecond))

	// MB here is 10^6, the conventional unit for a throughput rate.
	if secs > 0 {
		fmt.Fprintf(w, "  throughput  %.1f MB/s\n", float64(res.Bytes)/1e6/secs)
	} else {
		fmt.Fprintf(w, "  throughput  n/a (run too short to measure)\n")
	}

	if usage.PeakRSSOK {
		fmt.Fprintf(w, "  peak memory %s\n", humanBytes(int64(usage.PeakRSSBytes)))
	} else {
		fmt.Fprintf(w, "  peak memory n/a (not available on this platform)\n")
	}

	// getrusage yields CUMULATIVE cpu time, so only an average over the run can
	// be derived. A true peak would need sampling on a ticker; do not label
	// this figure as a maximum.
	if usage.CPUTimeOK {
		fmt.Fprintf(w, "  cpu time    %s\n", usage.CPUTime.Round(time.Millisecond))
		if secs > 0 {
			fmt.Fprintf(w, "  avg cpu     %.1f%% (of one core)\n",
				usage.CPUTime.Seconds()/secs*100)
		}
	} else {
		fmt.Fprintf(w, "  cpu time    n/a (not available on this platform)\n")
	}

	for _, warn := range res.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", warn)
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
