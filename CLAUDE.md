# secure-unzip


## System & Project Overview:

Develop a cross-platform command-line utility in Go named secure-unzip under the MIT License. The tool acts as a security-hardened drop-in alternative for standard unzip, designed to safely extract archives while mitigating risks such as Zip Slip, Zip Bombs, file permission exploits, and system resource exhaustion.

### 1. Command-Line Interface (CLI) & Syntax

* Compatibility: Mimic the core syntax and flags of standard unzip (e.g., secure-unzip [options] archive.zip [-d extract_dir]).
* Resource Constraint Flags:
    * -max-size <bytes>: Absolute limit on total uncompressed output size (default: the size that was returned by ).
    * -max-files <count>: Limit on the maximum number of extracted files/directories to prevent inode exhaustion (default: 10,000).
    * -cpu-limit <percent>: Throttle extraction execution to stay under a specific CPU usage threshold.
    * -max-mode <octal>: Set a permission ceiling mask for extracted files (e.g., 0644).
    * -read-only: Post-extraction flag to enforce read-only permissions on all extracted files after writing.

### 2. Security & Hardening Features
* Zip Slip Prevention: Validate every canonical target path before writing. Abort if any file attempts directory traversal outside the specified destination directory.
* Zip Bomb & Memory Defense: Monitor uncompressed output streams in real-time. Abort immediately if -max-size or compressed-to-uncompressed expansion ratio limits are breached.
* Permission Masking & Locking:
    * Strip dangerous permissions (e.g., 777 or unwanted executable bits) based on -max-mode.
    * If -read-only is active, write the file data first, then explicitly remove write permissions (0444 or 0400).
* Resource Throttling: Implement rate limiting/pausing to observe CPU usage thresholds during extraction.

### 3. Security Testing Suite (docs/benchmark/security_report.md)
   Create a Go test suite (_test.go) and fixture generator to validate security mechanics:
* Malicious Fixture Generator: Build scripts to generate test archives containing:
    * A Zip Slip payload (../../etc/passwd).
    * A Zip Bomb payload (highly compressed zero-filled files).
    * An Inode Exhaustion payload (thousands of tiny empty files).
    * An Overly Permissive File payload (0777 permissions).
* Security Validation Engine:
    * Run tests comparing secure-unzip against standard system unzip.
    * Assert that secure-unzip successfully catches, safely aborts, or modifies the payload (e.g., stopping at 1,000 files), while standard unzip demonstrates unsafe behavior.
* Output: Format the security test outcomes, pass/fail statuses, and behavior comparisons, writing the final report to docs/benchmark/security_report.md.

### 4.Benchmarking via Existing Frameworks (docs/benchmark/performance_report.md)
 
Provide an external benchmark script (Bash or PHP) that leverages hyperfine and GNU /usr/bin/time to perform statistical performance execution side-by-side with standard unzip:

* Framing & Execution:
    * Use hyperfine --warmup 3 --export-markdown ... to capture execution duration, mean timing, standard deviation, and comparative speed ratios across multiple iterations.
    * Use /usr/bin/time -v (or process profiling) to capture Peak Resident Set Size (Max RSS memory) and CPU usage percentage.
* Output: Combine the exported hyperfine markdown results and resource metrics into a structured summary report saved directly to docs/benchmark/performance_report.md.

### 5. Code Structure & License

* Include an MIT License file in the root directory.
* Provide clean, modular Go code (main.go, extractor/, security/, testutils/).
* Ensure all error messages clearly describe which security constraint was triggered.

## Agent documentation

`docs/agents/` is an OKF v0.1 knowledge base written for coding agents — one level deeper than this
file, with exact values, exact paths, and the reasoning behind non-obvious choices. Start at
`docs/agents/index.md`. As of 2026-08-06 the repo has no source code, so these docs record the
*specified* design and flag open questions; re-verify each doc as code lands.

* `docs/agents/architecture/index.md` — the planned package layout (`main.go`, `extractor/`,
  `security/`, `testutils/`) and their boundary rules, the ordered per-entry extraction pipeline,
  and the threat model mapping each attack class to the control that stops it.
* `docs/agents/cli/index.md` — every flag with its default and what it constrains, plus the open
  questions blocking implementation (the truncated `-max-size` default in §1, `-max-mode` default,
  `-cpu-limit` units, exit codes).
* `docs/agents/testing/index.md` — the malicious fixtures and what each must prove against system
  `unzip`, and the hyperfine + `/usr/bin/time` benchmark harness including the macOS BSD-time caveat.
* `docs/agents/decisions/index.md` — decision records covering Go and single-binary distribution,
  MIT licensing, the unzip-compatible CLI surface, fail-closed aborts, write-then-lock read-only
  ordering, and using hyperfine over Go benchmarks.
