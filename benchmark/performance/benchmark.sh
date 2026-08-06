#!/usr/bin/env bash
#
# Performance benchmark harness for secure-unzip.
# Implements docs/agents/testing/performance-benchmarking.md.
#
#   hyperfine --warmup 3 --export-markdown ...  -> duration, mean, stddev, speed ratio
#   GNU time -v / BSD time -l                   -> peak RSS, CPU percentage
#
# Both are run side-by-side against the system unzip, on every archive in
# benchmark/performance/examples/. Results are combined into
# docs/benchmark/performance_report.md.
#
# Usage:
#   benchmark/performance/benchmark.sh [-b BINARY] [-e EXAMPLES_DIR] [-o REPORT] [-w WARMUP] [-r RUNS]
#
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BINARY="$REPO_ROOT/bin/secure-unzip"
EXAMPLES="$REPO_ROOT/benchmark/performance/examples"
REPORT="$REPO_ROOT/docs/benchmark/performance_report.md"
WARMUP=3
RUNS=10

# secure-unzip runs with its hardening ON — measuring it with --secure=no would
# answer the wrong question. The single exception is -max-ratio: the benign
# compressible-text fixture is legitimately ~290:1 and would abort under the
# default ceiling of 100, so the ratio check is disabled and every other
# security default (path validation, max-size, max-files, mode masking) stands.
SECURE_FLAGS=${SECURE_FLAGS:--q -o -max-ratio 0}
UNZIP_FLAGS="-qq -o"

while getopts "b:e:o:w:r:h" opt; do
  case "$opt" in
    b) BINARY=$OPTARG ;;
    e) EXAMPLES=$OPTARG ;;
    o) REPORT=$OPTARG ;;
    w) WARMUP=$OPTARG ;;
    r) RUNS=$OPTARG ;;
    h) sed -n '2,16p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done

die() { printf 'benchmark: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*" >&2; }

# ------------------------------------------------------------------ preflight

command -v hyperfine >/dev/null || die "hyperfine not found (brew install hyperfine)"
command -v unzip >/dev/null || die "system unzip not found — nothing to compare against"
[ -x "$BINARY" ] || die "$BINARY not built — run 'make build-host' first"

# The archives are gitignored, so a fresh clone has none. Generate them rather
# than failing: a benchmark that refuses to run until you read its error message
# is a benchmark nobody runs.
if [ ! -d "$EXAMPLES" ] || ! compgen -G "$EXAMPLES/*.zip" >/dev/null; then
  GENERATOR="$REPO_ROOT/benchmark/performance/generate_examples.py"
  command -v python3 >/dev/null || die "no archives in $EXAMPLES and python3 is unavailable to generate them"
  [ -f "$GENERATOR" ] || die "no archives in $EXAMPLES and $GENERATOR is missing"
  note "no archives in $EXAMPLES — generating (this takes ~10s)"
  python3 "$GENERATOR" >&2 || die "fixture generation failed"
  compgen -G "$EXAMPLES/*.zip" >/dev/null || die "generator produced no archives in $EXAMPLES"
fi

# GNU time exposes -v (Max RSS + CPU %). macOS ships BSD time, which does not;
# fall back to BSD 'time -l' and derive CPU% from user+sys over wall. See the
# platform caveat in docs/agents/testing/performance-benchmarking.md.
TIME_KIND=none
if command -v gtime >/dev/null; then
  TIME_BIN=$(command -v gtime); TIME_KIND=gnu
elif /usr/bin/time -v true >/dev/null 2>&1; then
  TIME_BIN=/usr/bin/time; TIME_KIND=gnu
elif /usr/bin/time -l true >/dev/null 2>&1; then
  TIME_BIN=/usr/bin/time; TIME_KIND=bsd
  # NOTE: gtime comes from the 'gnu-time' formula, NOT 'coreutils' — coreutils
  # ships gdate/gtimeout but no time(1). BSD 'time -l' gives the same two
  # numbers (RSS in bytes, and CPU derived from user+sys over wall).
  note "GNU time absent; using BSD 'time -l' (brew install gnu-time for -v)"
else
  note "no usable time(1) — resource metrics will be omitted"
fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
OUTDIR="$WORK/out"
EXPORTS="$WORK/exports"; mkdir -p "$EXPORTS"
mkdir -p "$(dirname "$REPORT")"

HOST_OS=$(uname -srm)
HOST_CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null \
  || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' \
  || echo unknown)
UNZIP_VER=$(unzip -v 2>/dev/null | head -1 || echo unknown)
SECURE_VER=$("$BINARY" --version 2>/dev/null | head -1 || echo unknown)
STAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# ------------------------------------------------------------ resource metrics
# Runs one extraction under time(1) and echoes "<peak_rss_kib> <cpu_percent>".
# Both fields are "-" when unavailable, so the caller never has to branch.

measure() {
  local cmdline=$1 log="$WORK/time.log"
  [ "$TIME_KIND" = none ] && { echo "- -"; return; }

  rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
  if [ "$TIME_KIND" = gnu ]; then
    "$TIME_BIN" -v -o "$log" bash -c "$cmdline" >/dev/null 2>&1 || true
    local rss cpu
    rss=$(awk -F': *' '/Maximum resident set size/ {print $2}' "$log")
    cpu=$(awk -F': *' '/Percent of CPU this job got/ {gsub(/%/,"",$2); print $2}' "$log")
    echo "${rss:--} ${cpu:--}"
  else
    # BSD: 'time -l' prints "real user sys" then a resource block; RSS is bytes.
    { "$TIME_BIN" -l bash -c "$cmdline" >/dev/null; } 2>"$log" || true
    awk '
      /real[ \t]+[0-9]/ { real=$1; user=$3; sys=$5 }
      /maximum resident set size/ { rss=$1 }
      END {
        printf "%s %s\n",
          (rss  != "" ? int(rss/1024)              : "-"),
          (real+0 > 0 ? int((user+sys)/real*100)   : "-")
      }' "$log"
  fi
}

# ------------------------------------------------------------------- main loop

printf 'benchmarking %s vs system unzip\n' "$BINARY" >&2

ROWS_TIME=()
ROWS_RES=()

for zip in "$EXAMPLES"/*.zip; do
  name=$(basename "$zip" .zip)
  note "$name"

  secure_cmd="'$BINARY' $SECURE_FLAGS -d '$OUTDIR' '$zip'"
  unzip_cmd="unzip $UNZIP_FLAGS -d '$OUTDIR' '$zip'"
  export_md="$EXPORTS/$name.md"

  # Prove both commands actually succeed before timing them: hyperfine reports
  # a non-zero exit as a generic failure, which would otherwise look like a
  # harness problem rather than "the extractor refused this archive".
  skip=""
  for pair in "secure-unzip:$secure_cmd" "unzip:$unzip_cmd"; do
    label=${pair%%:*}; cmd=${pair#*:}
    rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
    if ! err=$(eval "$cmd" 2>&1 >/dev/null); then
      note "  $label failed: ${err:-exit $?}"
      skip=1
    fi
  done
  [ -n "$skip" ] && { note "  skipping $name"; continue; }

  # Both extractors must start from an empty destination on every run, so the
  # measurement is extraction cost and not overwrite-vs-create cost.
  # --time-unit pins the exported column to ms; without it hyperfine switches to
  # seconds for slower archives and the merged table would mix units silently.
  hyperfine \
    --warmup "$WARMUP" --runs "$RUNS" \
    --time-unit millisecond \
    --prepare "rm -rf '$OUTDIR'" \
    --command-name "secure-unzip ($name)" "$secure_cmd" \
    --command-name "unzip ($name)" "$unzip_cmd" \
    --export-markdown "$export_md" \
    --export-json "$EXPORTS/$name.json" \
    >/dev/null 2>&1 || { note "  hyperfine failed on $name — skipped"; continue; }

  # hyperfine's own markdown body: header rows dropped, data rows kept.
  while IFS= read -r line; do ROWS_TIME+=("$line"); done \
    < <(grep -E '^\| `' "$export_md" || true)

  read -r s_rss s_cpu <<<"$(measure "$secure_cmd")"
  read -r u_rss u_cpu <<<"$(measure "$unzip_cmd")"
  files=$(unzip -l "$zip" | awk 'END {print $2}')

  ROWS_RES+=("| \`$name\` | $files | $s_rss | $s_cpu | $u_rss | $u_cpu |")

  # The tool's own --verbose accounting, captured on the largest archive. Not a
  # benchmark result — it is a cross-check that the throughput and file counts
  # secure-unzip reports about itself agree with what hyperfine measured from
  # the outside. A wild disagreement means one of the two is lying.
  size=$(wc -c <"$zip")
  if [ "$size" -gt "${SELF_SIZE:-0}" ]; then
    SELF_SIZE=$size
    SELF_NAME=$name
    rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
    SELF_REPORT=$(eval "'$BINARY' $SECURE_FLAGS -verbose -d '$OUTDIR' '$zip'" 2>&1 >/dev/null || true)
  fi
done

rm -rf "$OUTDIR"
[ ${#ROWS_TIME[@]} -gt 0 ] || die "every archive failed — no report written"

# ---------------------------------------------------------------- report

case "$TIME_KIND" in
  gnu) time_note="GNU \`time -v\` (\`$TIME_BIN\`)" ;;
  bsd) time_note="BSD \`time -l\` — GNU \`time -v\` unavailable on this host; install \`gnu-time\` for parity" ;;
  *)   time_note="unavailable on this host — resource columns are empty" ;;
esac

{
  echo "# Performance Report"
  echo
  echo "Generated by \`benchmark/performance/benchmark.sh\` on $STAMP. Do not edit by hand."
  echo
  echo "| | |"
  echo "| --- | --- |"
  echo "| host | $HOST_OS |"
  echo "| cpu | $HOST_CPU |"
  echo "| secure-unzip | $SECURE_VER |"
  echo "| system unzip | $UNZIP_VER |"
  echo "| hyperfine | $(hyperfine --version) |"
  echo "| runs | $RUNS timed, $WARMUP warmup |"
  echo "| resource tool | $time_note |"
  echo
  echo "## Timing (hyperfine)"
  echo
  echo "Each archive extracts into a freshly emptied destination directory."
  echo "\`Relative\` compares the two commands within one archive only."
  echo
  echo "| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |"
  echo "| :--- | ---: | ---: | ---: | ---: |"
  printf '%s\n' "${ROWS_TIME[@]}"
  echo
  echo "## Resources (single unwarmed run)"
  echo
  echo "Peak RSS in KiB, CPU as percent of one core."
  echo
  echo "| Archive | Files | secure-unzip RSS | secure-unzip CPU% | unzip RSS | unzip CPU% |"
  echo "| :--- | ---: | ---: | ---: | ---: | ---: |"
  printf '%s\n' "${ROWS_RES[@]}"
  echo
  if [ -n "${SELF_REPORT:-}" ]; then
    echo "## secure-unzip self-report (\`--verbose\`)"
    echo
    echo "From a single unwarmed run on \`$SELF_NAME\`, the largest archive in the corpus."
    echo "Shown as a cross-check on the tables above, **not** as a benchmark result:"
    echo "if these counts and throughput disagree wildly with hyperfine, one of the two is wrong."
    echo
    echo '```'
    printf '%s\n' "$SELF_REPORT"
    echo '```'
    echo
  fi
  echo "## Notes"
  echo
  echo "- These are the authoritative numbers. The tool's own \`--verbose\` statistics are"
  echo "  single-run, self-reported and unwarmed — never quote them as benchmark results."
  echo "- Regenerate fixtures with \`python3 benchmark/performance/generate_examples.py\`"
  echo "  (\`SCALE=n\` for larger corpora); archive sizes and ratios are listed in"
  echo "  \`benchmark/performance/examples/README.md\`."
  echo "- Extract to a local SSD. A network mount or RAM disk measures the filesystem,"
  echo "  not the extractor."
} > "$REPORT"

printf 'wrote %s\n' "$REPORT" >&2
