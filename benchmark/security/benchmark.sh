#!/usr/bin/env bash
#
# Security harness for secure-unzip.
# Implements docs/agents/testing/security-test-suite.md.
#
# Runs every archive in benchmark/security/examples/ through BOTH secure-unzip
# and the system unzip, and asserts the *difference*: ours defuses the payload
# while the standard tool does not. A check that only looked at secure-unzip
# would not prove anything was gained (CLAUDE.md §3).
#
# Results are written to docs/benchmark/security_report.md.
#
# Usage:
#   benchmark/security/benchmark.sh [-b BINARY] [-e EXAMPLES_DIR] [-o REPORT] [-k]
#     -k  keep the scratch directory for inspection
#
set -uo pipefail   # NOT -e: a fixture that aborts the extractor is the expected
                   # result here, so non-zero exits are data, not failures.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BINARY="$REPO_ROOT/bin/secure-unzip"
EXAMPLES="$REPO_ROOT/benchmark/security/examples"
REPORT="$REPO_ROOT/docs/benchmark/security_report.md"
KEEP=0

while getopts "b:e:o:kh" opt; do
  case "$opt" in
    b) BINARY=$OPTARG ;;
    e) EXAMPLES=$OPTARG ;;
    o) REPORT=$OPTARG ;;
    k) KEEP=1 ;;
    h) sed -n '2,18p' "$0"; exit 0 ;;
    *) exit 2 ;;
  esac
done

die()  { printf 'security: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*" >&2; }

# ------------------------------------------------------------------ preflight

command -v unzip >/dev/null || die "system unzip not found — nothing to compare against"
[ -x "$BINARY" ] || die "$BINARY not built — run 'make build-host' first"

if [ ! -d "$EXAMPLES" ] || ! compgen -G "$EXAMPLES/*.zip" >/dev/null; then
  GENERATOR="$REPO_ROOT/benchmark/security/generate_examples.py"
  command -v python3 >/dev/null || die "no archives in $EXAMPLES and python3 is unavailable to generate them"
  [ -f "$GENERATOR" ] || die "no archives in $EXAMPLES and $GENERATOR is missing"
  note "no archives in $EXAMPLES — generating"
  python3 "$GENERATOR" >&2 || die "fixture generation failed"
fi

WORK=$(mktemp -d)
if [ "$KEEP" = 1 ]; then
  trap 'printf "scratch kept at %s\n" "$WORK" >&2' EXIT
else
  trap 'rm -rf "$WORK"' EXIT
fi

# The slip and symlink fixtures aim at /tmp/secure-unzip-pwned*. Anything the
# extractors put there is proof of an escape, so the canary is checked and
# cleared around every single run — a leftover from an earlier fixture would
# otherwise be misread as a later one escaping.
CANARY_GLOB='/tmp/secure-unzip-pwned*'

canary_hits() { compgen -G "$CANARY_GLOB" 2>/dev/null | tr '\n' ' '; }
canary_clear() { rm -rf $CANARY_GLOB 2>/dev/null || true; }

canary_clear

# ------------------------------------------------------------------ expectations
#
# Per fixture: the extra flags needed to exercise the control, what
# secure-unzip must do, and a one-line description of the attack.
#
#   abort:<constraint>  exit 3 AND the message names that constraint
#   refuse              any non-zero exit with a message, nothing written
#   clean               exit 0 (the payload is defused, not rejected)
#   graceful            may succeed or fail, but must not crash or escape

expectation() {
  case "$1" in
    benign-control)             FLAGS=""                  EXPECT="clean"              ATTACK="none — ordinary archive (control)" ;;
    bomb-ratio-1000x)           FLAGS=""                  EXPECT="abort:max-ratio"    ATTACK="~1 KiB compressed expands to 1 MiB" ;;
    liar-declared-1kb-real-1mb) FLAGS=""                  EXPECT="refuse"             ATTACK="headers declare 1 KiB, stream yields 1 MiB" ;;
    bomb-nested-3-levels)       FLAGS=""                  EXPECT="clean"              ATTACK="zip inside zip inside zip" ;;
    slip-relative-traversal)    FLAGS=""                  EXPECT="abort:zip-slip"     ATTACK="entry named ../../../tmp/…" ;;
    slip-absolute-path)         FLAGS=""                  EXPECT="abort:zip-slip"     ATTACK="entry named /tmp/…" ;;
    slip-symlink-escape)        FLAGS=""                  EXPECT="abort:symlink-escape" ATTACK="symlink out of the destination, then a write through it" ;;
    inodes-1000-files)          FLAGS="--max-files 100"   EXPECT="abort:max-files"    ATTACK="1000 tiny files (inode exhaustion)" ;;
    perms-0777-setuid)          FLAGS="--max-mode 0644"   EXPECT="clean"              ATTACK="entries stored 0777 and setuid 4755" ;;
    deep-directory-nesting)     FLAGS=""                  EXPECT="graceful"           ATTACK="file 256 directories deep" ;;
    names-control-chars)        FLAGS=""                  EXPECT="graceful"           ATTACK="names with newline, backslash, tabs, -rf" ;;
    duplicate-entries)          FLAGS=""                  EXPECT="graceful"           ATTACK="same filename stored twice" ;;
    *)                          FLAGS=""                  EXPECT="graceful"           ATTACK="(no expectation recorded)" ;;
  esac
}

# ------------------------------------------------------------------ post-checks
#
# Fixtures whose payload is defused rather than rejected need the OUTPUT
# inspected: "exit 0" alone would pass even if the dangerous bits survived.

post_check() { # $1=fixture $2=outdir -> echoes a verdict fragment, or nothing
  case "$1" in
    perms-0777-setuid)
      local bad=0 detail=""
      while IFS= read -r f; do
        local mode; mode=$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null)
        # Anything group/other-writable, or any setuid/setgid bit, is a failure.
        case "$mode" in
          *[2367]) bad=1; detail="$detail $(basename "$f")=$mode" ;;
        esac
        [ "${#mode}" -gt 3 ] && { bad=1; detail="$detail $(basename "$f")=$mode"; }
      done < <(find "$2" -type f 2>/dev/null)
      [ "$bad" = 1 ] && echo "permissions still unsafe:$detail"
      ;;
    bomb-nested-3-levels)
      # Must not recurse: exactly one entry, still a .zip, left on disk.
      local n; n=$(find "$2" -type f 2>/dev/null | wc -l | tr -d ' ')
      [ "$n" -gt 1 ] && echo "recursed into nested archives ($n files)"
      ;;
  esac
}

# ------------------------------------------------------------------ run helpers

# run_tool <cmdline> <root> <dest> -> sets RC, OUT, ESCAPED
#
# Escapes are detected two ways, and both are needed:
#   1. The /tmp canary, for a payload that reached an absolute path.
#   2. Any file under the fixture's own tree but OUTSIDE its destination —
#      which is what a ../../../ payload produces once the destination is
#      nested inside a scratch root. Watching only the canary would miss it
#      entirely and report a containment breach as a clean run.
run_tool() {
  local cmd=$1 root=$2 dest=$3
  rm -rf "$root"; mkdir -p "$dest"
  canary_clear
  OUT=$(eval "$cmd" 2>&1); RC=$?

  local strays canary
  strays=$(find "$root" -type l -o -type f 2>/dev/null | grep -v "^$dest/" | tr '\n' ' ')
  canary=$(canary_hits)
  canary_clear

  ESCAPED=""
  [ -n "$strays" ] && ESCAPED="${strays# }"
  [ -n "$canary" ] && ESCAPED="$ESCAPED $canary"
  # Report paths relative to the scratch root; absolute temp paths are noise.
  ESCAPED=$(printf '%s' "$ESCAPED" | sed "s|$root/||g" | sed 's/^ *//;s/ *$//')
}

# classify secure-unzip's behaviour against its expectation
verdict_secure() { # $1=expect $2=rc $3=out $4=escaped $5=postfail
  local expect=$1 rc=$2 out=$3 escaped=$4 postfail=$5

  [ -n "$escaped" ] && { echo "FAIL|escaped the destination: $escaped"; return; }
  [ -n "$postfail" ] && { echo "FAIL|$postfail"; return; }

  case "$expect" in
    abort:*)
      local want=${expect#abort:}
      if [ "$rc" != 3 ]; then
        echo "FAIL|expected exit 3 (security abort), got $rc"
      elif ! printf '%s' "$out" | grep -q -- "$want"; then
        echo "FAIL|aborted but did not name the '$want' constraint"
      else
        echo "PASS|aborted, named \`$want\`"
      fi
      ;;
    refuse)
      if [ "$rc" = 0 ]; then echo "FAIL|extracted a malformed archive instead of refusing"
      else echo "PASS|refused (exit $rc)"; fi
      ;;
    clean)
      if [ "$rc" = 0 ]; then echo "PASS|extracted safely (exit 0)"
      else echo "FAIL|expected a clean extraction, got exit $rc"; fi
      ;;
    graceful)
      # Signals show as 128+n. A crash is never an acceptable answer to a
      # hostile archive, even when the archive is refused.
      if [ "$rc" -ge 128 ]; then echo "FAIL|crashed (exit $rc)"
      elif [ "$rc" = 0 ]; then echo "PASS|handled it (exit 0)"
      else echo "PASS|rejected cleanly (exit $rc)"; fi
      ;;
  esac
}

# describe what the system unzip did, and whether it was unsafe
verdict_unzip() { # $1=rc $2=outdir $3=escaped
  local rc=$1 out=$2 escaped=$3
  if [ -n "$escaped" ]; then
    echo "UNSAFE|wrote outside the destination: $escaped"
    return
  fi
  local files bytes worst=""
  files=$(find "$out" -type f 2>/dev/null | wc -l | tr -d ' ')
  bytes=$(find "$out" -type f -exec cat {} + 2>/dev/null | wc -c | tr -d ' ')
  while IFS= read -r f; do
    local mode; mode=$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null)
    case "$mode" in *[2367]) worst="$mode" ;; esac
    [ "${#mode}" -gt 3 ] && worst="$mode"
  done < <(find "$out" -type f 2>/dev/null)

  if [ -n "$worst" ]; then
    echo "UNSAFE|preserved mode $worst"
  else
    echo "ok|extracted $files files, $bytes bytes (exit $rc)"
  fi
}

# ------------------------------------------------------------------ main loop

printf 'security-testing %s vs system unzip\n' "$BINARY" >&2

ROWS=()
PASS=0; FAIL=0; UNSAFE_BASELINE=0

for zip in "$EXAMPLES"/*.zip; do
  name=$(basename "$zip" .zip)
  expectation "$name"
  note "$name"

  # A destination nested this deep means ../../../tmp payloads land inside the
  # scratch tree rather than on the real /tmp, while still being a genuine
  # escape from the extractor's point of view.
  s_root="$WORK/secure/$name"; s_out="$s_root/a/b/c/dest"
  u_root="$WORK/unzip/$name";  u_out="$u_root/a/b/c/dest"

  run_tool "'$BINARY' -q $FLAGS -d '$s_out' '$zip'" "$s_root" "$s_out"
  s_rc=$RC; s_out_txt=$OUT; s_escaped=$ESCAPED
  s_post=$(post_check "$name" "$s_out")

  IFS='|' read -r s_status s_detail <<<"$(verdict_secure "$EXPECT" "$s_rc" "$s_out_txt" "$s_escaped" "$s_post")"

  run_tool "unzip -qq -o '$zip' -d '$u_out'" "$u_root" "$u_out"
  u_rc=$RC; u_escaped=$ESCAPED
  IFS='|' read -r u_status u_detail <<<"$(verdict_unzip "$u_rc" "$u_out" "$u_escaped")"

  case "$s_status" in
    PASS) PASS=$((PASS+1)) ;;
    FAIL) FAIL=$((FAIL+1)); note "  FAIL: $s_detail" ;;
  esac
  [ "$u_status" = UNSAFE ] && UNSAFE_BASELINE=$((UNSAFE_BASELINE+1))

  u_cell="$u_detail"
  [ "$u_status" = UNSAFE ] && u_cell="**UNSAFE** — $u_detail"

  status_cell="PASS"
  [ "$s_status" = FAIL ] && status_cell="**FAIL**"

  ROWS+=("| \`$name\` | $ATTACK | $s_detail | $u_cell | $status_cell |")
done

canary_clear
TOTAL=$((PASS+FAIL))

# ------------------------------------------------------------------ report

UNZIP_VER=$(unzip -v 2>/dev/null | head -1 || echo unknown)
SECURE_VER=$("$BINARY" --version 2>/dev/null | head -1 || echo unknown)

{
  echo "# Security Report"
  echo
  echo "Generated by \`benchmark/security/benchmark.sh\` on $(date -u '+%Y-%m-%dT%H:%M:%SZ'). Do not edit by hand."
  echo
  echo "| | |"
  echo "| --- | --- |"
  echo "| host | $(uname -srm) |"
  echo "| secure-unzip | $SECURE_VER |"
  echo "| system unzip | $UNZIP_VER |"
  echo "| result | **$PASS/$TOTAL** fixtures defused |"
  echo "| baseline | system unzip behaved unsafely on **$UNSAFE_BASELINE** of them |"
  echo
  echo "Each archive is run through both extractors into a throwaway directory."
  echo "The point is the *difference*: secure-unzip must defuse the payload where the"
  echo "standard tool does not. A row where both behave safely proves nothing was lost,"
  echo "not that nothing was gained."
  echo
  echo "| Fixture | Attack | secure-unzip | system unzip | Result |"
  echo "| :--- | :--- | :--- | :--- | :--- |"
  printf '%s\n' "${ROWS[@]}"
  echo
  echo "## Notes"
  echo
  echo "- Fixtures are generated by \`python3 benchmark/security/generate_examples.py\`"
  echo "  (\`make fixtures\`) and are gitignored; the manifest in"
  echo "  \`benchmark/security/examples/README.md\` is tracked."
  echo "- Destinations are nested \`a/b/c/dest\` inside a scratch directory, so a"
  echo "  \`../../../tmp\` payload is a real escape from the extractor's point of view"
  echo "  without touching the real \`/tmp\`. The \`$CANARY_GLOB\` canary is checked and"
  echo "  cleared around every individual run."
  echo "- Every abort must name the constraint that fired; the assertions match on the"
  echo "  constraint name, not on the exit code alone."
  echo "- The Go suite (\`go test ./...\`) covers the same controls as unit and"
  echo "  end-to-end tests and is the CI gate. This harness is the wider,"
  echo "  differential corpus and is run on demand via \`make security\`."
} > "$REPORT"

printf 'wrote %s (%d/%d passed)\n' "$REPORT" "$PASS" "$TOTAL" >&2
[ "$FAIL" -eq 0 ] || exit 1
