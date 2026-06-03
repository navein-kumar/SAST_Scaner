#!/usr/bin/env bash
#
# scan.sh  --  FULLY OFFLINE SAST + SCA + secrets scan of a local source folder.
#
# Prereq: run ./install.sh once (with internet). This script makes NO network calls.
#
# Usage:
#   ./scan.sh <TARGET_DIR> [OUTPUT_DIR]
#   CODEQL_LANGS=csharp,java ./scan.sh <TARGET_DIR>     # override autodetect
#
# Per-tool raw outputs (kept separate, as requested):
#   semgrep.json  opengrep.json  codeql.sarif  trivy.json  depcheck.json  gitleaks.json
# Merged, report-ready:
#   combined.json  summary.csv  summary.txt
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="$HERE/bundle"
BIN="$BUNDLE/bin"
TRIVY_CACHE="$BUNDLE/trivy-cache"
SEMGREP="$BUNDLE/semgrep-venv/bin/semgrep"
# The bin/semgrep wrapper hard-codes the build-time install path in its shebang line,
# so it breaks the moment the bundle is unzipped to a different path on the air-gapped
# box. We instead run the wrapper SCRIPT through the venv's python explicitly
# ("python /path/bin/semgrep ..."), which ignores the stale shebang and is fully
# relocatable, while still using semgrep's supported entrypoint (the `-m semgrep`
# module form is deprecated and exits non-zero in this version).
SEMGREP_PY="$BUNDLE/semgrep-venv/bin/python3"
OPENGREP="$BIN/opengrep"
# Point at the real CodeQL binary, NOT bundle/bin/codeql -- that is an absolute
# symlink created at build time, so it dangles once the bundle is unzipped to a
# different path and CodeQL would be silently "skipped".
CODEQL="$BUNDLE/codeql/codeql"
[ -x "$CODEQL" ] || CODEQL="$BIN/codeql"   # fallback for older bundles
TRIVY="$BIN/trivy"
GITLEAKS="$BIN/gitleaks"
DEPCHECK="$BUNDLE/dependency-check/bin/dependency-check.sh"
RULES_REPO="$BUNDLE/semgrep-rules"
# Extra engines, bundled self-contained. Their findings are merged under the
# existing tool names (flawfinder->semgrep, cppcheck->opengrep, trufflehog->gitleaks)
# so no new tool name appears in the report. All run with NO network.
CPPCHECK="$BUNDLE/cppcheck/cppcheck"
CPPCHECK_LIB="$BUNDLE/cppcheck/lib"
DEVSKIM="$BUNDLE/devskim/devskim"   # Microsoft DevSkim (multi-lang, strong C#); runs on bundled dotnet
TRUFFLEHOG="$BIN/trufflehog"

# Build one --config per top-level rule directory. Pointing semgrep/opengrep at
# the repo ROOT fails: it tries to parse non-rule files (.pre-commit-config.yaml,
# template.yaml, stats/, scripts/, libsonnet/) and aborts the whole scan.
RULE_ARGS=()
build_rule_args() {
  local n
  for d in "$RULES_REPO"/*/; do
    n="$(basename "$d")"
    [[ " scripts stats libsonnet " == *" $n "* ]] && continue
    RULE_ARGS+=(--config "$d")
  done
}
[ -d "$RULES_REPO" ] && build_rule_args

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
skip() { printf '\033[1;90m[-]\033[0m %s (not installed, skipped)\n' "$*"; }

TARGET="${1:-}"
[ -n "$TARGET" ] || die "usage: ./scan.sh <TARGET_DIR> [OUTPUT_DIR]"
[ -d "$TARGET" ] || die "target dir not found: $TARGET"
TARGET="$(cd "$TARGET" && pwd)"

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${2:-$HERE/reports/$TS}"
mkdir -p "$OUT" || die "cannot create output dir: $OUT (check permissions / disk space)"

# Runtime prerequisites for the scanning machine (may differ from the install box).
# python3 is required for the merge + HTML report (stdlib only). Fail fast here
# instead of after every scanner has run.
command -v python3 >/dev/null 2>&1 \
  || die "python3 not found — required for the merge/report step. Install it (e.g. sudo apt-get install -y python3) and re-run."
# Verify the output destination is actually writable before doing any work.
if ! ( : > "$OUT/.wtest" ) 2>/dev/null; then
  die "output dir not writable: $OUT (check permissions / disk space)"
fi
rm -f "$OUT/.wtest"

log "Target : $TARGET"
log "Output : $OUT"
echo

# ===========================================================================
# Self-heal the Semgrep venv after relocation.
# The venv console scripts (semgrep, pysemgrep, ...) hard-code the build-time
# python path in their shebang. Once the bundle is unzipped to a different path
# on the air-gapped box, `semgrep` aborts with
#   Error: exception ... execvp pysemgrep
# and SILENTLY contributes ZERO findings -- which roughly HALVES the total
# (only Opengrep's SAST findings remain). Rewrite the shebangs to the python
# that actually exists here so Semgrep runs and the offline count matches the
# online install. Idempotent; skips symlinks and non-python files.
heal_semgrep_venv() {
  local b="$BUNDLE/semgrep-venv/bin" f first n=0
  [ -d "$b" ] || return 0
  for f in "$b"/*; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    IFS= read -r first < "$f" 2>/dev/null || continue
    case "$first" in
      "#!"*python*)
        [ "$first" = "#!$b/python3" ] && continue
        sed -i "1s|^#!.*|#!$b/python3|" "$f" 2>/dev/null && n=$((n+1)) ;;
    esac
  done
  [ "$n" -gt 0 ] && log "semgrep venv relocated to this path ($n script shebangs fixed)"
  return 0
}
heal_semgrep_venv

# ===========================================================================
# 1. SAST -- Semgrep OSS
# ===========================================================================
if [ -x "$SEMGREP_PY" ] && [ -f "$SEMGREP" ] && "$SEMGREP_PY" -c 'import semgrep' >/dev/null 2>&1; then
  log "[SAST] semgrep ..."
  SEMGREP_SEND_METRICS=off "$SEMGREP_PY" "$SEMGREP" scan \
    "${RULE_ARGS[@]}" --metrics=off --no-git-ignore --json --quiet \
    --output "$OUT/semgrep.json" "$TARGET" || warn "semgrep non-zero"
  [ -f "$OUT/semgrep.json" ] || echo '{"results":[]}' > "$OUT/semgrep.json"
  ok "-> semgrep.json"
else skip "semgrep (venv python missing or incompatible)"; echo '{"results":[]}' > "$OUT/semgrep.json"; fi

# ===========================================================================
# 2. SAST -- Opengrep (Semgrep fork; same rule format & JSON schema)
# ===========================================================================
if [ -x "$OPENGREP" ]; then
  log "[SAST] opengrep ..."
  "$OPENGREP" scan \
    "${RULE_ARGS[@]}" --no-git-ignore --json --quiet \
    --output "$OUT/opengrep.json" "$TARGET" || warn "opengrep non-zero"
  ok "-> opengrep.json"
else skip "opengrep"; echo '{"results":[]}' > "$OUT/opengrep.json"; fi

# ===========================================================================
# 2b. SAST (C/C++) -- flawfinder + cppcheck.
# Semgrep/Opengrep rules are thin for C/C++. These two source-level analyzers
# (no compiler/build needed, fully offline) add real C/C++ coverage. Their raw
# outputs are kept separate; the merger folds them under semgrep (flawfinder)
# and opengrep (cppcheck) so no new tool name appears.
# ===========================================================================
: > "$OUT/flawfinder.csv"; : > "$OUT/cppcheck.xml"
_has_cpp() { [ -n "$(find "$TARGET" -type f \( -iname '*.c' -o -iname '*.cc' -o -iname '*.cpp' -o -iname '*.cxx' -o -iname '*.h' -o -iname '*.hpp' -o -iname '*.hxx' \) -print -quit 2>/dev/null)" ]; }
if _has_cpp; then
  if [ -x "$SEMGREP_PY" ] && "$SEMGREP_PY" -c 'import flawfinder' >/dev/null 2>&1; then
    log "[SAST] flawfinder (C/C++) ..."
    # --minlevel=0 includes the lowest (INFO) level too, so nothing is hidden.
    "$SEMGREP_PY" -m flawfinder --csv --minlevel=0 "$TARGET" > "$OUT/flawfinder.csv" 2>/dev/null \
      || warn "flawfinder non-zero"
    ok "-> flawfinder.csv"
  fi
  if [ -x "$CPPCHECK" ]; then
    log "[SAST] cppcheck (C/C++) ..."
    LD_LIBRARY_PATH="$CPPCHECK_LIB" "$CPPCHECK" \
      --enable=warning,style,performance,portability --library=std \
      -j "$(nproc 2>/dev/null || echo 2)" \
      --quiet --inline-suppr --xml --xml-version=2 "$TARGET" 2>"$OUT/cppcheck.xml" \
      || warn "cppcheck non-zero"
    ok "-> cppcheck.xml"
  fi
else
  log "[SAST] flawfinder/cppcheck skipped (no C/C++ files)"
fi

# ===========================================================================
# 2c. SAST (multi-language, strong C#) -- Microsoft DevSkim. Merged under semgrep.
# Runs on the bundled .NET runtime; fully offline (rules are embedded).
# ===========================================================================
: > "$OUT/devskim.sarif"
if [ -x "$DEVSKIM" ] && [ -x "$BUNDLE/dotnet/dotnet" ]; then
  log "[SAST] devskim (C#/C++/multi) ..."
  DOTNET_ROOT="$BUNDLE/dotnet" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    "$DEVSKIM" analyze -I "$TARGET" -O "$OUT/devskim.sarif" -f sarif \
    >/dev/null 2>"$OUT/devskim.err" || warn "devskim non-zero (see devskim.err)"
  [ -s "$OUT/devskim.sarif" ] || echo '{"runs":[]}' > "$OUT/devskim.sarif"
  ok "-> devskim.sarif"
else skip "devskim"; echo '{"runs":[]}' > "$OUT/devskim.sarif"; fi

# ===========================================================================
# 3. SAST -- CodeQL (per-language DB, build-mode none = no compiler needed)
# ===========================================================================
if [ -x "$CODEQL" ]; then
  # CodeQL's C# extractor (even with build-mode=none) shells out to the `dotnet`
  # CLI to resolve NuGet/dependency info. If dotnet is ABSENT it does not degrade
  # gracefully -- it crashes with "Missing dotnet CLI" / "Aborted (core dumped)"
  # (exit 134). We ship a self-contained .NET SDK inside the bundle and put it on
  # PATH so C# extraction works with NO system dotnet and NO network.
  if [ -x "$BUNDLE/dotnet/dotnet" ]; then
    export DOTNET_ROOT="$BUNDLE/dotnet"
    export PATH="$BUNDLE/dotnet:$PATH"
    export DOTNET_CLI_TELEMETRY_OPTOUT=1
    export DOTNET_NOLOGO=1
    export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
    export DOTNET_CLI_HOME="$BUNDLE/dotnet/.home"
    mkdir -p "$BUNDLE/dotnet/.home" 2>/dev/null || true
    # Keep the buildless extractor from reaching nuget.org for restore; offline it
    # just uses whatever is present and continues (no hang, no crash).
    export CODEQL_EXTRACTOR_CSHARP_BUILDLESS_DEPENDENCY_FETCHING="${CODEQL_EXTRACTOR_CSHARP_BUILDLESS_DEPENDENCY_FETCHING:-false}"
  fi
  # autodetect languages from file extensions unless overridden
  if [ -n "${CODEQL_LANGS:-}" ]; then
    langs="$CODEQL_LANGS"
  else
    langs=""
    # pipe-free detection: find ... -print -quit stops at first match (no SIGPIPE
    # race with `grep -q`, which under `set -o pipefail` silently dropped languages)
    has_ext() { [ -n "$(find "$TARGET" -type f \( "$@" \) -print -quit 2>/dev/null)" ]; }
    has_ext -iname '*.cs'                                          && langs="$langs,csharp"
    has_ext -iname '*.java'                                        && langs="$langs,java"
    has_ext -iname '*.js' -o -iname '*.ts' -o -iname '*.jsx' -o -iname '*.tsx' && langs="$langs,javascript"
    has_ext -iname '*.py'                                          && langs="$langs,python"
    has_ext -iname '*.go'                                          && langs="$langs,go"
    has_ext -iname '*.c' -o -iname '*.cc' -o -iname '*.cpp' -o -iname '*.h' -o -iname '*.hpp' && langs="$langs,cpp"
    has_ext -iname '*.rb'                                          && langs="$langs,ruby"
    langs="${langs#,}"
  fi
  # CodeQL C/C++ cannot use build-mode=none: it requires a real compile with the
  # full toolchain + all headers, which is not possible on an air-gapped box. Drop
  # cpp from the CodeQL set (Semgrep/Opengrep already scan C/C++ source directly).
  # Force an attempt anyway with: CODEQL_ALLOW_CPP=1 ./scan.sh ...
  if [ -z "${CODEQL_ALLOW_CPP:-}" ] && printf '%s' ",$langs," | grep -qi ',cpp,'; then
    warn "codeql: skipping C/C++ (build-mode=none unsupported offline; covered by Semgrep/Opengrep)"
    langs="$(printf '%s' "$langs" | tr ',' '\n' | grep -viw 'cpp' | paste -sd, - | sed 's/^,//;s/,$//')"
  fi
  : > "$OUT/codeql.sarif"
  if [ -z "$langs" ]; then
    warn "codeql: no supported language detected, skipping"
    echo '{"runs":[]}' > "$OUT/codeql.sarif"
  else
    log "[SAST] codeql (langs: $langs) ..."
    merged_sarif="$OUT/codeql.sarif"; first=1; sariflist=()
    # ---- Auto-adaptive resource limits (sized to THIS machine, not static) --
    # CodeQL C#/Java extraction is memory-hungry; an unbounded run on a small box
    # aborts with exit 134 (core dumped) = OOM. Auto-size --ram and --threads to
    # the host so it adapts whether the box has 4 cores/16GB or 32 cores/128GB:
    #   ram cap = 75% of physical RAM (headroom for the OS + the dotnet extractor)
    #   threads = cores - 1 (minimum 1; fewer threads also lowers peak memory)
    # Override either explicitly if you must: CODEQL_RAM=<MB> CODEQL_THREADS=<n>.
    _total_ram_mb=0
    [ -r /proc/meminfo ] && _total_ram_mb=$(awk '/^MemTotal:/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
    [ -z "$_total_ram_mb" ] && _total_ram_mb=0
    _cores=$(nproc 2>/dev/null || echo 2)
    if [ -n "${CODEQL_RAM:-}" ]; then
      _cq_ram="$CODEQL_RAM"
    elif [ "$_total_ram_mb" -gt 0 ]; then
      _cq_ram=$(( _total_ram_mb * 75 / 100 ))
      [ "$_cq_ram" -lt 1024 ] && _cq_ram="$_total_ram_mb"   # very small box: use what we have
    else
      _cq_ram=""                                            # cannot detect: let CodeQL decide
    fi
    if [ -n "${CODEQL_THREADS:-}" ]; then
      _cq_threads="$CODEQL_THREADS"
    elif [ "$_cores" -gt 1 ]; then
      _cq_threads=$(( _cores - 1 ))
    else
      _cq_threads=1
    fi
    CQ_RAM_ARG=(); [ -n "$_cq_ram" ] && CQ_RAM_ARG=(--ram="$_cq_ram")
    CQ_THREADS="$_cq_threads"
    log "  codeql auto-config: threads=$CQ_THREADS ram=${_cq_ram:-auto}MB (host: ${_cores} cores / ${_total_ram_mb}MB RAM)"
    IFS=',' read -ra LARR <<< "$langs"
    for lang in "${LARR[@]}"; do
      [ -z "$lang" ] && continue
      db="$OUT/codeql-db-$lang"
      rm -rf "$db"
      log "  creating db for $lang (build-mode none) ..."
      if "$CODEQL" database create "$db" --language="$lang" --build-mode=none \
            --threads="$CQ_THREADS" "${CQ_RAM_ARG[@]}" \
            --source-root="$TARGET" --overwrite >/dev/null 2>"$OUT/codeql-$lang.err"; then
        log "  analyzing $lang ..."
        # Resolve the query suite to its LOCAL file inside the CodeQL bundle.
        # Passing a bare suite name lets CodeQL fetch packs from ghcr.io; using
        # the on-disk .qls + a local --search-path keeps analyze fully offline.
        suite="$(find "$BUNDLE/codeql/qlpacks" -path "*${lang}-queries*/codeql-suites/${lang}-security-and-quality.qls" 2>/dev/null | sort | tail -1)"
        [ -z "$suite" ] && suite="${lang}-security-and-quality.qls"   # fallback to name
        "$CODEQL" database analyze "$db" \
          --format=sarif-latest --output="$OUT/codeql-$lang.sarif" \
          --search-path "$BUNDLE/codeql/qlpacks" \
          --threads="$CQ_THREADS" "${CQ_RAM_ARG[@]}" "$suite" \
          >/dev/null 2>>"$OUT/codeql-$lang.err" \
          && sariflist+=("$OUT/codeql-$lang.sarif") \
          || warn "  codeql analyze failed for $lang (see codeql-$lang.err)"
      else
        # Surface the common OOM case with an actionable hint.
        if grep -q 'code 134\|core dumped\|OutOfMemory' "$OUT/codeql-$lang.err" 2>/dev/null; then
          warn "  codeql db create CRASHED for $lang (likely out of memory)."
          warn "    Retry with limits, e.g.:  CODEQL_RAM=4096 CODEQL_THREADS=2 ./scan.sh \"$TARGET\""
          warn "    Or skip this language:    CODEQL_LANGS=\"\$(echo $langs | sed 's/$lang,\\?//;s/,\\$//')\" ./scan.sh \"$TARGET\""
        else
          warn "  codeql db create failed for $lang (see codeql-$lang.err)"
        fi
      fi
    done
    # keep first sarif as the canonical codeql.sarif; merger reads codeql-*.sarif glob too
    if [ ${#sariflist[@]} -gt 0 ]; then
      cp "${sariflist[0]}" "$OUT/codeql.sarif"
      ok "-> codeql-*.sarif (${#sariflist[@]} language(s))"
    else
      echo '{"runs":[]}' > "$OUT/codeql.sarif"
    fi
  fi
else skip "codeql"; echo '{"runs":[]}' > "$OUT/codeql.sarif"; fi

# ===========================================================================
# 4. SCA + secrets + IaC misconfig -- Trivy (offline)
# ===========================================================================
if [ -x "$TRIVY" ]; then
  log "[SCA] trivy fs (offline) ..."
  "$TRIVY" --cache-dir "$TRIVY_CACHE" fs \
    --scanners vuln,secret,misconfig \
    --offline-scan --skip-db-update --skip-java-db-update --skip-check-update \
    --format json --output "$OUT/trivy.json" "$TARGET" || warn "trivy non-zero"
  ok "-> trivy.json"
else skip "trivy"; echo '{"Results":[]}' > "$OUT/trivy.json"; fi

# ===========================================================================
# 5. SCA -- OWASP Dependency-Check (offline, --noupdate)
# ===========================================================================
if [ -x "$DEPCHECK" ] && [ -z "${SKIP_DEPCHECK:-}" ]; then
  # Prefer the bundled JRE 17 so Dependency-Check (needs Java 11+) works even when
  # the client box has old Java (e.g. Java 8) or none at all -- nothing to install.
  if [ -x "$BUNDLE/jre/bin/java" ]; then
    export JAVA_HOME="$BUNDLE/jre"
    export PATH="$BUNDLE/jre/bin:$PATH"
  fi
  if ! command -v java >/dev/null 2>&1; then
    # Dependency-Check is a Java app; without a JRE it can't run. Skip cleanly
    # so the rest of the scan + merge still completes.
    warn "[SCA] dependency-check skipped: Java (JRE 11+) not found on this machine"
    echo '{"dependencies":[]}' > "$OUT/depcheck.json"
  else
    log "[SCA] OWASP dependency-check (offline, $(java -version 2>&1 | head -1)) ..."
    # Disable every analyzer that phones home, or an air-gapped run errors with
    # "Connect to https://ossindex.sonatype.org:443 ... failed" (OSS Index),
    # plus Maven Central and the Node Audit service. CVE matching still works
    # offline from the cached NVD data downloaded by install.sh.
    "$DEPCHECK" --scan "$TARGET" --noupdate \
      --disableOssIndex --disableCentral --disableNodeAudit \
      --data "$BUNDLE/dependency-check/data" \
      --format JSON --out "$OUT" --prettyPrint >/dev/null 2>"$OUT/depcheck.err" \
      || warn "dependency-check non-zero (see depcheck.err)"
    [ -f "$OUT/dependency-check-report.json" ] && mv "$OUT/dependency-check-report.json" "$OUT/depcheck.json"
    [ -f "$OUT/depcheck.json" ] || echo '{"dependencies":[]}' > "$OUT/depcheck.json"
    ok "-> depcheck.json"
  fi
else skip "dependency-check"; echo '{"dependencies":[]}' > "$OUT/depcheck.json"; fi

# ===========================================================================
# 6. Secrets -- Gitleaks (fully offline)
# ===========================================================================
if [ -x "$GITLEAKS" ]; then
  log "[SECRETS] gitleaks ..."
  if "$GITLEAKS" dir --help >/dev/null 2>&1; then
    "$GITLEAKS" dir "$TARGET" --report-format json --report-path "$OUT/gitleaks.json" \
      --no-banner --exit-code 0 || warn "gitleaks non-zero"
  else
    "$GITLEAKS" detect --source "$TARGET" --no-git \
      --report-format json --report-path "$OUT/gitleaks.json" \
      --no-banner --exit-code 0 || warn "gitleaks non-zero"
  fi
  [ -f "$OUT/gitleaks.json" ] || echo '[]' > "$OUT/gitleaks.json"
  ok "-> gitleaks.json"
else skip "gitleaks"; echo '[]' > "$OUT/gitleaks.json"; fi

# ===========================================================================
# 6b. Secrets -- trufflehog (offline, --no-verification). Merged under gitleaks.
# ===========================================================================
: > "$OUT/trufflehog.json"
if [ -x "$TRUFFLEHOG" ]; then
  log "[SECRETS] trufflehog ..."
  "$TRUFFLEHOG" filesystem --no-verification --json "$TARGET" > "$OUT/trufflehog.json" 2>/dev/null \
    || warn "trufflehog non-zero"
  ok "-> trufflehog.json"
else skip "trufflehog"; fi

# ===========================================================================
# Merge
# ===========================================================================
echo
log "Merging ..."
python3 "$HERE/lib/merge_report.py" \
  --semgrep  "$OUT/semgrep.json" \
  --opengrep "$OUT/opengrep.json" \
  --codeql-glob "$OUT/codeql-*.sarif" \
  --trivy    "$OUT/trivy.json" \
  --depcheck "$OUT/depcheck.json" \
  --gitleaks "$OUT/gitleaks.json" \
  --flawfinder "$OUT/flawfinder.csv" \
  --cppcheck   "$OUT/cppcheck.xml" \
  --devskim    "$OUT/devskim.sarif" \
  --trufflehog "$OUT/trufflehog.json" \
  --target   "$TARGET" \
  --out-json "$OUT/combined.json" \
  --out-csv  "$OUT/summary.csv" \
  --out-txt  "$OUT/summary.txt"

python3 "$HERE/lib/html_report.py" \
  --in "$OUT/combined.json" --out "$OUT/report.html" --target "$TARGET"

# v2 report (scan-statistics panel + per-application filter) is OPT-IN only, to
# avoid sending the client a second/different-looking report. Enable with:
#   REPORT_V2=1 ./scan.sh ...
# By default only the familiar v1 report.html is produced.
if [ -n "${REPORT_V2:-}" ] && [ -f "$HERE/lib/html_report_v2.py" ]; then
  python3 "$HERE/lib/html_report_v2.py" \
    --in "$OUT/combined.json" --out "$OUT/report_v2.html" --target "$TARGET" \
    || warn "v2 report generation failed (v1 report.html still produced)"
fi

echo
cat "$OUT/summary.txt"
echo
ok "Reports in: $OUT"
