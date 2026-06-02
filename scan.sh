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
OPENGREP="$BIN/opengrep"
CODEQL="$BIN/codeql"
TRIVY="$BIN/trivy"
GITLEAKS="$BIN/gitleaks"
DEPCHECK="$BUNDLE/dependency-check/bin/dependency-check.sh"
RULES_REPO="$BUNDLE/semgrep-rules"

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
# 1. SAST -- Semgrep OSS
# ===========================================================================
if [ -x "$SEMGREP" ]; then
  log "[SAST] semgrep ..."
  SEMGREP_SEND_METRICS=off "$SEMGREP" scan \
    "${RULE_ARGS[@]}" --metrics=off --no-git-ignore --json --quiet \
    --output "$OUT/semgrep.json" "$TARGET" || warn "semgrep non-zero"
  ok "-> semgrep.json"
else skip "semgrep"; echo '{"results":[]}' > "$OUT/semgrep.json"; fi

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
# 3. SAST -- CodeQL (per-language DB, build-mode none = no compiler needed)
# ===========================================================================
if [ -x "$CODEQL" ]; then
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
  : > "$OUT/codeql.sarif"
  if [ -z "$langs" ]; then
    warn "codeql: no supported language detected, skipping"
    echo '{"runs":[]}' > "$OUT/codeql.sarif"
  else
    log "[SAST] codeql (langs: $langs) ..."
    merged_sarif="$OUT/codeql.sarif"; first=1; sariflist=()
    # C# / Java extraction is memory-hungry; on small boxes it aborts with
    # "exited abnormally (code 134) ... (core dumped)" = OOM. Let the user cap
    # CodeQL's RAM and threads. Fewer threads also lowers peak memory.
    #   CODEQL_RAM=4096 CODEQL_THREADS=2 ./scan.sh ...
    CQ_RAM_ARG=(); [ -n "${CODEQL_RAM:-}" ] && CQ_RAM_ARG=(--ram="$CODEQL_RAM")
    CQ_THREADS="${CODEQL_THREADS:-0}"
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
  if ! command -v java >/dev/null 2>&1; then
    # Dependency-Check is a Java app; without a JRE it can't run. Skip cleanly
    # so the rest of the scan + merge still completes.
    warn "[SCA] dependency-check skipped: Java (JRE 11+) not found on this machine"
    echo '{"dependencies":[]}' > "$OUT/depcheck.json"
  else
    log "[SCA] OWASP dependency-check (offline) ..."
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
  --target   "$TARGET" \
  --out-json "$OUT/combined.json" \
  --out-csv  "$OUT/summary.csv" \
  --out-txt  "$OUT/summary.txt"

python3 "$HERE/lib/html_report.py" \
  --in "$OUT/combined.json" --out "$OUT/report.html" --target "$TARGET"

echo
cat "$OUT/summary.txt"
echo
ok "Reports in: $OUT"
