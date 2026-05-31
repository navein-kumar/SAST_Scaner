#!/usr/bin/env bash
#
# install.sh  --  ONE-TIME ONLINE SETUP for the offline SAST/SCA/secrets scanner.
#
# Run ONCE while the machine has internet. Downloads every tool, ruleset, and
# vulnerability database into ./bundle so scan.sh can later run network-disabled.
#
#   SAST    : Semgrep OSS + rules, Opengrep + rules, CodeQL CLI bundle
#   SCA     : Trivy (+ offline DBs), OWASP Dependency-Check (+ NVD data)
#   SECRETS : Gitleaks   (Trivy also does secrets)
#
# Usage:
#   ./install.sh                 # install everything (default)
#   ./install.sh semgrep trivy   # install only the named tools
#
# Tool names: semgrep opengrep codeql trivy depcheck gitleaks
#
# Optional env:
#   NVD_API_KEY=xxxx   speeds up OWASP Dependency-Check NVD download a LOT
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="$HERE/bundle"
BIN="$BUNDLE/bin"
TRIVY_CACHE="$BUNDLE/trivy-cache"

mkdir -p "$BIN" "$TRIVY_CACHE"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- arch ------------------------------------------------------------------
RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64|amd64)  TRIVY_ARCH="64bit"; GL_ARCH="x64";   OG_ARCH="manylinux_x86";    CODEQL_OK=1 ;;
  aarch64|arm64) TRIVY_ARCH="ARM64"; GL_ARCH="arm64"; OG_ARCH="manylinux_aarch64"; CODEQL_OK=1 ;;
  *) die "unsupported architecture: $RAW_ARCH" ;;
esac
log "arch=$RAW_ARCH"

gh_latest() {  # $1 = owner/repo  -> latest tag
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

# ===========================================================================
install_semgrep() {
  log "Semgrep OSS (venv) ..."
  if [ ! -x "$BUNDLE/semgrep-venv/bin/semgrep" ]; then
    python3 -m venv "$BUNDLE/semgrep-venv"
    "$BUNDLE/semgrep-venv/bin/pip" install --quiet --upgrade pip
    "$BUNDLE/semgrep-venv/bin/pip" install --quiet semgrep
  fi
  ok "semgrep: $("$BUNDLE/semgrep-venv/bin/semgrep" --version 2>/dev/null)"
  _clone_rules
}

_clone_rules() {
  log "Semgrep/Opengrep community rules ..."
  if [ -d "$BUNDLE/semgrep-rules/.git" ]; then
    git -C "$BUNDLE/semgrep-rules" pull --ff-only --quiet || warn "rules pull skipped"
  else
    git clone --depth 1 https://github.com/semgrep/semgrep-rules "$BUNDLE/semgrep-rules"
  fi
  ok "rules: $(find "$BUNDLE/semgrep-rules" -name '*.y*ml' | wc -l) files"
}

# ===========================================================================
install_opengrep() {
  log "Opengrep ..."
  local tag asset
  tag="$(gh_latest opengrep/opengrep)"
  asset="opengrep_${OG_ARCH}"
  curl -fsSL -o "$BIN/opengrep" \
    "https://github.com/opengrep/opengrep/releases/download/${tag}/${asset}"
  chmod +x "$BIN/opengrep"
  ok "opengrep: $("$BIN/opengrep" --version 2>/dev/null | head -1)"
  [ -d "$BUNDLE/semgrep-rules/.git" ] || _clone_rules
}

# ===========================================================================
install_codeql() {
  log "CodeQL CLI bundle (includes extractors + standard query packs) ..."
  # The *bundle* asset ships the CLI plus precompiled query packs => fully offline.
  local tag url
  tag="$(gh_latest github/codeql-action)"
  url="https://github.com/github/codeql-action/releases/download/${tag}/codeql-bundle-linux64.tar.gz"
  curl -fsSL -o /tmp/codeql-bundle.tar.gz "$url"
  rm -rf "$BUNDLE/codeql"
  tar -xzf /tmp/codeql-bundle.tar.gz -C "$BUNDLE"   # extracts to $BUNDLE/codeql
  ln -sf "$BUNDLE/codeql/codeql" "$BIN/codeql"
  ok "codeql: $("$BIN/codeql" version --format=terse 2>/dev/null)"
}

# ===========================================================================
install_trivy() {
  log "Trivy ..."
  local tag ver tgz
  tag="$(gh_latest aquasecurity/trivy)"; ver="${tag#v}"
  tgz="trivy_${ver}_Linux-${TRIVY_ARCH}.tar.gz"
  curl -fsSL -o "/tmp/$tgz" \
    "https://github.com/aquasecurity/trivy/releases/download/${tag}/${tgz}"
  tar -xzf "/tmp/$tgz" -C "$BIN" trivy && chmod +x "$BIN/trivy"
  ok "trivy: $("$BIN/trivy" --version 2>/dev/null | head -1)"
  log "Trivy offline DBs ..."
  "$BIN/trivy" --cache-dir "$TRIVY_CACHE" fs --download-db-only
  "$BIN/trivy" --cache-dir "$TRIVY_CACHE" fs --download-java-db-only || warn "java-db skipped"
  # Pre-cache the misconfig policy bundle so offline runs don't fall back to
  # embedded checks (which logs a noisy ERROR). One online misconfig scan pulls it.
  local tmpd; tmpd="$(mktemp -d)"; printf 'FROM alpine\n' > "$tmpd/Dockerfile"
  "$BIN/trivy" --cache-dir "$TRIVY_CACHE" fs --scanners misconfig --quiet "$tmpd" >/dev/null 2>&1 || true
  rm -rf "$tmpd"
  ok "trivy DBs + policy checks cached"
}

# ===========================================================================
install_gitleaks() {
  log "Gitleaks ..."
  local tag ver tgz
  tag="$(gh_latest gitleaks/gitleaks)"; ver="${tag#v}"
  tgz="gitleaks_${ver}_linux_${GL_ARCH}.tar.gz"
  curl -fsSL -o "/tmp/$tgz" \
    "https://github.com/gitleaks/gitleaks/releases/download/${tag}/${tgz}"
  tar -xzf "/tmp/$tgz" -C "$BIN" gitleaks && chmod +x "$BIN/gitleaks"
  ok "gitleaks: $("$BIN/gitleaks" version 2>/dev/null)"
}

# ===========================================================================
install_depcheck() {
  log "OWASP Dependency-Check ..."
  command -v java >/dev/null || { warn "Java not found - Dependency-Check needs JRE 11+. Skipping."; return; }
  local tag ver zip
  tag="$(gh_latest jeremylong/DependencyCheck)"; ver="${tag#v}"
  zip="dependency-check-${ver}-release.zip"
  curl -fsSL -o "/tmp/$zip" \
    "https://github.com/jeremylong/DependencyCheck/releases/download/${tag}/${zip}"
  rm -rf "$BUNDLE/dependency-check"
  ( cd "$BUNDLE" && unzip -q "/tmp/$zip" )    # -> $BUNDLE/dependency-check
  chmod +x "$BUNDLE/dependency-check/bin/dependency-check.sh"
  ok "dependency-check: installed"

  log "Downloading NVD data (the slow part; use NVD_API_KEY to speed up) ..."
  local key_args=()
  [ -n "${NVD_API_KEY:-}" ] && key_args=(--nvdApiKey "$NVD_API_KEY")
  "$BUNDLE/dependency-check/bin/dependency-check.sh" \
      --updateonly --data "$BUNDLE/dependency-check/data" "${key_args[@]}" \
    && ok "NVD data downloaded" \
    || warn "NVD update incomplete (rate-limited?). Re-run install with NVD_API_KEY."
}

# ===========================================================================
TOOLS=("$@")
[ ${#TOOLS[@]} -eq 0 ] && TOOLS=(semgrep opengrep codeql trivy depcheck gitleaks)

for t in "${TOOLS[@]}"; do
  case "$t" in
    semgrep)  install_semgrep ;;
    opengrep) install_opengrep ;;
    codeql)   install_codeql ;;
    trivy)    install_trivy ;;
    depcheck) install_depcheck ;;
    gitleaks) install_gitleaks ;;
    *) warn "unknown tool: $t" ;;
  esac
  echo
done

ok "Bundle ready in $BUNDLE"
echo "Disconnect network, then run:   ./scan.sh /path/to/source"
