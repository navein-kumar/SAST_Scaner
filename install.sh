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
# Prerequisites are checked (and, where possible, auto-installed) before any
# download runs. Opt out of auto-install with SKIP_DEP_INSTALL=1 (you'll get the
# exact manual install commands instead).
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="$HERE/bundle"
BIN="$BUNDLE/bin"
TRIVY_CACHE="$BUNDLE/trivy-cache"
TMP="$BUNDLE/tmp"          # download scratch dir (kept inside the bundle so it is
                          # always writable; avoids /tmp noexec/full/permission
                          # issues that cause curl "failure writing to output").

mkdir -p "$BIN" "$TRIVY_CACHE" "$TMP"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ===========================================================================
# Prerequisites: downloader, package manager, and preflight auto-install.
# ===========================================================================

# ---- downloader (curl preferred, wget fallback) ---------------------------
DL=""
detect_downloader() {
  if   command -v curl >/dev/null 2>&1; then DL="curl"
  elif command -v wget >/dev/null 2>&1; then DL="wget"
  else DL=""; fi
}

fetch() {  # fetch <url> <outfile>   (creates parent dirs, retries on flaky net)
  local url="$1" out="$2"
  mkdir -p "$(dirname "$out")"
  case "$DL" in
    curl) curl -fsSL --retry 3 --retry-delay 2 --create-dirs -o "$out" "$url" ;;
    wget) wget -q --tries=3 -O "$out" "$url" ;;
    *)    die "no downloader available (need curl or wget)" ;;
  esac
}

fetch_stdout() {  # fetch <url> -> stdout
  local url="$1"
  case "$DL" in
    curl) curl -fsSL --retry 3 --retry-delay 2 "$url" ;;
    wget) wget -q --tries=3 -O- "$url" ;;
    *)    die "no downloader available (need curl or wget)" ;;
  esac
}

# ---- package manager detection --------------------------------------------
PKG=""; PKG_INSTALL=""; SUDO=""
detect_pkg_mgr() {
  if   command -v apt-get >/dev/null 2>&1; then PKG="apt";    PKG_INSTALL="apt-get install -y"
  elif command -v dnf     >/dev/null 2>&1; then PKG="dnf";    PKG_INSTALL="dnf install -y"
  elif command -v yum     >/dev/null 2>&1; then PKG="yum";    PKG_INSTALL="yum install -y"
  elif command -v zypper  >/dev/null 2>&1; then PKG="zypper"; PKG_INSTALL="zypper install -y"
  elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"; PKG_INSTALL="pacman -S --noconfirm"
  elif command -v apk     >/dev/null 2>&1; then PKG="apk";    PKG_INSTALL="apk add"
  elif command -v brew    >/dev/null 2>&1; then PKG="brew";   PKG_INSTALL="brew install"
  fi
  # need root for system package installs; use sudo if we are not root
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
}

# ---- map a generic dependency name to this distro's package name ----------
sys_pkg() {  # sys_pkg <generic> -> distro package name(s)
  case "$1" in
    curl)  echo curl ;;
    tar)   echo tar ;;
    git)   echo git ;;
    unzip) echo unzip ;;
    python3)
      case "$PKG" in
        apt)            echo "python3" ;;
        pacman)         echo "python" ;;
        brew)           echo "python" ;;
        *)              echo "python3" ;;
      esac ;;
    venv)  # python venv + pip
      case "$PKG" in
        apt)            echo "python3-venv python3-pip" ;;
        dnf|yum|zypper) echo "python3-pip" ;;
        pacman)         echo "python-pip" ;;
        apk)            echo "python3 py3-pip" ;;
        brew)           echo "python" ;;
        *)              echo "python3-venv python3-pip" ;;
      esac ;;
    java)  # JRE 17 (Dependency-Check needs Java 11+; 17 is the safe choice)
      case "$PKG" in
        apt)            echo "openjdk-17-jre-headless" ;;
        dnf|yum)        echo "java-17-openjdk-headless" ;;
        zypper)         echo "java-17-openjdk-headless" ;;
        pacman)         echo "jre17-openjdk-headless" ;;
        apk)            echo "openjdk17-jre-headless" ;;
        brew)           echo "openjdk@17" ;;
        *)              echo "openjdk-17-jre" ;;
      esac ;;
  esac
}

install_pkgs() {  # install_pkgs <distro pkg names...>   -> 0 on success
  [ $# -eq 0 ] && return 0
  if [ -z "$PKG_INSTALL" ]; then return 1; fi
  if [ -n "$SUDO" ]; then log "Installing (sudo): $*"; else log "Installing: $*"; fi
  [ "$PKG" = "apt" ] && { $SUDO apt-get update -y >/dev/null 2>&1 || true; }
  # shellcheck disable=SC2086
  $SUDO $PKG_INSTALL "$@"
}

# major Java version, or 0 if java is missing/unparseable (handles "17.0.1" and "1.8.0")
java_major() {
  command -v java >/dev/null 2>&1 || { echo 0; return; }
  local v
  v="$(java -version 2>&1 | head -1 | sed -E 's/.*version "([0-9]+)(\.([0-9]+))?.*/\1 \3/')"
  set -- $v
  if [ "${1:-0}" = "1" ]; then echo "${2:-0}"; else echo "${1:-0}"; fi
}

# Print the manual install command for a set of generic deps, then die.
die_with_hint() {  # die_with_hint <generic deps...>
  local pkgs=() g
  for g in "$@"; do pkgs+=( $(sys_pkg "$g") ); done
  warn "Missing prerequisites: $*"
  if [ -n "$PKG_INSTALL" ]; then
    die "Install them, then re-run ./install.sh :
      ${SUDO:+sudo }$PKG_INSTALL ${pkgs[*]}"
  fi
  die "Could not detect a package manager. Install these manually, then re-run:  $*"
}

preflight() {  # preflight <requested tool list...>
  log "Checking prerequisites ..."
  detect_downloader
  detect_pkg_mgr

  # figure out which optional deps the requested tools actually need
  local need_git=0 need_venv=0 need_unzip=0 need_java=0 t
  for t in "$@"; do
    case "$t" in
      semgrep)  need_git=1; need_venv=1 ;;
      opengrep) need_git=1 ;;
      depcheck) need_unzip=1; need_java=1 ;;
    esac
  done

  # ---- writability of the output destination ------------------------------
  if ! ( : > "$TMP/.wtest" ) 2>/dev/null; then
    die "Cannot write to bundle dir: $TMP  (check permissions / disk space)"
  fi
  rm -f "$TMP/.wtest"

  # ---- gather missing HARD deps (block the whole install) -----------------
  local missing=()
  [ -z "$DL" ] && missing+=("curl")                                  # curl OR wget
  command -v tar     >/dev/null 2>&1 || missing+=("tar")
  command -v python3 >/dev/null 2>&1 || missing+=("python3")
  [ "$need_git"   -eq 1 ] && ! command -v git   >/dev/null 2>&1 && missing+=("git")
  [ "$need_unzip" -eq 1 ] && ! command -v unzip >/dev/null 2>&1 && missing+=("unzip")
  # python venv + pip (the classic "pip/venv not found" on fresh Debian/Ubuntu).
  # NB: `venv --help` can succeed while pip is still unavailable, so we also
  # require the ensurepip module that bootstraps pip inside the venv.
  if [ "$need_venv" -eq 1 ] && command -v python3 >/dev/null 2>&1; then
    if ! python3 -m venv --help >/dev/null 2>&1 || ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
      missing+=("venv")
    fi
  fi

  if [ ${#missing[@]} -gt 0 ]; then
    if [ -n "${SKIP_DEP_INSTALL:-}" ]; then
      die_with_hint "${missing[@]}"
    fi
    warn "Missing prerequisites: ${missing[*]} — attempting auto-install ..."
    local pkgs=() g
    for g in "${missing[@]}"; do pkgs+=( $(sys_pkg "$g") ); done
    if ! install_pkgs "${pkgs[@]}"; then
      die_with_hint "${missing[@]}"
    fi
    # re-detect after install and re-verify
    detect_downloader
    local still=()
    [ -z "$DL" ] && still+=("curl")
    command -v tar     >/dev/null 2>&1 || still+=("tar")
    command -v python3 >/dev/null 2>&1 || still+=("python3")
    [ "$need_git"   -eq 1 ] && ! command -v git   >/dev/null 2>&1 && still+=("git")
    [ "$need_unzip" -eq 1 ] && ! command -v unzip >/dev/null 2>&1 && still+=("unzip")
    [ "$need_venv"  -eq 1 ] && command -v python3 >/dev/null 2>&1 && \
      { python3 -m venv --help >/dev/null 2>&1 && python3 -c 'import ensurepip' >/dev/null 2>&1 || still+=("venv"); }
    [ ${#still[@]} -gt 0 ] && die_with_hint "${still[@]}"
    ok "prerequisites installed"
  fi

  # ---- python version sanity (Semgrep needs 3.8+) -------------------------
  if [ "$need_venv" -eq 1 ] && command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null \
      || warn "python3 is older than 3.8 ($(python3 -V 2>&1)); Semgrep install may fail."
  fi

  # ---- Java is SOFT: only depcheck needs it; never blocks the rest --------
  if [ "$need_java" -eq 1 ]; then
    local jv; jv="$(java_major)"
    if [ "$jv" -lt 11 ]; then
      if command -v java >/dev/null 2>&1; then
        warn "Java $jv found but Dependency-Check needs 11+ (17 recommended)."
      else
        warn "Java (JRE 17+) not found — needed by OWASP Dependency-Check."
      fi
      if [ -z "${SKIP_DEP_INSTALL:-}" ]; then
        # shellcheck disable=SC2046
        install_pkgs $(sys_pkg java) || true
        jv="$(java_major)"
      fi
      if [ "$jv" -lt 11 ]; then
        warn "No usable Java — Dependency-Check will be skipped (everything else still runs)."
        warn "To enable it later:  ${SUDO:+sudo }${PKG_INSTALL:-<pkg-mgr> install} $(sys_pkg java)"
      else
        ok "java: $(java -version 2>&1 | head -1)"
      fi
    else
      ok "java: $(java -version 2>&1 | head -1)"
    fi
  fi

  ok "downloader: ${DL:-none}    package manager: ${PKG:-none}${SUDO:+ (sudo)}"
}

# ---- arch ------------------------------------------------------------------
RAW_ARCH="$(uname -m)"
case "$RAW_ARCH" in
  x86_64|amd64)  TRIVY_ARCH="64bit"; GL_ARCH="x64";   OG_ARCH="manylinux_x86";    CODEQL_OK=1 ;;
  aarch64|arm64) TRIVY_ARCH="ARM64"; GL_ARCH="arm64"; OG_ARCH="manylinux_aarch64"; CODEQL_OK=1 ;;
  *) die "unsupported architecture: $RAW_ARCH" ;;
esac
log "arch=$RAW_ARCH"

# ---- requested tools + preflight (must run before any download) -----------
TOOLS=("$@")
[ ${#TOOLS[@]} -eq 0 ] && TOOLS=(semgrep opengrep codeql trivy depcheck gitleaks)
preflight "${TOOLS[@]}"
echo

gh_latest() {  # $1 = owner/repo  -> latest tag
  fetch_stdout "https://api.github.com/repos/$1/releases/latest" \
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
  fetch "https://github.com/opengrep/opengrep/releases/download/${tag}/${asset}" \
    "$BIN/opengrep"
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
  fetch "$url" "$TMP/codeql-bundle.tar.gz"
  rm -rf "$BUNDLE/codeql"
  tar -xzf "$TMP/codeql-bundle.tar.gz" -C "$BUNDLE"   # extracts to $BUNDLE/codeql
  rm -f "$TMP/codeql-bundle.tar.gz"                   # reclaim the ~hundreds of MB
  ln -sf "$BUNDLE/codeql/codeql" "$BIN/codeql"
  ok "codeql: $("$BIN/codeql" version --format=terse 2>/dev/null)"
}

# ===========================================================================
install_trivy() {
  log "Trivy ..."
  local tag ver tgz
  tag="$(gh_latest aquasecurity/trivy)"; ver="${tag#v}"
  tgz="trivy_${ver}_Linux-${TRIVY_ARCH}.tar.gz"
  fetch "https://github.com/aquasecurity/trivy/releases/download/${tag}/${tgz}" \
    "$TMP/$tgz"
  tar -xzf "$TMP/$tgz" -C "$BIN" trivy && chmod +x "$BIN/trivy"
  rm -f "$TMP/$tgz"
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
  fetch "https://github.com/gitleaks/gitleaks/releases/download/${tag}/${tgz}" \
    "$TMP/$tgz"
  tar -xzf "$TMP/$tgz" -C "$BIN" gitleaks && chmod +x "$BIN/gitleaks"
  rm -f "$TMP/$tgz"
  ok "gitleaks: $("$BIN/gitleaks" version 2>/dev/null)"
}

# ===========================================================================
install_depcheck() {
  log "OWASP Dependency-Check ..."
  if [ "$(java_major)" -lt 11 ]; then
    warn "Java 11+ (JRE 17 recommended) not available - skipping Dependency-Check."
    warn "Enable it with:  ${SUDO:+sudo }${PKG_INSTALL:-<pkg-mgr> install} $(sys_pkg java)   then re-run ./install.sh depcheck"
    return
  fi
  local tag ver zip
  tag="$(gh_latest jeremylong/DependencyCheck)"; ver="${tag#v}"
  zip="dependency-check-${ver}-release.zip"
  fetch "https://github.com/jeremylong/DependencyCheck/releases/download/${tag}/${zip}" \
    "$TMP/$zip"
  rm -rf "$BUNDLE/dependency-check"
  ( cd "$BUNDLE" && unzip -q "$TMP/$zip" )    # -> $BUNDLE/dependency-check
  rm -f "$TMP/$zip"
  chmod +x "$BUNDLE/dependency-check/bin/dependency-check.sh"
  ok "dependency-check: installed"

  log "Downloading NVD data (the slow part; an NVD API key speeds it up a LOT) ..."

  # Resolve the NVD API key: env var wins, else read the saved key file.
  local nvd_key="${NVD_API_KEY:-}"
  if [ -z "$nvd_key" ] && [ -f "$HERE/.nvd_api_key" ]; then
    nvd_key="$(tr -d '[:space:]' < "$HERE/.nvd_api_key")"
    [ -n "$nvd_key" ] && log "Using saved NVD API key from .nvd_api_key"
  fi

  local dc="$BUNDLE/dependency-check/bin/dependency-check.sh"
  local data="$BUNDLE/dependency-check/data"

  if [ -n "$nvd_key" ]; then
    if "$dc" --updateonly --data "$data" --nvdApiKey "$nvd_key"; then
      ok "NVD data downloaded (with API key)"
      return
    fi
    warn "NVD update with API key failed (bad/expired key or rate-limited). Falling back to keyless mode ..."
  fi

  # Fallback: keyless default mode (slow, but works without a key).
  "$dc" --updateonly --data "$data" \
    && ok "NVD data downloaded (keyless mode)" \
    || warn "NVD update incomplete (rate-limited?). Re-run ./install.sh depcheck to resume."
}

# ===========================================================================
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
