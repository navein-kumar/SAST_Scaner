#!/usr/bin/env bash
#
# run.sh  --  one-command launcher for the FULLY OFFLINE SAST / SCA / secrets scan.
#
# The air-gapped box needs NO internet. Everything (tools, rules, CVE databases,
# CodeQL query packs, and the .NET SDK used by the C# extractor) is prebuilt
# inside ./bundle. Do NOT run install.sh here; that is only for rebuilding the
# bundle on a machine that has internet.
#
# Usage:
#   ./run.sh [TARGET_DIR]                 # default TARGET_DIR=/repos
#
# Examples:
#   ./run.sh /repos                       # scan every repo folder under /repos
#   ./run.sh /repos/1_web_app             # scan a single repo
#   CODEQL_RAM=4096 CODEQL_THREADS=2 ./run.sh /repos   # manually cap CodeQL
#   CODEQL_ALLOW_CPP=1 ./run.sh /repos    # force a CodeQL C/C++ attempt (needs toolchain)
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-/repos}"

echo "=============================================================="
echo "  Offline SAST Scanner"
echo "  Target : $TARGET"
echo "  Engines: semgrep opengrep codeql(C#) trivy dependency-check gitleaks"
echo "  Network: NOT required (fully air-gapped)"
echo "=============================================================="

[ -d "$HERE/bundle" ] || { echo "ERROR: bundle/ not found next to run.sh. Extract the FULL archive first."; exit 1; }
[ -x "$HERE/bundle/dotnet/dotnet" ] || echo "WARN: bundled dotnet missing; CodeQL C# may be limited."
[ -d "$TARGET" ] || { echo "ERROR: target dir not found: $TARGET"; exit 1; }

exec "$HERE/scan.sh" "$TARGET"
