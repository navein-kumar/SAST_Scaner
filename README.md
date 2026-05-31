# SAST Scanner

SAST + SCA + secrets scanner for a local source folder, built to run with **no
network access**.

Install once **with** internet; after that every scan runs **network-disabled** —
built for air-gapped / internet-restricted environments where the Semgrep cloud
(and similar SaaS) can't be used.

## Engines

| Stage | Tools |
|-------|-------|
| **SAST** (code analysis) | Semgrep OSS · Opengrep · CodeQL |
| **SCA** (dependency CVEs) | Trivy · OWASP Dependency-Check |
| **Secrets** | Gitleaks (Trivy also scans secrets) |
| **IaC misconfig** | Trivy |

All six run; results are kept **both** as raw per-tool files **and** merged into a
single normalized report. Duplicates across tools are intentional — validate/filter
them yourself.

## Setup (once, online)

```bash
./install.sh                 # install everything (default)
./install.sh semgrep trivy   # or only named tools
```

Downloads every tool, ruleset, and vulnerability DB into `./bundle/` (multi-GB,
git-ignored, regenerable). Tool names: `semgrep opengrep codeql trivy depcheck gitleaks`.

Optional: `NVD_API_KEY=xxxx ./install.sh` — greatly speeds up Dependency-Check's
NVD data download.

## Scan — one command

```bash
./scan.sh /path/to/source
```

That's it. **No other steps.** One run does scan → merge → HTML report. It makes
**no network calls**.

```bash
./scan.sh /path/to/source /custom/output/dir   # optional output dir
CODEQL_LANGS=csharp,java ./scan.sh /path/to/source   # override language autodetect
SKIP_DEPCHECK=1 ./scan.sh /path/to/source            # skip the slow Dependency-Check
```

CodeQL languages are autodetected from file extensions (csharp, java, javascript,
python, go, cpp, ruby) unless `CODEQL_LANGS` is set.

## Output

Written to `reports/<timestamp>/` (or your custom dir):

**Raw per-tool** (kept separate, as-is):
`semgrep.json` · `opengrep.json` · `codeql-*.sarif` · `trivy.json` · `depcheck.json` · `gitleaks.json`

**Merged / report-ready:**

| File | Use |
|------|-----|
| `combined.json` | normalized findings (incl. code-evidence snippets) |
| `summary.csv` | spreadsheet / import |
| `summary.txt` | quick terminal read |
| `report.html` | self-contained interactive report (open in any browser) |

### report.html

Single file, inline CSS/JS — **works air-gapped**, no external assets. Filter by
severity / category / tool, free-text search, sortable columns. **Click any
finding row** to expand its **code evidence**: the source lines around the issue
with the offending line highlighted. SCA findings show the package's declaration
in the manifest (`.csproj`, `package-lock.json`, etc.). Findings with no source
location (some IaC misconfig) say so.

> Code evidence is read from the target folder at scan time and baked into
> `report.html`, so the report keeps working even if the source is later removed.

## View the report

```bash
cd reports && python3 -m http.server 8888
# then open http://<host>:8888/<timestamp>/report.html
```

## Normalized finding schema

`tool · category · severity · rule_id · title · file · line · package · version · fix`

Severities are normalized across tools to: `CRITICAL HIGH MEDIUM LOW INFO UNKNOWN`.

## Layout

```
install.sh            one-time online setup
scan.sh               scan + merge + HTML (the only command you run)
lib/merge_report.py   normalize 6 tools -> combined.json / csv / txt (+ snippets)
lib/html_report.py    combined.json -> self-contained report.html
bundle/               tools + rules + vuln DBs   (git-ignored)
reports/              scan outputs               (git-ignored)
```

## Requirements

Linux x86_64 or arm64 · `python3` (stdlib only) · `bash` · internet **only** for
`install.sh`. CodeQL uses `--build-mode=none`, so no compiler/build is needed for
the scanned project.
