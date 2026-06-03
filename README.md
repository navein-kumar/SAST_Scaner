# SAST Scanner (offline SAST / SCA / secrets)

A self-contained, fully offline SAST + SCA + secrets scanner for source code
(strong C# and C++ coverage). It runs **with no internet** once the tool bundle is
built. Engines are merged into one combined report (HTML + CSV + JSON), with raw
per-tool output kept alongside.

This repository is split into two folders so the two workflows stay separate.

## `online/`  — build the bundle (needs internet, run once)

Use this on a machine **with internet** to download every tool, ruleset and
vulnerability database into `online/bundle/`.

```
cd online
./install.sh                 # downloads + builds the full bundle
./run.sh /path/to/source     # then scan (offline from here on)
```

After `install.sh` finishes you have a complete, self-contained `bundle/`. Package
the whole `online/` folder (now containing `bundle/`) into a tar and ship it to the
air-gapped client.

## `offline/`  — run on the air-gapped client (no internet, nothing to install)

This is what the client runs. They receive the prebuilt archive
(`sast-scanner-airgap.tar.gz`, produced from the `online/` folder after the build),
extract it, and run:

```
cd offline            # (the extracted package, with bundle/ alongside)
./run.sh /repos       # scan every repo folder under /repos
```

No system install is required: the .NET SDK, JRE, Python venv, and all scanner
binaries are inside the bundle. The client box only needs `python3` and `bash`.

See `offline/AIRGAP-README.md` for the full client instructions.

## Engines (merged under 6 tool names)

| Report name | Engines folded in | Languages |
|-------------|-------------------|-----------|
| `semgrep`   | Semgrep + flawfinder + DevSkim | C#, C++, multi |
| `opengrep`  | Opengrep + cppcheck | C#, C++, multi |
| `codeql`    | CodeQL (build-mode none) | C#, JS, Python, Java, Go, Ruby |
| `trivy`     | Trivy | SCA, secrets, IaC misconfig |
| `depcheck`  | OWASP Dependency-Check (bundled JRE) | SCA (NVD) |
| `gitleaks`  | Gitleaks + TruffleHog | secrets |

C/C++ cannot be analyzed by CodeQL offline (it needs a compiler), so flawfinder,
cppcheck and DevSkim provide the C/C++ depth instead. Findings are never
deduplicated: every engine's results are shown in full. INFO-level findings are
included from all tools.

## Outputs (per scan, under `reports/<timestamp>/`)

- `report.html`  : combined, interactive report
- `combined.json`, `summary.csv`, `summary.txt` (with a scan-statistics block:
  folders scanned, file counts, per-application breakdown)
- raw per-tool output: `semgrep.json`, `opengrep.json`, `codeql-*.sarif`,
  `trivy.json`, `depcheck.json`, `gitleaks.json`, `flawfinder.csv`, `cppcheck.xml`,
  `devskim.sarif`, `trufflehog.json`

## Notes

- The `bundle/` directories and the packaged `*.tar.gz` are git-ignored (multi-GB,
  regenerable). Only the source/scripts are tracked here.
- Resource limits (CodeQL RAM/threads) are auto-sized to the host at runtime.
