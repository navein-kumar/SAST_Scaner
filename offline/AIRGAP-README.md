# Offline SAST Scanner: Air-Gapped Usage

This bundle is fully self-contained. It runs with NO internet access. Everything
the scanners need (tools, rules, vulnerability databases, CodeQL query packs, the
.NET SDK for C# extraction, and the NVD data for Dependency-Check) is inside
`bundle/`. Do NOT run `install.sh` on the air-gapped box. `install.sh` is only for
rebuilding the bundle on a machine that has internet.

## 1. Requirements on the air-gapped machine

- Linux x86_64 (built and tested on Ubuntu 22.04).
- `python3` (3.10.x recommended, matches the bundled Semgrep environment).
- `java` (JRE 11 or newer) for OWASP Dependency-Check.
- `bash`, `tar`, `find`, standard core utilities.
- Roughly 6 GB free disk for the unzipped bundle plus room for reports.

Nothing else. The .NET SDK is shipped inside the bundle, so the system does NOT
need dotnet installed.

## 2. Unzip

You can extract to ANY path (the scanner resolves its own location at runtime).

```
tar -xzf sast-scanner-airgap.tar.gz -C /opt
cd /opt/SAST_Scaner
```

## 3. Run a scan

```
./scan.sh /path/to/source/code
```

Reports are written to `reports/<timestamp>/`:
- `report.html`     human-readable combined report
- `combined.json`   merged machine-readable findings
- `summary.txt` / `summary.csv`
- per-tool raw output: `semgrep.json`, `opengrep.json`, `codeql-*.sarif`,
  `trivy.json`, `depcheck.json`, `gitleaks.json`

## 4. Language notes (C++ and C#)

- C#  : scanned by Semgrep, Opengrep, and CodeQL (CodeQL uses build-mode=none and
        the bundled .NET SDK, so no compilation and no internet are needed).
- C++ : scanned by Semgrep, Opengrep, and Trivy. CodeQL is intentionally skipped
        for C/C++ because CodeQL requires a full compile of the project, which is
        not possible offline. To force a CodeQL C++ attempt anyway (needs the build
        toolchain): `CODEQL_ALLOW_CPP=1 ./scan.sh /path/to/source`.

## 5. If CodeQL runs out of memory on a small box

CodeQL C# extraction is memory-hungry. Cap it:

```
CODEQL_RAM=4096 CODEQL_THREADS=2 ./scan.sh /path/to/source
```

## 6. Restrict which languages CodeQL builds

```
CODEQL_LANGS=csharp ./scan.sh /path/to/source
```

## 7. Confirm it made no network calls (optional)

```
sudo unshare -n bash -c "ip link set lo up; ./scan.sh /path/to/source"
```

A successful run with the network namespace detached proves the scan is fully
offline.

## 8. Scanning many repos at once + coverage assurance

You can place several repos under one parent and scan them in a single run:

```
/repos/1_web_app
/repos/2_mobile_app
/repos/3_manager_app
...
./scan.sh /repos
```

For every immediate sub-folder of the target, the report adds one INFO-level row
in the "COVERAGE" category, for example:

```
Scanned: 3_manager_app (212 files, 0 findings)
```

This proves the folder WAS walked and scanned even when it has zero
vulnerabilities, so a clean repo never silently disappears from the results.
These rows appear in `report.html` (filter Category = COVERAGE, or Severity =
INFO), in `summary.csv`, and in the "Scan coverage" block of `summary.txt`. They
are counted separately from the vulnerability total so they do not inflate it.

## 9. Resource auto-sizing

CodeQL memory and thread count are auto-detected from the host at run time
(roughly 75 percent of physical RAM, and CPU cores minus one). No manual tuning
is needed on a 4-core/16GB box or a larger one. To override:

```
CODEQL_RAM=4096 CODEQL_THREADS=2 ./scan.sh /repos
```
