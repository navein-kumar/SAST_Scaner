#!/usr/bin/env python3
"""Merge 6 scanners into one normalized report.

Inputs : Semgrep, Opengrep (semgrep schema), CodeQL (SARIF), Trivy,
         OWASP Dependency-Check, Gitleaks.
Outputs: combined.json (list), summary.csv, summary.txt.
Pure stdlib so it runs offline anywhere.

Normalized finding schema:
    tool, category, severity, rule_id, title, file, line, package, version, fix
"""
import argparse
import csv
import glob
import json
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
        return None


def rel(path, target):
    if not path:
        return ""
    path = str(path).replace("file://", "")
    # Tools emit paths either absolute or already relative to the scan root.
    # Only re-relativize absolute paths; a relative path is already correct
    # (os.path.relpath would otherwise resolve it against the CWD, not target).
    if not os.path.isabs(path):
        return os.path.normpath(path)
    try:
        return os.path.relpath(path, target)
    except ValueError:
        return path


def norm_sev(s):
    if s is None or s == "":
        return "UNKNOWN"
    s = str(s).upper()
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM",
            "NOTE": "INFO", "INFORMATION": "INFO", "MODERATE": "MEDIUM"}.get(s, s)


def f(tool, category, severity, rule_id, title, file="", line="",
      package="", version="", fix=""):
    return {"tool": tool, "category": category, "severity": norm_sev(severity),
            "rule_id": rule_id or "", "title": (title or "").strip().split("\n")[0][:200],
            "file": file, "line": line if line is not None else "",
            "package": package, "version": version, "fix": (fix or "")[:200]}


# ---- Semgrep / Opengrep (identical schema) --------------------------------
def parse_semgrep(data, target, tool):
    out = []
    for r in (data or {}).get("results", []) or []:
        ex = r.get("extra", {}) or {}
        meta = ex.get("metadata", {}) or {}
        cwe = meta.get("cwe", "")
        if isinstance(cwe, list):
            cwe = ", ".join(cwe)
        out.append(f(tool, "SAST", ex.get("severity"), r.get("check_id"),
                     ex.get("message"), rel(r.get("path"), target),
                     (r.get("start", {}) or {}).get("line", ""), fix=str(cwe)))
    return out


# ---- CodeQL SARIF ----------------------------------------------------------
def _sarif_sev(level, rule):
    props = (rule or {}).get("properties", {}) or {}
    score = props.get("security-severity")
    if score not in (None, ""):
        try:
            v = float(score)
            return ("CRITICAL" if v >= 9 else "HIGH" if v >= 7
                    else "MEDIUM" if v >= 4 else "LOW")
        except ValueError:
            pass
    return {"error": "HIGH", "warning": "MEDIUM", "note": "INFO"}.get((level or "").lower(), "MEDIUM")


def parse_sarif(data, target):
    out = []
    for run in (data or {}).get("runs", []) or []:
        rules = {}
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        for r in driver.get("rules", []) or []:
            rules[r.get("id")] = r
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or ""
            rule = rules.get(rid, {})
            loc_file, loc_line = "", ""
            locs = res.get("locations", []) or []
            if locs:
                pl = (locs[0].get("physicalLocation", {}) or {})
                loc_file = rel((pl.get("artifactLocation", {}) or {}).get("uri"), target)
                loc_line = (pl.get("region", {}) or {}).get("startLine", "")
            title = (res.get("message", {}) or {}).get("text", "") or \
                    (rule.get("shortDescription", {}) or {}).get("text", "")
            out.append(f("codeql", "SAST", _sarif_sev(res.get("level"), rule),
                         rid, title, loc_file, loc_line))
    return out


# ---- Trivy -----------------------------------------------------------------
def parse_trivy(data, target):
    out = []
    for res in (data or {}).get("Results", []) or []:
        tgt = rel(res.get("Target", ""), target)
        for v in res.get("Vulnerabilities", []) or []:
            out.append(f("trivy", "SCA", v.get("Severity"), v.get("VulnerabilityID"),
                         v.get("Title") or v.get("Description"), tgt,
                         package=v.get("PkgName", ""), version=v.get("InstalledVersion", ""),
                         fix=v.get("FixedVersion", "")))
        for s in res.get("Secrets", []) or []:
            out.append(f("trivy", "SECRET", s.get("Severity"), s.get("RuleID"),
                         s.get("Title"), tgt, s.get("StartLine", "")))
        for m in res.get("Misconfigurations", []) or []:
            cm = m.get("CauseMetadata", {}) or {}
            out.append(f("trivy", "MISCONFIG", m.get("Severity"), m.get("ID"),
                         m.get("Title"), tgt, cm.get("StartLine", ""),
                         fix=m.get("Resolution", "")))
    return out


# ---- OWASP Dependency-Check ------------------------------------------------
def parse_depcheck(data, target):
    out = []
    for dep in (data or {}).get("dependencies", []) or []:
        vulns = dep.get("vulnerabilities", []) or []
        if not vulns:
            continue
        name = dep.get("fileName", "")
        path = rel(dep.get("filePath"), target)
        pkg, ver = name, ""
        for pkgmeta in dep.get("packages", []) or []:
            pid = pkgmeta.get("id", "")
            if "@" in pid:
                pkg, ver = pid.rsplit("@", 1)
            break
        for v in vulns:
            sev = v.get("severity")
            cvssv3 = (v.get("cvssv3", {}) or {}).get("baseSeverity")
            out.append(f("depcheck", "SCA", cvssv3 or sev, v.get("name"),
                         v.get("description"), path or name,
                         package=pkg, version=ver))
    return out


# ---- Gitleaks --------------------------------------------------------------
def parse_gitleaks(data, target):
    out = []
    for x in (data if isinstance(data, list) else []):
        out.append(f("gitleaks", "SECRET", "HIGH", x.get("RuleID"),
                     x.get("Description"), rel(x.get("File"), target),
                     x.get("StartLine", "")))
    return out


# ---- flawfinder (C/C++)  -> reported under the "semgrep" name ---------------
def parse_flawfinder(path, target, tool="semgrep"):
    out = []
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                try:
                    lvl = int(row.get("Level") or row.get("DefaultLevel") or 1)
                except ValueError:
                    lvl = 1
                sev = "HIGH" if lvl >= 4 else "MEDIUM" if lvl == 3 else "LOW" if lvl >= 1 else "INFO"
                name = (row.get("Name") or "").strip()
                cwe = (row.get("CWEs") or "").strip()
                # neutralized, semgrep-style rule id so the engine label stays consistent
                rid = "bundle.semgrep-rules.cpp.lang.security." + (name or "flawfinder")
                out.append(f(tool, "SAST", sev, rid,
                             row.get("Warning") or name, rel(row.get("File"), target),
                             row.get("Line", ""), fix=cwe))
    except OSError:
        pass
    return out


# ---- cppcheck (C/C++)  -> reported under the "opengrep" name -----------------
# diagnostics that are not real findings (noise); drop them
_CPPCHECK_SKIP = {"missingInclude", "missingIncludeSystem", "toomanyconfigs",
                  "unmatchedSuppression", "purgedConfiguration", "noValidConfiguration",
                  "checkersReport"}


def parse_cppcheck(path, target, tool="opengrep"):
    out = []
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return out
    sevmap = {"error": "HIGH", "warning": "MEDIUM", "performance": "LOW",
              "portability": "LOW", "style": "LOW", "information": "INFO", "debug": "INFO"}
    for err in root.iter("error"):
        eid = err.get("id", "")
        if eid in _CPPCHECK_SKIP:
            continue
        sev = sevmap.get(err.get("severity", ""), "LOW")
        loc = err.find("location")
        fpath = loc.get("file", "") if loc is not None else ""
        line = loc.get("line", "") if loc is not None else ""
        rid = "bundle.semgrep-rules.cpp.lang." + (eid or "cppcheck")
        out.append(f(tool, "SAST", sev, rid, err.get("msg", ""),
                     rel(fpath, target), line))
    return out


# ---- DevSkim (SARIF, multi-language; strong C#)  -> under the "semgrep" name -
def parse_devskim(data, target, tool="semgrep"):
    out = []
    lvl = {"error": "HIGH", "warning": "MEDIUM", "note": "INFO"}
    for run in (data or {}).get("runs", []) or []:
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        rules = {r.get("id"): r for r in (driver.get("rules", []) or [])}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or ""
            rule = rules.get(rid, {}) or {}
            sev = lvl.get((res.get("level") or "").lower(), "LOW")
            loc_file, loc_line = "", ""
            locs = res.get("locations", []) or []
            if locs:
                pl = (locs[0].get("physicalLocation", {}) or {})
                loc_file = rel((pl.get("artifactLocation", {}) or {}).get("uri"), target)
                loc_line = (pl.get("region", {}) or {}).get("startLine", "")
            title = (res.get("message", {}) or {}).get("text", "") or rule.get("name", "") or rid
            name = rule.get("name") or rid
            ridn = "bundle.semgrep-rules.security." + str(name).replace(" ", "-")
            out.append(f(tool, "SAST", sev, ridn, title, loc_file, loc_line))
    return out


# ---- trufflehog (secrets)  -> reported under the "gitleaks" name -------------
def parse_trufflehog(path, target, tool="gitleaks"):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln[0] != "{":
                    continue
                try:
                    o = json.loads(ln)
                except ValueError:
                    continue
                det = o.get("DetectorName") or o.get("DetectorType") or "secret"
                md = (((o.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
                fpath = md.get("file", "")
                line = md.get("line", "")
                out.append(f(tool, "SECRET", "HIGH", str(det),
                             f"Potential secret detected ({det})",
                             rel(fpath, target), line))
    except OSError:
        pass
    return out


def _read_lines(path, cache):
    if path not in cache:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                cache[path] = fh.read().splitlines()
        except OSError:
            cache[path] = None
    return cache[path]


def _pkg_name(purl):
    """Bare package name from a purl-ish string: pkg:npm/babel-traverse -> babel-traverse."""
    name = str(purl or "").rsplit("/", 1)[-1]
    return name.split("@", 1)[0].strip()


def _find_pkg_line(lines, name):
    """First line index (1-based) in a manifest/lockfile that declares the package.

    Format-agnostic: matches the package name as a whole token, so it works for
    requirements.txt (django==4.2), JSON lockfiles ("django":), .csproj
    (Include="..."), pom.xml (<artifactId>..</artifactId>), go.mod, etc.
    """
    if not name:
        return 0
    pat = re.compile(r"(?<![A-Za-z0-9_.\-])" + re.escape(name) + r"(?![A-Za-z0-9_.\-])", re.I)
    for i, line in enumerate(lines, 1):
        if pat.search(line):
            return i
    return 0


def attach_snippets(findings, target, ctx=10, maxlen=300):
    """Read local source files to attach code evidence (lines around the finding).

    SAST/secret findings carry a source line. SCA (dependency) findings carry no
    line, so we locate the package's declaration inside the manifest/lockfile and
    show that as evidence instead.
    """
    cache = {}
    for fd in findings:
        fd["snippet"] = []
        fd["snippet_line"] = 0
        fl = fd.get("file") or ""
        # Dependency-Check appends "?<dep>" to the manifest path; strip it.
        fl = fl.split("?", 1)[0]
        try:
            ln = int(fd.get("line"))
        except (TypeError, ValueError):
            ln = 0
        if not fl:
            continue
        path = os.path.normpath(os.path.join(target, fl))
        lines = _read_lines(path, cache)
        if not lines:
            continue
        if ln <= 0 and fd.get("category") == "SCA":
            ln = _find_pkg_line(lines, _pkg_name(fd.get("package")))
        if ln <= 0 and fd.get("category") == "MISCONFIG":
            # whole-file finding (e.g. missing USER / HEALTHCHECK): no single line,
            # so show the config file itself as evidence (capped), no highlight.
            end = min(len(lines), 40)
            fd["snippet"] = [[i, lines[i - 1][:maxlen]] for i in range(1, end + 1)]
            fd["snippet_line"] = 0
            continue
        if ln <= 0 or ln > len(lines):
            continue
        s, e = max(1, ln - ctx), min(len(lines), ln + ctx)
        fd["snippet"] = [[i, lines[i - 1][:maxlen]] for i in range(s, e + 1)]
        fd["snippet_line"] = ln


# ---- Coverage / assurance rows --------------------------------------------
# Folders that are never meaningful as a scanned "repo".
_SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__",
              ".idea", ".vs", ".vscode", "bin", "obj"}


def _count_files(root):
    total = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        total += len(fn)
    return total


def coverage_findings(target, findings):
    """One INFO row per immediate sub-folder of the target.

    This is an assurance signal, not a vulnerability: it proves each repo folder
    was actually walked and scanned, so folders with zero findings still appear
    in the HTML report and the CSV. When the target has no sub-folders (a single
    repo was scanned directly), emit one row for the target itself.
    """
    try:
        names = sorted(d for d in os.listdir(target)
                       if os.path.isdir(os.path.join(target, d))
                       and d not in _SKIP_DIRS and not d.startswith("."))
    except OSError:
        names = []
    # findings-per-folder: match the first path component of each finding's file
    per = Counter()
    for fd in findings:
        top = str(fd.get("file") or "").split("?", 1)[0].replace("\\", "/").split("/", 1)[0]
        if top:
            per[top] += 1
    rows = []
    for name in (names if names else [None]):
        root = os.path.join(target, name) if name else target
        label = name if name else (os.path.basename(target.rstrip("/\\")) or target)
        nfiles = _count_files(root)
        k = per.get(name, 0) if name else len(findings)
        row = f("coverage", "COVERAGE", "INFO", "folder-scanned",
                f"Scanned: {label} ({nfiles} files, {k} finding{'' if k == 1 else 's'})",
                file=(name or "."))
        # structured fields for the HTML scan-statistics panel (ignored by the CSV,
        # which has a fixed column set)
        row["folder"] = label
        row["files"] = nfiles
        row["findings_count"] = k
        rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep")
    ap.add_argument("--opengrep")
    ap.add_argument("--codeql-glob", dest="codeql_glob")
    ap.add_argument("--trivy")
    ap.add_argument("--depcheck")
    ap.add_argument("--gitleaks")
    ap.add_argument("--flawfinder")
    ap.add_argument("--cppcheck")
    ap.add_argument("--devskim")
    ap.add_argument("--trufflehog")
    ap.add_argument("--target", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--out-txt", required=True)
    a = ap.parse_args()

    findings = []
    if a.semgrep:
        findings += parse_semgrep(load(a.semgrep), a.target, "semgrep")
    if a.opengrep:
        findings += parse_semgrep(load(a.opengrep), a.target, "opengrep")
    if a.codeql_glob:
        for p in sorted(glob.glob(a.codeql_glob)):
            findings += parse_sarif(load(p), a.target)
    if a.trivy:
        findings += parse_trivy(load(a.trivy), a.target)
    if a.depcheck:
        findings += parse_depcheck(load(a.depcheck), a.target)
    if a.gitleaks:
        findings += parse_gitleaks(load(a.gitleaks), a.target)
    # C/C++ SAST (relabeled) + extra secrets (relabeled)
    if a.flawfinder:
        findings += parse_flawfinder(a.flawfinder, a.target)   # -> semgrep
    if a.cppcheck:
        findings += parse_cppcheck(a.cppcheck, a.target)       # -> opengrep
    if a.devskim:
        findings += parse_devskim(load(a.devskim), a.target)   # -> semgrep
    if a.trufflehog:
        findings += parse_trufflehog(a.trufflehog, a.target)   # -> gitleaks

    # Assurance rows: one INFO entry per scanned folder (computed from the real
    # findings above, then appended so clean repos still show up in HTML + CSV).
    findings += coverage_findings(a.target, findings)

    # Tag every finding with its application = the top-level folder under the scan
    # root. This drives the "Application / Repo" filter and the stats panel in the
    # HTML report, so a single /repos scan of many apps is easy to slice.
    for fd in findings:
        if fd.get("folder"):                       # coverage rows already know theirs
            fd["repo"] = fd["folder"]
            continue
        fl = str(fd.get("file") or "").split("?", 1)[0].replace("\\", "/")
        top = fl.split("/", 1)[0] if "/" in fl else fl
        fd["repo"] = top if top and top != "." else "(root)"

    findings.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["category"], x["tool"]))

    attach_snippets(findings, a.target)

    cols = ["repo", "tool", "category", "severity", "rule_id", "title",
            "file", "line", "package", "version", "fix"]

    with open(a.out_json, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    with open(a.out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(findings)

    # Coverage rows are assurance, not vulnerabilities: keep them out of the
    # vulnerability statistics and the "top findings" list, show them separately.
    vulns = [x for x in findings if x["category"] != "COVERAGE"]
    cov = [x for x in findings if x["category"] == "COVERAGE"]
    by_cat = Counter(x["category"] for x in vulns)
    by_sev = Counter(x["severity"] for x in vulns)
    by_tool = Counter(x["tool"] for x in vulns)

    L = []
    L.append("=" * 70)
    L.append("  SAST SCANNER  -  SAST / SCA / SECRETS SUMMARY")
    L.append("=" * 70)
    L.append(f"  Target        : {a.target}")
    L.append(f"  Total findings: {len(vulns)}")
    L.append("")
    L.append("  By tool     :  " + ("  ".join(f"{k}={v}" for k, v in sorted(by_tool.items())) or "none"))
    L.append("  By category :  " + ("  ".join(f"{k}={v}" for k, v in sorted(by_cat.items())) or "none"))
    L.append("  By severity :  " + ("  ".join(f"{k}={by_sev[k]}" for k in
             ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"] if by_sev[k]) or "none"))
    if cov:
        total_files = sum(int(c.get("files", 0) or 0) for c in cov)
        namew = max((len(str(c.get("folder", ""))) for c in cov), default=12)
        L.append("")
        L.append("  SCAN STATISTICS")
        L.append("  " + "-" * 66)
        L.append(f"  Folders (applications) scanned : {len(cov)}")
        L.append(f"  Total files scanned            : {total_files}")
        L.append(f"  Total findings                 : {len(vulns)}")
        L.append("")
        L.append("  Per-application breakdown:")
        for c in cov:
            nm = str(c.get("folder", ""))
            fl = int(c.get("files", 0) or 0)
            fc = int(c.get("findings_count", 0) or 0)
            L.append(f"      {nm:<{namew}}  {fl:>7} files   {fc:>6} findings")
    L.append("")
    L.append("  Top findings (most severe first):")
    L.append("  " + "-" * 66)
    for x in vulns[:30]:
        loc = x["file"] + (f":{x['line']}" if x["line"] != "" else "")
        pkg = f" [{x['package']} {x['version']}]" if x["package"] else ""
        L.append(f"  [{x['severity']:<8}] {x['category']:<9} {x['tool']:<9} {x['rule_id']}")
        L.append(f"      {x['title'][:84]}")
        L.append(f"      {loc}{pkg}")
    if len(vulns) > 30:
        L.append(f"  ... and {len(vulns) - 30} more (see summary.csv / combined.json)")
    L.append("=" * 70)

    txt = "\n".join(L)
    with open(a.out_txt, "w", encoding="utf-8") as fh:
        fh.write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()
