#!/usr/bin/env python3
"""Render combined.json into a single self-contained, offline HTML report.

No external assets (CSS/JS are inline) so it works on an air-gapped box.
Interactive: filter by severity/category/tool, free-text search, click column
headers to sort.

Usage:
  python3 html_report.py --in combined.json --out report.html --target NAME
"""
import argparse
import datetime
import html
import json
import os
from collections import Counter

SEV_COLORS = {
    "CRITICAL": "#7b001c", "HIGH": "#d7263d", "MEDIUM": "#e8852b",
    "LOW": "#e3b505", "INFO": "#2a7de1", "UNKNOWN": "#7f8c8d",
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", default="")
    a = ap.parse_args()

    try:
        with open(a.inp, encoding="utf-8") as fh:
            findings = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        findings = []

    by_sev = Counter(f.get("severity", "UNKNOWN") for f in findings)
    by_cat = Counter(f.get("category", "?") for f in findings)
    by_tool = Counter(f.get("tool", "?") for f in findings)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # severity summary cards
    cards = ""
    for s in SEV_ORDER:
        if by_sev.get(s):
            cards += (f'<div class="card" style="border-top:4px solid {SEV_COLORS[s]}">'
                      f'<div class="num">{by_sev[s]}</div><div class="lbl">{s}</div></div>')
    total_card = (f'<div class="card" style="border-top:4px solid #111">'
                  f'<div class="num">{len(findings)}</div><div class="lbl">TOTAL</div></div>')

    def chips(counter):
        return "".join(f'<span class="chip">{html.escape(str(k))}'
                       f'<b>{v}</b></span>' for k, v in sorted(counter.items()))

    data_json = json.dumps(findings).replace("</", "<\\/")
    sev_colors_json = json.dumps(SEV_COLORS)
    target = html.escape(a.target)

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Offline SAST/SCA/Secrets Report</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1c2733}}
header{{background:#0f1b2d;color:#fff;padding:18px 24px}}
header h1{{margin:0 0 4px;font-size:20px}}
header .meta{{font-size:13px;opacity:.8}}
.wrap{{padding:20px 24px;max-width:1500px;margin:0 auto}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}}
.card{{background:#fff;border-radius:8px;padding:12px 18px;min-width:96px;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}}
.card .num{{font-size:26px;font-weight:700}}
.card .lbl{{font-size:11px;letter-spacing:.5px;color:#667}}
.chips{{margin:6px 0 14px}}
.chip{{display:inline-block;background:#fff;border:1px solid #dde3ea;border-radius:14px;padding:3px 10px;margin:3px;font-size:12px;color:#445}}
.chip b{{margin-left:6px;color:#0f1b2d}}
.controls{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;align-items:center}}
.controls input,.controls select{{padding:7px 10px;border:1px solid #cdd5df;border-radius:6px;font-size:13px}}
.controls input[type=search]{{flex:1;min-width:220px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);font-size:13px}}
th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid #eef1f4;vertical-align:top}}
th{{background:#0f1b2d;color:#fff;cursor:pointer;white-space:nowrap;position:sticky;top:0}}
th:hover{{background:#1c3354}}
tr:hover td{{background:#f7fafd}}
.sev{{font-weight:700;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;display:inline-block}}
.cat{{font-size:11px;color:#556;background:#eef1f4;border-radius:4px;padding:2px 6px}}
.tool{{font-size:11px;font-weight:600;color:#2a7de1}}
.mono{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#334}}
.title{{max-width:520px}}
.rid{{color:#667;font-size:11px;word-break:break-all}}
#count{{font-size:13px;color:#556;margin-left:auto}}
.footer{{padding:14px 24px;font-size:12px;color:#889;text-align:center}}
</style></head>
<body>
<header>
  <h1>Offline SAST / SCA / Secrets Report</h1>
  <div class="meta">Target: <b>{target}</b> &nbsp;·&nbsp; Generated: {ts} &nbsp;·&nbsp; Engines: semgrep · opengrep · codeql · trivy · dependency-check · gitleaks</div>
</header>
<div class="wrap">
  <div class="cards">{total_card}{cards}</div>
  <div class="chips"><b style="font-size:12px;color:#667">By tool:</b> {chips(by_tool)}</div>
  <div class="chips"><b style="font-size:12px;color:#667">By category:</b> {chips(by_cat)}</div>
  <div class="controls">
    <input type="search" id="q" placeholder="Search rule, title, file, package...">
    <select id="fsev"><option value="">All severities</option></select>
    <select id="fcat"><option value="">All categories</option></select>
    <select id="ftool"><option value="">All tools</option></select>
    <span id="count"></span>
  </div>
  <table id="tbl">
    <thead><tr>
      <th data-k="severity">Severity</th><th data-k="category">Category</th>
      <th data-k="tool">Tool</th><th data-k="rule_id">Rule</th>
      <th data-k="title">Title</th><th data-k="file">Location</th>
      <th data-k="package">Package</th><th data-k="fix">Fix / CWE</th>
    </tr></thead>
    <tbody id="rows"></tbody>
  </table>
</div>
<div class="footer">Generated by offline-sast · {len(findings)} findings · raw per-tool JSON/SARIF alongside this file</div>
<script>
const DATA = {data_json};
const SEVC = {sev_colors_json};
const SEVRANK = {{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,UNKNOWN:5}};
const $=s=>document.querySelector(s);
function uniq(k){{return [...new Set(DATA.map(d=>d[k]).filter(x=>x!==''&&x!=null))].sort();}}
for(const s of Object.keys(SEVRANK)) if(DATA.some(d=>d.severity===s)) $('#fsev').add(new Option(s,s));
for(const c of uniq('category')) $('#fcat').add(new Option(c,c));
for(const t of uniq('tool')) $('#ftool').add(new Option(t,t));
let sortK='severity', sortAsc=true;
function esc(s){{return (s==null?'':String(s)).replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));}}
function render(){{
  const q=$('#q').value.toLowerCase(), fs=$('#fsev').value, fc=$('#fcat').value, ft=$('#ftool').value;
  let rows=DATA.filter(d=>{{
    if(fs&&d.severity!==fs)return false;
    if(fc&&d.category!==fc)return false;
    if(ft&&d.tool!==ft)return false;
    if(q){{const blob=(d.rule_id+' '+d.title+' '+d.file+' '+d.package+' '+d.tool).toLowerCase();if(!blob.includes(q))return false;}}
    return true;
  }});
  rows.sort((a,b)=>{{
    let x,y;
    if(sortK==='severity'){{x=SEVRANK[a.severity]??9;y=SEVRANK[b.severity]??9;}}
    else{{x=(a[sortK]||'').toString().toLowerCase();y=(b[sortK]||'').toString().toLowerCase();}}
    if(x<y)return sortAsc?-1:1; if(x>y)return sortAsc?1:-1; return 0;
  }});
  $('#count').textContent=rows.length+' / '+DATA.length+' shown';
  $('#rows').innerHTML=rows.map(d=>{{
    const loc=esc(d.file)+(d.line!==''&&d.line!=null?':'+esc(d.line):'');
    const pkg=d.package?esc(d.package)+(d.version?' '+esc(d.version):''):'';
    return `<tr>
      <td><span class="sev" style="background:${{SEVC[d.severity]||'#777'}}">${{esc(d.severity)}}</span></td>
      <td><span class="cat">${{esc(d.category)}}</span></td>
      <td><span class="tool">${{esc(d.tool)}}</span></td>
      <td class="rid">${{esc(d.rule_id)}}</td>
      <td class="title">${{esc(d.title)}}</td>
      <td class="mono">${{loc}}</td>
      <td class="mono">${{pkg}}</td>
      <td class="mono">${{esc(d.fix)}}</td>
    </tr>`;}}).join('');
}}
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{{
  const k=th.dataset.k; if(sortK===k)sortAsc=!sortAsc; else{{sortK=k;sortAsc=true;}} render();
}});
['#q','#fsev','#fcat','#ftool'].forEach(s=>$(s).addEventListener('input',render));
render();
</script>
</body></html>"""

    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print(f"HTML report -> {a.out}  ({len(findings)} findings)")


if __name__ == "__main__":
    main()
