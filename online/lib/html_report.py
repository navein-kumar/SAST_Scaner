#!/usr/bin/env python3
"""Render combined.json into a single self-contained HTML report.

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
<title>SAST Scanner</title>
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
.btn{{padding:7px 12px;border:1px solid #0f1b2d;background:#0f1b2d;color:#fff;border-radius:6px;font-size:13px;cursor:pointer}}
.btn:hover{{background:#1c3354}}
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
tr.main{{cursor:pointer}}
tr.main td:first-child{{position:relative;padding-left:24px}}
.caret{{position:absolute;left:8px;color:#99a;font-size:10px;transition:transform .12s}}
tr.main.open .caret{{transform:rotate(90deg)}}
tr.detail td{{background:#0f1b2d;padding:0}}
tr.detail.hidden{{display:none}}
.evidence{{margin:0;padding:12px 16px;overflow-x:auto}}
.evidence .path{{color:#9cc; font-family:ui-monospace,Consolas,monospace;font-size:12px;margin-bottom:6px;word-break:break-all}}
pre.code{{margin:0;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;line-height:1.5;color:#dde}}
pre.code .ln{{display:inline-block;width:46px;color:#5a6b85;text-align:right;padding-right:12px;user-select:none}}
pre.code .row{{display:block;white-space:pre}}
pre.code .row.hit{{background:#5a1a26;border-left:3px solid #d7263d;margin-left:-3px}}
.noev{{color:#8aa;font-size:12px;padding:12px 16px;font-style:italic}}
.wholefile{{color:#e8852b;font-size:12px;margin:0 16px 8px;font-style:italic}}
.footer{{padding:14px 24px;font-size:12px;color:#889;text-align:center}}
</style></head>
<body>
<header>
  <h1>SAST Scanner &middot; SAST / SCA / Secrets Report</h1>
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
    <button id="expView" class="btn" title="Export the currently filtered rows to CSV">&#10515; Export view</button>
    <button id="expAll" class="btn" title="Export every finding to CSV">&#10515; Export all</button>
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
<div class="footer">Generated by SAST Scanner · {len(findings)} findings · raw per-tool JSON/SARIF alongside this file</div>
<script>
const DATA = {data_json};
const SEVC = {sev_colors_json};
const SEVRANK = {{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,UNKNOWN:5}};
const $=s=>document.querySelector(s);
function uniq(k){{return [...new Set(DATA.map(d=>d[k]).filter(x=>x!==''&&x!=null))].sort();}}
for(const s of Object.keys(SEVRANK)) if(DATA.some(d=>d.severity===s)) $('#fsev').add(new Option(s,s));
for(const c of uniq('category')) $('#fcat').add(new Option(c,c));
for(const t of uniq('tool')) $('#ftool').add(new Option(t,t));
let sortK='severity', sortAsc=true, currentRows=[];
function esc(s){{return (s==null?'':String(s)).replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));}}
const COLS=['tool','category','severity','rule_id','title','location','package','version','fix'];
function csvCell(v){{v=(v==null?'':String(v));return /[",\\n\\r]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;}}
function locOf(d){{
  const f=String(d.file||'').split('?')[0];
  if(!f) return '';
  let ln=(d.line!==''&&d.line!=null)?d.line:(d.snippet_line||0);
  if(!ln) ln=1;            // whole-file finding (e.g. missing USER) -> anchor at top of file
  return f+'#L'+ln;
}}
function exportCSV(rows,name){{
  const lines=[COLS.join(',')];
  for(const d of rows){{
    const rec=Object.assign({{}},d,{{location:locOf(d)}});
    lines.push(COLS.map(k=>csvCell(rec[k])).join(','));
  }}
  const blob=new Blob(['\\ufeff'+lines.join('\\r\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download=name;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
}}
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
  currentRows=rows;
  $('#count').textContent=rows.length+' / '+DATA.length+' shown';
  $('#rows').innerHTML=rows.map(d=>{{
    const loc=esc(d.file)+(d.line!==''&&d.line!=null?':'+esc(d.line):'');
    const pkg=d.package?esc(d.package)+(d.version?' '+esc(d.version):''):'';
    return `<tr class="main">
      <td><span class="caret">&#9656;</span><span class="sev" style="background:${{SEVC[d.severity]||'#777'}}">${{esc(d.severity)}}</span></td>
      <td><span class="cat">${{esc(d.category)}}</span></td>
      <td><span class="tool">${{esc(d.tool)}}</span></td>
      <td class="rid">${{esc(d.rule_id)}}</td>
      <td class="title">${{esc(d.title)}}</td>
      <td class="mono">${{loc}}</td>
      <td class="mono">${{pkg}}</td>
      <td class="mono">${{esc(d.fix)}}</td>
    </tr>
    <tr class="detail hidden"><td colspan="8">${{evidence(d)}}</td></tr>`;}}).join('');
}}
function evidence(d){{
  const snip=d.snippet||[];
  if(!snip.length){{
    return '<div class="noev">No code evidence &mdash; '
      +(d.category==='SCA'?'dependency/package finding (no source line).'
        :'no source location available for this finding.')+'</div>';
  }}
  const hit=d.snippet_line;
  const lineNo=(d.line!==''&&d.line!=null)?d.line:(hit||'');
  const path=esc(String(d.file).split('?')[0])+(lineNo!==''?':'+esc(lineNo):'');
  const note=(hit===0||hit==='')
    ?'<div class="wholefile">Whole-file finding &mdash; the issue is a missing/global setting, so no single line is highlighted. Full file shown below.</div>'
    :'';
  const body=snip.map(([n,t])=>
    `<span class="row${{n===hit?' hit':''}}"><span class="ln">${{n}}</span>${{esc(t)}}</span>`).join('');
  return `<div class="evidence"><div class="path">${{path}}</div>${{note}}<pre class="code">${{body}}</pre></div>`;
}}
$('#rows').addEventListener('click',e=>{{
  const tr=e.target.closest('tr.main'); if(!tr)return;
  const det=tr.nextElementSibling;
  if(det&&det.classList.contains('detail')){{det.classList.toggle('hidden');tr.classList.toggle('open');}}
}});
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{{
  const k=th.dataset.k; if(sortK===k)sortAsc=!sortAsc; else{{sortK=k;sortAsc=true;}} render();
}});
['#q','#fsev','#fcat','#ftool'].forEach(s=>$(s).addEventListener('input',render));
const STAMP=new Date().toISOString().slice(0,10);
$('#expView').onclick=()=>exportCSV(currentRows,'findings-filtered-'+STAMP+'.csv');
$('#expAll').onclick=()=>exportCSV(DATA,'findings-all-'+STAMP+'.csv');
render();
</script>
</body></html>"""

    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print(f"HTML report -> {a.out}  ({len(findings)} findings)")


if __name__ == "__main__":
    main()
