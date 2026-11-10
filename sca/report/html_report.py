"""Self-contained HTML report (one file, no internet needed, prints well to PDF)."""
from __future__ import annotations

from html import escape
from typing import Dict, List

from .. import __version__
from ..cwe import info
from ..models import SEVERITIES, Finding, ScanResult

CSS = """
:root{--bg:#f6f5f1;--card:#fff;--ink:#1c1b19;--muted:#6b6a65;--line:#e2e0d8;--code:#f1efe8;
--critical:#9b1c1c;--high:#c2410c;--medium:#a16207;--low:#1d5f8a;--info:#5f5e5a;--ai:#4c3d99;
--ok:#15803d}
@media(prefers-color-scheme:dark){:root{--bg:#161614;--card:#1f1f1c;--ink:#ecebe6;--muted:#a09f98;
--line:#34332f;--code:#2a2925;--critical:#f87171;--high:#fb923c;--medium:#facc15;--low:#60a5fa;
--info:#a3a29b;--ai:#a99cf0;--ok:#4ade80}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,
"Segoe UI",Roboto,"Noto Sans Arabic",Tahoma,sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:24px;margin:0 0 2px;letter-spacing:-.01em}
h2{font-size:17px;margin:34px 0 12px}
.sub{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:240px 1fr;gap:16px;margin-top:20px}
@media(max-width:720px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}
.score{text-align:center}
.score b{display:block;font-size:64px;line-height:1;font-weight:700;letter-spacing:-.03em}
.score span{font-size:13px;color:var(--muted)}
.grade{display:inline-block;margin-top:10px;padding:3px 14px;border-radius:99px;font-weight:700;
border:2px solid currentColor}
.sev-row{display:flex;gap:8px;flex-wrap:wrap}
.sev-box{flex:1;min-width:92px;border:1px solid var(--line);border-radius:8px;padding:10px 12px;
border-top:4px solid var(--c)}
.sev-box b{font-size:26px;display:block;line-height:1.1}
.sev-box span{font-size:12px;color:var(--muted);text-transform:capitalize}
.bar{display:flex;height:10px;border-radius:99px;overflow:hidden;margin:14px 0 4px;
background:var(--line)}
.bar i{display:block;background:var(--c)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
td,th{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}
td.n{text-align:right;font-variant-numeric:tabular-nums;width:60px}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.filters button{font:inherit;font-size:13px;padding:5px 12px;border-radius:99px;cursor:pointer;
border:1px solid var(--line);background:var(--card);color:var(--ink)}
.filters button.on{background:var(--ink);color:var(--bg);border-color:var(--ink)}
details.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--c);
border-radius:8px;margin-bottom:8px}
details.f.fp{opacity:.72}
summary{cursor:pointer;padding:11px 14px;display:flex;gap:10px;align-items:baseline;
flex-wrap:wrap;list-style:none}
summary::-webkit-details-marker{display:none}
.pill{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--c);
min-width:62px}
.t{font-weight:600;flex:1;min-width:200px}
.loc{font:12px ui-monospace,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}
.body{padding:2px 14px 14px;border-top:1px solid var(--line)}
.meta{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0}
.tag{font-size:12px;padding:2px 9px;border-radius:99px;background:var(--code);color:var(--ink);
text-decoration:none}
.tag.ai{color:var(--ai);border:1px solid var(--ai);background:none}
.tag.ok{color:var(--ok);border:1px solid var(--ok);background:none}
pre{background:var(--code);border-radius:6px;padding:10px 12px;overflow-x:auto;margin:10px 0;
font:12.5px/1.5 ui-monospace,Consolas,monospace;direction:ltr;text-align:left}
pre .hit{background:color-mix(in srgb,var(--c) 22%,transparent);display:block}
.lbl{font-size:12px;font-weight:700;color:var(--muted);margin:12px 0 2px;text-transform:uppercase;
letter-spacing:.04em}
.aibox{border-left:3px solid var(--ai);padding:2px 0 2px 12px;margin-top:12px}
.aibox .lbl{color:var(--ai)}
p{margin:4px 0}
.note{font-size:12.5px;color:var(--muted);margin-top:28px;border-top:1px solid var(--line);
padding-top:12px}
@media print{body{background:#fff}details.f{break-inside:avoid}.filters{display:none}
details.f>.body{display:block}}
"""

JS = """
document.querySelectorAll('.filters button').forEach(function(b){b.addEventListener('click',
function(){document.querySelectorAll('.filters button').forEach(function(x){
x.classList.remove('on')});b.classList.add('on');var s=b.dataset.sev;
document.querySelectorAll('details.f').forEach(function(d){
d.style.display=(s==='all'||(d.dataset.status==='open'&&d.dataset.sev===s)||d.dataset.status===s)?'':'none'})})});
window.addEventListener('beforeprint',function(){document.querySelectorAll('details.f')
.forEach(function(d){d.open=true})});
"""


STATUS_TEXT = {"open": "open", "needs_review": "needs review",
               "likely_false_positive": "likely false positive",
               "dismissed": "dismissed by the reviewer"}


def _context_html(finding: Finding) -> str:
    if not finding.context:
        return escape(finding.snippet)
    out = []
    marker = "%4d |" % finding.line
    for row in finding.context.split("\n"):
        text = escape(row)
        out.append('<span class="hit">%s</span>' % text if row.startswith(marker) else text)
    return "\n".join(out).replace("</span>\n", "</span>")


def _finding_html(finding: Finding) -> str:
    kb = info(finding.cwe)
    tags = []
    if finding.cwe:
        tags.append('<a class="tag" href="%s">%s %s</a>'
                    % (escape(kb["url"]), escape(finding.cwe), escape(kb["name"])
                       if kb["name"] != finding.cwe else ""))
    if finding.owasp:
        tags.append('<span class="tag">%s</span>' % escape(finding.owasp))
    tags.append('<span class="tag">risk %.1f / 10</span>' % finding.risk_score)
    tags.append('<span class="tag">confidence %d%%</span>' % round(finding.confidence * 100))
    tags.append('<span class="tag">engines: %s</span>' % escape(", ".join(finding.engines)))
    if finding.tier == "confirmed":
        tags.append('<span class="tag ok">confirmed: %s</span>'
                    % escape("; ".join(finding.evidence)))
    elif finding.tier:
        tags.append('<span class="tag">probable: not independently confirmed</span>')
    if finding.ml_score is not None:
        tags.append('<span class="tag ai">ML %d%%</span>' % round(finding.ml_score * 100))
    if finding.ai_verdict:
        tags.append('<span class="tag ai">AI: %s</span>'
                    % escape(finding.ai_verdict.replace("_", " ")))
    if finding.user_verdict:
        tags.append('<span class="tag ok">reviewer: %s</span>'
                    % escape(finding.user_verdict.replace("_", " ")))
    parts = ['<div class="meta">%s</div>' % "".join(tags),
             "<pre>%s</pre>" % _context_html(finding)]
    if finding.description:
        parts.append('<div class="lbl">Why it matters</div><p dir="auto">%s</p>'
                     % escape(finding.description))
    if finding.fix:
        parts.append('<div class="lbl">How to fix</div><p dir="auto">%s</p>'
                     % escape(finding.fix))
    if finding.ai_explanation or finding.ai_fix:
        ai = ['<div class="aibox"><div class="lbl">AI review (%s)</div>'
              % escape(finding.ai_model or "model")]
        if finding.ai_explanation:
            ai.append('<p dir="auto">%s</p>' % escape(finding.ai_explanation))
        if finding.ai_fix:
            ai.append('<pre dir="auto">%s</pre>' % escape(finding.ai_fix))
        ai.append("</div>")
        parts.append("".join(ai))
    fp = finding.status != "open"
    return (
        '<details class="f%s" data-sev="%s" data-status="%s" style="--c:var(--%s)">'
        '<summary><span class="pill">%s</span><span class="t">%s%s</span>'
        '<span class="loc">%s:%d</span></summary><div class="body">%s</div></details>'
        % (" fp" if fp else "", finding.severity, finding.status, finding.severity,
           finding.severity, escape(finding.title),
           " (%s)" % STATUS_TEXT[finding.status] if fp else "",
           escape(finding.file), finding.line, "".join(parts))
    )


def render_html(result: ScanResult) -> str:
    counts = result.counts()
    total = sum(counts.values())
    grade_color = {"A": "ok", "B": "ok", "C": "medium", "D": "high", "F": "critical"}[
        result.grade]
    sev_boxes = "".join(
        '<div class="sev-box" style="--c:var(--%s)"><b>%d</b><span>%s</span></div>'
        % (s, counts[s], s) for s in SEVERITIES)
    bar = "".join('<i style="--c:var(--%s);width:%.2f%%"></i>' % (s, 100.0 * counts[s] / total)
                  for s in SEVERITIES if total and counts[s])

    by_owasp: Dict[str, int] = {}
    by_file: Dict[str, int] = {}
    for finding in result.open_findings:
        by_owasp[finding.owasp] = by_owasp.get(finding.owasp, 0) + 1
        by_file[finding.file] = by_file.get(finding.file, 0) + 1
    owasp_rows = "".join('<tr><td>%s</td><td class="n">%d</td></tr>' % (escape(k), v)
                         for k, v in sorted(by_owasp.items(), key=lambda kv: -kv[1]))
    file_rows = "".join('<tr><td class="loc">%s</td><td class="n">%d</td></tr>' % (escape(k), v)
                        for k, v in sorted(by_file.items(), key=lambda kv: -kv[1])[:10])
    engine_rows = "".join('<tr><td>%s</td><td>%s</td></tr>' % (escape(k), escape(v))
                          for k, v in result.engine_notes.items())
    engine_rows += "".join('<tr><td>AI: %s</td><td>%s</td></tr>' % (escape(k), escape(str(v)))
                           for k, v in result.ai.items())
    langs = ", ".join("%s (%d)" % (k, v) for k, v in
                      sorted(result.languages.items(), key=lambda kv: -kv[1]))
    fp_count = len(result.findings) - len(result.open_findings)
    other = ["%d %s" % (result.status_count(key), text) for key, text in STATUS_TEXT.items()
             if key != "open" and result.status_count(key)]
    confirmed = sum(1 for f in result.open_findings if f.tier == "confirmed")

    buttons: List[str] = ['<button class="on" data-sev="all">All (%d)</button>'
                          % len(result.findings)]
    buttons += ['<button data-sev="%s">%s (%d)</button>' % (s, s.capitalize(), counts[s])
                for s in SEVERITIES if counts[s]]
    buttons += ['<button data-sev="%s">%s (%d)</button>'
                % (key, text.capitalize(), result.status_count(key))
                for key, text in STATUS_TEXT.items()
                if key != "open" and result.status_count(key)]
    findings_html = "".join(_finding_html(f) for f in result.findings) or \
        '<div class="card">No findings. Remember that a clean scan is not a proof of security.</div>'

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security report</title><style>%(css)s</style></head><body><main>
<h1>Secure Code Analyzer</h1>
<div class="sub">%(target)s</div>
<div class="sub">%(date)s &middot; %(files)d files &middot; %(lines)d lines &middot; %(duration).1f s
&middot; %(langs)s</div>
<div class="grid">
 <div class="card score"><span>Security score</span><b style="color:var(--%(gc)s)">%(score)d</b>
  <span>out of 100</span><br><span class="grade" style="color:var(--%(gc)s)">Grade %(grade)s</span></div>
 <div class="card"><div class="sev-row">%(sev_boxes)s</div><div class="bar">%(bar)s</div>
  <div class="sub">%(total)d open findings%(fp_note)s</div></div>
</div>
<div class="grid" style="grid-template-columns:1fr 1fr">
 <div class="card"><h2 style="margin-top:0">OWASP Top 10 (2021)</h2>
  <table>%(owasp_rows)s</table></div>
 <div class="card"><h2 style="margin-top:0">Most affected files</h2>
  <table>%(file_rows)s</table></div>
</div>
<h2>Findings</h2>
<div class="filters">%(buttons)s</div>
%(findings)s
<h2>Engines</h2>
<div class="card"><table><tr><th>Engine</th><th>Status</th></tr>%(engine_rows)s</table></div>
<div class="note">Generated by Secure Code Analyzer %(version)s. The security score is a heuristic
of this tool and not an official CVSS score. Static analysis can miss vulnerabilities and can report
false positives; AI reviews can be wrong. Verify findings before acting on them.</div>
</main><script>%(js)s</script></body></html>""" % {
        "css": CSS, "js": JS, "target": escape(result.target), "date": escape(result.started_at),
        "files": result.files_scanned, "lines": result.lines_scanned,
        "duration": result.duration_seconds, "langs": escape(langs), "gc": grade_color,
        "score": result.score, "grade": result.grade, "sev_boxes": sev_boxes, "bar": bar,
        "total": total,
        "fp_note": " (%d confirmed by independent evidence)%s" % (
            confirmed, " &middot; not counted: " + escape(", ".join(other)) if other else ""),
        "owasp_rows": owasp_rows or "<tr><td>None</td></tr>",
        "file_rows": file_rows or "<tr><td>None</td></tr>",
        "buttons": "".join(buttons), "findings": findings_html, "engine_rows": engine_rows,
        "version": __version__,
    }
