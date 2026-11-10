"""PDF report (uses fpdf2, pure Python).

The built-in PDF fonts only cover Latin characters, so non-Latin text (for example Arabic
AI explanations) is left out of the PDF; the HTML report shows everything.
"""
from __future__ import annotations

from typing import List

from ..models import SEVERITIES, ScanResult

COLORS = {"critical": (153, 27, 27), "high": (194, 65, 12), "medium": (180, 120, 10),
          "low": (37, 99, 150), "info": (100, 100, 100)}
GRADE_COLORS = {"A": (21, 128, 61), "B": (77, 124, 15), "C": (180, 120, 10),
                "D": (194, 65, 12), "F": (153, 27, 27)}
MAX_FINDINGS = 300


def _latin(text: str, limit: int = 0) -> str:
    text = (text or "").replace("\t", "    ").replace("\r", "")
    out = text.encode("latin-1", "ignore").decode("latin-1")
    return out[:limit] if limit else out


def _is_latin(text: str) -> bool:
    if not text:
        return False
    kept = text.encode("latin-1", "ignore")
    return len(kept) >= 0.9 * len(text)


def render_pdf(result: ScanResult) -> bytes:
    try:
        from fpdf import FPDF
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PDF export needs fpdf2: pip install fpdf2") from exc

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_title("Secure Code Analyzer report")
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    def line(text: str, size: int = 10, style: str = "", color=(30, 30, 30),
             height: float = 5.5) -> None:
        pdf.set_font("Helvetica", style, size)
        pdf.set_text_color(*color)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(width, height, _latin(text) or " ")

    line("Secure Code Analyzer", 20, "B")
    line("Security assessment report", 12, "", (90, 90, 90))
    pdf.ln(3)
    line("Target: %s" % result.target, 9)
    line("Scan date: %s    Duration: %.1f s" % (result.started_at, result.duration_seconds), 9)
    line("Files: %d    Lines of code: %d    Engines: %s"
         % (result.files_scanned, result.lines_scanned, ", ".join(result.engines_used)), 9)
    pdf.ln(4)

    line("Security score: %d / 100    Grade: %s" % (result.score, result.grade), 16, "B",
         GRADE_COLORS.get(result.grade, (30, 30, 30)), 8)
    counts = result.counts()
    line("   ".join("%s: %d" % (s.capitalize(), counts[s]) for s in SEVERITIES), 11, "B")
    hidden = len(result.findings) - len(result.open_findings)
    confirmed = sum(1 for f in result.open_findings if f.tier == "confirmed")
    line("%d of the %d open findings are confirmed by independent evidence."
         % (confirmed, len(result.open_findings)), 9, "", (90, 90, 90))
    if hidden:
        line("%d finding(s) are not counted in the score (needs review, likely false positive "
             "or dismissed) and are listed at the end." % hidden, 9, "I", (90, 90, 90))
    for key in ("ml", "llm"):
        if result.ai.get(key):
            line("AI %s: %s" % (key.upper(), result.ai[key]), 8, "", (90, 90, 90), 4.5)
    pdf.ln(3)

    by_owasp = {}
    for finding in result.open_findings:
        by_owasp[finding.owasp] = by_owasp.get(finding.owasp, 0) + 1
    if by_owasp:
        line("Findings by OWASP Top 10 category", 12, "B")
        for name, count in sorted(by_owasp.items(), key=lambda kv: -kv[1]):
            line("  %3d   %s" % (count, name), 9)
        pdf.ln(3)

    line("Findings", 14, "B")
    shown: List = result.findings[:MAX_FINDINGS]
    for number, finding in enumerate(shown, start=1):
        if pdf.get_y() > pdf.h - 55:
            pdf.add_page()
        pdf.ln(2)
        tag = finding.severity.upper()
        if finding.status != "open":
            tag += " (%s)" % finding.status.replace("_", " ")
        elif finding.tier == "confirmed":
            tag += ", confirmed"
        line("%d. [%s] %s" % (number, tag, finding.title), 10, "B",
             COLORS[finding.severity])
        line("%s:%d    %s    risk %.1f/10    confidence %d%%    engines: %s"
             % (finding.file, finding.line, finding.cwe or "-", finding.risk_score,
                round(finding.confidence * 100), ", ".join(finding.engines)), 8, "",
             (90, 90, 90), 4.5)
        if finding.snippet:
            pdf.set_font("Courier", "", 8)
            pdf.set_text_color(20, 20, 20)
            pdf.set_fill_color(243, 244, 246)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(width, 4.5, _latin(finding.snippet, 300) or " ", fill=True)
        if _is_latin(finding.description):
            line(finding.description, 9)
        if _is_latin(finding.fix):
            line("Fix: " + finding.fix, 9, "I")
        if finding.evidence and finding.status == "open":
            line("Confirmed: " + "; ".join(finding.evidence), 8, "", (21, 128, 61), 4.5)
        if finding.ai_verdict:
            line("AI review (%s): %s" % (finding.ai_model, finding.ai_verdict.replace("_", " ")),
                 9, "B", (70, 50, 140))
            if _is_latin(finding.ai_explanation):
                line(finding.ai_explanation, 9, "", (70, 50, 140))
    if len(result.findings) > MAX_FINDINGS:
        line("... %d more findings are in the HTML/JSON report."
             % (len(result.findings) - MAX_FINDINGS), 9, "I")
    if not result.findings:
        line("No findings.", 10)

    pdf.ln(4)
    line("The security score is a heuristic of this tool, not an official CVSS score. "
         "Static analysis can miss vulnerabilities and can report false positives; "
         "review the findings before acting on them.", 8, "I", (110, 110, 110), 4.5)
    return bytes(pdf.output())
