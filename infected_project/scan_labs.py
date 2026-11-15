"""Scan every downloaded lab with the static engines and write RESULTS.md and results.json.

    python infected_project/scan_labs.py              # every lab that fetch_labs.py brought
    python infected_project/scan_labs.py --reports    # also an HTML and JSON report per lab

Static engines only: no AI provider is called, so the numbers do not depend on a model.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from sca import __version__  # noqa: E402
from sca.cwe import info  # noqa: E402
from sca.pipeline import ScanOptions, run_scan  # noqa: E402
from sca.report import write_reports  # noqa: E402


def summarize(lab: dict, result) -> dict:
    open_findings = result.open_findings
    cwes = Counter(f.cwe for f in open_findings)
    return {
        "name": lab["name"], "repo": lab["repo"], "commit": lab["commit"],
        "languages": lab["languages"], "files": result.files_scanned,
        "lines": result.lines_scanned, "seconds": round(result.duration_seconds, 1),
        "score": result.score, "grade": result.grade, "open": len(open_findings),
        "confirmed": sum(1 for f in open_findings if f.tier == "confirmed"),
        "severity": result.counts(), "engines": result.engines_used,
        "top_weaknesses": [[cwe, info(cwe)["name"] if info(cwe)["name"] != cwe else "", n]
                           for cwe, n in cwes.most_common(5)],
    }


def write_markdown(rows: list) -> None:
    total = {k: sum(r[k] for r in rows) for k in ("files", "lines", "open", "confirmed")}
    lines = [
        "# Scan results of the training labs / نتائج فحص المختبرات",
        "",
        "Secure Code Analyzer %s, static engines only (no AI), %s. Produced by "
        "`python infected_project/scan_labs.py`; each lab at the commit in `labs.json`."
        % (__version__, date.today().isoformat()),
        "",
        "أداة Secure Code Analyzer %s بالمحركات الستاتيكية فقط (دون ذكاء اصطناعي). "
        "كل مختبر عند الـ commit المذكور في `labs.json`." % __version__,
        "",
        "| Lab | Languages | Files | Lines | Findings | Confirmed | Critical | High | "
        "Score | Time | Main weaknesses found |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for r in rows:
        lines.append("| [%s](https://github.com/%s) | %s | %d | %s | %d | %d | %d | %d | %d (%s) "
                     "| %.1f s | %s |" % (
                         r["name"], r["repo"], r["languages"], r["files"],
                         format(r["lines"], ","), r["open"], r["confirmed"],
                         r["severity"]["critical"], r["severity"]["high"], r["score"],
                         r["grade"], r["seconds"],
                         ", ".join(("%s %s (%d)" % (c, n, k)).replace("  ", " ")
                                   for c, n, k in r["top_weaknesses"])))
    lines += [
        "| **All %d labs** | | **%d** | **%s** | **%d** | **%d** | | | | | |"
        % (len(rows), total["files"], format(total["lines"], ","), total["open"],
           total["confirmed"]),
        "",
        "*Findings* are the open findings; *confirmed* ones are backed by independent evidence "
        "(input traced to the line, or a weakness that is a property of the line itself). "
        "The rest are probable and wait for a review. How good these findings are, and what "
        "was missed, is in [REVIEW.md](REVIEW.md).",
        "",
    ]
    (HERE / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reports", action="store_true", help="HTML + JSON report per lab")
    args = parser.parse_args()
    labs = json.loads((HERE / "labs.json").read_text(encoding="utf-8"))
    present = [lab for lab in labs if (HERE / lab["name"]).is_dir()]
    if not present:
        print("No lab downloaded yet. Run: python infected_project/fetch_labs.py")
        return 1
    options = ScanOptions(use_llm=False, save=False)
    rows = []
    for lab in present:
        print("Scanning %s ..." % lab["name"], flush=True)
        result = run_scan(str(HERE / lab["name"]), options)
        rows.append(summarize(lab, result))
        print("  %d files, %d findings (%d confirmed), score %d (%s), %.1f s"
              % (result.files_scanned, rows[-1]["open"], rows[-1]["confirmed"], result.score,
                 result.grade, result.duration_seconds), flush=True)
        if args.reports:
            write_reports(result, str(HERE / "reports" / lab["name"]), ["html", "json"])
    (HERE / "results.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    write_markdown(rows)
    print("\nWrote %s and %s" % (HERE / "RESULTS.md", HERE / "results.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
