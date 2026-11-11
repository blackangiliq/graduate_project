"""Score the tool on an OWASP Benchmark project: test cases that were NOT written with it.

    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava
    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython
    python evaluation/owasp_benchmark.py BenchmarkJava BenchmarkPython

Each Benchmark test case is one source file with one planted weakness of a known category
(SQL injection, weak hash, ...). About half of the cases are real vulnerabilities; the other
half look alike but are safe. The file `expectedresults-*.csv` says which is which.

A test case counts as "flagged" when the tool reports, in that file, an open finding of the
category of the test case. From that the usual Benchmark numbers follow:

    TPR   = flagged real cases / all real cases          (how much is found)
    FPR   = flagged safe cases / all safe cases          (how many false alarms)
    score = TPR - FPR      (0 = no better than guessing, 1 = perfect)

Only the static engines run here (no AI provider), in the default and in the strict mode.
The Benchmark projects are GPL licensed and are not part of this repository; only the
numbers measured on them are stored in evaluation/owasp_benchmark.md and .json.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sca import __version__  # noqa: E402
from sca.cwe import canonical  # noqa: E402
from sca.pipeline import ScanOptions, run_scan  # noqa: E402

# Benchmark category -> the CWE ids of this tool that mean the same weakness
CATEGORY_CWES: Dict[str, Set[str]] = {
    "cmdi": {"CWE-78", "CWE-77"},
    "codeinj": {"CWE-94", "CWE-95"},
    "crypto": {"CWE-327", "CWE-326"},
    "deserialization": {"CWE-502"},
    "hash": {"CWE-327", "CWE-328", "CWE-916"},
    "ldapi": {"CWE-90"},
    "pathtraver": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "redirect": {"CWE-601"},
    "securecookie": {"CWE-614", "CWE-1004"},
    "sqli": {"CWE-89", "CWE-564"},
    "trustbound": {"CWE-501"},
    "weakrand": {"CWE-330", "CWE-338"},
    "xpathi": {"CWE-643"},
    "xss": {"CWE-79"},
    "xxe": {"CWE-611"},
}
CATEGORY_NAME = {
    "cmdi": "Command injection", "codeinj": "Code injection", "crypto": "Weak encryption",
    "deserialization": "Insecure deserialization", "hash": "Weak hash",
    "ldapi": "LDAP injection", "pathtraver": "Path traversal", "redirect": "Open redirect",
    "securecookie": "Insecure cookie", "sqli": "SQL injection",
    "trustbound": "Trust boundary violation", "weakrand": "Weak randomness",
    "xpathi": "XPath injection", "xss": "Cross-site scripting", "xxe": "XML external entity",
}
CONFIGS: List[Tuple[str, Dict[str, Any]]] = [
    ("default", {}),
    ("strict", {"strict": True}),
]


def load_expected(project: Path) -> Tuple[Dict[str, Tuple[str, bool]], str]:
    path = sorted(project.glob("expectedresults-*.csv"))[-1]
    expected: Dict[str, Tuple[str, bool]] = {}
    for row in csv.reader(path.open(encoding="utf-8")):
        if row and not row[0].startswith("#"):
            expected[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")
    return expected, path.name


def test_folder(project: Path) -> Path:
    for candidate in ("src/main/java/org/owasp/benchmark/testcode", "testcode"):
        if (project / candidate).is_dir():
            return project / candidate
    raise SystemExit("No test code folder in %s" % project)


def commit(project: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(project), "log", "-1", "--format=%h %cd",
                               "--date=short"], capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""


def flagged_cases(folder: Path, options: Dict[str, Any]) -> Tuple[Dict[str, Set[str]], float, int]:
    """test name -> canonical CWE ids of its open findings."""
    started = time.time()
    result = run_scan(str(folder), ScanOptions(use_llm=False, use_semgrep=False,
                                               use_gitleaks=False, use_feedback=False,
                                               save=False, **options))
    found: Dict[str, Set[str]] = {}
    for finding in result.open_findings:
        name = re.match(r"(BenchmarkTest\d+)", Path(finding.file).name)
        if name:
            found.setdefault(name.group(1), set()).add(canonical(finding.cwe))
    return found, time.time() - started, result.lines_scanned


def score(expected: Dict[str, Tuple[str, bool]], found: Dict[str, Set[str]]
          ) -> List[Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for name, (category, real) in expected.items():
        row = rows.setdefault(category, {"category": category, "tp": 0, "fn": 0, "fp": 0,
                                         "tn": 0})
        wanted = {canonical(c) for c in CATEGORY_CWES.get(category, set())}
        flagged = bool(found.get(name, set()) & wanted)
        row["tp" if real and flagged else "fn" if real else "fp" if flagged else "tn"] += 1
    out = []
    for category in sorted(rows):
        row = rows[category]
        row["tpr"] = row["tp"] / max(1, row["tp"] + row["fn"])
        row["fpr"] = row["fp"] / max(1, row["fp"] + row["tn"])
        row["score"] = row["tpr"] - row["fpr"]
        out.append(row)
    return out


def summary(rows: List[Dict[str, Any]]) -> Dict[str, float]:
    """The Benchmark's own overall figure is the average over categories."""
    tp, fn = sum(r["tp"] for r in rows), sum(r["fn"] for r in rows)
    fp, tn = sum(r["fp"] for r in rows), sum(r["tn"] for r in rows)
    return {
        "tpr_avg": sum(r["tpr"] for r in rows) / len(rows),
        "fpr_avg": sum(r["fpr"] for r in rows) / len(rows),
        "score_avg": sum(r["score"] for r in rows) / len(rows),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": tp / max(1, tp + fp), "recall": tp / max(1, tp + fn),
    }


def table(rows: List[Dict[str, Any]], strict: List[Dict[str, Any]]) -> str:
    lines = ["| Category | Real | Safe | TPR | FPR | Score | Strict: TPR | Strict: FPR | Strict: score |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    by_category = {r["category"]: r for r in strict}
    for row in rows:
        other = by_category[row["category"]]
        lines.append("| %s | %d | %d | %.0f%% | %.0f%% | %+.2f | %.0f%% | %.0f%% | %+.2f |" % (
            CATEGORY_NAME.get(row["category"], row["category"]), row["tp"] + row["fn"],
            row["fp"] + row["tn"], 100 * row["tpr"], 100 * row["fpr"], row["score"],
            100 * other["tpr"], 100 * other["fpr"], other["score"]))
    a, b = summary(rows), summary(strict)
    lines.append("| **Average over categories** | %d | %d | **%.0f%%** | **%.0f%%** | **%+.2f** "
                 "| **%.0f%%** | **%.0f%%** | **%+.2f** |" % (
                     a["tp"] + a["fn"], a["fp"] + a["tn"], 100 * a["tpr_avg"],
                     100 * a["fpr_avg"], a["score_avg"], 100 * b["tpr_avg"], 100 * b["fpr_avg"],
                     b["score_avg"]))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("projects", nargs="+", type=Path, help="Benchmark checkouts")
    parser.add_argument("--out", type=Path, default=ROOT / "evaluation" / "owasp_benchmark")
    args = parser.parse_args()

    report: Dict[str, Any] = {"tool_version": __version__, "projects": []}
    text = ["# Results on the OWASP Benchmark\n",
            "Measured with `python evaluation/owasp_benchmark.py` (static engines only, no AI "
            "provider), tool version %s. These test cases were not written with the tool. "
            "A test case counts as flagged when the tool reports an open finding of the "
            "case's own category in its file. `score = TPR - FPR`: 0 is no better than "
            "guessing, 1 is perfect.\n" % __version__,
            "How to read the history: `owasp_benchmark_baseline.md` holds the first run "
            "(version 1.2.0), made before anything in the tool had been written with these "
            "cases in view. The Benchmark then showed which weakness types the tool did not "
            "know at all. Version 1.3 added them (sink rules for Java; LDAP, XPath, XXE, "
            "cookie and session sinks and dead-branch folding for Python) while looking at "
            "the odd-numbered cases only. The even-numbered cases were never looked at; "
            "their score is reported separately below each table. The cases of one category "
            "are generated from shared templates, so the two halves are similar and the "
            "even half is a weaker check than a different benchmark would be.\n"]
    for project in args.projects:
        expected, expected_file = load_expected(project)
        folder = test_folder(project)
        entry: Dict[str, Any] = {"name": project.name, "commit": commit(project),
                                 "expected": expected_file, "cases": len(expected),
                                 "configs": {}}
        results = {}
        found_by_mode: Dict[str, Dict[str, Set[str]]] = {}
        for label, options in CONFIGS:
            found, seconds, lines = flagged_cases(folder, options)
            found_by_mode[label] = found
            rows = score(expected, found)
            results[label] = rows
            entry["configs"][label] = {"rows": rows, "summary": summary(rows),
                                       "seconds": round(seconds, 1), "lines": lines}
            print("%-16s %-8s score %+.2f  TPR %.0f%%  FPR %.0f%%  (%d lines, %.0f s)" % (
                project.name, label, summary(rows)["score_avg"],
                100 * summary(rows)["tpr_avg"], 100 * summary(rows)["fpr_avg"], lines, seconds))
        # The new rules of version 1.3 were written while looking at the odd-numbered cases
        # only. The even-numbered cases were never looked at: they are the honest check.
        halves = {}
        for label, keep in (("development", 1), ("held_out", 0)):
            subset = {n: v for n, v in expected.items() if int(n[-5:]) % 2 == keep}
            halves[label] = {mode: summary(score(subset, found_by_mode[mode]))
                             for mode in found_by_mode}
        entry["halves"] = halves
        report["projects"].append(entry)
        overall = entry["configs"]["default"]["summary"]
        text += ["## %s\n" % project.name,
                 "%d test cases (%s, commit %s), %s lines, scanned in %.0f s. Over all cases "
                 "in the default mode: %d real cases flagged and %d missed, %d safe cases "
                 "flagged and %d left alone (precision %.2f, recall %.2f).\n" % (
                     len(expected), expected_file, entry["commit"],
                     format(entry["configs"]["default"]["lines"], ","),
                     entry["configs"]["default"]["seconds"], overall["tp"], overall["fn"],
                     overall["fp"], overall["tn"], overall["precision"], overall["recall"]),
                 table(results["default"], results["strict"]) + "\n",
                 "Average score by half of the test cases (the rules added in version 1.3 "
                 "were written looking at the odd-numbered cases only):\n",
                 "| Cases | Default: TPR | FPR | score | Strict: TPR | FPR | score |",
                 "|---|---:|---:|---:|---:|---:|---:|"]
        for label, title in (("development", "Odd-numbered (seen during development)"),
                             ("held_out", "Even-numbered (never looked at)")):
            a, b = halves[label]["default"], halves[label]["strict"]
            text.append("| %s | %.0f%% | %.0f%% | %+.2f | %.0f%% | %.0f%% | %+.2f |" % (
                title, 100 * a["tpr_avg"], 100 * a["fpr_avg"], a["score_avg"],
                100 * b["tpr_avg"], 100 * b["fpr_avg"], b["score_avg"]))
        text.append("")
    args.out.with_suffix(".json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    args.out.with_suffix(".md").write_text("\n".join(text), encoding="utf-8")
    print("Wrote %s and %s" % (args.out.with_suffix(".md"), args.out.with_suffix(".json")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
