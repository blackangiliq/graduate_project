"""Measures the accuracy of the analyzer on the labelled samples.

    python evaluation/evaluate.py                 # static engines
    python evaluation/evaluate.py --llm           # also with the local LLM review (needs Ollama)

For each configuration it counts:
    TP  true positive   a real vulnerability that was reported
    FP  false positive  a report where nothing is wrong
    FN  false negative  a real vulnerability that was missed
and computes precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = harmonic mean of both.

Ground truth: samples/ground_truth.json (tags in samples/vulnerable_app) and the rule that
every finding in samples/safe_app is a false positive.

IMPORTANT: these samples were written together with the tool, so the numbers show that the
pipeline works; they are NOT an unbiased benchmark. For the thesis, also run a public
benchmark (see docs/GUIDE_AR.md, section "التقييم").
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sca.cwe import canonical  # noqa: E402
from sca.models import Finding  # noqa: E402
from sca.pipeline import ScanOptions, run_scan  # noqa: E402

TAG = re.compile(r"\[([A-Z]\d{2})\]")
VULN_DIR = ROOT / "samples" / "vulnerable_app"
SAFE_DIR = ROOT / "samples" / "safe_app"


def load_ground_truth() -> List[Dict]:
    """Return one item per tagged line: file, line, required CWEs, accepted CWEs, hard flag."""
    tags = json.loads((ROOT / "samples" / "ground_truth.json").read_text(encoding="utf-8"))["tags"]
    items, seen = [], set()
    for path in sorted(VULN_DIR.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(VULN_DIR).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for tag in TAG.findall(line):
                if tag not in tags:
                    raise SystemExit("Tag %s in %s is missing from ground_truth.json" % (tag, rel))
                seen.add(tag)
                spec = tags[tag]
                items.append({
                    "tag": tag, "file": rel, "line": number,
                    "cwe": [canonical(c) for c in spec.get("cwe", [])],
                    "also": [canonical(c) for c in spec.get("also", [])],
                    "hard": bool(spec.get("hard")), "note": spec.get("note", ""),
                })
    missing = set(tags) - seen
    if missing:
        raise SystemExit("Tags in ground_truth.json not found in the samples: %s" % sorted(missing))
    return items


def score(findings: List[Finding], safe_findings: List[Finding], truth: List[Dict]) -> Dict:
    expected = [(item, cwe) for item in truth for cwe in item["cwe"]]
    matched = set()
    false_positives: List[Finding] = list(safe_findings)
    for finding in findings:
        cwe = canonical(finding.cwe)
        hit = False
        for index, (item, wanted) in enumerate(expected):
            if item["file"] == finding.file and abs(item["line"] - finding.line) <= 1 \
                    and wanted == cwe:
                matched.add(index)
                hit = True
        if hit:
            continue
        accepted = any(item["file"] == finding.file and abs(item["line"] - finding.line) <= 1
                       and cwe in item["also"] for item in truth)
        if not accepted:
            false_positives.append(finding)
    tp = len(matched)
    fn_items = [expected[i] for i in range(len(expected)) if i not in matched]
    fp = len(false_positives)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + len(fn_items)) if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "fn": len(fn_items),
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "missed": [{"tag": i["tag"], "file": i["file"], "line": i["line"], "cwe": c,
                    "hard": i["hard"], "note": i["note"]} for i, c in fn_items],
        "false_positives": [{"file": ("safe_app/" if f in safe_findings else "") + f.file,
                             "line": f.line, "cwe": f.cwe, "title": f.title,
                             "engines": f.engines, "confidence": f.confidence}
                            for f in false_positives],
    }


def run_config(name: str, options: ScanOptions, truth: List[Dict]) -> Dict:
    options.save = False
    vulnerable = run_scan(str(VULN_DIR), options)
    safe = run_scan(str(SAFE_DIR), options)
    result = score(vulnerable.open_findings, safe.open_findings, truth)
    result["name"] = name
    result["ai"] = vulnerable.ai
    return result


def static_options(**overrides) -> ScanOptions:
    # use_feedback=False: the measurement must not depend on reviews stored on this machine
    base = dict(use_rules=False, use_ast=False, use_secrets=False, use_bandit=False,
                use_semgrep=False, use_gitleaks=False, use_ml=False, use_llm=False,
                use_feedback=False)
    base.update(overrides)
    return ScanOptions(**base)


def load_llm_settings(args) -> Dict:
    """Provider settings: saved configuration (python -m sca config), --provider/--model win."""
    from sca.ai.llm import DEFAULT_MODEL
    from sca.ai.providers import load_config

    config = load_config()
    provider = args.provider or config.preset
    same = provider == config.preset
    model = args.model or (config.model if same else "") or \
        (DEFAULT_MODEL if provider == "ollama" else "")
    return {"llm_provider": provider, "llm_model": model,
            "llm_base_url": config.base_url if same else "",
            "llm_api_key": config.api_key if same else ""}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--llm", action="store_true",
                        help="add runs reviewed by the configured AI provider")
    parser.add_argument("--deep", action="store_true", help="the AI also audits whole files")
    parser.add_argument("--provider", help="AI provider (default: saved setting)")
    parser.add_argument("--model", help="model name (default: saved setting)")
    parser.add_argument("--out", default=str(ROOT / "evaluation" / "results"))
    args = parser.parse_args()

    truth = load_ground_truth()
    total = sum(len(i["cwe"]) for i in truth)
    hard = sum(len(i["cwe"]) for i in truth if i["hard"])
    decoys = sum(1 for i in truth if not i["cwe"])
    print("Ground truth: %d vulnerabilities (%d marked hard), %d safe decoy lines, "
          "plus the safe_app folder\n" % (total, hard, decoys))

    configs: List[Tuple[str, ScanOptions]] = [
        ("Bandit only (Python baseline)", static_options(use_bandit=True)),
        ("Pattern rules + secrets", static_options(use_rules=True, use_secrets=True)),
        ("+ Python AST taint engine", static_options(use_rules=True, use_secrets=True,
                                                     use_ast=True)),
        ("All static engines", static_options(use_rules=True, use_secrets=True, use_ast=True,
                                              use_bandit=True, use_semgrep=True,
                                              use_gitleaks=True)),
    ]
    everything = dict(use_rules=True, use_secrets=True, use_ast=True, use_bandit=True,
                      use_semgrep=True, use_gitleaks=True)
    configs.append(("All static, strict mode (confirmed only)",
                    static_options(strict=True, **everything)))
    if args.llm or args.deep:
        settings = load_llm_settings(args)
        configs.append(("All static + AI review", static_options(
            use_ml=True, use_llm=True, llm_max_findings=500, llm_deep_scan=args.deep,
            **everything, **settings)))
        configs.append(("All static + AI review, strict mode", static_options(
            use_ml=True, use_llm=True, llm_max_findings=500, llm_deep_scan=args.deep,
            strict=True, **everything, **settings)))

    results = [run_config(name, options, truth) for name, options in configs]

    header = "| Configuration | TP | FP | FN | Precision | Recall | F1 |"
    lines = [header, "|---|---:|---:|---:|---:|---:|---:|"]
    for r in results:
        lines.append("| %s | %d | %d | %d | %.3f | %.3f | %.3f |" % (
            r["name"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"], r["f1"]))
    table = "\n".join(lines)
    print(table)

    last = next(r for r in results if r["name"] == "All static engines")
    print("\nMissed by '%s':" % last["name"])
    for m in last["missed"]:
        print("  %s %s:%d %s%s - %s" % (m["tag"], m["file"], m["line"], m["cwe"],
                                         " [hard]" if m["hard"] else "", m["note"]))
    print("\nFalse positives of '%s':" % last["name"])
    for f in last["false_positives"]:
        print("  %s:%d %s %s (%s)" % (f["file"], f["line"], f["cwe"], f["title"],
                                     "+".join(f["engines"])))
    if any("AI review" in r["name"] for r in results):
        print("\nAI status: %s" % results[-1]["ai"].get("llm"))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    md = ["# Evaluation results", "",
          "Samples: `samples/vulnerable_app` (%d labelled vulnerabilities, %d of them marked "
          "hard, %d safe decoy lines) and `samples/safe_app` (no vulnerabilities)."
          % (total, hard, decoys), "",
          "These samples were written together with the tool. The numbers show that the "
          "pipeline works end to end; they are not an unbiased benchmark.", "", table, "",
          "## Missed (%s)" % last["name"], ""]
    md += ["- `%s:%d` %s%s: %s" % (m["file"], m["line"], m["cwe"],
                                   " (hard)" if m["hard"] else "", m["note"])
           for m in last["missed"]] or ["- none"]
    md += ["", "## False positives (%s)" % last["name"], ""]
    md += ["- `%s:%d` %s %s (engines: %s)" % (f["file"], f["line"], f["cwe"], f["title"],
                                             ", ".join(f["engines"]))
           for f in last["false_positives"]] or ["- none"]
    out.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\nSaved %s and %s" % (out.with_suffix(".md"), out.with_suffix(".json")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
