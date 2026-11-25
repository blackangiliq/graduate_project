"""Measures the Flutter / Android part of the analyzer.

    python evaluation/flutter_eval.py                  # samples, labs, and probe builds if given
    python evaluation/flutter_eval.py --apks DIR       # DIR holds the probe builds (debug.apk ...)
    python evaluation/flutter_eval.py --no-labs        # skip the three Flutter labs

1. Samples   samples/flutter_vulnerable_app, labelled by samples/flutter_ground_truth.json
             (comment tags and anchors), and samples/flutter_safe_app, where every finding is a
             false positive: TP, FP, FN, precision, recall and F1 per configuration, counted
             exactly as evaluation/evaluate.py counts them.
2. DVMA      module-level recall: a module of config/registry/categories counts as found when
             an open finding in lib/modules/<category>/<module>/ has one of its CWEs.
3. Ostorlab, DVFA   recall per file / per challenge from evaluation/flutter_truth/*.json.
4. APK probe which weaknesses planted in samples/flutter_apk_probe are still found in the app
             packages built from it (tools/build_flutter_apks.py), next to its source scan.
             The folder comes from --apks or the SCA_FLUTTER_PROBE_DIR environment variable.
5. API probe which server addresses, keys and service identifiers of
             samples/flutter_api_probe the API and key inventory lists, in its source and in
             the packages built from it (--api-apks or SCA_FLUTTER_API_DIR), against
             evaluation/flutter_truth/api_probe.json.

Static engines only: no AI provider is called and reviews stored on this computer are not
used. Writes evaluation/flutter_results.json and .md (--out changes the path).

IMPORTANT: the samples and the probe were written together with the tool, so their numbers
show that the module works; they are not an unbiased benchmark. The labs were not written
with the tool, but their truth files were written for this evaluation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from evaluate import TAG, score, static_options  # noqa: E402
from sca import __version__  # noqa: E402
from sca.cwe import canonical  # noqa: E402
from sca.models import Finding, ScanResult  # noqa: E402
from sca.pipeline import ScanOptions, run_scan  # noqa: E402

SAMPLES = ROOT / "samples"
VULN_DIR = SAMPLES / "flutter_vulnerable_app"
SAFE_DIR = SAMPLES / "flutter_safe_app"
PROBE_DIR = SAMPLES / "flutter_apk_probe"
GROUND_TRUTH = SAMPLES / "flutter_ground_truth.json"
TRUTH_DIR = HERE / "flutter_truth"
LABS_DIR = ROOT / "infected_project"
LINE_WINDOW = 1            # a finding may be one line away from the labelled line (evaluate.py)
TAG_GROUPS = (("D", "Dart code"),
              ("M", "Android, iOS, Firebase, web and build configuration"),
              ("G", "Dependencies (pubspec.lock)"))
LAB_TRUTH = (("Ostorlab-Insecure-Flutter", "ostorlab.json"), ("DVFA", "dvfa.json"))
PROBE_BUILDS = (("debug", "debug.apk"), ("profile", "profile.apk"), ("release", "release.apk"),
                ("release_obf", "release_obf.apk"), ("aab", "release.aab"))
EVERYTHING = dict(use_rules=True, use_secrets=True, use_ast=True, use_bandit=True,
                  use_semgrep=True, use_gitleaks=True, use_c_memory=True, use_flutter=True)
MAIN_CONFIG = "All static engines"


def configurations() -> List[Tuple[str, ScanOptions]]:
    """The configurations measured on the samples; the labs and the probe use MAIN_CONFIG."""
    return [
        ("Pattern rules + secrets (no Flutter checks)",
         static_options(use_rules=True, use_secrets=True, use_flutter=False)),
        (MAIN_CONFIG, static_options(**EVERYTHING)),
        ("All static, strict mode (confirmed only)", static_options(strict=True, **EVERYTHING)),
    ]


def scan(target: Path, options: Optional[ScanOptions] = None) -> ScanResult:
    """One scan, never stored in the history."""
    options = options or static_options(**EVERYTHING)
    options.save = False
    return run_scan(str(target), options)


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ 1. samples
def resolve_anchor(folder: Path, anchor: Dict[str, str]) -> int:
    """The line an anchor labels: the first line of anchor["file"] that contains
    anchor["text"], searching from the first line that contains anchor["near"] (from line 1
    without near); 0 when there is none. Same rule as tests/test_flutter_samples.py."""
    lines = (folder / anchor["file"]).read_text(encoding="utf-8").splitlines()
    start = 0
    if anchor.get("near"):
        start = next((i for i, line in enumerate(lines) if anchor["near"] in line), len(lines))
    return next((i + 1 for i in range(start, len(lines)) if anchor["text"] in lines[i]), 0)


def load_ground_truth(folder: Path = VULN_DIR, truth_file: Path = GROUND_TRUTH) -> List[Dict]:
    """One item per labelled line, as evaluate.load_ground_truth returns them: tag, file, line,
    required CWEs, accepted CWEs, hard flag and note."""
    tags = read_json(truth_file)["tags"]
    places: Dict[str, Tuple[str, int]] = {}
    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(folder).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for tag in TAG.findall(line):
                if tag not in tags:
                    raise SystemExit("Tag %s in %s is missing from %s" % (tag, rel,
                                                                          truth_file.name))
                places[tag] = (rel, number)
    for tag, spec in tags.items():
        if "anchor" in spec:
            number = resolve_anchor(folder, spec["anchor"])
            if not number:
                raise SystemExit("The anchor of %s does not label a line" % tag)
            places[tag] = (spec["anchor"]["file"], number)
    missing = sorted(set(tags) - set(places))
    if missing:
        raise SystemExit("Tags of %s not found in the sample: %s" % (truth_file.name, missing))
    return [{"tag": tag, "file": rel, "line": number,
             "cwe": [canonical(c) for c in tags[tag].get("cwe", [])],
             "also": [canonical(c) for c in tags[tag].get("also", [])],
             "hard": bool(tags[tag].get("hard")), "note": tags[tag].get("note", "")}
            for tag, (rel, number) in sorted(places.items(), key=lambda kv: (kv[1], kv[0]))]


def truth_counts(truth: List[Dict]) -> Dict[str, int]:
    return {"weaknesses": sum(len(i["cwe"]) for i in truth),
            "hard": sum(len(i["cwe"]) for i in truth if i["hard"]),
            "decoys": sum(1 for i in truth if not i["cwe"])}


def score_samples(vulnerable: List[Finding], safe: List[Finding], truth: List[Dict]) -> Dict:
    """evaluate.score, with the false positives of the safe app named by its folder."""
    result = score(vulnerable, safe, truth)
    for item in result["false_positives"]:
        if item["file"].startswith("safe_app/"):
            item["file"] = "%s/%s" % (SAFE_DIR.name, item["file"][len("safe_app/"):])
    return result


def recall_by_group(truth: List[Dict], missed: List[Dict]) -> List[Dict]:
    """Recall of each part of the sample (tag letters D, M, G)."""
    rows = []
    for letter, name in TAG_GROUPS:
        expected = sum(len(i["cwe"]) for i in truth if i["tag"][0] == letter)
        lost = sum(1 for m in missed if m["tag"][0] == letter)
        rows.append({"group": letter, "name": name, "expected": expected,
                     "found": expected - lost,
                     "recall": round((expected - lost) / expected, 3) if expected else 0.0})
    return rows


def evaluate_samples(configs: Optional[Sequence[Tuple[str, ScanOptions]]] = None) -> Dict:
    truth = load_ground_truth()
    results = []
    for name, options in configs or configurations():
        began = time.time()
        vulnerable = scan(VULN_DIR, options)
        safe = scan(SAFE_DIR, options)
        result = score_samples(vulnerable.open_findings, safe.open_findings, truth)
        result.update(name=name, seconds=round(time.time() - began, 1))
        results.append(result)
    main = next((r for r in results if r["name"] == MAIN_CONFIG), results[-1])
    return {"truth": truth_counts(truth), "configs": results, "main": main["name"],
            "groups": recall_by_group(truth, main["missed"])}


# ------------------------------------------------------------------ matching
def at_location(finding: Finding, cwes: Iterable[str], file: str, line: int) -> bool:
    return (finding.file == file and abs(finding.line - line) <= LINE_WINDOW
            and canonical(finding.cwe) in {canonical(c) for c in cwes})


def describe(finding: Finding) -> Dict[str, Any]:
    return {"file": finding.file, "line": finding.line, "cwe": canonical(finding.cwe),
            "rules": list(finding.rule_ids)}


def describe_all(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
    """The findings once each, in file and line order."""
    unique = {id(f): f for f in findings}
    return [describe(f) for f in sorted(unique.values(), key=lambda f: (f.file, f.line))]


def scan_facts(result: ScanResult, seconds: float) -> Dict[str, Any]:
    return {"files": result.files_scanned, "lines": result.lines_scanned,
            "open": len(result.open_findings), "seconds": round(seconds, 1)}


# ------------------------------------------------------------------ 2. DVMA
def load_dvma(root: Path) -> List[Dict[str, Any]]:
    """DVMA's registry: one entry per module with its category, id, title, canonical CWEs and
    the folder of its code. A category is one YAML file or a folder of shards."""
    folder = root / "config" / "registry" / "categories"
    modules = []
    for path in sorted(folder.glob("*.yaml")) + sorted(folder.glob("*/*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for category, body in data.items():
            for module in (body or {}).get("vulnerabilities") or []:
                modules.append({
                    "category": category, "id": module["id"], "title": module.get("title", ""),
                    "cwe": sorted({canonical(c) for c in module.get("cwe") or []}),
                    "folder": "lib/modules/%s/%s/" % (category, module["id"])})
    return modules


def score_dvma(modules: List[Dict[str, Any]], findings: List[Finding],
               kinds: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """Module-level recall: found = an open finding in the module's folder with one of its
    CWEs; any = any open finding in the folder. Totals per category and per kind."""
    rows = []
    for module in modules:
        inside = [f for f in findings if f.file.startswith(module["folder"])]
        found = [f for f in inside if canonical(f.cwe) in module["cwe"]]
        rows.append(dict(module, kind=kinds.get(module["category"], {}).get("kind", ""),
                         found=bool(found), any=bool(inside), by=describe_all(found)))

    def total(name: str, group: List[Dict]) -> Dict[str, Any]:
        count = len(group)
        return {"name": name, "modules": count, "found": sum(r["found"] for r in group),
                "any": sum(r["any"] for r in group),
                "recall": round(sum(r["found"] for r in group) / count, 3) if count else 0.0}
    categories = []
    for name in dict.fromkeys(r["category"] for r in rows):
        group = [r for r in rows if r["category"] == name]
        categories.append(dict(total(name, group), kind=group[0]["kind"]))
    by_kind = [total(kind, [r for r in rows if r["kind"] == kind])
               for kind in dict.fromkeys(r["kind"] for r in rows)]
    # app-level findings (manifest, Info.plist, Gradle, CI) belong to no single module
    outside = Counter(rule for f in findings if not f.file.startswith("lib/modules/")
                      for rule in f.rule_ids[:1])
    return {"total": total("all", rows), "categories": categories, "kinds": by_kind,
            "outside": dict(outside.most_common()), "modules": rows}


def category_order(root: Path) -> List[str]:
    """DVMA's own order of categories (config/registry/meta.yaml), if it has one."""
    path = root / "config" / "registry" / "meta.yaml"
    try:
        order = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("category_order")
    except (OSError, yaml.YAMLError):
        return []
    return [str(name) for name in order or []]


def evaluate_dvma(root: Path) -> Dict[str, Any]:
    truth = read_json(TRUTH_DIR / "dvma.json")
    modules = load_dvma(root)
    order = category_order(root)
    modules.sort(key=lambda m: order.index(m["category"]) if m["category"] in order
                 else len(order))
    began = time.time()
    result = scan(root)
    out = score_dvma(modules, result.open_findings, truth["categories"])
    out["scan"] = scan_facts(result, time.time() - began)
    out["kinds_text"] = truth["kinds"]
    out["why"] = {name: spec["why"] for name, spec in truth["categories"].items()}
    return out


# ------------------------------------------------------------------ 3. labs with truth files
def score_lab(truth: Dict[str, Any], findings: List[Finding]) -> Dict[str, Any]:
    """Recall per item of a lab truth file (see evaluation/flutter_truth/dvfa.json)."""
    items, matched = [], set()
    for item in truth["items"]:
        hits = [f for f in findings for place in item["locations"]
                if at_location(f, item["cwe"], place["file"], place["line"])]
        matched.update(id(f) for f in hits)
        items.append({"id": item["id"], "title": item["title"], "cwe": item["cwe"],
                      "hard": bool(item.get("hard")), "where": item["locations"],
                      "found": bool(hits), "by": describe_all(hits),
                      "note": item.get("note", "")})

    def recall(group: List[Dict]) -> Dict[str, Any]:
        found = sum(i["found"] for i in group)
        return {"items": len(group), "found": found,
                "recall": round(found / len(group), 3) if group else 0.0}
    return {"unit": truth.get("unit", "item"), "all": recall(items),
            "not_hard": recall([i for i in items if not i["hard"]]),
            "matched_findings": len(matched), "items": items}


def evaluate_lab(root: Path, truth_file: Path) -> Dict[str, Any]:
    began = time.time()
    result = scan(root)
    out = score_lab(read_json(truth_file), result.open_findings)
    out["scan"] = scan_facts(result, time.time() - began)
    return out


# ------------------------------------------------------------------ 4. APK probe
def probe_match(item: Dict[str, Any], finding: Finding, globs: Sequence[str]) -> bool:
    if canonical(finding.cwe) != canonical(item["cwe"]):
        return False
    if not any(fnmatchcase(finding.file, glob) for glob in globs):
        return False
    rules = item.get("rules") or []
    return not rules or any(fnmatchcase(rule, pattern)
                            for rule in finding.rule_ids for pattern in rules)


def score_probe(items: List[Dict[str, Any]], findings: List[Finding],
                mode: str) -> Dict[str, Any]:
    """Status of every item in one scan ("source" or a build mode): found, missed, n/a
    (not expected and not found) or unexpected (found where it should not be)."""
    status, used = {}, set()
    for item in items:
        globs = item.get("source", []) if mode == "source" else item.get("app", [])
        expected = bool(globs) and (mode == "source" or mode in item.get("modes", [mode]))
        hits = [f for f in findings if globs and probe_match(item, f, globs)]
        used.update(id(f) for f in hits)
        status[item["id"]] = {
            "state": ("found" if hits else "missed") if expected
            else ("unexpected" if hits else "n/a"),
            "by": describe_all(hits)}
    others = [dict(describe(f), severity=f.severity, title=f.title)
              for f in findings if id(f) not in used]
    return {"items": status, "others": others}


def probe_builds(folder: Path) -> List[Tuple[str, Path]]:
    return [(mode, folder / name) for mode, name in PROBE_BUILDS if (folder / name).is_file()]


def evaluate_probe(folder: Optional[Path]) -> Dict[str, Any]:
    """Source scan of the probe plus one scan per build found in `folder`."""
    items = read_json(TRUTH_DIR / "apk_probe.json")["items"]
    runs: List[Dict[str, Any]] = []
    targets: List[Tuple[str, Path]] = [("source", PROBE_DIR)]
    targets += probe_builds(folder) if folder else []
    for mode, target in targets:
        began = time.time()
        result = scan(target)
        seconds = time.time() - began
        run = dict(score_probe(items, result.open_findings, mode), mode=mode,
                   target=target.name if mode != "source" else "samples/flutter_apk_probe",
                   scan=scan_facts(result, seconds))
        if mode != "source":
            facts = result.app or {}
            run["package"] = {key: facts.get(key) for key in (
                "size_bytes", "sha256", "build_mode", "obfuscated", "dart_version")}
        runs.append(run)
    modes = [run["mode"] for run in runs]
    shown = [item for item in items
             if item.get("source") or set(item.get("modes", modes)) & set(modes)]
    built_by = {}
    if folder and (folder / "builds.json").is_file():
        sdk = read_json(folder / "builds.json").get("sdk") or {}
        built_by = {"flutter": sdk.get("flutterVersion", ""), "dart": sdk.get("dartSdkVersion", "")}
    planted = [item for item in shown if item["id"].startswith("P")]
    totals = {run["mode"]: sum(run["items"][i["id"]]["state"] == "found" for i in planted)
              for run in runs}
    return {"items": [{key: item[key] for key in ("id", "what", "cwe")} for item in shown],
            "planted": len(planted), "found": totals, "runs": runs, "built_with": built_by,
            "apk_folder_given": bool(folder)}


API_PROBE_DIR = SAMPLES / "flutter_api_probe"
API_BUILDS = (("debug", "debug.apk"), ("release", "release.apk"),
              ("obfuscated", "release_obf.apk"))


def inventory_match(match: Dict[str, Any], apis: Dict[str, Any]) -> bool:
    """True when the inventory of one scan lists what a row of api_probe.json describes."""
    keys = apis.get("keys") or []
    alerts = {a.get("code") for a in apis.get("alerts") or []}
    if "key_advice" in match:
        return any(k.get("advice") == match["key_advice"] for k in keys)
    if "key_used_by" in match:
        return any(match["key_used_by"] in (k.get("used_by") or "") for k in keys)
    if "key_role" in match:
        return any((k.get("claims") or {}).get("role") == match["key_role"] for k in keys)
    if "key_file" in match:
        return any(loc.get("file", "").endswith(match["key_file"])
                   for k in keys for loc in k.get("locations") or [])
    if "env_secret" in match:
        return any(e.get("name") == match["env_secret"] and e.get("secret")
                   for e in apis.get("env") or [])
    if "alert" in match:
        return match["alert"] in alerts
    if "endpoint_alert" in match:
        return any(match["endpoint_alert"] in e.get("alerts", [])
                   for e in apis.get("endpoints") or [])
    if "path_alert" in match:
        return any(match["path_alert"] in p.get("alerts", []) for p in apis.get("paths") or [])
    if "endpoint" in match:
        return any(e.get("url") == match["endpoint"] for e in apis.get("endpoints") or [])
    if "host" in match:
        return any(e.get("host") == match["host"] for e in apis.get("endpoints") or [])
    if "firebase" in match:
        return all((apis.get("firebase") or {}).get(name) for name in match["firebase"])
    if "config" in match:
        return any(c.get("label") == match["config"] for c in apis.get("config") or [])
    if "paths" in match:
        return set(match["paths"]) <= {p.get("path") for p in apis.get("paths") or []}
    if "calls" in match:
        return len(apis.get("calls") or []) >= match["calls"]
    raise ValueError("unknown match %r" % match)


def evaluate_inventory(folder: Optional[Path]) -> Dict[str, Any]:
    """The API and key inventory of samples/flutter_api_probe: its source, and the packages
    built from it in `folder` (debug.apk, release.apk, release_obf.apk)."""
    items = read_json(TRUTH_DIR / "api_probe.json")["items"]
    targets: List[Tuple[str, Path]] = [("source", API_PROBE_DIR)]
    builds = [(mode, folder / name) for mode, name in API_BUILDS
              if folder and (folder / name).is_file()]
    targets += builds
    runs = []
    for mode, target in targets:
        began = time.time()
        result = scan(target)
        apis = (result.app or {}).get("apis") or {}
        states = {}
        for item in items:
            expected = mode in item.get("modes", ["source", "debug", "release", "obfuscated"])
            found = inventory_match(item["match"], apis)
            states[item["id"]] = ("found" if found else "missed") if expected \
                else ("unexpected" if found else "n/a")
        summary = apis.get("summary") or {}
        runs.append({"mode": mode, "target": target.name if mode != "source"
                     else "samples/flutter_api_probe", "items": states,
                     "seconds": round(time.time() - began, 1),
                     "summary": {key: summary.get(key) for key in (
                         "endpoints", "hosts", "keys", "secret_keys", "calls", "paths",
                         "config", "env")},
                     "alerts": summary.get("alerts") or {}})
    expected = {run["mode"]: sum(1 for i in items if run["mode"] in i.get(
        "modes", ["source", "debug", "release", "obfuscated"])) for run in runs}
    found = {run["mode"]: sum(1 for state in run["items"].values() if state == "found")
             for run in runs}
    return {"items": [{key: item[key] for key in ("id", "what")} for item in items],
            "runs": runs, "expected": expected, "found": found,
            "apk_folder_given": bool(builds)}


def markdown_inventory(inv: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    if not inv["apk_folder_given"]:
        lines += ["Only the source scan: no folder of builds was given (`--api-apks DIR` or "
                  "SCA_FLUTTER_API_DIR; build them with `python tools/build_flutter_apks.py "
                  "--app flutter_api_probe --modes release,obfuscated,debug --out DIR`).", ""]
    runs = inv["runs"]
    lines += ["`samples/flutter_api_probe` is full of server addresses and keys "
              "(evaluation/flutter_truth/api_probe.json lists %d items). Each column is one "
              "scan: the source folder, then the packages built from it. *found* = listed by "
              "the inventory (`facts['apis']`), **missed** = present but not listed, *-* = not "
              "expected in that scan (a key written in parts in the source, or calls in a "
              "release build that keeps no code text)." % len(inv["items"]), ""]
    lines.append("| Id | Item | %s |" % " | ".join(r["mode"] for r in runs))
    lines.append("|---|---|" + "---|" * len(runs))
    for item in inv["items"]:
        lines.append("| %s | %s | %s |" % (item["id"], item["what"], " | ".join(
            STATE_TEXT[r["items"][item["id"]]] for r in runs)))
    lines.append("| | **Listed** | %s |" % " | ".join(
        "**%d of %d**" % (inv["found"][r["mode"]], inv["expected"][r["mode"]]) for r in runs))
    lines += ["", "| Scan | Addresses | Hosts | Keys (secret) | Calls | API paths | Service IDs "
              "| .env entries | Alerts (danger / warning / info) | Time |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|"]
    for run in runs:
        s, a = run["summary"], run["alerts"]
        lines.append("| %s | %s | %s | %s (%s) | %s | %s | %s | %s | %s / %s / %s | %.1f s |" % (
            run["target"], s["endpoints"], s["hosts"], s["keys"], s["secret_keys"], s["calls"],
            s["paths"], s["config"], s["env"], a.get("danger", 0), a.get("warning", 0),
            a.get("info", 0), run["seconds"]))
    return lines + [""]


# ------------------------------------------------------------------ report
def pct(value: float) -> str:
    return "%.1f%%" % (100 * value)


def markdown(results: Dict[str, Any]) -> str:
    lines = ["# Flutter / Android evaluation", "",
             "Secure Code Analyzer %s, static engines only (no AI), %s. Produced by "
             "`python evaluation/flutter_eval.py`." % (results["version"], results["date"]), ""]
    sections = [("Flutter samples", markdown_samples(results["samples"]))]
    labs = results.get("labs") or {}
    if "DVMA" in labs:
        sections.append(("DVMA: module-level recall", markdown_dvma(labs["DVMA"])))
    for name, _truth in LAB_TRUTH:
        if name in labs:
            sections.append(("%s: recall per %s" % (name, labs[name]["unit"]),
                             markdown_lab(name, labs[name])))
    if not labs:
        sections.append(("Labs", ["Not measured: the labs are not downloaded (`python "
                                  "infected_project/fetch_labs.py`) or `--no-labs` was given.",
                                  ""]))
    sections.append(("What survives compilation: the APK probe", markdown_probe(results["probe"])))
    if results.get("inventory"):
        sections.append(("API and key inventory: the API probe",
                         markdown_inventory(results["inventory"])))
    for number, (title, body) in enumerate(sections, start=1):
        lines += ["## %d. %s" % (number, title), ""] + body
    return "\n".join(lines).rstrip() + "\n"


def rule_list(hits: List[Dict[str, Any]]) -> str:
    return "; ".join("%s (line %d)" % ("+".join(h["rules"]), h["line"]) for h in hits) or "-"


def markdown_samples(samples: Dict[str, Any]) -> List[str]:
    counts = samples["truth"]
    main = next(r for r in samples["configs"] if r["name"] == samples["main"])
    lines = ["`samples/flutter_vulnerable_app` (%d labelled weaknesses, %d of them marked hard, "
             "%d safe decoy lines) and `samples/flutter_safe_app` (no weaknesses: every finding "
             "there is a false positive). A finding counts when it has the labelled CWE and is "
             "at most one line away. These samples were written together with the tool: the "
             "numbers show that the module works end to end; they are not an unbiased "
             "benchmark." % (counts["weaknesses"], counts["hard"], counts["decoys"]), "",
             "| Configuration | TP | FP | FN | Precision | Recall | F1 |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for r in samples["configs"]:
        lines.append("| %s | %d | %d | %d | %.3f | %.3f | %.3f |" % (
            r["name"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"], r["f1"]))
    lines += ["", "Recall by part of the sample (%s):" % main["name"], "",
              "| Part | Labelled | Found | Recall |", "|---|---:|---:|---:|"]
    lines += ["| %s (%s) | %d | %d | %s |" % (g["name"], g["group"], g["expected"], g["found"],
                                               pct(g["recall"])) for g in samples["groups"]]
    lines += ["", "### Missed (%s)" % main["name"], ""]
    lines += ["- `%s:%d` %s %s%s: %s" % (m["file"], m["line"], m["tag"], m["cwe"],
                                         " (hard)" if m["hard"] else "", m["note"])
              for m in main["missed"]] or ["- none"]
    lines += ["", "### False positives (%s)" % main["name"], ""]
    lines += ["- `%s:%d` %s %s (engines: %s)" % (f["file"], f["line"], f["cwe"], f["title"],
                                                 ", ".join(f["engines"]))
              for f in main["false_positives"]] or ["- none"]
    return lines + [""]


def markdown_dvma(dvma: Dict[str, Any]) -> List[str]:
    total = dvma["total"]
    lines = ["DVMA's registry (`config/registry/categories`) lists %d modules with their CWEs; "
             "the code of each is in `lib/modules/<category>/<module>/`. A module counts as "
             "**found** when an open finding in its folder has one of its CWEs, and as "
             "**any finding** when its folder has an open finding of any kind. Scan: %d files, "
             "%s lines, %d open findings, %.1f s." % (
                 total["modules"], dvma["scan"]["files"], format(dvma["scan"]["lines"], ","),
                 dvma["scan"]["open"], dvma["scan"]["seconds"]), "",
             "| Category | Kind | Modules | Found | Recall | Any finding |",
             "|---|---|---:|---:|---:|---:|"]
    for c in dvma["categories"]:
        lines.append("| %s | %s | %d | %d | %s | %d |" % (
            c["name"], c["kind"], c["modules"], c["found"], pct(c["recall"]), c["any"]))
    lines.append("| **All** | | **%d** | **%d** | **%s** | **%d** |" % (
        total["modules"], total["found"], pct(total["recall"]), total["any"]))
    lines += ["", "By kind of weakness (a judgement per category, written in "
              "`evaluation/flutter_truth/dvma.json`):", "",
              "| Kind | What it means | Modules | Found | Recall |", "|---|---|---:|---:|---:|"]
    lines += ["| %s | %s | %d | %d | %s |" % (k["name"], dvma["kinds_text"].get(k["name"], ""),
                                              k["modules"], k["found"], pct(k["recall"]))
              for k in dvma["kinds"]]
    runtime = [c["name"] for c in dvma["categories"] if c["kind"] == "runtime"]
    lines += ["", "The %s categories are AI, behaviour and runtime weaknesses (prompt injection, "
              "agent tool abuse, consent, missing root/tamper/debugger defences). They are not "
              "patterns in the source, so static analysis is not expected to find them; the "
              "*design* categories need the intended behaviour of the app (who may call what), "
              "which a pattern or structural check only sees where it leaves a mark in code or "
              "configuration." % ", ".join(runtime), ""]
    outside = dvma["outside"]
    lines += ["Findings outside the module folders are not counted above, because they belong "
              "to the whole app rather than to one module: %d open findings, by check: %s." % (
                  sum(outside.values()),
                  ", ".join("%s %d" % item for item in outside.items()) or "none"), ""]
    return lines


def markdown_lab(name: str, lab: Dict[str, Any]) -> List[str]:
    scan_ = lab["scan"]
    unit = lab["unit"]
    lines = ["Truth: `evaluation/flutter_truth/%s` (one item per %s, with file and line). An "
             "item counts as found when an open finding with one of its CWEs is at most one "
             "line away from one of its locations. Scan: %d files, %s lines, %d open findings "
             "(%d of them on a truth item), %.1f s." % (
                 dict(LAB_TRUTH)[name], unit, scan_["files"], format(scan_["lines"], ","),
                 scan_["open"], lab["matched_findings"], scan_["seconds"]), "",
             "Recall: **%d of %d %ss (%s)**; without the items marked hard: %d of %d (%s)." % (
                 lab["all"]["found"], lab["all"]["items"], unit, pct(lab["all"]["recall"]),
                 lab["not_hard"]["found"], lab["not_hard"]["items"],
                 pct(lab["not_hard"]["recall"])), "",
             "| Id | Weakness | CWE | Where | Found | By |", "|---|---|---|---|---|---|"]
    for item in lab["items"]:
        lines.append("| %s | %s%s | %s | %s | %s | %s |" % (
            item["id"], item["title"], " (hard)" if item["hard"] else "",
            ", ".join(item["cwe"]),
            ", ".join("`%s:%d`" % (Path(p["file"]).name, p["line"]) for p in item["where"])
            or "-", "yes" if item["found"] else "no", rule_list(item["by"])))
    return lines + [""]


STATE_TEXT = {"found": "found", "missed": "**missed**", "n/a": "-", "unexpected": "unexpected"}


def markdown_probe(probe: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    if not probe["apk_folder_given"]:
        lines += ["Only the source scan: no folder of probe builds was given (`--apks DIR` or "
                  "SCA_FLUTTER_PROBE_DIR; build them with `python tools/build_flutter_apks.py "
                  "--out DIR --modes debug,release,obfuscated,aab`).", ""]
    runs = probe["runs"]
    built = probe.get("built_with") or {}
    lines += ["`samples/flutter_apk_probe` holds %d planted weaknesses (P rows); B rows are "
              "properties of a build mode. Each column is one scan with all static engines: "
              "the source folder, then the packages built from it%s. *found* = reported, "
              "**missed** = present but not reported, *-* = not expected in that scan, "
              "*unexpected* = reported where it should not be." % (
                  probe["planted"], " with Flutter %s (Dart %s)" % (built["flutter"], built["dart"])
                  if built.get("flutter") else ""), ""]
    lines.append("| Id | Weakness | CWE | %s |" % " | ".join(r["mode"] for r in runs))
    lines.append("|---|---|---|" + "---|" * len(runs))
    for item in probe["items"]:
        lines.append("| %s | %s | %s | %s |" % (item["id"], item["what"], item["cwe"], " | ".join(
            STATE_TEXT[r["items"][item["id"]]["state"]] for r in runs)))
    lines.append("| | **Planted weaknesses found** | | %s |" % " | ".join(
        "**%d of %d**" % (probe["found"][r["mode"]], probe["planted"]) for r in runs))
    lines += ["", "| Scan | Package size | Build mode found | Dart obfuscated | Files | Open "
              "findings | Other findings | Time |", "|---|---:|---|---|---:|---:|---:|---:|"]
    for run in runs:
        package = run.get("package") or {}
        size = package.get("size_bytes")
        obfuscated = package.get("obfuscated")
        lines.append("| %s | %s | %s | %s | %d | %d | %d | %.1f s |" % (
            run["target"], "%.1f MB" % (size / 1e6) if size else "-",
            package.get("build_mode") or "-",
            "-" if obfuscated is None else ("yes" if obfuscated else "no"),
            run["scan"]["files"], run["scan"]["open"], len(run["others"]),
            run["scan"]["seconds"]))
    others = [(run["target"], o) for run in runs for o in run["others"]]
    lines += ["", "Other findings (not on a P or B row):", ""]
    lines += ["- %s: `%s:%d` %s %s" % (target, o["file"], o["line"], o["cwe"],
                                       "+".join(o["rules"])) for target, o in others] or ["- none"]
    return lines + [""]


# ------------------------------------------------------------------ main
def run_all(apks: Optional[Path], labs: bool = True,
            api_apks: Optional[Path] = None) -> Dict[str, Any]:
    results: Dict[str, Any] = {"version": __version__, "date": date.today().isoformat(),
                               "samples": evaluate_samples(), "labs": {}}
    if labs:
        if (LABS_DIR / "DVMA" / "config" / "registry").is_dir():
            results["labs"]["DVMA"] = evaluate_dvma(LABS_DIR / "DVMA")
        for name, truth in LAB_TRUTH:
            if (LABS_DIR / name).is_dir():
                results["labs"][name] = evaluate_lab(LABS_DIR / name, TRUTH_DIR / truth)
    results["probe"] = evaluate_probe(apks)
    results["inventory"] = evaluate_inventory(api_apks)
    return results


def print_summary(results: Dict[str, Any]) -> None:
    samples = results["samples"]
    for r in samples["configs"]:
        print("Samples, %s: precision %.3f, recall %.3f, F1 %.3f (TP %d, FP %d, FN %d)" % (
            r["name"], r["precision"], r["recall"], r["f1"], r["tp"], r["fp"], r["fn"]))
    for name, lab in results["labs"].items():
        part = lab["total"] if name == "DVMA" else lab["all"]
        count = part.get("modules", part.get("items"))
        print("%s: %d of %d found (%s)" % (name, part["found"], count, pct(part["recall"])))
    probe = results["probe"]
    print("APK probe, planted weaknesses found: %s" % ", ".join(
        "%s %d/%d" % (mode, found, probe["planted"]) for mode, found in probe["found"].items()))
    inv = results.get("inventory")
    if inv:
        print("API probe, inventory items listed: %s" % ", ".join(
            "%s %d/%d" % (mode, found, inv["expected"][mode])
            for mode, found in inv["found"].items()))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--apks", default=os.environ.get("SCA_FLUTTER_PROBE_DIR", ""),
                        help="folder with the probe builds: debug.apk, release.apk, "
                             "release_obf.apk, release.aab (default: SCA_FLUTTER_PROBE_DIR)")
    parser.add_argument("--api-apks", default=os.environ.get("SCA_FLUTTER_API_DIR", ""),
                        help="folder with the builds of samples/flutter_api_probe: debug.apk, "
                             "release.apk, release_obf.apk (default: SCA_FLUTTER_API_DIR)")
    parser.add_argument("--no-labs", action="store_true", help="skip DVMA, DVFA and Ostorlab")
    parser.add_argument("--out", default=str(HERE / "flutter_results"),
                        help="output path without suffix (default: evaluation/flutter_results)")
    args = parser.parse_args(argv)
    apks = Path(args.apks).expanduser() if args.apks else None
    if apks is not None and not probe_builds(apks):
        parser.error("no probe builds (debug.apk, release.apk, ...) in %s" % apks)
    api_apks = Path(args.api_apks).expanduser() if args.api_apks else None
    if api_apks is not None and not any((api_apks / name).is_file() for _, name in API_BUILDS):
        parser.error("no builds of the API probe (debug.apk, release.apk, release_obf.apk) "
                     "in %s" % api_apks)
    results = run_all(apks, labs=not args.no_labs, api_apks=api_apks)
    print_summary(results)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n",
                                        encoding="utf-8")
    out.with_suffix(".md").write_text(markdown(results), encoding="utf-8")
    print("Saved %s and %s" % (out.with_suffix(".md"), out.with_suffix(".json")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
