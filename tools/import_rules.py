"""Import open-source rule sets into the YAML rule format of this tool.

    python tools/import_rules.py --devskim PATH/TO/DevSkim --gitleaks PATH/TO/gitleaks \
                                 --corpus PATH/TO/folder-of-real-projects

Sources (both MIT licensed):
  DevSkim   https://github.com/microsoft/DevSkim     regular-expression rules for many languages
  Gitleaks  https://github.com/gitleaks/gitleaks     regular expressions for credential formats

A rule is not copied blindly. Each one is converted and must pass these checks, otherwise it
is left out and the reason is written to the import report:

  converts      the rule has no feature this engine lacks (multi-line conditions, file
                filters), its language is one the tool scans, its weakness maps to a CWE
  compiles      the expression is valid in Python (written for .NET / Go originally)
  fast          finishes on long, repetitive lines (run in the sandbox process)
  self-test     DevSkim: matches every "must-match" example of the rule and none of its
                "must-not-match" examples. Gitleaks: matches a string generated from its own
                expression
  clean corpus  matches nothing in the known-safe sample application

A rule that passes is then measured on real, well-known open-source projects (--corpus).
It ships ENABLED only if it is not a "manual review" rule and is quiet on that code;
otherwise it ships DISABLED, with the reason in its `note`, and can be switched on from the
Rules tab of the dashboard or with `python -m sca rules enable ID`.

This script needs Python 3.11+ (tomllib) and, for Gitleaks, `pip install exrex`.
The tool itself does not need this script: the converted rules are in sca/rules/imported/.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sca.engines import rules_engine, secrets  # noqa: E402
from sca.learn import sandbox, validate  # noqa: E402
from sca.walker import CODE_LANGUAGES, RULE_LANGUAGE, is_test_path, walk_project  # noqa: E402

OUT_DIR = ROOT / "sca" / "rules" / "imported"

# ----------------------------------------------------------------- shared helpers
RULE_LANGS = sorted({RULE_LANGUAGE.get(l, l) for l in CODE_LANGUAGES} | {"config", "html"})


def fix_inline_flags(pattern: str) -> str:
    """Go (RE2) and .NET accept `(?i)` in the middle of an expression, where it applies up
    to the end of the enclosing group. Python only accepts it at the very start, so rewrite
    `X(?i)Y)` as `X(?i:Y))`. Also `\\z` (Go) -> `\\Z` (Python)."""
    pattern = pattern.replace(r"\z", r"\Z")
    out: List[str] = []
    stack: List[int] = []          # for every open group: number of ")" owed before it closes
    i, in_class = 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = ch != "]"
            out.append(ch)
        elif ch == "[":
            in_class = True
            out.append(ch)
            if pattern[i + 1:i + 2] == "]":     # "[]...]": the first ] is a literal
                out.append("]")
                i += 1
        elif pattern.startswith("(?i)", i) and i > 0:
            out.append("(?i:")
            if stack:
                stack[-1] += 1
            else:
                stack.append(-1)                # sentinel: close at the end of the pattern
            i += 4
            continue
        elif ch == "(":
            stack.append(0)
            out.append(ch)
        elif ch == ")":
            owed = stack.pop() if stack and stack[-1] >= 0 else 0
            out.append(")" * owed + ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out) + ")" * sum(1 for s in stack if s == -1)


def python_ok(pattern: str) -> str:
    """'' if the expression compiles in Python, otherwise the error."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")      # a construct Python plans to reinterpret
            re.compile(pattern)
    except (re.error, Warning) as exc:
        return str(exc)
    return ""


def fast(pattern: str, exclude: str = "") -> str:
    _matches, error = sandbox.run_patterns(pattern, exclude, False,
                                           validate.stress_lines(pattern), timeout=6)
    return error


def clean_lines() -> List[str]:
    """Known-safe code: the safe sample application, plus the lines of the vulnerable sample
    that are safe on purpose (the "decoys" of samples/ground_truth.json)."""
    lines: List[str] = []
    for sf in walk_project(str(ROOT / "samples" / "safe_app")):
        lines += sf.lines
    tags = json.loads((ROOT / "samples" / "ground_truth.json").read_text(encoding="utf-8"))["tags"]
    decoys = ["[%s]" % tag for tag, item in tags.items() if not item["cwe"]]
    for sf in walk_project(str(ROOT / "samples" / "vulnerable_app")):
        lines += [line for line in sf.lines if any(d in line for d in decoys)]
    return lines


def git_commit(path: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(path), "log", "-1", "--format=%h %cd",
                               "--date=short"], capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""


# ----------------------------------------------------------------- real-code corpus
class Corpus:
    """Lines of real projects, grouped by rule language, split into product and test code."""

    def __init__(self, folders: List[Path]):
        self.lines: Dict[str, List[Tuple[str, str, bool]]] = {}   # lang -> (where, line, test)
        self.projects: List[Tuple[str, int]] = []
        for folder in folders:
            for project in sorted(p for p in folder.iterdir() if p.is_dir()):
                count = 0
                for sf in walk_project(str(project)):
                    test = is_test_path(sf.rel)
                    bucket = self.lines.setdefault(sf.rule_language, [])
                    for number, line in rules_engine.code_lines(sf):
                        bucket.append(("%s/%s:%d" % (project.name, sf.rel, number), line, test))
                        count += 1
                self.projects.append((project.name, count))

    def size(self, languages: List[str]) -> int:
        return sum(len(self.lines.get(l, [])) for l in self.languages(languages))

    def languages(self, languages: List[str]) -> List[str]:
        return list(self.lines) if "any" in languages else [l for l in languages if l in self.lines]

    def measure(self, rule: "rules_engine.Rule") -> Dict[str, Any]:
        """How often a rule fires on the corpus."""
        product, test, examples = 0, 0, []
        for language in self.languages(rule.languages):
            for where, line, is_test in self.lines[language]:
                if rule.kind == "secret":
                    hit = any(True for _ in secrets.match_secret_rule(rule, line))
                else:
                    hit = rule.matches(line)
                if not hit:
                    continue
                if is_test:
                    test += 1
                else:
                    product += 1
                    if len(examples) < 3:
                        examples.append("%s  %s" % (where, line.strip()[:120]))
        lines = self.size(rule.languages)
        return {"lines": lines, "product_hits": product, "test_hits": test,
                "per_10k": round(10000.0 * product / lines, 3) if lines else 0.0,
                "examples": examples}


# ----------------------------------------------------------------- DevSkim
DEVSKIM_LANG = {
    "javascript": "javascript", "javascriptreact": "javascript", "typescript": "javascript",
    "typescriptreact": "javascript", "c": "c", "cpp": "c", "csharp": "csharp",
    "razor": "csharp", "python": "python", "php": "php", "java": "java", "ruby": "ruby",
    "go": "go", "rust": "rust", "swift": "swift", "powershell": "powershell", "sql": "sql",
    "shellscript": "shell", "yaml": "config", "json": "config", "xml": "config",
    ".config": "config", "dotenv": "config", "dockerfile": "config",
    "pip-requirements": "config", "pip-config": "config", "html": "html",
}
# tag prefix -> CWE (first match wins); None = outside the scope of this tool
DEVSKIM_CWE = [
    ("Cryptography.Protocol", "CWE-327"), ("Cryptography.Certificate", "CWE-295"),
    ("Cryptography.Symmetric", "CWE-327"), ("Cryptography.Library", "CWE-327"),
    ("Cryptography.HashAlgorithm", "CWE-327"), ("Cryptography.BannedHashAlgorithm", "CWE-327"),
    ("Cryptography.PRNG", "CWE-338"), ("Cryptography.WeakRandomness", "CWE-338"),
    ("Deserialization", "CWE-502"), ("API.DangerousAPI", "CWE-120"),
    ("PHP.Injection", "CWE-98"), ("API.T-SQL", "CWE-78"),
    ("ControlFlow.DynamicExecution", "CWE-95"), ("ControlFlow.Permission", "CWE-693"),
    ("Implementation.Scripting.PowerShell", "CWE-95"), ("Python.DangerousFunctionCall", "CWE-95"),
    ("JavaScript.DangerousFunctionCall", "CWE-95"), ("TypeScript.DangerousFunctionCall", "CWE-95"),
    ("PHP.DangerousFunctionCall", "CWE-95"), ("Dotnet.Unsafecode", "CWE-120"),
    ("Framework.Android", "CWE-489"), ("SupplyChain.PackageSource", "CWE-494"),
    ("XML.XXE", "CWE-611"), ("Implementation.iOS.XML", "CWE-611"),
]
DEVSKIM_CWE_BY_ID = {"DS114352": "CWE-319", "DS101155": "CWE-319"}
DEVSKIM_SEVERITY = {"critical": "high", "important": "medium", "moderate": "low",
                    "bestpractice": "info", "manualreview": "low"}
DEVSKIM_CONFIDENCE = {"high": 0.7, "medium": 0.55, "low": 0.4}
REVIEW_ONLY = ("manualreview", "bestpractice")
# Rules that passed every automatic check but whose matches in the real-code corpus were
# read by hand and found to be mostly harmless. They ship disabled, with the reason.
REVIEWED_NOISY = {
    "DS187371": "its short cipher-mode names (EAX, CTS, ...) also match unrelated identifiers "
                "such as CPU register names",
    "DS197836": "its matches were ordinary HMAC calls and comments, not hashes of "
                "low-entropy data",
    "DS125134": "it also matches type declarations of the option, not only the place where "
                "validation is switched off",
    "DS169126": "it also matches the options that DISABLE old protocols (SSL_OP_NO_SSLv3)",
    "DS169125": "its only match was a help text that lists protocol names",
    "DS440010": "it flags every explicit TLS version, including a safe minimum version",
}


def devskim_part(part: Dict[str, Any]) -> str:
    text, kind = part["pattern"], str(part.get("type", "regex")).lower()
    if kind in ("string", "substring"):
        literal = re.escape(text)
        if kind == "string":       # a whole word, like DevSkim's "string" type
            literal = (r"(?<![A-Za-z0-9_])" if re.match(r"\w", text) else "") + literal + \
                      (r"(?![A-Za-z0-9_])" if re.search(r"\w$", text) else "")
        text = literal
    else:
        text = fix_inline_flags(text)
        if text.startswith("(?i)"):
            text = "(?i:%s)" % text[4:]
        if kind == "regexword":
            text = r"\b(?:%s)\b" % text
    if "i" in [m.lower() for m in part.get("modifiers") or []]:
        text = "(?i:%s)" % text
    return text


def convert_devskim(rule: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    if rule.get("conditions"):
        return None, "uses conditions on neighbouring lines (this engine works line by line)"
    if rule.get("applies_to_file_regex"):
        return None, "applies only to files selected by name"
    tags = rule.get("tags") or [""]
    cwe = DEVSKIM_CWE_BY_ID.get(rule["id"]) or next(
        (c for prefix, c in DEVSKIM_CWE if any(t.startswith(prefix) for t in tags)), None)
    if not cwe:
        return None, "outside the scope of this tool (%s)" % tags[0]
    if rule.get("applies_to"):
        languages = sorted({DEVSKIM_LANG[a] for a in rule["applies_to"] if a in DEVSKIM_LANG})
    elif rule.get("does_not_apply_to"):
        banned = {DEVSKIM_LANG.get(a) for a in rule["does_not_apply_to"]}
        languages = [l for l in RULE_LANGS if l not in banned]
    else:
        languages = ["any"]
    if not languages:
        return None, "language not scanned by this tool (%s)" % ", ".join(rule["applies_to"])
    parts = [devskim_part(p) for p in rule["patterns"]]
    pattern = parts[0] if len(parts) == 1 else "|".join("(?:%s)" % p for p in parts)
    severity = str(rule.get("severity", "moderate")).lower()
    out = {
        "id": "DEVSKIM-%s" % rule["id"],
        "source": rule["id"],
        "title": rule["name"].strip().rstrip("."),
        "languages": languages,
        "cwe": cwe,
        "severity": DEVSKIM_SEVERITY.get(severity, "low"),
        "confidence": DEVSKIM_CONFIDENCE.get(str(rule.get("confidence", "medium")).lower(), 0.55),
        "pattern": pattern,
        "message": " ".join(str(rule.get("description", "")).split()),
        "fix": " ".join(str(rule.get("recommendation", "")).split()),
        "examples_vulnerable": [str(x) for x in rule.get("must-match") or []][:4],
        "examples_safe": [str(x) for x in rule.get("must-not-match") or []][:4],
        "_review_only": severity in REVIEW_ONLY,
    }
    return out, ""


def self_test(raw: Dict[str, Any]) -> str:
    rule = rules_engine.parse_rule(raw, "imported")
    for sample in raw["examples_vulnerable"]:
        if not any(rule.matches(line) for line in sample.splitlines()):
            return "misses its own must-match example: %s" % sample[:80]
    for sample in raw["examples_safe"]:
        if any(rule.matches(line) for line in sample.splitlines()):
            return "matches its own must-not-match example: %s" % sample[:80]
    return ""


def import_devskim(path: Path, corpus: Optional[Corpus], clean: List[str], max_noise: float
                   ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    kept, report, seen = [], [], set()
    for file in sorted((path / "rules" / "default").rglob("*.json")):
        for rule in json.loads(file.read_text(encoding="utf-8-sig")):
            entry = {"source": "DevSkim", "id": rule["id"], "name": rule["name"]}
            raw, reason = convert_devskim(rule)
            if raw is not None:
                if raw["id"] in seen:                       # DevSkim reuses a few ids
                    raw["id"] += "-%d" % (sum(1 for s in seen if s.startswith(raw["id"])) + 1)
                reason = python_ok(raw["pattern"]) and "does not compile in Python: %s" \
                    % python_ok(raw["pattern"])
                reason = reason or fast(raw["pattern"]) or self_test(raw)
                if not reason:
                    compiled = rules_engine.parse_rule(raw, "imported")
                    hit = next((l for l in clean if compiled.matches(l)), None)
                    reason = "matches the known-safe sample: %s" % hit.strip()[:80] if hit else ""
            if reason or raw is None:
                report.append({**entry, "status": "skipped", "reason": reason})
                continue
            seen.add(raw["id"])
            review_only = raw.pop("_review_only")
            noise = corpus.measure(rules_engine.parse_rule(raw, "imported")) if corpus else None
            if review_only:
                raw["enabled"] = False
                raw["note"] = ("Review rule: DevSkim marks this pattern for manual review, "
                               "not as a confirmed weakness.")
            elif rule["id"] in REVIEWED_NOISY:
                raw["enabled"] = False
                raw["note"] = "Checked by hand on real code: %s." % REVIEWED_NOISY[rule["id"]]
            elif noise and noise["per_10k"] > max_noise:
                raw["enabled"] = False
                raw["note"] = ("Noisy on real code: %d matches in %d lines of well-known "
                               "open-source projects (%.2f per 10,000 lines)."
                               % (noise["product_hits"], noise["lines"], noise["per_10k"]))
            kept.append(raw)
            report.append({**entry, "status": "enabled" if raw.get("enabled", True)
                           else "disabled", "rule": raw["id"], "noise": noise,
                           "reason": raw.get("note", "")})
    return kept, report


# ----------------------------------------------------------------- Gitleaks
GITLEAKS_SKIP = {"generic-api-key": "the tool has its own generic secret detector"}
ACRONYMS = {"api": "API", "aws": "AWS", "gcp": "GCP", "pat": "PAT", "jwt": "JWT", "npm": "npm",
            "id": "ID", "oauth": "OAuth", "url": "URL", "ssh": "SSH", "pypi": "PyPI",
            "sdk": "SDK", "cicd": "CI/CD", "scim": "SCIM", "uri": "URI", "db": "DB"}


def gitleaks_title(rule_id: str) -> str:
    words = [ACRONYMS.get(w, w) for w in rule_id.split("-")]
    words[0] = words[0] if words[0] in ACRONYMS.values() else words[0].capitalize()
    return " ".join(words)


def generate_example(raw: Dict[str, Any]) -> str:
    """A line that the rule itself matches, built from its expression."""
    import random

    import exrex
    random.seed(raw["id"])              # the same result on every run
    rule = rules_engine.parse_rule(raw, "imported")
    source = re.sub(r"\\b|\(\?<?[!=][^)]*\)", "", raw["pattern"])     # drop zero-width parts
    for _ in range(400):
        try:
            candidate = exrex.getone(source, limit=12)
        except Exception:               # exrex does not support every construct
            return ""
        candidate = candidate.split("\n")[0]
        if len(candidate) <= 900 and any(True for _ in secrets.match_secret_rule(rule, candidate)):
            return candidate
    return ""


def import_gitleaks(path: Path, corpus: Optional[Corpus], clean: List[str]
                    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    import tomllib
    config = tomllib.loads((path / "config" / "gitleaks.toml").read_text(encoding="utf-8"))
    builtin = [re.compile(p) for _i, _t, p, _s, _c in secrets.KNOWN_FORMATS]
    kept, report = [], []
    for rule in config["rules"]:
        entry = {"source": "Gitleaks", "id": rule["id"], "name": rule.get("description", "")}
        reason, raw = "", None
        if rule["id"] in GITLEAKS_SKIP:
            reason = GITLEAKS_SKIP[rule["id"]]
        elif "regex" not in rule:
            reason = "matches file names, not file content"
        else:
            pattern = fix_inline_flags(rule["regex"])
            ignore_case = pattern.startswith("(?i)")
            raw = {
                "id": "GITLEAKS-%s" % rule["id"],
                "source": rule["id"],
                "kind": "secret",
                "title": gitleaks_title(rule["id"]),
                "languages": ["any"],
                "cwe": "CWE-798",
                "severity": "high",
                "confidence": 0.85 if rule.get("entropy") or not ignore_case else 0.7,
                "pattern": pattern[4:] if ignore_case else pattern,
                "message": " ".join(str(rule.get("description", "")).split()),
                "fix": "Revoke this credential, then load it from an environment variable or "
                       "a secret manager instead of the source code.",
                "keywords": [str(k).lower() for k in rule.get("keywords") or []],
            }
            if ignore_case:
                raw["ignore_case"] = True
            if rule.get("entropy"):
                raw["entropy"] = float(rule["entropy"])
            if rule.get("secretGroup"):
                raw["secret_group"] = int(rule["secretGroup"])
            flagged = "(?i)" + raw["pattern"] if ignore_case else raw["pattern"]
            reason = python_ok(flagged) and "does not compile in Python: %s" % python_ok(flagged)
            reason = reason or fast(flagged)
            if not reason:
                example = generate_example(raw)
                if not example:
                    reason = "could not be shown to match a string built from its own expression"
                elif any(b.search(example) for b in builtin):
                    reason = "the same key format is already built in"
                # the example is not stored: a file full of realistic-looking keys would
                # trip every secret scanner, including GitHub's push protection
            if not reason:
                compiled = rules_engine.parse_rule(raw, "imported")
                hit = next((l for l in clean
                            if any(True for _ in secrets.match_secret_rule(compiled, l))), None)
                reason = "matches the known-safe sample: %s" % hit.strip()[:80] if hit else ""
        if reason or raw is None:
            report.append({**entry, "status": "skipped", "reason": reason})
            continue
        noise = corpus.measure(rules_engine.parse_rule(raw, "imported")) if corpus else None
        if noise and noise["product_hits"] > 0:
            raw["enabled"] = False
            raw["note"] = ("Matched %d line(s) of product code in well-known open-source "
                           "projects, none of them a real credential." % noise["product_hits"])
        kept.append(raw)
        report.append({**entry, "status": "enabled" if raw.get("enabled", True) else "disabled",
                       "rule": raw["id"], "noise": noise, "reason": raw.get("note", "")})
    return kept, report


# ----------------------------------------------------------------- output
class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper, data):
    style = "'" if any(c in data for c in "\\[]{}()*+?|^$#:") and "\n" not in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str)


def write_rules(name: str, source: Dict[str, str], rules: List[Dict[str, Any]], intro: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    enabled = sum(1 for r in rules if r.get("enabled", True))
    header = "".join("# %s\n" % line for line in (intro % {
        "total": len(rules), "enabled": enabled, "disabled": len(rules) - enabled}).splitlines())
    body = yaml.dump({"source": source, "rules": rules}, Dumper=_Dumper, sort_keys=False,
                     allow_unicode=True, width=1000)
    path = OUT_DIR / name
    path.write_text(header + body, encoding="utf-8")
    return path


INTRO = """Rules imported from %(name)s (%(url)s), licence %(license)s.
%(copyright)s
Converted by tools/import_rules.py. Do not edit this file by hand: your changes would be
lost at the next import. To change, disable or enable a rule use the Rules tab of the
dashboard or `python -m sca rules ...`; such changes are stored in learned/edits.yaml.
%%(total)d rules: %%(enabled)d enabled, %%(disabled)d shipped disabled (see each rule's `note`)."""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--devskim", type=Path)
    parser.add_argument("--gitleaks", type=Path)
    parser.add_argument("--corpus", type=Path, action="append", default=[],
                        help="a folder whose sub-folders are real projects (repeatable)")
    parser.add_argument("--max-noise", type=float, default=0.5,
                        help="DevSkim rules above this many matches per 10,000 lines of the "
                             "corpus ship disabled (default 0.5)")
    parser.add_argument("--report", type=Path, default=ROOT / "evaluation" / "import_report.json")
    args = parser.parse_args()

    corpus = Corpus(args.corpus) if args.corpus else None
    clean = clean_lines()
    today = datetime.date.today().isoformat()
    report: Dict[str, Any] = {"date": today, "max_noise_per_10k": args.max_noise, "rules": []}
    if corpus:
        report["corpus"] = {"projects": corpus.projects,
                            "lines_by_language": {k: len(v) for k, v in corpus.lines.items()}}
    if args.devskim:
        rules, entries = import_devskim(args.devskim, corpus, clean, args.max_noise)
        source = {"name": "DevSkim", "url": "https://github.com/microsoft/DevSkim",
                  "license": "MIT", "copyright": "Copyright (c) Microsoft Corporation.",
                  "commit": git_commit(args.devskim), "imported": today}
        write_rules("devskim.yaml", source, rules, INTRO % source)
        report["rules"] += entries
    if args.gitleaks:
        rules, entries = import_gitleaks(args.gitleaks, corpus, clean)
        source = {"name": "Gitleaks", "url": "https://github.com/gitleaks/gitleaks",
                  "license": "MIT", "copyright": "Copyright (c) 2019 Zachary Rice.",
                  "commit": git_commit(args.gitleaks), "imported": today}
        write_rules("gitleaks.yaml", source, rules, INTRO % source)
        report["rules"] += entries
    args.report.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    for source in ("DevSkim", "Gitleaks"):
        rows = [r for r in report["rules"] if r["source"] == source]
        if rows:
            print("%-9s %3d in source: %3d enabled, %3d disabled, %3d skipped" % (
                source, len(rows), sum(r["status"] == "enabled" for r in rows),
                sum(r["status"] == "disabled" for r in rows),
                sum(r["status"] == "skipped" for r in rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
