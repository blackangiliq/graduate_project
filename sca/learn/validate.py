"""Automatic validation of a rule proposed by the AI.

An LLM can write a rule that is wrong, too broad, or dangerously slow. No candidate reaches
the reviewer before it passes every check below, and no candidate becomes active before the
reviewer approves it.

Checks for a new rule:
  schema        required fields, a real CWE id, a known severity and language
  compiles      the regular expression is valid               (run in the sandbox process)
  fast          finishes on long and repetitive lines         (catastrophic backtracking)
  specific      contains a literal anchor and does not match everyday code lines
  evidence      matches the vulnerable line it was learned from
  examples      matches its own vulnerable examples, none of its safe examples
  clean corpus  matches nothing in the known-safe code (safe samples, safe training lines,
                lines the reviewer dismissed as false positives)
  blast radius  does not flag an implausible share of the scanned project
  novelty       no active rule already reports the evidence line; not a duplicate pattern

Checks for an exclusion (a fix for a false positive of an existing rule):
  compiles, fast, matches the false positive, and must NOT match any known-vulnerable line
  that the rule is supposed to catch (so recall cannot silently drop).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..ai.seed_corpus import build_corpus
from ..cwe import canonical
from ..engines import rules_engine
from ..models import SEVERITY_RANK
from ..storage import Storage
from ..walker import CODE_LANGUAGES, RULE_LANGUAGE, SourceFile, walk_project
from . import sandbox

ROOT = Path(__file__).resolve().parent.parent.parent
MAX_PATTERN_LENGTH = 400
MAX_PROJECT_MATCHES = 25
MAX_PROJECT_SHARE = 0.02

BENIGN_PROBES = [
    "x = 1", "i += 1", "return result", "return 0;", "}", "{", "import os", "end",
    "const total = a + b;", "if (count > 0) {", "for item in items:", "print(name)",
    "console.log(value);", "$i = 0;", "public static void main(String[] args) {",
    "#include <stdio.h>", "name = user.name", "var x = y;", "func main() {", "else:",
    "    pass", "def run(self):", "function init() {", "int i = 0;", "echo $total;",
]
NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")


def _check(name: str, passed: bool, detail: str = "") -> Dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def stress_lines(pattern: str) -> List[str]:
    """Inputs that make badly written patterns explode."""
    literals = re.findall(r"[A-Za-z_]{2,}", pattern)[:6] or ["a"]
    lines = ["a" * 600, " " * 600, "(" * 300 + ")" * 300, 'x = "' + "a+" * 280,
             "a" * 599 + "!", "\t" * 300 + "x" * 300, "a,b," * 150, "'\"" * 300]
    for char in sorted(set(re.findall(r"[A-Za-z0-9]", pattern)))[:12]:
        lines.append(char * 599 + "!")
    for literal in literals:
        lines.append(((literal + " ") * 600)[:599] + "!")
        lines.append((literal + "(" + "a" * 560)[:600])
        lines.append(((literal + '("' + "x\\" * 20) * 30)[:600])
    return lines


def rule_languages(languages: Sequence[str]) -> List[str]:
    return sorted({RULE_LANGUAGE.get(l, l) for l in languages})


def clean_corpus(languages: Sequence[str], storage: Optional[Storage]) -> List[Tuple[str, str]]:
    """(origin, line) pairs of code that is known to be safe."""
    texts, labels = build_corpus()
    corpus = [("safe training line", t) for t, label in zip(texts, labels) if label == 0]
    wanted = set(rule_languages(languages))
    safe_dir = ROOT / "samples" / "safe_app"
    if safe_dir.is_dir():
        for sf in walk_project(str(safe_dir)):
            if sf.rule_language in wanted:
                corpus += [("safe sample %s:%d" % (sf.rel, n), line)
                           for n, line in rules_engine.code_lines(sf)]
    if storage is not None:
        for row in storage.feedback_rows():
            if row["verdict"] == "fp" and row.get("snippet"):
                corpus.append(("dismissed by the reviewer (%s)" % row.get("file", ""),
                               row["snippet"]))
    return corpus


def vulnerable_corpus(target_rule: Optional[rules_engine.Rule],
                      storage: Optional[Storage]) -> List[Tuple[str, str]]:
    """(origin, line) pairs of code that is known to be vulnerable."""
    texts, labels = build_corpus()
    corpus = [("vulnerable training line", t) for t, label in zip(texts, labels) if label == 1]
    vuln_dir = ROOT / "samples" / "vulnerable_app"
    if vuln_dir.is_dir():
        for sf in walk_project(str(vuln_dir)):
            corpus += [("vulnerable sample %s:%d" % (sf.rel, n), line)
                       for n, line in rules_engine.code_lines(sf)]
    if storage is not None:
        for row in storage.feedback_rows():
            if row["verdict"] == "tp" and row.get("snippet"):
                corpus.append(("confirmed by the reviewer (%s)" % row.get("file", ""),
                               row["snippet"]))
    if target_rule is not None:
        corpus = [(origin, line) for origin, line in corpus if target_rule.matches(line)]
    return corpus


def _run(pattern: str, exclude: str, ignore_case: bool, groups: Dict[str, List[str]]
         ) -> Tuple[Optional[Dict[str, List[int]]], str]:
    """Run the rule once over several groups of lines; return matches per group."""
    names = list(groups)
    lines: List[str] = []
    bounds = []
    for name in names:
        bounds.append((name, len(lines), len(lines) + len(groups[name])))
        lines.extend(groups[name])
    matches, error = sandbox.run_patterns(pattern, exclude, ignore_case, lines)
    if matches is None:
        return None, error
    out = {name: [] for name in names}
    for index in matches:
        for name, start, end in bounds:
            if start <= index < end:
                out[name].append(index - start)
    return out, ""


def validate_rule(candidate: Dict[str, Any], files: Optional[List[SourceFile]] = None,
                  storage: Optional[Storage] = None) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    pattern = str(candidate.get("pattern") or "")
    exclude = str(candidate.get("exclude") or "")
    ignore_case = bool(candidate.get("ignore_case"))
    languages = [str(l) for l in candidate.get("languages") or []]
    cwe = canonical(str(candidate.get("cwe") or ""))
    evidence = str((candidate.get("evidence") or {}).get("snippet") or "")
    vulnerable = [str(x) for x in candidate.get("examples_vulnerable") or [] if str(x).strip()]
    safe = [str(x) for x in candidate.get("examples_safe") or [] if str(x).strip()]

    # ---- schema
    problems = []
    if not candidate.get("title"):
        problems.append("no title")
    if not re.fullmatch(r"CWE-\d{1,4}", cwe or ""):
        problems.append("cwe must look like CWE-89")
    if str(candidate.get("severity", "")).lower() not in SEVERITY_RANK:
        problems.append("unknown severity")
    if not languages or any(l not in CODE_LANGUAGES for l in languages):
        problems.append("unknown language")
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        problems.append("pattern missing or longer than %d characters" % MAX_PATTERN_LENGTH)
    if NESTED_QUANTIFIER.search(pattern):
        problems.append("nested quantifier such as (a+)+")
    if not evidence and (len(vulnerable) < 2 or len(safe) < 2):
        problems.append("a rule without evidence needs at least 2 vulnerable and 2 safe examples")
    checks.append(_check("schema", not problems, "; ".join(problems)))
    if problems:
        return {"passed": False, "checks": checks, "project_matches": [], "match_count": 0}

    # ---- everything that needs the regular expression runs in the sandbox
    corpus = clean_corpus(languages, storage)
    wanted = set(rule_languages(languages))
    project: List[Tuple[str, int, str]] = []
    language_lines = 0
    for sf in files or []:
        if sf.rule_language in wanted:
            for number, line in rules_engine.code_lines(sf):
                language_lines += 1
                project.append((sf.rel, number, line))
    groups = {
        "stress": stress_lines(pattern),
        "probes": BENIGN_PROBES,
        "evidence": [evidence] if evidence else [],
        "vulnerable": vulnerable,
        "safe": safe,
        "clean": [line for _, line in corpus],
        "project": [line for _, _, line in project],
    }
    result, error = _run(pattern, exclude, ignore_case, groups)
    if result is None:
        slow = "slow" in error
        checks.append(_check("compiles", slow, "" if slow else error))
        if slow:
            checks.append(_check("fast", False, error))
        return {"passed": False, "checks": checks, "project_matches": [], "match_count": 0}
    checks.append(_check("compiles", True))
    checks.append(_check("fast", True, "finished on %d stress lines" % len(groups["stress"])))

    # ---- specific
    anchor = re.search(r"[A-Za-z_]{3,}", re.sub(r"\\[A-Za-z]", " ", pattern))
    probe_hits = [BENIGN_PROBES[i] for i in result["probes"]]
    detail = []
    if not anchor:
        detail.append("no literal word of 3+ letters to anchor on")
    if probe_hits:
        detail.append("matches everyday code such as: %s" % probe_hits[0])
    checks.append(_check("specific", not detail, "; ".join(detail)))

    # ---- evidence
    if evidence:
        checks.append(_check("evidence", bool(result["evidence"]),
                             "" if result["evidence"] else
                             "does not match the line it was learned from: %s" % evidence[:120]))

    # ---- examples
    needed = len(vulnerable) if len(vulnerable) < 2 else max(2, (2 * len(vulnerable) + 2) // 3)
    missed = [vulnerable[i] for i in range(len(vulnerable)) if i not in result["vulnerable"]]
    wrong = [safe[i] for i in result["safe"]]
    detail = []
    if len(result["vulnerable"]) < needed:
        detail.append("misses its own vulnerable example: %s" % missed[0][:100])
    if wrong:
        detail.append("matches its own safe example: %s" % wrong[0][:100])
    checks.append(_check("examples", not detail, "; ".join(detail) or "%d/%d vulnerable matched, "
                         "0/%d safe matched" % (len(result["vulnerable"]), len(vulnerable),
                                                len(safe))))

    # ---- clean corpus
    hits = [corpus[i] for i in result["clean"]]
    checks.append(_check("clean corpus", not hits,
                         "matches known-safe code (%s): %s" % (hits[0][0], hits[0][1][:100])
                         if hits else "0 matches in %d known-safe lines" % len(corpus)))

    # ---- blast radius
    count = len(result["project"])
    preview = [{"file": project[i][0], "line": project[i][1], "text": project[i][2].strip()[:200]}
               for i in result["project"][:8]]
    too_many = count > MAX_PROJECT_MATCHES or (
        language_lines >= 200 and count > MAX_PROJECT_SHARE * language_lines)
    if files is not None:
        checks.append(_check("blast radius", not too_many,
                             "%d matches in %d lines of the scanned project%s"
                             % (count, language_lines, " - too broad" if too_many else "")))

    # ---- novelty
    detail = []
    for rule in rules_engine.load_rules():
        if rule.pattern.pattern == pattern:
            detail.append("identical to rule %s" % rule.id)
            break
        if evidence and canonical(rule.cwe) == cwe and set(rule.languages) & wanted \
                and rule.matches(evidence):
            detail.append("rule %s already reports this line" % rule.id)
            break
    checks.append(_check("novelty", not detail, "; ".join(detail)))

    return {"passed": all(c["passed"] for c in checks), "checks": checks,
            "project_matches": preview, "match_count": count}


def validate_exclude(candidate: Dict[str, Any], storage: Optional[Storage] = None
                     ) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    exclude = str(candidate.get("exclude") or "")
    false_positive = str((candidate.get("evidence") or {}).get("snippet") or "")
    target = next((r for r in rules_engine.load_rules()
                   if r.id == candidate.get("target_rule")), None)
    problems = []
    if target is None:
        problems.append("the rule %s does not exist" % candidate.get("target_rule"))
    if not exclude or len(exclude) > MAX_PATTERN_LENGTH:
        problems.append("exclusion missing or longer than %d characters" % MAX_PATTERN_LENGTH)
    if NESTED_QUANTIFIER.search(exclude):
        problems.append("nested quantifier such as (a+)+")
    if not false_positive:
        problems.append("no false-positive line to learn from")
    checks.append(_check("schema", not problems, "; ".join(problems)))
    if problems:
        return {"passed": False, "checks": checks, "project_matches": [], "match_count": 0}

    known = vulnerable_corpus(target, storage)
    groups = {"stress": stress_lines(exclude), "probes": BENIGN_PROBES,
              "fp": [false_positive], "vulnerable": [line for _, line in known]}
    result, error = _run(exclude, "", False, groups)
    if result is None:
        slow = "slow" in error
        checks.append(_check("compiles", slow, "" if slow else error))
        if slow:
            checks.append(_check("fast", False, error))
        return {"passed": False, "checks": checks, "project_matches": [], "match_count": 0}
    checks.append(_check("compiles", True))
    checks.append(_check("fast", True))
    checks.append(_check("specific", len(result["probes"]) <= 1,
                         "" if len(result["probes"]) <= 1 else
                         "the exclusion matches everyday code and would switch the rule off"))
    checks.append(_check("fixes the false positive", bool(result["fp"]),
                         "" if result["fp"] else "does not match the false-positive line"))
    lost = [known[i] for i in result["vulnerable"]]
    checks.append(_check("keeps true positives", not lost,
                         "would hide a known vulnerability (%s): %s" % (lost[0][0], lost[0][1][:100])
                         if lost else "0 of %d known-vulnerable lines are hidden" % len(known)))
    return {"passed": all(c["passed"] for c in checks), "checks": checks,
            "project_matches": [], "match_count": 0}


def validate(candidate: Dict[str, Any], files: Optional[List[SourceFile]] = None,
             storage: Optional[Storage] = None) -> Dict[str, Any]:
    if candidate.get("kind") == "exclude":
        return validate_exclude(candidate, storage)
    return validate_rule(candidate, files, storage)
