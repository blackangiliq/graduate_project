"""Pattern engine: runs the YAML rules in sca/rules against each source line.

A rule looks like this (see sca/rules/*.yaml):

    - id: JS-SQLI-001
      title: SQL query built with string concatenation
      languages: [javascript]
      cwe: CWE-89
      severity: high
      confidence: 0.7
      pattern: '<regular expression that marks a vulnerable line>'
      exclude: '<optional regular expression; if it also matches, the line is ignored>'

You can add your own rules by dropping another .yaml file in the rules folder.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from ..models import Finding
from ..walker import SourceFile

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
MAX_LINE_LENGTH = 600  # longer lines are almost always minified or generated code


@dataclass
class Rule:
    id: str
    title: str
    languages: List[str]
    cwe: str
    severity: str
    confidence: float
    pattern: "re.Pattern[str]"
    exclude: Optional["re.Pattern[str]"] = None
    message: str = ""
    fix: str = ""


def load_rules(rules_dir: Optional[Path] = None) -> List[Rule]:
    rules: List[Rule] = []
    seen = set()
    for path in sorted((rules_dir or RULES_DIR).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for raw in data:
            rule_id = raw["id"]
            if rule_id in seen:
                raise ValueError("Duplicate rule id %s in %s" % (rule_id, path.name))
            seen.add(rule_id)
            flags = re.IGNORECASE if raw.get("ignore_case") else 0
            rules.append(Rule(
                id=rule_id,
                title=raw["title"],
                languages=list(raw["languages"]),
                cwe=raw.get("cwe", ""),
                severity=raw.get("severity", "medium"),
                confidence=float(raw.get("confidence", 0.6)),
                pattern=re.compile(raw["pattern"], flags),
                exclude=re.compile(raw["exclude"], flags) if raw.get("exclude") else None,
                message=raw.get("message", ""),
                fix=raw.get("fix", ""),
            ))
    return rules


_RULE_CACHE: Dict[str, List[Rule]] = {}


def _rules_for(language: str) -> List[Rule]:
    if "all" not in _RULE_CACHE:
        _RULE_CACHE["all"] = load_rules()
    if language not in _RULE_CACHE:
        _RULE_CACHE[language] = [r for r in _RULE_CACHE["all"]
                                 if language in r.languages or "any" in r.languages]
    return _RULE_CACHE[language]


def scan_file(sf: SourceFile) -> List[Finding]:
    rules = _rules_for(sf.rule_language)
    if not rules:
        return []
    findings: List[Finding] = []
    in_block_comment = False
    for number, line in enumerate(sf.lines, start=1):
        stripped = line.strip()
        if not stripped or len(line) > MAX_LINE_LENGTH:
            continue
        # skip comments: a commented-out vulnerable line is not a vulnerability
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*") and "*/" not in stripped:
            in_block_comment = True
            continue
        if sf.is_comment(number):
            continue
        for rule in rules:
            if not rule.pattern.search(line):
                continue
            if rule.exclude and rule.exclude.search(line):
                continue
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, file=sf.rel, line=number,
                severity=rule.severity, cwe=rule.cwe, description=rule.message,
                fix=rule.fix, confidence=rule.confidence, engines=["rules"],
                snippet=stripped, context=sf.context(number), language=sf.language,
            ))
    return findings


def scan(files: Iterable[SourceFile]) -> List[Finding]:
    out: List[Finding] = []
    for sf in files:
        out.extend(scan_file(sf))
    return out
