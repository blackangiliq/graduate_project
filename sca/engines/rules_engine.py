"""Pattern engine: runs YAML rules against each source line.

Two kinds of rules are loaded:
  * built-in rules   sca/rules/*.yaml           (written and tested with the tool)
  * learned rules    learned/rules.yaml         (proposed by the AI, validated automatically,
                                                 approved by a human - see sca/learn/)
plus learned/overrides.yaml: extra "exclude" patterns that were approved to silence a
false positive of an existing rule.

A rule looks like this:

    - id: JS-SQLI-001
      title: SQL query built with string concatenation
      languages: [javascript]
      cwe: CWE-89
      severity: high
      confidence: 0.7
      pattern: '<regular expression that marks a vulnerable line>'
      exclude: '<optional regular expression; if it also matches, the line is ignored>'
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import yaml

from ..models import Finding
from ..walker import SourceFile

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
MAX_LINE_LENGTH = 600  # longer lines are almost always minified or generated code


def learned_dir() -> Path:
    override = os.environ.get("SCA_LEARNED_DIR")
    return Path(override) if override else Path(__file__).resolve().parent.parent.parent / "learned"


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
    origin: str = "builtin"                       # builtin | learned
    extra_excludes: List["re.Pattern[str]"] = field(default_factory=list)

    def matches(self, line: str) -> bool:
        if not self.pattern.search(line):
            return False
        if self.exclude and self.exclude.search(line):
            return False
        return not any(extra.search(line) for extra in self.extra_excludes)


def parse_rule(raw: Dict, origin: str = "builtin") -> Rule:
    flags = re.IGNORECASE if raw.get("ignore_case") else 0
    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        languages=[str(x) for x in raw["languages"]],
        cwe=str(raw.get("cwe", "")),
        severity=str(raw.get("severity", "medium")),
        confidence=float(raw.get("confidence", 0.6)),
        pattern=re.compile(raw["pattern"], flags),
        exclude=re.compile(raw["exclude"], flags) if raw.get("exclude") else None,
        message=str(raw.get("message", "")),
        fix=str(raw.get("fix", "")),
        origin=origin,
    )


def load_builtin(rules_dir: Optional[Path] = None) -> List[Rule]:
    rules: List[Rule] = []
    seen = set()
    for path in sorted((rules_dir or RULES_DIR).glob("*.yaml")):
        for raw in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            if raw["id"] in seen:
                raise ValueError("Duplicate rule id %s in %s" % (raw["id"], path.name))
            seen.add(raw["id"])
            rules.append(parse_rule(raw))
    return rules


def load_learned() -> List[Rule]:
    """Approved learned rules. A broken entry is skipped: a bad learned rule must never
    stop a scan."""
    path = learned_dir() / "rules.yaml"
    if not path.is_file():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except (yaml.YAMLError, OSError):
        return []
    rules = []
    for raw in data:
        try:
            rules.append(parse_rule(raw, origin="learned"))
        except (KeyError, TypeError, ValueError, re.error):
            continue
    return rules


def load_overrides() -> Dict[str, List[str]]:
    path = learned_dir() / "overrides.yaml"
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}
    return {str(k): [str(x) for x in (v or [])] for k, v in data.items()} \
        if isinstance(data, dict) else {}


def _stamp() -> Tuple:
    files = sorted(RULES_DIR.glob("*.yaml")) + [learned_dir() / "rules.yaml",
                                                learned_dir() / "overrides.yaml"]
    return tuple((str(p), p.stat().st_mtime_ns if p.exists() else 0) for p in files)


_CACHE: Dict[Tuple, List[Rule]] = {}


def load_rules(rules_dir: Optional[Path] = None, include_learned: bool = True) -> List[Rule]:
    """All active rules. The result is cached until a rule file changes on disk."""
    if rules_dir is not None:
        return load_builtin(rules_dir)
    key = (_stamp(), include_learned)
    if key not in _CACHE:
        rules = load_builtin()
        if include_learned:
            ids = {r.id for r in rules}
            rules += [r for r in load_learned() if r.id not in ids]
            for rule_id, patterns in load_overrides().items():
                for rule in rules:
                    if rule.id != rule_id:
                        continue
                    for text in patterns:
                        try:
                            rule.extra_excludes.append(re.compile(text))
                        except re.error:
                            continue
        _CACHE.clear()
        _CACHE[key] = rules
    return _CACHE[key]


def rules_for(language: str, rules: Optional[List[Rule]] = None,
              disabled: Optional[Set[str]] = None) -> List[Rule]:
    disabled = disabled or set()
    return [r for r in (rules if rules is not None else load_rules())
            if (language in r.languages or "any" in r.languages) and r.id not in disabled]


def code_lines(sf: SourceFile) -> Iterable[Tuple[int, str]]:
    """Yield (line number, text) for the lines a rule may be applied to: no blank lines,
    no comments, no over-long (minified) lines."""
    in_block_comment = False
    for number, line in enumerate(sf.lines, start=1):
        stripped = line.strip()
        if not stripped or len(line) > MAX_LINE_LENGTH:
            continue
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*") and "*/" not in stripped:
            in_block_comment = True
            continue
        if sf.is_comment(number):
            continue
        yield number, line


def scan_file(sf: SourceFile, disabled: Optional[Set[str]] = None,
              rules: Optional[List[Rule]] = None) -> List[Finding]:
    active = rules_for(sf.rule_language, rules, disabled)
    if not active:
        return []
    findings: List[Finding] = []
    for number, line in code_lines(sf):
        for rule in active:
            if not rule.matches(line):
                continue
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, file=sf.rel, line=number,
                severity=rule.severity, cwe=rule.cwe, description=rule.message,
                fix=rule.fix, confidence=rule.confidence,
                engines=["learned" if rule.origin == "learned" else "rules"],
                snippet=sf.line_text(number), context=sf.context(number),
                language=sf.language,
            ))
    return findings


def scan(files: Iterable[SourceFile], disabled: Optional[Set[str]] = None) -> List[Finding]:
    rules = load_rules()
    out: List[Finding] = []
    for sf in files:
        out.extend(scan_file(sf, disabled, rules))
    return out
