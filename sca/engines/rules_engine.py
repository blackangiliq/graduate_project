"""Pattern engine: runs YAML rules against each source line.

Where rules come from (the "origin" of a rule):

  builtin    sca/rules/*.yaml            written and tested with the tool
  imported   sca/rules/imported/*.yaml   converted from open-source rule sets (DevSkim,
                                         Gitleaks) by tools/import_rules.py; each file names
                                         its source and licence
  learned    learned/rules.yaml          proposed by the AI, validated, approved by a human
  custom     learned/custom.yaml         written by the user (dashboard, CLI or by hand)

and two files with the user's changes to rules that ship with the tool:

  learned/edits.yaml      {rule id: {field: new value}}   edit, disable or enable a rule
  learned/overrides.yaml  {rule id: [regex, ...]}         approved extra exclusions

A rule looks like this:

    - id: JS-SQLI-001
      title: SQL query built with string concatenation
      languages: [javascript]        # or [any]
      cwe: CWE-89
      severity: high                 # critical | high | medium | low | info
      confidence: 0.7                # 0..1
      pattern: '<regular expression that marks a vulnerable line>'
      exclude: '<optional regular expression; if it also matches, the line is ignored>'
      ignore_case: false             # optional
      enabled: true                  # optional; false = shipped but switched off
      message: '...'                 # optional explanation
      fix: '...'                     # optional advice
      examples_vulnerable: [...]     # optional lines the rule must match
      examples_safe: [...]           # optional lines the rule must not match

A rule with `kind: secret` is run by the secrets engine instead (sca/engines/secrets.py):
its match is treated as a credential, masked everywhere, and may require `keywords`
(cheap pre-filter) and a minimum `entropy`.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

from ..models import Finding
from ..walker import SourceFile

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
IMPORTED_DIR = RULES_DIR / "imported"
MAX_LINE_LENGTH = 600  # longer lines are almost always minified or generated code
ORIGINS = ("builtin", "imported", "learned", "custom")
# the fields a user may change through learned/edits.yaml
EDITABLE = ("title", "languages", "cwe", "severity", "confidence", "pattern", "exclude",
            "ignore_case", "message", "fix", "enabled")


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
    origin: str = "builtin"                       # builtin | imported | learned | custom
    extra_excludes: List["re.Pattern[str]"] = field(default_factory=list)
    kind: str = "pattern"                         # pattern | secret
    enabled: bool = True
    default_enabled: bool = True                  # what the rule file itself says
    edited: bool = False                          # changed through learned/edits.yaml
    ignore_case: bool = False
    source: str = ""                              # for imported rules: "DevSkim DS425070"
    license: str = ""
    url: str = ""
    note: str = ""
    keywords: List[str] = field(default_factory=list)
    entropy: float = 0.0
    secret_group: int = 0
    examples_vulnerable: List[str] = field(default_factory=list)
    examples_safe: List[str] = field(default_factory=list)
    file: str = ""                                # the YAML file the rule was read from

    def matches(self, line: str) -> bool:
        if not self.pattern.search(line):
            return False
        if self.exclude and self.exclude.search(line):
            return False
        return not any(extra.search(line) for extra in self.extra_excludes)

    def as_dict(self) -> Dict[str, Any]:
        """Plain values, for the dashboard, the CLI and export."""
        return {
            "id": self.id, "title": self.title, "languages": list(self.languages),
            "cwe": self.cwe, "severity": self.severity, "confidence": self.confidence,
            "pattern": self.pattern.pattern,
            "exclude": self.exclude.pattern if self.exclude else "",
            "ignore_case": self.ignore_case, "message": self.message, "fix": self.fix,
            "kind": self.kind, "origin": self.origin, "enabled": self.enabled,
            "default_enabled": self.default_enabled, "edited": self.edited,
            "source": self.source, "license": self.license, "url": self.url,
            "note": self.note, "keywords": list(self.keywords), "entropy": self.entropy,
            "extra_excludes": [e.pattern for e in self.extra_excludes],
            "examples_vulnerable": list(self.examples_vulnerable),
            "examples_safe": list(self.examples_safe), "file": self.file,
        }


def parse_rule(raw: Dict, origin: str = "builtin", meta: Optional[Dict] = None,
               file: str = "") -> Rule:
    meta = meta or {}
    flags = re.IGNORECASE if raw.get("ignore_case") else 0
    learned = raw.get("learned") if isinstance(raw.get("learned"), dict) else {}
    source = str(raw.get("source", "") or "")
    if meta.get("name") and source:
        source = "%s %s" % (meta["name"], source)
    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        languages=[str(x) for x in raw["languages"]],
        cwe=str(raw.get("cwe", "")),
        severity=str(raw.get("severity", "medium")).lower(),
        confidence=max(0.0, min(1.0, float(raw.get("confidence", 0.6)))),
        pattern=re.compile(raw["pattern"], flags),
        exclude=re.compile(raw["exclude"], flags) if raw.get("exclude") else None,
        message=str(raw.get("message", "") or ""),
        fix=str(raw.get("fix", "") or ""),
        origin=origin,
        kind="secret" if raw.get("kind") == "secret" else "pattern",
        enabled=bool(raw.get("enabled", True)),
        default_enabled=bool(raw.get("enabled", True)),
        ignore_case=bool(raw.get("ignore_case")),
        source=source or str(learned.get("source", "") or ""),
        license=str(meta.get("license", "") or ""),
        url=str(meta.get("url", "") or ""),
        note=str(raw.get("note", "") or ""),
        keywords=[str(k).lower() for k in raw.get("keywords") or []],
        entropy=float(raw.get("entropy", 0) or 0),
        secret_group=int(raw.get("secret_group", 0) or 0),
        examples_vulnerable=[str(x) for x in (raw.get("examples_vulnerable")
                                              or learned.get("examples_vulnerable") or [])],
        examples_safe=[str(x) for x in (raw.get("examples_safe")
                                        or learned.get("examples_safe") or [])],
        file=file,
    )


def _read_yaml(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None


def _raw_shipped(rules_dir: Optional[Path] = None
                 ) -> List[Tuple[Dict, str, Dict, str]]:
    """(raw rule, origin, source metadata, file name) for every rule that ships with the tool.
    A built-in file is a list of rules; an imported file is {source: {...}, rules: [...]}."""
    out: List[Tuple[Dict, str, Dict, str]] = []
    seen = set()
    base = rules_dir or RULES_DIR
    groups = [(sorted(base.glob("*.yaml")), "builtin")]
    if rules_dir is None:
        groups.append((sorted(IMPORTED_DIR.glob("*.yaml")), "imported"))
    for paths, origin in groups:
        for path in paths:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            meta = data.get("source", {}) if isinstance(data, dict) else {}
            for raw in (data.get("rules", []) if isinstance(data, dict) else data):
                if raw["id"] in seen:
                    raise ValueError("Duplicate rule id %s in %s" % (raw["id"], path.name))
                seen.add(raw["id"])
                out.append((raw, origin, meta, path.name))
    return out


def load_builtin(rules_dir: Optional[Path] = None) -> List[Rule]:
    """The rules that ship with the tool, exactly as written in their files."""
    return [parse_rule(raw, origin, meta, name)
            for raw, origin, meta, name in _raw_shipped(rules_dir)]


def _load_user_file(name: str, origin: str) -> List[Rule]:
    """Rules from learned/rules.yaml or learned/custom.yaml. A broken entry is skipped: a bad
    rule must never stop a scan."""
    data = _read_yaml(learned_dir() / name)
    rules = []
    for raw in data if isinstance(data, list) else []:
        try:
            rules.append(parse_rule(raw, origin=origin, file="learned/" + name))
        except (KeyError, TypeError, ValueError, re.error):
            continue
    return rules


def load_learned() -> List[Rule]:
    return _load_user_file("rules.yaml", "learned")


def load_custom() -> List[Rule]:
    return _load_user_file("custom.yaml", "custom")


def load_overrides() -> Dict[str, List[str]]:
    data = _read_yaml(learned_dir() / "overrides.yaml")
    return {str(k): [str(x) for x in (v or [])] for k, v in data.items()} \
        if isinstance(data, dict) else {}


def load_edits() -> Dict[str, Dict[str, Any]]:
    data = _read_yaml(learned_dir() / "edits.yaml")
    if not isinstance(data, dict):
        return {}
    return {str(k): {f: v[f] for f in EDITABLE if f in v}
            for k, v in data.items() if isinstance(v, dict)}


def _stamp() -> Tuple:
    folder = learned_dir()
    files = sorted(RULES_DIR.glob("*.yaml")) + sorted(IMPORTED_DIR.glob("*.yaml")) + [
        folder / "rules.yaml", folder / "custom.yaml", folder / "edits.yaml",
        folder / "overrides.yaml"]
    return tuple((str(p), p.stat().st_mtime_ns if p.exists() else 0) for p in files)


_CACHE: Dict[Tuple, List[Rule]] = {}


def all_rules(include_user: bool = True) -> List[Rule]:
    """Every rule the tool knows, enabled or not, with the user's edits and exclusions
    applied. The result is cached until a rule file changes on disk."""
    key = (_stamp(), include_user)
    if key in _CACHE:
        return _CACHE[key]
    edits = load_edits() if include_user else {}
    rules: List[Rule] = []
    for raw, origin, meta, name in _raw_shipped():
        rule = None
        if raw["id"] in edits:
            try:      # a broken edit is ignored, the original rule stays in force
                rule = parse_rule({**raw, **edits[raw["id"]]}, origin, meta, name)
                rule.edited = True
                rule.default_enabled = bool(raw.get("enabled", True))
            except (KeyError, TypeError, ValueError, re.error):
                rule = None
        rules.append(rule or parse_rule(raw, origin, meta, name))
    if include_user:
        ids = {r.id for r in rules}
        for rule in load_learned() + load_custom():
            if rule.id not in ids:
                ids.add(rule.id)
                rules.append(rule)
        by_id = {r.id: r for r in rules}
        for rule_id, patterns in load_overrides().items():
            for text in patterns if rule_id in by_id else []:
                try:
                    by_id[rule_id].extra_excludes.append(re.compile(text))
                except re.error:
                    continue
    _CACHE.clear()
    _CACHE[key] = rules
    return rules


def load_rules(rules_dir: Optional[Path] = None, include_learned: bool = True) -> List[Rule]:
    """The active pattern rules: enabled, and not of kind "secret"."""
    if rules_dir is not None:
        return [r for r in load_builtin(rules_dir) if r.enabled and r.kind == "pattern"]
    return [r for r in all_rules(include_learned) if r.enabled and r.kind == "pattern"]


def secret_rules() -> List[Rule]:
    """The active rules of kind "secret" (run by the secrets engine)."""
    return [r for r in all_rules() if r.enabled and r.kind == "secret"]


def get_rule(rule_id: str) -> Optional[Rule]:
    return next((r for r in all_rules() if r.id == rule_id), None)


def rules_for(language: str, rules: Optional[List[Rule]] = None,
              disabled: Optional[Set[str]] = None) -> List[Rule]:
    disabled = disabled or set()
    return [r for r in (rules if rules is not None else load_rules())
            if (language in r.languages or "any" in r.languages) and r.id not in disabled
            and r.enabled and r.kind == "pattern"]


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
