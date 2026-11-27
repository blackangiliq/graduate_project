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
      files: []                      # optional name patterns: ['*.gradle', '**/web/index.html']
      cwe: CWE-89
      severity: high                 # critical | high | medium | low | info
      confidence: 0.7                # 0..1
      pattern: '<regular expression that marks a vulnerable line>'
      exclude: '<optional regular expression; if it also matches, the line is ignored>'
      ignore_case: false             # optional
      enabled: true                  # optional; false = shipped but switched off
      message: '...'                 # optional explanation
      fix: '...'                     # optional advice
      near: '<optional expression>'  # the rule only fires if this matches a neighbouring line
      within: 5                      # ... at most this many lines above or below (default 5)
      requires_taint: false          # true = report only when user input is traced to the line
      code_only: false               # require the pattern in code outside comments and strings
      examples_vulnerable: [...]     # optional lines the rule must match
      examples_safe: [...]           # optional lines the rule must not match

A rule with `kind: secret` is run by the secrets engine instead (sca/engines/secrets.py):
its match is treated as a credential, masked everywhere, and may require `keywords`
(cheap pre-filter) and a minimum `entropy`.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import yaml

from ..models import Finding
from ..walker import SourceFile
from . import taint_lite

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
IMPORTED_DIR = RULES_DIR / "imported"
MAX_LINE_LENGTH = 600  # longer lines are almost always minified or generated code
ORIGINS = ("builtin", "imported", "learned", "custom")
# the fields a user may change through learned/edits.yaml
EDITABLE = ("title", "languages", "files", "cwe", "severity", "confidence", "pattern",
            "exclude", "ignore_case", "message", "fix", "enabled", "near", "within",
            "requires_taint", "code_only")
DEFAULT_WITHIN = 5
# text that is not code: the strings dump of a binary, the stand-in for a binary file
SKIPPED_ORIGINS = ("strings", "placeholder")


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
    near: Optional["re.Pattern[str]"] = None      # must match a line close to the match
    within: int = DEFAULT_WITHIN                  # how close, in lines
    requires_taint: bool = False                  # only report when input is traced
    code_only: bool = False                       # ignore calls quoted in strings or comments
    files: List[str] = field(default_factory=list)  # only files matching these patterns

    def applies_to(self, rel: str) -> bool:
        """True if the rule looks at the file with this relative path: the rule names no
        file patterns, or one of them matches the path or the file name. A pattern is a
        glob that ignores case ("*.gradle", "**/web/index.html"); a leading "**/" also
        matches a file in the top folder."""
        if not self.files:
            return True
        path = rel.replace("\\", "/").lower()
        name = path.rsplit("/", 1)[-1]
        for glob in self.files:
            glob = glob.replace("\\", "/").lower()
            globs = (glob, glob[3:]) if glob.startswith("**/") else (glob,)
            if any(fnmatch.fnmatchcase(target, g) for g in globs for target in (path, name)):
                return True
        return False

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
            "files": list(self.files),
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
            "near": self.near.pattern if self.near else "", "within": self.within,
            "requires_taint": self.requires_taint, "code_only": self.code_only,
        }

    def near_ok(self, lines: List[str], number: int) -> bool:
        """True if the rule has no `near` condition, or a line within `within` lines of
        line `number` (1-based, the line itself included) matches it."""
        if self.near is None:
            return True
        first, last = max(0, number - 1 - self.within), min(len(lines), number + self.within)
        return any(self.near.search(lines[i]) for i in range(first, last)
                   if len(lines[i]) <= MAX_LINE_LENGTH)


def file_patterns(value: Any) -> List[str]:
    """The `files` field as a list of patterns. Text is read as patterns separated by commas."""
    if isinstance(value, str):
        value = value.split(",")
    return [str(x).strip() for x in value or [] if str(x).strip()]


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
        near=re.compile(raw["near"], flags) if raw.get("near") else None,
        within=max(0, min(60, int(raw.get("within", DEFAULT_WITHIN) or 0))),
        requires_taint=bool(raw.get("requires_taint")),
        code_only=bool(raw.get("code_only")),
        files=file_patterns(raw.get("files")),
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
    stamp = []
    for path in files:
        try:
            info = path.stat()
            stamp.append((str(path), info.st_mtime_ns, info.st_size))
        except OSError:
            stamp.append((str(path), 0, 0))
    return tuple(stamp)


_CACHE: Dict[Tuple, List[Rule]] = {}


def invalidate() -> None:
    """Forget the cached rule set. Called after every write to a rule file: two writes can
    fall within one tick of the file system clock, which the time stamp alone would miss."""
    _CACHE.clear()


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


_ASSIGNED_PYTHON_STRING = re.compile(r"""^[\w.]+(?:\s*:\s*[\w.]+)?\s*=\s*[rRbBuUfF]*(?P<quote>'''|\"\"\")""")


def code_lines(sf: SourceFile) -> Iterable[Tuple[int, str]]:
    """Yield (line number, text) for the lines a rule may be applied to: no blank lines,
    no comments, no over-long (minified) lines."""
    in_block_comment = False
    docstring = ""                   # the quote that closes the Python docstring we are in
    python = sf.language == "python"
    for number, line in enumerate(sf.lines, start=1):
        stripped = line.strip()
        if python:                   # a docstring is documentation, not code
            if docstring:
                if docstring in stripped:
                    docstring = ""
                continue
            opener = next((q for q in ('"""', "'''") if stripped.lstrip("rRbBuUfF").startswith(q)), "")
            if opener:
                if opener not in stripped.lstrip("rRbBuUfF")[3:]:
                    docstring = opener
                continue
            # Otherwise an assigned multiline string's closing delimiter looks like a
            # new docstring, hiding real statements that follow it.
            assigned = _ASSIGNED_PYTHON_STRING.match(stripped)
            if assigned and assigned["quote"] not in stripped[assigned.end():]:
                docstring = assigned["quote"]
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


SCRIPT_OPEN = re.compile(r"<script\b", re.IGNORECASE)
SCRIPT_CLOSE = re.compile(r"</script\s*>", re.IGNORECASE)
INLINE_SCRIPT = re.compile(r"""\bon[a-z]+\s*=\s*["']|javascript:""", re.IGNORECASE)


def script_lines(sf: SourceFile) -> Set[int]:
    """The lines of a page that hold JavaScript: inside <script> ... </script>, or an inline
    event handler (onclick="...") or javascript: URL. The rest is markup and text, where a
    word like eval() in a lesson is not code."""
    inside = False
    lines: Set[int] = set()
    for number, line in enumerate(sf.lines, start=1):
        opened = bool(SCRIPT_OPEN.search(line))
        if inside or opened or INLINE_SCRIPT.search(line):
            lines.add(number)
        if opened:
            inside = True
        if SCRIPT_CLOSE.search(line):
            inside = bool(SCRIPT_OPEN.search(SCRIPT_CLOSE.split(line)[-1]))
    return lines


# Strip documentation and other non-executable text for opt-in library API checks.
# Retaining line breaks keeps the coordinates in the original file. A literal becomes
# a sentinel so, for example, a string argument cannot turn into a no-argument call.
_QUOTES = (
    r"""'''[\s\S]*?(?:'''|\Z)|""" + r'"""[\s\S]*?(?:"""|\Z)|'
    r"""'(?:\\.|[^'\\\n])*(?:'|$)|"(?:\\.|[^"\\\n])*(?:"|$)"""
)
_C_STYLE_TEXT = re.compile(r'@"(?:[^"]|"")*(?:"|\Z)|' + _QUOTES
                           + r"|\x60(?:\\[\s\S]|[^\x60\\])*(?:\x60|\Z)"
                           + r"|//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)", re.MULTILINE)
_PYTHON_TEXT = re.compile(_QUOTES + r"|\#[^\n]*", re.MULTILINE)


def unquoted_code_lines(sf: SourceFile) -> List[str]:
    """Keep code tokens and line coordinates for rules written against API calls."""
    pattern = _PYTHON_TEXT if sf.language == "python" else _C_STYLE_TEXT

    def blank(match: re.Match) -> str:
        return "\0" + "\n" * match[0].count("\n")

    return pattern.sub(blank, "\n".join(sf.lines)).split("\n")


def scan_file(sf: SourceFile, disabled: Optional[Set[str]] = None,
              rules: Optional[List[Rule]] = None) -> List[Finding]:
    if sf.origin in SKIPPED_ORIGINS:
        return []
    active: List[Rule] = []
    ids: Set[str] = set()
    for language in sf.rule_languages:           # a page also gets the JavaScript rules
        for rule in rules_for(language, rules, disabled):
            if rule.id not in ids and rule.applies_to(sf.rel):
                ids.add(rule.id)
                active.append(rule)
    if not active:
        return []
    # On a page, a JavaScript rule (that is not also a rule of the page's own language)
    # looks only at the lines that hold script.
    own = sf.rule_language
    page_only = {r.id for r in active if len(sf.rule_languages) > 1
                 and own not in r.languages and "any" not in r.languages}
    scripts = script_lines(sf) if page_only else set()
    findings: List[Finding] = []
    source_code = None
    for number, line in code_lines(sf):
        for rule in active:
            if rule.id in page_only and number not in scripts:
                continue
            if not rule.matches(line) or not rule.near_ok(sf.lines, number):
                continue
            if rule.code_only:
                if source_code is None:
                    source_code = unquoted_code_lines(sf)
                if not rule.pattern.search(source_code[number - 1]):
                    continue
            traced = False
            if rule.requires_taint:        # a sink rule: silent unless input reaches the line
                traced = taint_lite.is_traced(sf, number)
                if not traced:
                    continue
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, file=sf.rel, line=number,
                severity=rule.severity, cwe=rule.cwe, description=rule.message,
                fix=rule.fix, engines=["learned" if rule.origin == "learned" else "rules"],
                confidence=min(0.95, rule.confidence + taint_lite.BOOST) if traced
                else rule.confidence,
                snippet=sf.line_text(number), context=sf.context(number),
                language=sf.language, tainted=traced,
            ))
    return findings


def scan(files: Iterable[SourceFile], disabled: Optional[Set[str]] = None) -> List[Finding]:
    rules = load_rules()
    out: List[Finding] = []
    for sf in files:
        out.extend(scan_file(sf, disabled, rules))
    return out
