"""Rule management: everything a user can do with the rules, used by the dashboard
(Rules tab) and by `python -m sca rules ...`.

    list / show          every rule the tool knows, enabled or not, with its origin
    try_rule             run an expression on a piece of code and see which lines it marks
    check                test a rule before saving it (errors block, warnings inform)
    create               add your own rule                      -> learned/custom.yaml
    update               change any field of any rule
    set_enabled          switch a rule off or on
    reset                undo your changes to a rule that ships with the tool
    delete               remove a custom or learned rule
    remove_exclusion     drop an approved exclusion of a rule   -> learned/overrides.yaml
    export_yaml / import_yaml   move rules between computers

Rules that ship with the tool (origins "builtin" and "imported") are never rewritten. A
change to one of them is stored as a small entry in learned/edits.yaml, so it survives an
update of the tool and can be undone with `reset`. Custom and learned rules live in the
user's own files and are changed in place.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

from .cwe import canonical
from .engines import rules_engine
from .engines.rules_engine import EDITABLE, Rule
from .learn import sandbox, validate
from .models import SEVERITY_RANK
from .storage import Storage
from .walker import CODE_LANGUAGES

# every language name a rule may use
LANGUAGES = ["any"] + CODE_LANGUAGES + ["config", "html"]
ID_FORMAT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{2,63}")
USER_FILES = {"learned": "rules.yaml", "custom": "custom.yaml"}
# the fields of a rule as they are written to a YAML file, in this order
FILE_KEYS = ("id", "kind", "title", "languages", "cwe", "severity", "confidence", "pattern",
             "exclude", "ignore_case", "near", "within", "requires_taint", "enabled",
             "message", "fix", "keywords", "entropy",
             "secret_group", "examples_vulnerable", "examples_safe", "note", "learned")
HEADERS = {
    "custom.yaml": "# Your own rules. Managed by the Rules tab of the dashboard and by\n"
                   "# `python -m sca rules new|edit|delete`. You can also edit this file by hand.\n",
    "rules.yaml": "# Learned rules: proposed by the AI, validated automatically, approved by a "
                  "human.\n# Managed by `python -m sca rules` and the Learning tab. "
                  "You can edit or delete entries by hand.\n",
    "edits.yaml": "# Your changes to rules that ship with the tool: {rule id: {field: value}}.\n"
                  "# Delete an entry (or use `python -m sca rules reset ID`) to undo it.\n",
    "overrides.yaml": "# Approved exclusions: a line matching one of these is skipped by the rule.\n",
}


class RuleError(ValueError):
    """The requested change is not possible; the message says why."""


# ------------------------------------------------------------------ files
def _path(name: str):
    folder = rules_engine.learned_dir()
    folder.mkdir(parents=True, exist_ok=True)
    return folder / name


def _read(name: str, default: Any) -> Any:
    path = _path(name)
    if not path.is_file():
        return default
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, type(default)) else default


def _write(name: str, data: Any) -> None:
    body = yaml.safe_dump(data, sort_keys=isinstance(data, dict), allow_unicode=True,
                          width=1000) if data else ("{}\n" if isinstance(data, dict) else "[]\n")
    _path(name).write_text(HEADERS[name] + body, encoding="utf-8")
    rules_engine.invalidate()


def _clean(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the known fields, in file order, without empty values."""
    out: Dict[str, Any] = {}
    for key in FILE_KEYS:
        value = raw.get(key)
        if value in (None, "", [], {}) or (key in ("ignore_case",) and not value) \
                or (key == "enabled" and value is True) or (key == "kind" and value != "secret") \
                or (key in ("entropy", "secret_group", "requires_taint") and not value) \
                or (key == "within" and (not raw.get("near")
                                         or value == rules_engine.DEFAULT_WITHIN)):
            continue
        out[key] = value
    return out


# ------------------------------------------------------------------ read
def list_rules(origin: Optional[str] = None, language: Optional[str] = None,
               cwe: Optional[str] = None, kind: Optional[str] = None,
               enabled: Optional[bool] = None, text: str = "") -> List[Rule]:
    """Every rule that matches the filters. `language` also selects rules for "any"."""
    wanted_cwe = canonical(cwe) if cwe else ""
    needle = text.strip().lower()
    out = []
    for rule in rules_engine.all_rules():
        if origin and rule.origin != origin:
            continue
        if kind and rule.kind != kind:
            continue
        if enabled is not None and rule.enabled != enabled:
            continue
        if wanted_cwe and canonical(rule.cwe) != wanted_cwe:
            continue
        if language and language not in rule.languages and "any" not in rule.languages \
                and rules_engine_language(language) not in rule.languages:
            continue
        if needle and needle not in ("%s %s %s %s %s" % (
                rule.id, rule.title, rule.pattern.pattern, rule.source, rule.message)).lower():
            continue
        out.append(rule)
    return out


def rules_engine_language(language: str) -> str:
    from .walker import RULE_LANGUAGE
    return RULE_LANGUAGE.get(language, language)


def get(rule_id: str) -> Rule:
    rule = rules_engine.get_rule(rule_id)
    if rule is None:
        raise RuleError("No rule with id %s" % rule_id)
    return rule


def summary() -> Dict[str, Any]:
    """Counts for the top of the Rules tab."""
    rules = rules_engine.all_rules()
    by_origin = {origin: {"total": 0, "enabled": 0} for origin in rules_engine.ORIGINS}
    for rule in rules:
        by_origin[rule.origin]["total"] += 1
        by_origin[rule.origin]["enabled"] += int(rule.enabled)
    return {
        "total": len(rules), "enabled": sum(r.enabled for r in rules),
        "pattern": sum(r.kind == "pattern" for r in rules),
        "secret": sum(r.kind == "secret" for r in rules),
        "edited": sum(r.edited for r in rules), "by_origin": by_origin,
        "exclusions": sum(len(v) for v in rules_engine.load_overrides().values()),
    }


def shipped_raw(rule_id: str) -> Optional[Dict[str, Any]]:
    """A shipped rule exactly as its file defines it (before the user's edits)."""
    return next((raw for raw, _o, _m, _f in rules_engine._raw_shipped() if raw["id"] == rule_id),
                None)


# ------------------------------------------------------------------ try and check
def try_rule(pattern: str, exclude: str, ignore_case: bool, code: str
             ) -> Tuple[Optional[List[int]], str]:
    """Run an expression on some code. Returns (1-based numbers of the lines it marks, "") or
    (None, error). Runs in the sandbox process, so a runaway expression cannot hang the tool."""
    lines = code.splitlines()
    matches, error = sandbox.run_patterns(pattern, exclude or "", ignore_case, lines)
    if matches is None:
        return None, error
    return [index + 1 for index in matches], ""


def check(raw: Dict[str, Any], storage: Optional[Storage] = None,
          replacing: Optional[str] = None) -> Dict[str, Any]:
    """Test a rule before it is saved.

    errors    the rule cannot be saved: a missing or invalid field, an expression that does
              not compile or is dangerously slow, an example of its own that it fails
    warnings  the rule can be saved but deserves a second look: it matches everyday code or
              known-safe code, or it repeats an existing rule
    """
    errors: List[str] = []
    warnings: List[str] = []
    raw = normalise(raw)
    rule_id = str(raw.get("id") or "")
    pattern = str(raw.get("pattern") or "")
    exclude = str(raw.get("exclude") or "")
    ignore_case = bool(raw.get("ignore_case"))
    languages = [str(l) for l in raw.get("languages") or []]
    vulnerable = [str(x) for x in raw.get("examples_vulnerable") or [] if str(x).strip()]
    safe = [str(x) for x in raw.get("examples_safe") or [] if str(x).strip()]

    if not ID_FORMAT.fullmatch(rule_id):
        errors.append("id: 3-64 letters, digits, '-', '_' or '.', for example MY-SQLI-001")
    elif rule_id != replacing and rules_engine.get_rule(rule_id) is not None:
        errors.append("id: a rule called %s already exists" % rule_id)
    if not str(raw.get("title") or "").strip():
        errors.append("title: missing")
    if not languages or any(l not in LANGUAGES for l in languages):
        errors.append("languages: choose from %s" % ", ".join(LANGUAGES))
    if not re.fullmatch(r"CWE-\d{1,4}", str(raw.get("cwe") or "")):
        errors.append("cwe: must look like CWE-89")
    if str(raw.get("severity", "")).lower() not in SEVERITY_RANK:
        errors.append("severity: one of %s" % ", ".join(SEVERITY_RANK))
    try:
        if not 0.0 <= float(raw.get("confidence", 0.6)) <= 1.0:
            raise ValueError
    except (TypeError, ValueError):
        errors.append("confidence: a number between 0 and 1")
    if not pattern:
        errors.append("pattern: missing")
    if raw.get("near"):
        try:
            re.compile(str(raw["near"]))
        except re.error as exc:
            errors.append("near: %s" % exc)
    try:
        if not 0 <= int(raw.get("within", rules_engine.DEFAULT_WITHIN) or 0) <= 60:
            raise ValueError
    except (TypeError, ValueError):
        errors.append("within: a number of lines between 0 and 60")
    if errors:
        return {"passed": False, "errors": errors, "warnings": warnings}

    corpus = validate.clean_corpus([l for l in languages if l in CODE_LANGUAGES]
                                   or CODE_LANGUAGES, storage)
    groups = {"stress": validate.stress_lines(pattern), "probes": validate.BENIGN_PROBES,
              "vulnerable": vulnerable, "safe": safe, "clean": [line for _, line in corpus]}
    result, error = validate._run(pattern, exclude, ignore_case, groups)
    if result is None:
        errors.append("pattern: %s" % error)
        return {"passed": False, "errors": errors, "warnings": warnings}
    missed = [vulnerable[i] for i in range(len(vulnerable)) if i not in result["vulnerable"]]
    if missed:
        errors.append("examples: the rule misses its own vulnerable example: %s" % missed[0][:100])
    if result["safe"]:
        errors.append("examples: the rule matches its own safe example: %s"
                      % safe[result["safe"][0]][:100])
    if raw.get("kind") != "secret":
        if not re.search(r"[A-Za-z_]{3,}", re.sub(r"\\[A-Za-z]", " ", pattern)):
            warnings.append("The expression has no literal word of 3+ letters; it may match "
                            "far more than intended.")
        if result["probes"]:
            warnings.append("It matches everyday code such as: %s"
                            % validate.BENIGN_PROBES[result["probes"][0]])
        if result["clean"]:
            origin, line = corpus[result["clean"][0]]
            warnings.append("It matches %d line(s) of known-safe code, for example (%s): %s"
                            % (len(result["clean"]), origin, line.strip()[:100]))
        if not vulnerable:
            warnings.append("No vulnerable example given: add at least one line the rule "
                            "must match, so a later edit cannot silently break it.")
    twin = next((r.id for r in rules_engine.all_rules()
                 if r.pattern.pattern == pattern and r.id not in (rule_id, replacing)), None)
    if twin:
        warnings.append("Rule %s has exactly the same expression." % twin)
    return {"passed": not errors, "errors": errors, "warnings": warnings}


def _require_valid(raw: Dict[str, Any], storage: Optional[Storage], replacing: Optional[str]
                   ) -> Dict[str, Any]:
    result = check(raw, storage, replacing)
    if not result["passed"]:
        raise RuleError("; ".join(result["errors"]))
    return result


# ------------------------------------------------------------------ change
def create(raw: Dict[str, Any], storage: Optional[Storage] = None) -> Dict[str, Any]:
    """Add a rule written by the user. Returns the result of `check` (with its warnings)."""
    raw = normalise({"severity": "medium", **raw})
    result = _require_valid(raw, storage, None)
    rules = _read("custom.yaml", [])
    rules.append(_clean(raw))
    _write("custom.yaml", rules)
    return result


def normalise(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Accept "89" or "cwe-89" for the weakness and any letter case for the severity."""
    raw = dict(raw)
    if "cwe" in raw:
        raw["cwe"] = canonical_or_same(raw["cwe"])
    if "severity" in raw:
        raw["severity"] = str(raw["severity"]).lower()
    return raw


def canonical_or_same(cwe: Any) -> str:
    text = str(cwe or "").strip().upper()
    digits = re.fullmatch(r"(?:CWE-)?(\d{1,4})", text)
    return "CWE-%d" % int(digits.group(1)) if digits else text


def update(rule_id: str, changes: Dict[str, Any], storage: Optional[Storage] = None
           ) -> Dict[str, Any]:
    """Change fields of a rule. Shipped rules are edited through learned/edits.yaml."""
    rule = get(rule_id)
    changes = {k: v for k, v in changes.items() if k in EDITABLE + (
        "examples_vulnerable", "examples_safe")}
    changes = normalise(changes)
    current = rule.as_dict()
    merged = {**{k: current[k] for k in FILE_KEYS if k in current}, **changes, "id": rule_id}
    result = _require_valid(merged, storage, rule_id)

    if rule.origin in USER_FILES:
        name = USER_FILES[rule.origin]
        rules = _read(name, [])
        for index, entry in enumerate(rules):
            if isinstance(entry, dict) and entry.get("id") == rule_id:
                rules[index] = _clean({**entry, **changes})
        _write(name, rules)
        return result

    original = shipped_raw(rule_id) or {}
    edits = _read("edits.yaml", {})
    entry = {**(edits.get(rule_id) or {}), **{k: v for k, v in changes.items() if k in EDITABLE}}
    defaults = {"exclude": "", "ignore_case": False, "message": "", "fix": "", "enabled": True,
                "confidence": 0.6, "severity": "medium"}
    entry = {k: v for k, v in entry.items()        # keep only real differences
             if v != original.get(k, defaults.get(k))}
    if entry:
        edits[rule_id] = entry
    else:
        edits.pop(rule_id, None)
    _write("edits.yaml", edits)
    return result


def set_enabled(rule_id: str, enabled: bool) -> None:
    rule = get(rule_id)
    if rule.origin in USER_FILES:
        name = USER_FILES[rule.origin]
        rules = _read(name, [])
        for entry in rules:
            if isinstance(entry, dict) and entry.get("id") == rule_id:
                entry["enabled"] = bool(enabled)
        _write(name, [_clean(r) for r in rules])
        return
    edits = _read("edits.yaml", {})
    entry = dict(edits.get(rule_id) or {})
    original = bool((shipped_raw(rule_id) or {}).get("enabled", True))
    if bool(enabled) == original:
        entry.pop("enabled", None)
    else:
        entry["enabled"] = bool(enabled)
    if entry:
        edits[rule_id] = entry
    else:
        edits.pop(rule_id, None)
    _write("edits.yaml", edits)


def set_enabled_many(rule_ids: Sequence[str], enabled: bool) -> int:
    """Switch several rules on or off. Returns how many actually changed."""
    changed = 0
    for rule_id in rule_ids:
        if get(rule_id).enabled != bool(enabled):
            set_enabled(rule_id, enabled)
            changed += 1
    return changed


def reset(rule_id: str) -> bool:
    """Undo every change made to a shipped rule. True if there was something to undo."""
    rule = get(rule_id)
    if rule.origin in USER_FILES:
        raise RuleError("%s is your own rule: edit or delete it instead" % rule_id)
    edits = _read("edits.yaml", {})
    if rule_id not in edits:
        return False
    del edits[rule_id]
    _write("edits.yaml", edits)
    return True


def delete(rule_id: str) -> None:
    """Remove a custom or learned rule. Shipped rules can only be disabled."""
    rule = get(rule_id)
    if rule.origin not in USER_FILES:
        raise RuleError("%s ships with the tool and cannot be deleted; disable it instead"
                        % rule_id)
    name = USER_FILES[rule.origin]
    _write(name, [r for r in _read(name, []) if not (isinstance(r, dict)
                                                     and r.get("id") == rule_id)])


def remove_exclusion(rule_id: str, exclude: str) -> bool:
    overrides = _read("overrides.yaml", {})
    patterns = list(overrides.get(rule_id) or [])
    if exclude not in patterns:
        return False
    patterns.remove(exclude)
    if patterns:
        overrides[rule_id] = patterns
    else:
        overrides.pop(rule_id, None)
    _write("overrides.yaml", overrides)
    return True


# ------------------------------------------------------------------ export / import
def export_yaml(ids: Optional[Sequence[str]] = None, origin: Optional[str] = None) -> str:
    """Rules as YAML text that `import_yaml` (or another copy of the tool) can read."""
    rules = [r for r in rules_engine.all_rules()
             if (ids is None or r.id in ids) and (origin is None or r.origin == origin)]
    return yaml.safe_dump([_clean(r.as_dict()) for r in rules], sort_keys=False,
                          allow_unicode=True, width=1000) if rules else "[]\n"


def import_yaml(text: str, storage: Optional[Storage] = None
                ) -> Tuple[List[str], List[str]]:
    """Add rules from YAML text as custom rules. Returns (ids added, problems)."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [], ["Not valid YAML: %s" % str(exc).splitlines()[0]]
    if isinstance(data, dict):
        data = data.get("rules")
    if not isinstance(data, list):
        return [], ["Expected a list of rules."]
    added, problems = [], []
    for index, raw in enumerate(data, start=1):
        if not isinstance(raw, dict):
            problems.append("Entry %d is not a rule." % index)
            continue
        try:
            create(raw, storage)
            added.append(str(raw.get("id")))
        except RuleError as exc:
            problems.append("%s: %s" % (raw.get("id") or "entry %d" % index, exc))
    return added, problems


TEMPLATE = """# A rule for Secure Code Analyzer. Fill it in and add it with:
#     python -m sca rules new this-file.yaml
- id: MY-RULE-001                 # unique name
  title: Short description of the weakness
  languages: [javascript]         # any, %(languages)s
  cwe: CWE-89                     # https://cwe.mitre.org
  severity: high                  # critical, high, medium, low, info
  confidence: 0.6                 # 0..1: how sure the rule is on its own
  pattern: 'db\\.query\\(\\s*"[^"]*"\\s*\\+'     # marks a vulnerable line
  exclude: ''                     # optional: if this also matches, the line is ignored
  ignore_case: false
  near: ''                        # optional: only fire if this matches a neighbouring line
  within: 5                       # ... at most this many lines above or below
  requires_taint: false           # true = report only when user input is traced to the line
  message: Why this line is dangerous.
  fix: How to write it safely.
  examples_vulnerable:            # lines the rule MUST match (checked when you save)
    - 'db.query("SELECT * FROM t WHERE id=" + id)'
  examples_safe:                  # lines the rule must NOT match
    - 'db.query("SELECT * FROM t WHERE id=?", [id])'
""" % {"languages": ", ".join(CODE_LANGUAGES + ["config", "html"])}
