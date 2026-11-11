"""The approved learned rules, stored as YAML so they can be read, edited and committed.

    learned/rules.yaml      new rules
    learned/overrides.yaml  extra exclusions for existing rules:  {rule_id: [regex, ...]}

Candidates that are still waiting for approval live in the SQLite database
(sca/storage.py), not here: only approved rules take part in a scan.
"""
from __future__ import annotations

from datetime import date
from typing import Any, Dict, List

import yaml

from ..engines import rules_engine
from ..engines.rules_engine import learned_dir
from ..storage import Storage

PROBATION_CONFIDENCE = 0.55   # a new learned rule starts here; reviews move it up or down
RULE_KEYS = ("id", "title", "languages", "cwe", "severity", "confidence", "pattern", "exclude",
             "ignore_case", "message", "fix")


def _path(name: str):
    folder = learned_dir()
    folder.mkdir(parents=True, exist_ok=True)
    return folder / name


def read_learned() -> List[Dict[str, Any]]:
    path = _path("rules.yaml")
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [r for r in data if isinstance(r, dict)]


def _write_learned(rules: List[Dict[str, Any]]) -> None:
    header = ("# Learned rules: proposed by the AI, validated automatically, approved by a "
              "human.\n# Managed by `python -m sca rules` and the Learning tab. "
              "You can edit or delete entries by hand.\n")
    body = yaml.safe_dump(rules, sort_keys=False, allow_unicode=True, width=1000) if rules else "[]\n"
    _path("rules.yaml").write_text(header + body, encoding="utf-8")
    rules_engine.invalidate()


def add_learned_rule(candidate: Dict[str, Any]) -> Dict[str, Any]:
    rule = {key: candidate[key] for key in RULE_KEYS if candidate.get(key) not in (None, "")}
    rule["confidence"] = PROBATION_CONFIDENCE
    rule["learned"] = {
        "source": candidate.get("source", ""),
        "origin": candidate.get("origin", ""),
        "approved": date.today().isoformat(),
        "examples_vulnerable": candidate.get("examples_vulnerable", [])[:5],
        "examples_safe": candidate.get("examples_safe", [])[:5],
    }
    rules = [r for r in read_learned() if r.get("id") != rule["id"]]
    rules.append(rule)
    _write_learned(rules)
    return rule


def remove_learned_rule(rule_id: str) -> bool:
    rules = read_learned()
    kept = [r for r in rules if r.get("id") != rule_id]
    if len(kept) == len(rules):
        return False
    _write_learned(kept)
    return True


def read_overrides() -> Dict[str, List[str]]:
    path = _path("overrides.yaml")
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): list(v or []) for k, v in data.items()} if isinstance(data, dict) else {}


def add_override(rule_id: str, exclude: str) -> None:
    overrides = read_overrides()
    patterns = overrides.setdefault(rule_id, [])
    if exclude not in patterns:
        patterns.append(exclude)
    header = "# Approved exclusions: a line matching one of these is skipped by the rule.\n"
    _path("overrides.yaml").write_text(
        header + yaml.safe_dump(overrides, sort_keys=True, allow_unicode=True, width=1000),
        encoding="utf-8")
    rules_engine.invalidate()


def approve(storage: Storage, candidate_id: str) -> Dict[str, Any]:
    """The human decision: make a validated candidate part of the rule set."""
    candidate = storage.get_candidate(candidate_id)
    if candidate is None:
        raise KeyError("No candidate with id %s" % candidate_id)
    if not (candidate.get("validation") or {}).get("passed"):
        raise ValueError("Candidate %s did not pass validation and cannot be approved"
                         % candidate_id)
    if candidate.get("kind") == "exclude":
        add_override(candidate["target_rule"], candidate["exclude"])
    else:
        add_learned_rule(candidate)
    storage.set_candidate_status(candidate_id, "approved")
    return candidate


def reject(storage: Storage, candidate_id: str) -> None:
    if storage.get_candidate(candidate_id) is None:
        raise KeyError("No candidate with id %s" % candidate_id)
    storage.set_candidate_status(candidate_id, "rejected")
