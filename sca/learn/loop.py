"""The learning loop.

    scan with the static engines
        |
    LLM deep scan finds a vulnerability that no rule reported  ---->  propose a NEW RULE
    LLM (or the reviewer) says a rule's finding is false       ---->  propose an EXCLUSION
        |
    automatic validation (validate.py); on failure the reasons are sent back to the
    model once so it can correct itself
        |
    candidate waits as "pending"  -->  human approves  -->  learned/rules.yaml
        |
    the next scan finds the same weakness statically: fast, offline, without the LLM

`bootstrap` fills gaps without a project: for a language and weakness that have no rule,
the model writes one from its own knowledge. Such rules have weaker evidence and are
labelled as bootstrap candidates.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from ..ai import llm as llm_module
from ..cwe import canonical
from ..engines import rules_engine, secrets
from ..models import Finding, ScanResult
from ..storage import Storage
from ..walker import CODE_LANGUAGES, RULE_LANGUAGE, SourceFile, walk_project
from . import propose, store, validate

ProgressFn = Callable[[str, float], None]
ATTEMPTS = 2                 # one proposal + one self-correction
FP_CONFIDENCE = 0.8          # LLM confidence needed to learn an exclusion from its verdict

WEB_CWES = ["CWE-89", "CWE-78", "CWE-79", "CWE-95", "CWE-22", "CWE-502", "CWE-327",
            "CWE-338", "CWE-295", "CWE-601", "CWE-918"]
NATIVE_CWES = ["CWE-120", "CWE-134", "CWE-78", "CWE-338", "CWE-377"]
SCRIPT_CWES = ["CWE-78", "CWE-95", "CWE-295", "CWE-732", "CWE-494"]
BOOTSTRAP_CWES = {"c": NATIVE_CWES, "cpp": NATIVE_CWES, "shell": SCRIPT_CWES,
                  "powershell": SCRIPT_CWES, "sql": ["CWE-89"]}


def load_files(target: str) -> List[SourceFile]:
    """Read the project again and mask its secrets (needed to learn after a scan)."""
    files = list(walk_project(target))
    secrets.scan(files)
    return files


def _exists(storage: Storage, candidate: Dict[str, Any]) -> bool:
    """True if an equal candidate is already pending or approved."""
    fingerprint = (candidate.get("evidence") or {}).get("fingerprint")
    for other in storage.list_candidates():
        if other["status"] not in ("pending", "approved"):
            continue
        if other["id"] == candidate["id"]:
            return True
        if fingerprint and other.get("kind") == candidate.get("kind") and \
                (other.get("evidence") or {}).get("fingerprint") == fingerprint:
            return True
    return False


def _propose_and_validate(make: Callable[[Optional[Dict[str, Any]]], Dict[str, Any]],
                          files: Optional[List[SourceFile]], storage: Storage
                          ) -> Optional[Dict[str, Any]]:
    """Ask for a candidate, validate it, and give the model one chance to correct it."""
    candidate: Optional[Dict[str, Any]] = None
    for _ in range(ATTEMPTS):
        candidate = make(candidate)
        candidate["validation"] = validate.validate(candidate, files, storage)
        if candidate["validation"]["passed"]:
            break
    assert candidate is not None
    candidate["status"] = "pending" if candidate["validation"]["passed"] else "rejected_auto"
    if candidate["status"] == "pending" and _exists(storage, candidate):
        return None
    storage.save_candidate(candidate)
    return candidate


def learn_from_scan(result: ScanResult, files: List[SourceFile], client: Any, storage: Storage,
                    max_candidates: int = 20, progress: Optional[ProgressFn] = None
                    ) -> List[Dict[str, Any]]:
    """Turn what the LLM taught us in this scan into rule candidates."""
    progress = progress or (lambda message, fraction: None)
    by_rel = {sf.rel: sf for sf in files}
    regex_rules = {r.id: r for r in rules_engine.load_rules()}
    done = {(c.get("evidence") or {}).get("fingerprint") for c in storage.list_candidates()
            if c["status"] in ("pending", "approved")}

    # 1. vulnerabilities found only by the LLM and confirmed by its second pass -> new rule
    new_rule_targets = [
        f for f in result.findings
        if f.engines == ["llm"] and f.status == "open" and f.ai_verdict == "true_positive"
        and f.file in by_rel and f.fingerprint not in done]
    # 2. findings of a regex rule judged false by the LLM or the reviewer -> exclusion
    exclusion_targets = []
    for finding in result.findings:
        false_positive = finding.user_verdict == "false_positive" or (
            finding.ai_verdict == "false_positive"
            and (finding.ai_confidence or 0) >= FP_CONFIDENCE
            and finding.user_verdict != "true_positive")
        rule = next((regex_rules[r] for r in finding.rule_ids if r in regex_rules), None)
        if false_positive and rule is not None and finding.fingerprint not in done:
            exclusion_targets.append((finding, rule))

    jobs: List[Callable[[Optional[Dict[str, Any]]], Dict[str, Any]]] = []
    for finding in new_rule_targets:
        jobs.append(lambda prev, f=finding: propose.propose_rule(client, f, by_rel[f.file], prev))
    for finding, rule in exclusion_targets:
        jobs.append(lambda prev, f=finding, r=rule:
                    propose.propose_exclude(client, f, r, by_rel.get(f.file), prev))
    jobs = jobs[:max_candidates]

    created: List[Dict[str, Any]] = []
    errors = 0
    for index, job in enumerate(jobs):
        progress("Learning %d/%d" % (index + 1, len(jobs)), index / max(1, len(jobs)))
        try:
            candidate = _propose_and_validate(job, files, storage)
        except llm_module.LLMError:
            errors += 1
            if errors >= 3:
                break
            continue
        if candidate is not None:
            created.append(candidate)
    progress("Done", 1.0)
    return created


def learn_from_feedback(client: Any, storage: Storage, max_candidates: int = 20
                        ) -> List[Dict[str, Any]]:
    """Propose exclusions for the false positives the reviewer has dismissed so far."""
    regex_rules = {r.id: r for r in rules_engine.load_rules()}
    done = {(c.get("evidence") or {}).get("fingerprint") for c in storage.list_candidates()
            if c["status"] in ("pending", "approved")}
    created: List[Dict[str, Any]] = []
    for row in storage.feedback_rows():
        if len(created) >= max_candidates:
            break
        if row["verdict"] != "fp" or row["fingerprint"] in done:
            continue
        rule = next((regex_rules[r] for r in row["rule_ids"] if r in regex_rules), None)
        if rule is None:
            continue
        finding = Finding(rule_id=rule.id, title=row.get("title") or rule.title,
                          file=row.get("file") or "", line=1, cwe=row.get("cwe") or rule.cwe,
                          snippet=row.get("snippet") or "", context=row.get("snippet") or "",
                          language=row.get("language") or "", user_verdict="false_positive")
        try:
            candidate = _propose_and_validate(
                lambda prev, f=finding, r=rule: propose.propose_exclude(client, f, r, None, prev),
                None, storage)
        except llm_module.LLMError:
            break
        if candidate is not None:
            # keep the reviewer's fingerprint so the same row is not proposed twice
            candidate["evidence"]["fingerprint"] = row["fingerprint"]
            storage.save_candidate(candidate)
            created.append(candidate)
    return created


def coverage_matrix() -> Dict[str, Dict[str, int]]:
    """language -> {CWE: number of active rules}. Python also has the AST engine."""
    matrix: Dict[str, Dict[str, int]] = {language: {} for language in CODE_LANGUAGES}
    for rule in rules_engine.load_rules():
        for language in CODE_LANGUAGES:
            if RULE_LANGUAGE.get(language, language) in rule.languages:
                cwe = canonical(rule.cwe)
                matrix[language][cwe] = matrix[language].get(cwe, 0) + 1
    return matrix


def coverage_gaps(language: str, cwes: Optional[Sequence[str]] = None) -> List[str]:
    """The weaknesses that have no rule for this language yet."""
    if language == "python" and not cwes:
        return []            # Python is analysed by the AST engine, not by pattern rules
    wanted = [canonical(c) for c in (cwes or BOOTSTRAP_CWES.get(language, WEB_CWES))]
    covered = coverage_matrix().get(language, {})
    return [cwe for cwe in wanted if cwe and not covered.get(cwe)]


def bootstrap(client: Any, storage: Storage, language: str,
              cwes: Optional[Sequence[str]] = None, progress: Optional[ProgressFn] = None
              ) -> List[Dict[str, Any]]:
    """Ask the model for rules that fill the coverage gaps of one language."""
    progress = progress or (lambda message, fraction: None)
    if language not in CODE_LANGUAGES:
        raise ValueError("Unknown language: %s" % language)
    gaps = coverage_gaps(language, cwes)
    created: List[Dict[str, Any]] = []
    errors = 0
    for index, cwe in enumerate(gaps):
        progress("Bootstrap %s %s (%d/%d)" % (language, cwe, index + 1, len(gaps)),
                 index / max(1, len(gaps)))
        try:
            candidate = _propose_and_validate(
                lambda prev, c=cwe: propose.propose_bootstrap_rule(client, language, c, prev),
                None, storage)
        except llm_module.LLMError:
            errors += 1
            if errors >= 3:
                break
            continue
        if candidate is not None:
            created.append(candidate)
    progress("Done", 1.0)
    return created


def auto_approve(storage: Storage, candidates: List[Dict[str, Any]]) -> List[str]:
    """Approve validated candidates without a human. Only scan-derived rules qualify: they
    have real evidence. Bootstrap rules and exclusions always wait for a person."""
    approved = []
    for candidate in candidates:
        if candidate["status"] == "pending" and candidate.get("kind") == "rule" \
                and candidate.get("origin") == "scan":
            store.approve(storage, candidate["id"])
            approved.append(candidate["id"])
    return approved
