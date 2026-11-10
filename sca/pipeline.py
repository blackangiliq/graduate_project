"""The scan pipeline: the one function that runs every stage in order.

    1. walk      collect source files from the chosen folder
    2. detect    static engines: secrets, pattern rules (built-in + learned), Python AST,
                 Bandit, Opengrep/Semgrep, Gitleaks
    3. refine    rule track record (reviewer feedback), taint-lite tracing
    4. merge     remove duplicates, combine confidences, attach CWE/OWASP knowledge,
                 re-apply earlier reviewer verdicts
    5. ML        second-opinion probability from the classifier
    6. LLM       optional review, deep scan and verification by a local or cloud model
    7. assess    confirmed/probable tier, risk per finding, project score and grade
    8. store     save to the history database
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import merge, scoring
from .ai import llm as llm_module
from .ai.classifier import get_classifier
from .ai.providers import LLMConfig, make_client
from .engines import external, python_ast, rules_engine, secrets, taint_lite
from .learn import feedback as feedback_module
from .models import Finding, ScanResult, SEVERITY_RANK
from .storage import Storage
from .walker import SourceFile, walk_project

ProgressFn = Callable[[str, float], None]


@dataclass
class ScanOptions:
    # static engines
    use_rules: bool = True
    use_ast: bool = True
    use_secrets: bool = True
    use_bandit: bool = True
    use_semgrep: bool = True          # runs only if opengrep/semgrep is installed
    use_gitleaks: bool = True         # runs only if gitleaks is installed
    use_taint_lite: bool = True
    semgrep_config: str = "auto"
    exclude_dirs: List[str] = field(default_factory=list)
    # learning
    use_feedback: bool = True         # apply reviewer verdicts and rule track records
    strict: bool = False              # count only findings confirmed by independent evidence
    # AI
    use_ml: bool = True
    ml_model_path: Optional[str] = None
    use_llm: bool = False
    llm_provider: str = "ollama"      # a key of sca.ai.providers.PRESETS
    llm_host: str = llm_module.DEFAULT_HOST   # Ollama address (kept for compatibility)
    llm_base_url: str = ""            # overrides the provider's default address
    llm_api_key: str = ""             # never stored in the database or in reports
    llm_model: str = llm_module.DEFAULT_MODEL
    llm_max_findings: int = 30        # review the N most severe findings
    llm_deep_scan: bool = False
    llm_deep_max_files: int = 10
    llm_timeout: int = 180
    # output
    lang: str = "en"                  # language of explanations: en | ar
    save: bool = True


def client_from_options(options: ScanOptions) -> Any:
    base_url = options.llm_base_url
    if not base_url and options.llm_provider == "ollama":
        base_url = options.llm_host
    return make_client(LLMConfig(preset=options.llm_provider, base_url=base_url,
                                 api_key=options.llm_api_key, model=options.llm_model,
                                 timeout=options.llm_timeout))


def _noop(message: str, fraction: float) -> None:
    return None


def run_scan(target: str, options: Optional[ScanOptions] = None,
             progress: Optional[ProgressFn] = None,
             storage: Optional[Storage] = None) -> ScanResult:
    return scan_project(target, options, progress, storage)[0]


def scan_project(target: str, options: Optional[ScanOptions] = None,
                 progress: Optional[ProgressFn] = None,
                 storage: Optional[Storage] = None) -> Tuple[ScanResult, List[SourceFile]]:
    """Run the pipeline. Returns the result and the source files (used by the learner)."""
    options = options or ScanOptions()
    progress = progress or _noop
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError("Path does not exist: %s" % target)
    if storage is None:
        try:
            storage = Storage()
        except Exception:      # a read-only folder must not stop the scan
            storage = None

    started = time.time()
    result = ScanResult(target=str(root),
                        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # 1. walk -------------------------------------------------------------------
    progress("Collecting source files", 0.03)
    files: List[SourceFile] = list(walk_project(str(root), options.exclude_dirs))
    result.files_scanned = len(files)
    result.lines_scanned = sum(len(f.lines) for f in files)
    for sf in files:
        result.languages[sf.language] = result.languages.get(sf.language, 0) + 1
    by_rel: Dict[str, SourceFile] = {sf.rel: sf for sf in files}

    # 2. detect -----------------------------------------------------------------
    raw: List[Finding] = []

    def run_engine(name: str, enabled: bool, fraction: float, fn) -> None:
        if not enabled:
            return
        progress("Running engine: %s" % name, fraction)
        try:
            output = fn()
        except Exception as exc:  # one broken engine must not stop the whole scan
            result.engine_notes[name] = "failed: %s" % str(exc)[:200]
            return
        if isinstance(output, tuple):
            found, note = output
            result.engine_notes[name] = note
            if not note.startswith("ok"):
                return
        else:
            found = output
            result.engine_notes[name] = "ok (%d results)" % len(found)
        result.engines_used.append(name)
        raw.extend(found)

    # The secrets engine always runs first: even when its findings are switched off, the
    # values it finds are masked in every snippet, report and LLM prompt.
    secret_findings = secrets.scan(files)
    run_engine("secrets", options.use_secrets, 0.08, lambda: secret_findings)
    run_engine("rules", options.use_rules, 0.14, lambda: rules_engine.scan(files))
    learned = sum(1 for f in raw if f.engines == ["learned"])
    if learned:
        result.engine_notes["rules"] += " including %d from learned rules" % learned
    run_engine("ast", options.use_ast, 0.24, lambda: python_ast.scan(files))
    has_python = any(sf.language == "python" for sf in files)
    run_engine("bandit", options.use_bandit and has_python, 0.34,
               lambda: external.run_bandit(root))
    run_engine("semgrep", options.use_semgrep and external.semgrep_binary() is not None, 0.42,
               lambda: external.run_semgrep(root, options.semgrep_config))
    run_engine("gitleaks", options.use_gitleaks and external.gitleaks_binary() is not None,
               0.50, lambda: external.run_gitleaks(root))

    # external tools may report files we deliberately skip; keep only scanned files
    raw = [f for f in raw if f.file in by_rel]
    for finding in raw:
        sf = by_rel[finding.file]
        if not finding.language:
            finding.language = sf.language
        if not finding.context:
            finding.context = sf.context(finding.line)
        finding.snippet = sf.mask(finding.snippet)
        finding.context = sf.mask(finding.context)

    # 3. refine -----------------------------------------------------------------
    verdicts: Dict[str, str] = {}
    reviewed: List[Tuple[str, int]] = []
    if options.use_feedback and storage is not None:
        try:
            raw, quarantined = feedback_module.apply_rule_stats(raw, storage.rule_stats())
            rows = storage.feedback_rows()
            verdicts = {row["fingerprint"]: row["verdict"] for row in rows}
            reviewed = [(row["snippet"], 1 if row["verdict"] == "tp" else 0) for row in rows
                        if row.get("snippet") and row.get("cwe") != "CWE-798"]
            if quarantined:
                result.engine_notes["quarantine"] = (
                    "rules switched off after repeated false positives: %s"
                    % ", ".join(quarantined))
        except Exception as exc:
            result.engine_notes["feedback"] = "failed: %s" % str(exc)[:200]
    if options.use_taint_lite:
        traced = taint_lite.apply(raw, by_rel)
        if traced:
            result.engine_notes["taint-lite"] = "ok (user input traced to %d findings)" % traced

    # 4. merge ------------------------------------------------------------------
    progress("Merging results", 0.55)
    findings = merge.merge_findings(raw, options.lang)
    if verdicts:
        dismissed, confirmed = feedback_module.apply_verdicts(findings, verdicts)
        if dismissed or confirmed:
            result.engine_notes["feedback"] = (
                "ok (%d dismissed and %d confirmed from earlier reviews)"
                % (dismissed, confirmed))

    # 5. ML second opinion ------------------------------------------------------
    result.ai = {"ml": "disabled", "llm": "disabled"}
    if options.use_ml:
        progress("Scoring with the ML classifier", 0.60)
        try:
            classifier = get_classifier(options.ml_model_path, reviewed)
            if classifier is None:
                result.ai["ml"] = "unavailable (pip install scikit-learn)"
            else:
                scored = [f for f in findings if f.snippet and f.cwe != "CWE-798"]
                for finding, value in zip(scored,
                                          classifier.score_many([f.snippet for f in scored])):
                    finding.ml_score = round(value, 3)
                result.ai["ml"] = "ok - %s" % classifier.source
        except Exception as exc:
            result.ai["ml"] = "failed: %s" % str(exc)[:200]

    # 6. LLM review -------------------------------------------------------------
    if options.use_llm:
        _run_llm(findings, by_rel, options, result, progress, storage)

    # 7. assess -----------------------------------------------------------------
    progress("Calculating the security score", 0.95)
    result.findings = findings
    result.score, result.grade = scoring.score_all(findings, result.lines_scanned,
                                                   options.strict)
    if options.strict:
        result.engine_notes["strict mode"] = (
            "on: %d unconfirmed findings moved to 'needs review'"
            % result.status_count("needs_review"))
    result.findings.sort(key=lambda f: (f.status != "open", -SEVERITY_RANK[f.severity],
                                        -f.risk_score, f.file, f.line))
    result.duration_seconds = time.time() - started

    # 8. store ------------------------------------------------------------------
    if options.save and storage is not None:
        try:
            storage.save_scan(result)
        except Exception as exc:
            result.engine_notes["storage"] = "failed: %s" % str(exc)[:200]
    progress("Done", 1.0)
    return result, files


def _triage(client: Any, finding: Finding, context: str, options: ScanOptions,
            cache: Optional[Storage]) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Review one finding. Returns (answer, came_from_cache). Raises LLMError."""
    key = "triage|%s|%s|%s" % (client.label, options.lang, finding.fingerprint)
    answer = cache.cache_get(key) if cache else None
    if answer is not None:
        return answer, True
    answer = llm_module.triage_finding(client, finding, context, options.lang)
    if cache:
        cache.cache_put(key, answer)
    return answer, False


def _apply_answer(finding: Finding, answer: Dict[str, Any], client: Any) -> None:
    finding.ai_verdict = answer["verdict"]
    finding.ai_confidence = answer["confidence"]
    finding.ai_explanation = answer["explanation"] or finding.ai_explanation
    finding.ai_fix = answer["fix"] or finding.ai_fix
    finding.ai_model = client.label


def _run_llm(findings: List[Finding], by_rel: Dict[str, SourceFile], options: ScanOptions,
             result: ScanResult, progress: ProgressFn, storage: Optional[Storage]) -> None:
    client = client_from_options(options)
    ready, message = client.check()
    if not ready:
        result.ai["llm"] = "unavailable - %s" % message
        return
    if not client.is_local:
        result.ai["privacy"] = ("code snippets were sent to %s (secrets masked)"
                                % (urlparse(client.base_url).hostname or client.base_url))
    reviewed = cached = errors = 0
    last_error = ""

    def review(finding: Finding) -> bool:
        nonlocal reviewed, cached, errors, last_error
        sf = by_rel.get(finding.file)
        context = sf.context(finding.line, 15, 12) if sf else finding.context
        try:
            answer, from_cache = _triage(client, finding, context, options, storage)
        except llm_module.LLMError as exc:
            errors += 1
            last_error = str(exc)[:150]
            return False
        _apply_answer(finding, answer, client)
        reviewed += 1
        cached += int(from_cache)
        return True

    todo = [f for f in findings if f.status == "open"][: max(0, options.llm_max_findings)]
    for index, finding in enumerate(todo):
        progress("AI review %d/%d: %s" % (index + 1, len(todo), finding.title[:50]),
                 0.62 + 0.22 * index / max(1, len(todo)))
        review(finding)
        if errors >= 3:
            break  # the model is not responding; stop instead of waiting for N timeouts

    new_findings: List[Finding] = []
    if options.llm_deep_scan and errors < 3:
        code_files = [sf for sf in by_rel.values() if sf.language not in ("config", "html")]
        code_files.sort(key=lambda sf: -len(sf.lines))
        targets = code_files[: options.llm_deep_max_files]
        for index, sf in enumerate(targets):
            progress("AI deep scan %d/%d: %s" % (index + 1, len(targets), sf.rel),
                     0.84 + 0.07 * index / max(1, len(targets)))
            known = [f for f in findings if f.file == sf.rel]
            try:
                new_findings.extend(llm_module.deep_scan_file(client, sf, known, options.lang))
            except llm_module.LLMError as exc:
                errors += 1
                last_error = str(exc)[:150]
                if errors >= 3:
                    break
        if new_findings:
            new_findings = merge.merge_findings(new_findings, options.lang)
            # Second pass: a finding that only the model reported is checked again in a
            # separate request. Without that confirmation it stays "probable".
            for index, finding in enumerate(new_findings):
                progress("AI verification %d/%d" % (index + 1, len(new_findings)), 0.92)
                if errors >= 3 or not review(finding):
                    continue
            findings.extend(new_findings)
            if "llm" not in result.engines_used:
                result.engines_used.append("llm")

    note = "ok - %s reviewed %d findings (%d from cache)" % (client.label, reviewed, cached)
    if options.llm_deep_scan:
        verified = sum(1 for f in new_findings if f.ai_verdict == "true_positive")
        note += ", deep scan added %d (%d verified)" % (len(new_findings), verified)
    if errors:
        note += "; %d request(s) failed: %s" % (errors, last_error)
    result.ai["llm"] = note
    result.ai["llm_requests"] = client.requests
