"""The scan pipeline: the one function that runs every stage in order.

    1. walk      - collect source files from the chosen folder
    2. detect    - run the static engines (rules, AST, secrets, Bandit, Semgrep, Gitleaks)
    3. merge     - remove duplicates, combine confidences, attach CWE/OWASP knowledge
    4. ML        - second-opinion probability from the classifier
    5. LLM       - optional review and deep scan by a local model (Ollama)
    6. assess    - risk score per finding, security score and grade for the project
    7. store     - save to the history database
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import merge, scoring
from .ai import llm as llm_module
from .ai.classifier import get_classifier
from .engines import external, python_ast, rules_engine, secrets
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
    semgrep_config: str = "auto"
    exclude_dirs: List[str] = field(default_factory=list)
    # AI
    use_ml: bool = True
    ml_model_path: Optional[str] = None
    use_llm: bool = False
    llm_host: str = llm_module.DEFAULT_HOST
    llm_model: str = llm_module.DEFAULT_MODEL
    llm_max_findings: int = 30        # review the N most severe findings (local models are slow)
    llm_deep_scan: bool = False
    llm_deep_max_files: int = 10
    llm_timeout: int = 180
    # output
    lang: str = "en"                  # language of explanations: en | ar
    save: bool = True


def _noop(message: str, fraction: float) -> None:
    return None


def run_scan(target: str, options: Optional[ScanOptions] = None,
             progress: Optional[ProgressFn] = None,
             storage: Optional[Storage] = None) -> ScanResult:
    options = options or ScanOptions()
    progress = progress or _noop
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError("Path does not exist: %s" % target)

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

    # 3. merge ------------------------------------------------------------------
    progress("Merging results", 0.55)
    findings = merge.merge_findings(raw, options.lang)

    # 4. ML second opinion ------------------------------------------------------
    result.ai = {"ml": "disabled", "llm": "disabled"}
    if options.use_ml:
        progress("Scoring with the ML classifier", 0.60)
        try:
            classifier = get_classifier(options.ml_model_path)
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

    # 5. LLM review -------------------------------------------------------------
    if options.use_llm:
        _run_llm(findings, by_rel, options, result, progress, storage)

    # 6. assess -----------------------------------------------------------------
    progress("Calculating the security score", 0.95)
    result.findings = findings
    result.score, result.grade = scoring.score_all(findings, result.lines_scanned)
    result.findings.sort(key=lambda f: (f.status != "open", -SEVERITY_RANK[f.severity],
                                        -f.risk_score, f.file, f.line))
    result.duration_seconds = time.time() - started

    # 7. store ------------------------------------------------------------------
    if options.save:
        try:
            (storage or Storage()).save_scan(result)
        except Exception as exc:
            result.engine_notes["storage"] = "failed: %s" % str(exc)[:200]
    progress("Done", 1.0)
    return result


def _run_llm(findings: List[Finding], by_rel: Dict[str, SourceFile], options: ScanOptions,
             result: ScanResult, progress: ProgressFn, storage: Optional[Storage]) -> None:
    client = llm_module.OllamaClient(options.llm_host, options.llm_model, options.llm_timeout)
    if not client.available():
        result.ai["llm"] = ("unavailable - Ollama is not running at %s (install it from "
                            "https://ollama.com and run: ollama pull %s)"
                            % (options.llm_host, options.llm_model))
        return
    try:
        cache = storage or Storage()
    except Exception:
        cache = None
    reviewed = cached = errors = 0
    last_error = ""
    todo = findings[: max(0, options.llm_max_findings)]
    for index, finding in enumerate(todo):
        progress("LLM review %d/%d: %s" % (index + 1, len(todo), finding.title[:50]),
                 0.62 + 0.25 * index / max(1, len(todo)))
        sf = by_rel.get(finding.file)
        context = sf.context(finding.line, 15, 12) if sf else finding.context
        key = "triage|%s|%s|%s" % (client.model, options.lang, finding.fingerprint)
        answer = cache.cache_get(key) if cache else None
        if answer is None:
            try:
                answer = llm_module.triage_finding(client, finding, context, options.lang)
            except llm_module.LLMError as exc:
                errors += 1
                last_error = str(exc)[:150]
                if errors >= 3:
                    break  # the model is not responding; stop instead of waiting N timeouts
                continue
            if cache:
                cache.cache_put(key, answer)
        else:
            cached += 1
        finding.ai_verdict = answer["verdict"]
        finding.ai_confidence = answer["confidence"]
        finding.ai_explanation = answer["explanation"]
        finding.ai_fix = answer["fix"]
        finding.ai_model = client.model
        reviewed += 1

    new_findings: List[Finding] = []
    if options.llm_deep_scan and errors < 3:
        code_files = [sf for sf in by_rel.values() if sf.language not in ("config", "html")]
        code_files.sort(key=lambda sf: -len(sf.lines))
        targets = code_files[: options.llm_deep_max_files]
        for index, sf in enumerate(targets):
            progress("LLM deep scan %d/%d: %s" % (index + 1, len(targets), sf.rel),
                     0.87 + 0.07 * index / max(1, len(targets)))
            known = [f for f in findings if f.file == sf.rel]
            try:
                new_findings.extend(llm_module.deep_scan_file(client, sf, known, options.lang))
            except llm_module.LLMError as exc:
                errors += 1
                last_error = str(exc)[:150]
                if errors >= 3:
                    break
        if new_findings:
            # LLM-only findings keep their modest 0.5 confidence: nothing verified them
            findings.extend(merge.merge_findings(new_findings, options.lang))
            if "llm" not in result.engines_used:
                result.engines_used.append("llm")

    note = "ok - model %s reviewed %d findings (%d from cache)" % (client.model, reviewed, cached)
    if options.llm_deep_scan:
        note += ", deep scan added %d" % len(new_findings)
    if errors:
        note += "; %d request(s) failed: %s" % (errors, last_error)
    result.ai["llm"] = note
