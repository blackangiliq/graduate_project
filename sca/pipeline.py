"""The scan pipeline: the one function that runs every stage in order.

    1. walk      collect source files from the chosen folder, or decode the chosen app
                 package (.apk, .aab, ...) into virtual files; find a Flutter/Android project
    2. detect    static engines: secrets, pattern rules (built-in + learned), Python AST,
                 C memory checks, Flutter/Android checks, Bandit, Opengrep/Semgrep, Gitleaks
    3. refine    rule track record (reviewer feedback), app context, taint-lite tracing
    4. merge     remove duplicates, combine confidences, attach CWE/OWASP knowledge (and the
                 OWASP Mobile/MASVS class for apps), re-apply earlier reviewer verdicts
    5. ML        second-opinion probability from the classifier
    6. LLM       optional review, deep scan and verification by a local or cloud model
    7. assess    confirmed/probable tier, risk per finding, project score and grade
    8. store     save to the history database

The files of an app package are virtual (sca/flutter/context.py): each engine reads only the
origins it understands, and only real code and decoded text count as lines of code.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from . import flutter, merge, scoring
from .ai import llm as llm_module
from .ai.classifier import get_classifier
from .ai.providers import LLMConfig, make_client
from .engines import c_memory, external, python_ast, rules_engine, secrets, taint_lite
from .flutter.context import AI_ORIGINS, KLOC_ORIGINS, RULES_ORIGINS, SECRETS_ORIGINS
from .learn import feedback as feedback_module
from .models import Finding, ScanResult, SEVERITY_RANK
from .storage import Storage
from .walker import SourceFile, is_test_path, mask_secret, strip_bidi, walk_project

ProgressFn = Callable[[str, float], None]
TEST_CODE_FACTOR = 0.6
BANDIT_PASSWORD_TESTS = {"BANDIT-B105", "BANDIT-B106", "BANDIT-B107"}
APP_SKIP = "not used for app packages"           # why Bandit, Semgrep and Gitleaks skip an app


class Message(str):
    """One progress message of a scan. It reads as English text (what the command line
    prints) and keeps its template and values, so that the dashboard can translate it.

    kind: "step"    a stage starts              (kept in ScanResult.steps)
          "result"  what the stage found        (kept in ScanResult.steps)
          "file"    the file being read now     (shown while it happens, not kept)
    """
    kind: str
    template: str
    args: Tuple[Any, ...]

    def __new__(cls, kind: str, template: str, *args: Any) -> "Message":
        obj = super().__new__(cls, template % args if args else template)
        obj.kind, obj.template, obj.args = kind, template, args
        return obj


# What each static engine does, as shown while it runs: (name, what it is doing)
ENGINE_TEXT = {
    "secrets": ("Secrets", "looking for keys, passwords and tokens"),
    "rules": ("Pattern rules", "checking every line against the active rules"),
    "ast": ("Python AST", "following user input through the Python code"),
    "c-memory": ("C memory checks", "following pointers and outside data through each C "
                                    "function"),
    "bandit": ("Bandit", "running the Bandit analyzer on the Python files"),
    "semgrep": ("Opengrep/Semgrep", "running the external rule engine"),
    "gitleaks": ("Gitleaks", "searching the files for leaked credentials"),
    "flutter": ("Flutter/Android checks", "checking the app's manifest, network and signing "
                                          "settings, build and dependencies"),
}


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
    use_c_memory: bool = True         # C/C++ memory-safety checks (c_memory engine)
    use_flutter: bool = True          # Flutter/Android checks: manifest, signing, build, packages
    apk_tools: bool = False           # app packages: also use installed jadx and apksigner
    semgrep_config: str = "auto"
    exclude_dirs: List[str] = field(default_factory=list)
    # learning
    include_tests: bool = True        # False: skip test code (tests/, test_*.py, *.spec.js)
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


def is_app_target(path: Path) -> bool:
    """True when the scan target is an app package file (by its suffix)."""
    return path.is_file() and path.suffix.lower() in flutter.APP_SUFFIXES


def scan_project(target: str, options: Optional[ScanOptions] = None,
                 progress: Optional[ProgressFn] = None,
                 storage: Optional[Storage] = None) -> Tuple[ScanResult, List[SourceFile]]:
    """Run the pipeline. Returns the result and the source files (used by the learner).
    Raises FileNotFoundError for a missing target and flutter.AppError for an app package
    that cannot be read."""
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

    def say(kind: str, fraction: float, template: str, *args: Any) -> None:
        """Tell the caller what the scan is doing now, and keep steps and results."""
        message = Message(kind, template, *args)
        if kind != "file":
            result.steps.append(message)
        progress(message, fraction)

    # 1. walk -------------------------------------------------------------------
    ctx: Optional[flutter.MobileContext] = None
    if is_app_target(root):
        say("step", 0.01, "Unpacking the app %s", root.name)
        ctx = decode_app(root, options.apk_tools)
        files: List[SourceFile] = list(ctx.files)
        say("result", 0.02, "Decoded the app: %d files, %s build", len(files),
            ctx.facts.get("build_mode") or "unknown")
    else:
        say("step", 0.02, "Collecting the source files of %s", str(root))
        files = list(walk_project(str(root), options.exclude_dirs))
    # Everything in an app package ships to its users, whatever the folder is called (an
    # asset under test/ or mocks/ too): test code is only recognised in source folders.
    test_files = set() if ctx is not None else {sf.rel for sf in files if is_test_path(sf.rel)}
    if not options.include_tests and test_files:
        files = [sf for sf in files if sf.rel not in test_files]
        result.engine_notes["test code"] = "skipped %d test files" % len(test_files)
        say("result", 0.03, "Left out %d test files", len(test_files))
        test_files = set()
    if ctx is None and options.use_flutter and root.is_dir():
        try:
            ctx = flutter.load_project(root, files, options.exclude_dirs)
        except Exception as exc:  # a broken project file must not stop the scan
            result.engine_notes["flutter"] = "failed: %s" % _reason(exc)
            say("result", 0.03, "%s: failed - %s", ENGINE_TEXT["flutter"][0], _reason(exc))
        if ctx is not None:
            ctx.files = [sf for sf in ctx.files
                         if options.include_tests or not is_test_path(sf.rel)]
            files.extend(ctx.files)
            test_files |= {sf.rel for sf in ctx.files if is_test_path(sf.rel)}
            say("result", 0.03, "Found a Flutter project: %s" if ctx.kind == "flutter-project"
                else "Found an Android project: %s", ctx.facts.get("name") or root.name)
    if ctx is not None:
        result.app = ctx.facts
    result.files_scanned = len(files)
    result.lines_scanned = sum(len(f.lines) for f in files if f.origin in KLOC_ORIGINS)
    for sf in files:
        result.languages[sf.language] = result.languages.get(sf.language, 0) + 1
    by_rel: Dict[str, SourceFile] = {sf.rel: sf for sf in files}
    say("result", 0.04, "%d files, %d lines: %s", result.files_scanned, result.lines_scanned,
        ", ".join("%s %d" % item for item in sorted(result.languages.items(),
                                                    key=lambda kv: -kv[1])) or "-")
    rule_files = [sf for sf in files if sf.origin in RULES_ORIGINS]
    secret_files = [sf for sf in files if sf.origin in SECRETS_ORIGINS]
    is_app = ctx is not None and ctx.is_app

    # 2. detect -----------------------------------------------------------------
    raw: List[Finding] = []

    def each_file(name: str, scan_one: Callable[[SourceFile], List[Finding]],
                  targets: List[SourceFile], start: float, end: float) -> List[Finding]:
        """Run a per-file engine and say which file it is reading (at most 10 times a
        second, so that a large project is not slowed down by the messages)."""
        label = ENGINE_TEXT[name][0]
        out: List[Finding] = []
        shown = 0.0
        for index, sf in enumerate(targets):
            now = time.time()
            if now - shown >= 0.1:
                shown = now
                say("file", start + (end - start) * index / max(1, len(targets)),
                    "%s: file %d of %d - %s", label, index + 1, len(targets), sf.rel)
            out.extend(scan_one(sf))
        return out

    def run_engine(name: str, enabled: bool, fraction: float, fn,
                   skipped: str = "switched off") -> None:
        label, doing = ENGINE_TEXT[name]
        if not enabled:
            say("result", fraction, "%s: skipped - %s", label, skipped)
            return
        say("step", fraction, "%s: %s", label, doing)
        began = time.time()
        try:
            output = fn()
        except Exception as exc:  # one broken engine must not stop the whole scan
            result.engine_notes[name] = "failed: %s" % str(exc)[:200]
            say("result", fraction, "%s: failed - %s", label, str(exc)[:200])
            return
        if isinstance(output, tuple):
            found, note = output
            result.engine_notes[name] = note
            if not note.startswith("ok"):
                say("result", fraction, "%s: %s", label, note)
                return
        else:
            found = output
            result.engine_notes[name] = "ok (%d results)" % len(found)
        result.engines_used.append(name)
        raw.extend(found)
        say("result", fraction, "%s: %d found in %.1f s", label, len(found),
            time.time() - began)

    # The secrets engine always runs first: even when its findings are switched off, the
    # values it finds are masked in every snippet, report and LLM prompt.
    secret_rules = rules_engine.secret_rules()
    if options.use_secrets:
        run_engine("secrets", True, 0.06, lambda: each_file(
            "secrets", lambda sf: secrets.scan_file(sf, secret_rules), secret_files,
            0.06, 0.12))
    else:
        secrets.scan(secret_files)
        run_engine("secrets", False, 0.06, None)

    def scan_rules() -> List[Finding]:
        rule_set = rules_engine.load_rules()
        return each_file("rules", lambda sf: rules_engine.scan_file(sf, None, rule_set),
                         rule_files, 0.12, 0.30)

    run_engine("rules", options.use_rules, 0.12, scan_rules)
    learned = sum(1 for f in raw if f.engines == ["learned"])
    if learned:
        result.engine_notes["rules"] += " including %d from learned rules" % learned
    python_files = [sf for sf in rule_files if sf.language == "python"]
    run_engine("ast", options.use_ast, 0.30, lambda: each_file(
        "ast", python_ast.scan_file, python_files, 0.30, 0.38))
    c_files = [sf for sf in rule_files if sf.language in c_memory.LANGUAGES]
    run_engine("c-memory", options.use_c_memory and bool(c_files), 0.38, lambda: each_file(
        "c-memory", c_memory.scan_file, c_files, 0.38, 0.40),
        skipped="switched off" if not options.use_c_memory else "no C or C++ files")
    if "flutter" not in result.engine_notes:          # not when the project failed to load
        run_engine("flutter", options.use_flutter and ctx is not None, 0.40,
                   lambda: flutter.analyze(ctx, by_rel),
                   skipped="switched off" if not options.use_flutter
                   else "no Flutter or Android files")
    run_engine("bandit", options.use_bandit and bool(python_files) and not is_app, 0.40,
               lambda: external.run_bandit(root),
               skipped="switched off" if not options.use_bandit
               else APP_SKIP if is_app else "no Python files")
    semgrep_found = external.semgrep_binary() is not None
    gitleaks_found = external.gitleaks_binary() is not None
    run_engine("semgrep", options.use_semgrep and semgrep_found and not is_app, 0.48,
               lambda: external.run_semgrep(root, options.semgrep_config),
               skipped=APP_SKIP if is_app and options.use_semgrep
               else "switched off" if semgrep_found else "not installed")
    run_engine("gitleaks", options.use_gitleaks and gitleaks_found and not is_app, 0.52,
               lambda: external.run_gitleaks(root),
               skipped=APP_SKIP if is_app and options.use_gitleaks
               else "switched off" if gitleaks_found else "not installed")

    def add_note(name: str, text: str) -> None:
        result.engine_notes[name] = "%s; %s" % (result.engine_notes.get(name, "ok"), text)

    # external tools may report files we deliberately skip; keep only scanned files
    outside = sum(1 for f in raw if f.file not in by_rel and "flutter" in f.engines)
    if outside:
        add_note("flutter", "%d findings in files left out of the scan were not kept" % outside)
    raw = [f for f in raw if f.file in by_rel]
    # Bandit reports any literal given to a password-like name, placeholders included
    # ('your-secret-key-here'); the secrets engine already filters those, so do the same.
    raw = [f for f in raw
           if not (f.rule_id in BANDIT_PASSWORD_TESTS and 1 <= f.line <= len(by_rel[f.file].lines)
                   and secrets.placeholder_line(by_rel[f.file].lines[f.line - 1]))]
    # The key values that rules and structural checks report (Key.fromUtf8('...'),
    # storePassword=...) are masked like the secrets of the secrets engine, and every secret
    # is masked wherever it appears: a line of one file can quote the key of another.
    # From here on every file masks every secret of the scan, so the snippets, contexts,
    # facts, the inventory, the AI prompts and the rule learner all agree.
    share_secrets(raw, files, by_rel)
    for finding in raw:
        sf = by_rel[finding.file]
        if not finding.language:
            finding.language = sf.language
        if not finding.context:
            finding.context = sf.context(finding.line)
        finding.snippet = sf.mask(finding.snippet)
        finding.context = sf.mask(finding.context)
        _clean_quotes(finding, sf, is_app)
        if "flutter" in finding.engines:
            finding.title = sf.mask(finding.title)
            finding.description = sf.mask(finding.description)
    if ctx is not None:
        mask_facts(ctx, by_rel)

    # 3. refine -----------------------------------------------------------------
    if ctx is not None and options.use_flutter:
        try:
            refined = flutter.refine(raw, by_rel, ctx)
        except Exception as exc:  # the findings stay as the engines reported them
            add_note("flutter", "app context not applied: %s" % str(exc)[:200])
        else:
            if refined:
                add_note("flutter", "%d Google API keys of Firebase files lowered to low "
                                    "severity (identifiers, not secrets)" % refined)
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
                say("result", 0.54, "Rules switched off after repeated false positives: %s",
                    ", ".join(quarantined))
        except Exception as exc:
            result.engine_notes["feedback"] = "failed: %s" % str(exc)[:200]
    if options.use_taint_lite:
        say("step", 0.55, "Input tracing: checking whether user input reaches each finding")
        traced = taint_lite.apply(raw, by_rel)
        if traced:
            result.engine_notes["taint-lite"] = "ok (user input traced to %d findings)" % traced
        say("result", 0.55, "Input tracing: user input reaches %d findings", traced)

    # 4. merge ------------------------------------------------------------------
    say("step", 0.57, "Merging: removing duplicates and combining the evidence of the engines")
    findings = merge.merge_findings(raw, options.lang, mobile=bool(result.app))
    say("result", 0.58, "%d raw results merged into %d findings", len(raw), len(findings))
    in_tests = 0
    for finding in findings:
        if finding.file in test_files:
            # Test input is written by the developer, so a weakness in test code is rarely
            # exploitable: it is kept, with a lower confidence, and is never auto-confirmed.
            finding.test_code = True
            finding.confidence *= TEST_CODE_FACTOR
            in_tests += 1
    if in_tests:
        result.engine_notes["test code"] = (
            "ok (%d findings are in test code: lower confidence, not auto-confirmed)" % in_tests)
        say("result", 0.58, "%d findings are in test code: lower confidence, "
                            "never confirmed automatically", in_tests)
    if verdicts:
        dismissed, confirmed = feedback_module.apply_verdicts(findings, verdicts)
        if dismissed or confirmed:
            result.engine_notes["feedback"] = (
                "ok (%d dismissed and %d confirmed from earlier reviews)"
                % (dismissed, confirmed))
            say("result", 0.58, "Your earlier reviews: %d dismissed, %d confirmed",
                dismissed, confirmed)

    # 5. ML second opinion ------------------------------------------------------
    result.ai = {"ml": "disabled", "llm": "disabled"}
    if options.use_ml:
        say("step", 0.60, "ML classifier: a second opinion on each finding")
        try:
            classifier = get_classifier(options.ml_model_path, reviewed)
            if classifier is None:
                result.ai["ml"] = "unavailable (pip install scikit-learn)"
            else:
                scored = [f for f in findings if f.snippet and f.cwe != "CWE-798"
                          and "flutter" not in f.engines and _origin(by_rel, f) in AI_ORIGINS]
                for finding, value in zip(scored,
                                          classifier.score_many([f.snippet for f in scored])):
                    finding.ml_score = round(value, 3)
                result.ai["ml"] = "ok - %s" % classifier.source
                say("result", 0.61, "ML classifier: scored %d findings", len(scored))
        except Exception as exc:
            result.ai["ml"] = "failed: %s" % str(exc)[:200]
        if not result.ai["ml"].startswith("ok"):
            say("result", 0.61, "%s: %s", "ML classifier", result.ai["ml"])
    else:
        say("result", 0.61, "%s: skipped - %s", "ML classifier", "switched off")

    # 6. LLM review -------------------------------------------------------------
    if options.use_llm:
        say("step", 0.62, "AI review: asking the model about the most severe findings")
        _run_llm(findings, by_rel, options, result, progress, storage)
        say("result", 0.93, "%s: %s", "AI review", result.ai["llm"])
    else:
        say("result", 0.62, "%s: skipped - %s", "AI review", "switched off")

    # 7. assess -----------------------------------------------------------------
    say("step", 0.95, "Scoring: the risk of each finding and the score of the project")
    result.findings = findings
    result.score, result.grade = scoring.score_all(findings, result.lines_scanned,
                                                   options.strict)
    if options.strict:
        result.engine_notes["strict mode"] = (
            "on: %d unconfirmed findings moved to 'needs review'"
            % result.status_count("needs_review"))
    result.findings.sort(key=lambda f: (f.status != "open", -SEVERITY_RANK[f.severity],
                                        -f.risk_score, f.file, f.line))
    say("result", 0.96, "Score %d/100, grade %s: %d open findings, %d confirmed",
        result.score, result.grade, len(result.open_findings),
        sum(1 for f in result.open_findings if f.tier == "confirmed"))
    if ctx is not None:
        say("step", 0.965, "API inventory: listing the server addresses, API calls and keys "
                           "of the app")
        try:
            apis = add_inventory(ctx, files, findings)
        except Exception as exc:  # the findings and the other facts stay valid
            result.engine_notes["api inventory"] = "failed: %s" % _reason(exc)
            say("result", 0.965, "%s: failed - %s", "API inventory", _reason(exc))
        else:
            summary = apis["summary"]
            result.engine_notes["api inventory"] = (
                "ok (%d server addresses on %d hosts, %d keys, %d API calls, %d alerts)"
                % (summary["endpoints"], summary["hosts"], summary["keys"], summary["calls"],
                   len(apis["alerts"])))
            say("result", 0.965, "API inventory: %d server addresses on %d hosts (%d without "
                                 "TLS), %d keys (%d secret), %d API calls, %d API paths",
                summary["endpoints"], summary["hosts"], summary["cleartext"], summary["keys"],
                summary["secret_keys"], summary["calls"], summary["paths"])
    result.duration_seconds = time.time() - started
    say("result", 0.97, "Scan finished in %.1f s", result.duration_seconds)

    # 8. store ------------------------------------------------------------------
    if options.save and storage is not None:
        try:
            storage.save_scan(result)
            say("result", 1.0, "Saved in the history")
        except Exception as exc:
            result.engine_notes["storage"] = "failed: %s" % str(exc)[:200]
            say("result", 1.0, "%s: failed - %s", "History", str(exc)[:200])
    return result, files


def _origin(by_rel: Dict[str, SourceFile], finding: Finding) -> str:
    """Origin of the file a finding is in ("" for a file on disk)."""
    sf = by_rel.get(finding.file)
    return sf.origin if sf is not None else ""


def _reason(exc: BaseException) -> str:
    """An unexpected error in one line for the user: its type and message."""
    return ("%s: %s" % (type(exc).__name__, exc))[:200]


def decode_app(path: Path, use_tools: bool) -> "flutter.MobileContext":
    """flutter.load_app, with an unexpected failure of a decoder turned into an AppError,
    so that the user reads why the app cannot be scanned instead of a stack trace."""
    try:
        return flutter.load_app(path, use_tools=use_tools)
    except flutter.AppError:
        raise
    except Exception as exc:
        raise flutter.AppError("%s could not be decoded: %s" % (path.name, _reason(exc))) \
            from exc


def _mask_text(sf: SourceFile, text: str) -> str:
    """Text that quotes a file (the title of a Flutter/Android check), with the file's secrets
    masked: each secret quoted in full, and a secret that the quote cuts off right before a
    "..." marker (a long value shortened in a title)."""
    if not text or not sf.secret_values:
        return text
    text = sf.mask(text)
    if "..." not in text:
        return text
    for secret in sf.secret_values:
        for size in range(len(secret) - 1, 3, -1):
            part = secret[:size] + "..."
            if part in text:
                text = text.replace(part, mask_secret(secret)[:size] + "...")
                break
    return text


def _clean_quotes(finding: Finding, sf: SourceFile, in_app: bool) -> None:
    """Only the Flutter/Android checks quote the text of a file in titles and descriptions (a
    component name, a URL of a strings dump): the file's secrets are masked there too. The
    bidirectional control characters are removed from those texts, and from every title,
    description and quoted line of an app package (its text is untrusted and could show
    itself reordered). The titles of the other engines are never changed: they name a rule
    or a variable."""
    if "flutter" in finding.engines:
        finding.title = _mask_text(sf, finding.title)
        finding.description = _mask_text(sf, finding.description)
    if in_app or "flutter" in finding.engines:
        finding.title = strip_bidi(finding.title)
        finding.description = strip_bidi(finding.description)
    if in_app:                          # the decoded text of an app is never source code
        finding.snippet = strip_bidi(finding.snippet)
        finding.context = strip_bidi(finding.context)


def _strip_bidi_all(value: Any) -> Any:
    """value with the bidirectional control characters removed from every text in it; lists
    and dicts are changed in place (the scan result shares the facts dict)."""
    if isinstance(value, str):
        return strip_bidi(value)
    if isinstance(value, list):
        value[:] = [_strip_bidi_all(item) for item in value]
    elif isinstance(value, tuple):
        return tuple(_strip_bidi_all(item) for item in value)
    elif isinstance(value, dict):
        for key in list(value):
            item = _strip_bidi_all(value[key])
            clean = strip_bidi(key) if isinstance(key, str) else key
            if clean != key:
                del value[key]
            value[clean] = item
    return value


def share_secrets(findings: Iterable[Finding], files: Sequence[SourceFile],
                  by_rel: Dict[str, SourceFile]) -> None:
    """Make every file mask every secret of the scan. Besides the secrets of the secrets
    engine this takes the values of the other credential findings (a rule's hard-coded
    encryption key, a structural check's keystore password) and the secrets that addresses
    and .env files hold in plain sight (key and token query values, user:password@, webhook
    and bot tokens, secret .env values: see inventory.text_secrets). A short or plain value
    ('android') is masked only in its own file, so that it does not hide that word elsewhere."""
    from .cwe import canonical
    from .flutter.inventory import (FILE_LEVEL_RULES, KEY_CWES, rule_key_value, strong_value,
                                    text_secrets)

    # the values of each file: its secrets-engine values, the secrets of its addresses, and
    # the values of its other credential findings (found with the rule's own pattern)
    found: Dict[str, set] = {sf.rel: set(sf.secret_values) | set(text_secrets(sf))
                             for sf in files}
    patterns = {rule.id: rule.pattern for rule in rules_engine.load_rules()}
    for finding in findings:
        sf = by_rel.get(finding.file)
        if sf is None or "secrets" in finding.engines or finding.rule_id in FILE_LEVEL_RULES \
                or canonical(finding.cwe) not in KEY_CWES or not 1 <= finding.line <= len(sf.lines):
            continue
        value = rule_key_value(sf.lines[finding.line - 1], finding.rule_id,
                               patterns.get(finding.rule_id))
        if value:
            found.setdefault(sf.rel, set()).add(value)
    shared: set = set()
    own: Dict[str, set] = {}
    for rel, values in found.items():
        for value in values:
            if not value:
                continue
            if strong_value(value):
                shared.add(value)
            else:
                own.setdefault(rel, set()).add(value)
    for sf in files:
        sf.secret_values = sorted(shared | own.get(sf.rel, set()), key=len, reverse=True)


def mask_facts(ctx: "flutter.MobileContext", by_rel: Dict[str, SourceFile]) -> None:
    """Make the facts safe to show. The secrets that the secrets engine found are masked
    where the facts quote file text: the endpoint URLs (with the file each one comes from)
    and the deep links of the components (with the release manifests); only whole secrets
    are replaced. The bidirectional control characters are removed from every fact."""
    from .flutter.inventory import mask_url

    # each text with the secrets of its file: after share_secrets these are every strong
    # secret of the scan plus the weak values of that file
    for item in ctx.facts.get("endpoints") or []:
        sf = by_rel.get(item.get("file") or "") if isinstance(item, dict) else None
        if sf is not None and isinstance(item.get("url"), str):
            item["url"] = mask_url(sf.mask(item["url"]))
    manifests = [by_rel[rel] for rel, _ in ctx.manifests if rel in by_rel]
    for item in ctx.facts.get("components") or []:
        if not isinstance(item, dict) or not isinstance(item.get("deep_links"), list):
            continue
        links = []
        for link in item["deep_links"]:
            if isinstance(link, str):
                for sf in manifests:
                    link = sf.mask(link)
                link = mask_url(link)
            links.append(link)
        item["deep_links"] = links
    _strip_bidi_all(ctx.facts)


def add_inventory(ctx: "flutter.MobileContext", files: Sequence[SourceFile],
                  findings: Sequence[Finding]) -> Dict[str, Any]:
    """Build the API and key inventory (sca/flutter/inventory.py) into ctx.facts["apis"],
    without bidirectional control characters, and return it."""
    from .flutter import inventory

    apis = _strip_bidi_all(inventory.build(ctx, files, findings))
    ctx.facts["apis"] = apis
    return apis


def inspect_mobile(target: str, use_tools: bool = False, exclude_dirs: Sequence[str] = (),
                   key_rules: bool = False
                   ) -> Tuple[Optional["flutter.MobileContext"], List[SourceFile],
                              List[Finding], str]:
    """Decode an app package or read a Flutter/Android project folder and run only the
    Flutter/Android checks, as a scan does (secrets are found first so that every quote is
    masked). Returns (context with complete facts, files, findings of the checks, engine
    note); the context is None for a folder that is neither. Raises FileNotFoundError, and
    flutter.AppError for an app that cannot be decoded or a project that cannot be read."""
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError("Path does not exist: %s" % target)
    if is_app_target(root):
        ctx: Optional[flutter.MobileContext] = decode_app(root, use_tools)
        files = list(ctx.files)
    else:
        files = list(walk_project(str(root), list(exclude_dirs)))
        try:
            ctx = flutter.load_project(root, files, exclude_dirs) if root.is_dir() else None
        except Exception as exc:
            raise flutter.AppError("The Flutter/Android project in %s could not be read: %s"
                                   % (root.name, _reason(exc))) from exc
        if ctx is None:
            return None, files, [], ""
        files += ctx.files
    secret_findings = secrets.scan([sf for sf in files if sf.origin in SECRETS_ORIGINS])
    by_rel = {sf.rel: sf for sf in files}
    try:
        findings, note = flutter.analyze(ctx, by_rel)
    except Exception as exc:  # the facts of the loader are still worth showing
        findings, note = [], "failed: %s" % _reason(exc)
    inventory_error = ""
    try:                              # the keys of the inventory come from the secrets engine
        if key_rules:                 # and, as in a scan, from the rules that find keys
            from .cwe import canonical
            from .flutter.inventory import KEY_CWES
            rule_set = rules_engine.load_rules()
            secret_findings += [
                f for sf in files if sf.origin in RULES_ORIGINS
                for f in rules_engine.scan_file(sf, None, rule_set)
                if canonical(f.cwe) in KEY_CWES]
        # what a scan leaves out: suppressed lines (// nosec ...) and, for a project, tests
        secret_findings = [f for f in secret_findings if not merge.is_suppressed(f)
                           and (ctx.is_app or not is_test_path(f.file))]
    except Exception as exc:
        inventory_error = _reason(exc)
    # masked in the same order as a scan: every file masks every secret of the scan
    share_secrets(secret_findings + findings, files, by_rel)
    for finding in findings:
        if finding.file in by_rel:
            _clean_quotes(finding, by_rel[finding.file], ctx.is_app)
            finding.title = by_rel[finding.file].mask(finding.title)
            finding.description = by_rel[finding.file].mask(finding.description)
    mask_facts(ctx, by_rel)
    try:
        if inventory_error:
            raise RuntimeError(inventory_error)
        flutter.refine(secret_findings, by_rel, ctx)
        add_inventory(ctx, files, secret_findings
                      + [f for f in findings if not merge.is_suppressed(f)])
    except Exception as exc:  # the other facts are still worth showing
        note = "%s; API inventory failed: %s" % (note, _reason(exc))
    return ctx, files, findings, note


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

    # the analyzer's own summaries and keystore placeholders are never sent to the model
    todo = [f for f in findings if f.status == "open"
            and _origin(by_rel, f) in SECRETS_ORIGINS][: max(0, options.llm_max_findings)]
    for index, finding in enumerate(todo):
        progress(Message("file", "AI review %d of %d: %s", index + 1, len(todo),
                         finding.title[:50]),
                 0.62 + 0.22 * index / max(1, len(todo)))
        review(finding)
        if errors >= 3:
            break  # the model is not responding; stop instead of waiting for N timeouts

    new_findings: List[Finding] = []
    if options.llm_deep_scan and errors < 3:
        code_files = [sf for sf in by_rel.values() if sf.language not in ("config", "html")
                      and sf.origin in AI_ORIGINS]
        code_files.sort(key=lambda sf: -len(sf.lines))
        targets = code_files[: options.llm_deep_max_files]
        for index, sf in enumerate(targets):
            progress(Message("file", "AI deep scan %d of %d: %s", index + 1, len(targets),
                             sf.rel),
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
            new_findings = merge.merge_findings(new_findings, options.lang,
                                                mobile=bool(result.app))
            # Second pass: a finding that only the model reported is checked again in a
            # separate request. Without that confirmation it stays "probable".
            for index, finding in enumerate(new_findings):
                progress(Message("file", "AI verification %d of %d", index + 1,
                                 len(new_findings)), 0.92)
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
