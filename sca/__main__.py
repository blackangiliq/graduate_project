"""Command line interface.

    python -m sca scan <folder> [--llm] [--deep] [--strict] [--format html,json,sarif,pdf]
    python -m sca scan app.apk        # an app package (.apk, .aab, .apks, .xapk, .apkm)
    python -m sca flutter info|decode|deps|apis|tools ...   # look inside an app or Flutter project
    python -m sca config              # choose the AI provider and store the API key
    python -m sca learn <folder>      # let the AI propose new rules from a project
    python -m sca learn <folder> --rounds 5 --auto-approve    # keep learning until stable
    python -m sca learn --bootstrap all                       # fill gaps of every language
    python -m sca rules list          # review, approve or reject proposed rules
    python -m sca rules catalog       # every rule: built in, imported, learned, your own
    python -m sca rules new|edit|enable|disable|reset|delete|test|export|import ...
    python -m sca feedback fp <id>    # mark a finding as a false positive (or tp = real)
    python -m sca coverage            # rules per language and weakness
    python -m sca doctor              # show which engines and AI components are available
    python -m sca history             # list previous scans
    python -m sca train --dataset data.jsonl
    python -m sca ui                  # start the web dashboard
"""
from __future__ import annotations

import argparse
import json
import subprocess
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .models import SEVERITIES, SEVERITY_RANK
from .walker import strip_bidi

ROOT = Path(__file__).resolve().parent.parent
# characters never printed as they are: text from a scanned app could move the cursor or
# change the terminal, or reorder what is shown (Unicode bidirectional controls)
_CONTROL = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f]")


def _printable(text: Any) -> str:
    return strip_bidi(_CONTROL.sub(" ", str(text)))


def _safe_stdout() -> None:
    # Windows consoles often use a legacy code page; never crash on a character
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


# ------------------------------------------------------------------ shared LLM options
def _add_llm_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider", help="AI provider: ollama, openai, anthropic, gemini, "
                        "openrouter, groq, deepseek, mistral, custom (default: saved setting)")
    parser.add_argument("--model", help="model name (default: saved setting)")
    parser.add_argument("--base-url", help="address of the provider's API")
    parser.add_argument("--llm-host", help="Ollama address (same as --base-url for Ollama)")


def _llm_settings(args: argparse.Namespace) -> Dict[str, Any]:
    """Provider settings: command line first, then environment / .env, then defaults.
    The API key is only read from the environment or the .env file, never from the
    command line (it would end up in the shell history)."""
    from .ai.llm import DEFAULT_MODEL
    from .ai.providers import PRESETS, load_config

    config = load_config()
    provider = (getattr(args, "provider", None) or config.preset).lower()
    if provider not in PRESETS:
        raise SystemExit("Unknown provider '%s'. Choose one of: %s"
                         % (provider, ", ".join(PRESETS)))
    same = provider == config.preset
    model = getattr(args, "model", None) or (config.model if same else "")
    if not model and provider == "ollama":
        model = DEFAULT_MODEL
    base_url = getattr(args, "base_url", None) or getattr(args, "llm_host", None) or \
        (config.base_url if same else "")
    api_key = config.api_key if same else ""
    if not same:
        import os
        api_key = os.environ.get("SCA_LLM_API_KEY") or \
            os.environ.get(PRESETS[provider]["key_env"] or "-", "")
    return {"llm_provider": provider, "llm_model": model, "llm_base_url": base_url or "",
            "llm_api_key": api_key}


def _client(args: argparse.Namespace):
    from .pipeline import ScanOptions, client_from_options

    client = client_from_options(ScanOptions(**_llm_settings(args)))
    ready, message = client.check()
    if not ready:
        print("The AI provider is not ready: %s" % message, file=sys.stderr)
        print("Run `python -m sca config` to set the provider, model and API key.",
              file=sys.stderr)
        return None
    if not client.is_local:
        print("Note: code snippets will be sent to %s (secrets are masked)." % client.base_url,
              file=sys.stderr)
    return client


def _progress(args: argparse.Namespace):
    """Print what the scan is doing while it does it: each step, what the step found, and
    (in a terminal) the file being read, rewritten in place on one line."""
    live = sys.stderr.isatty()
    width = 96
    on_screen = [False]          # a "file" line is shown and must be cleared first

    def progress(message: str, fraction: float) -> None:
        if getattr(args, "quiet", False):
            return
        kind = getattr(message, "kind", "step")
        if kind == "file":
            if live:
                print("\r       %-*.*s" % (width, width, _printable(message)), end="",
                      file=sys.stderr, flush=True)
                on_screen[0] = True
            return
        if on_screen[0]:
            print("\r" + " " * (width + 7) + "\r", end="", file=sys.stderr)
            on_screen[0] = False
        if kind == "result":
            print("       -> %s" % _printable(message), file=sys.stderr)
        else:
            print("[%3d%%] %s" % (round(fraction * 100), _printable(message)), file=sys.stderr)
    return progress


# ------------------------------------------------------------------ scan
def _app_line(facts: Dict[str, Any]) -> str:
    """One line about a scanned app or project: package, version, kind and build."""
    from .report.html_report import KIND_TEXT, fact_text

    version = fact_text(facts.get("version_name"))
    if facts.get("version_code"):
        version = ("%s (%s)" % (version, fact_text(facts["version_code"]))).strip()
    kind = KIND_TEXT.get(str(facts.get("kind")), fact_text(facts.get("kind")))
    if facts.get("flutter") and facts.get("kind") != "flutter-project":   # said once
        kind += ", Flutter" + (" %s build" % fact_text(facts["build_mode"])
                               if facts.get("build_mode") else "")
    name = fact_text(facts.get("package") or facts.get("name")) or "-"
    return _printable(" ".join(part for part in (name, version, "- " + kind) if part))


def cmd_scan(args: argparse.Namespace) -> int:
    from .flutter import AppError
    from .pipeline import ScanOptions, run_scan
    from .report import write_reports

    options = ScanOptions(
        use_rules=not args.no_rules, use_ast=not args.no_ast, use_secrets=not args.no_secrets,
        use_bandit=not args.no_bandit, use_semgrep=not args.no_semgrep,
        use_gitleaks=not args.no_gitleaks, semgrep_config=args.semgrep_config,
        exclude_dirs=[d for d in args.exclude.split(",") if d],
        use_ml=not args.no_ml, ml_model_path=args.ml_model,
        use_llm=args.llm or args.deep, llm_max_findings=args.llm_max,
        llm_deep_scan=args.deep, lang=args.lang, save=not args.no_save,
        strict=args.strict, use_feedback=not args.no_feedback,
        include_tests=not args.skip_tests, use_taint_lite=not args.no_taint_lite,
        use_c_memory=not args.no_c_memory, use_flutter=not args.no_flutter,
        apk_tools=args.apk_tools,
        llm_deep_max_files=args.deep_max_files, llm_timeout=args.llm_timeout,
        **_llm_settings(args))
    try:
        result = run_scan(args.path, options, _progress(args))
    except (FileNotFoundError, AppError) as exc:
        print("Error: %s" % _printable(exc), file=sys.stderr)
        return 2

    counts = result.counts()
    print()
    print("Secure Code Analyzer %s" % __version__)
    print("Target : %s" % _printable(result.target))
    if result.app:
        print("App    : %s" % _app_line(result.app))
    print("Scanned: %d files, %d lines in %.1f s" % (result.files_scanned,
                                                     result.lines_scanned,
                                                     result.duration_seconds))
    print("Engines: %s" % ", ".join(result.engines_used))
    for name, note in result.engine_notes.items():
        if not note.startswith("ok"):
            print("  - %s: %s" % (name, _printable(note)))
    for name, note in result.ai.items():
        print("AI %-8s: %s" % (name, _printable(note)))
    print()
    apis = result.app.get("apis") if result.app else None
    if isinstance(apis, dict):
        from .report.html_report import api_alerts, api_summary
        print("APIs   : %s" % _printable(api_summary(apis)))
        serious = [text for level, text in api_alerts(apis) if level == "danger"]
        for text in serious[:8]:
            print("  ! %s" % _printable(text))
        if len(serious) > 8:
            print("  ! ... %d more alerts in the report" % (len(serious) - 8))
        print()
    print("Score  : %d / 100   Grade %s" % (result.score, result.grade))
    print("Open   : " + "   ".join("%s %d" % (s, counts[s]) for s in SEVERITIES))
    confirmed = sum(1 for f in result.open_findings if f.tier == "confirmed")
    print("         %d confirmed by independent evidence, %d probable"
          % (confirmed, len(result.open_findings) - confirmed))
    for status, label in (("needs_review", "not confirmed, moved to 'needs review' (strict mode)"),
                          ("likely_false_positive", "judged likely false positives by the AI review"),
                          ("dismissed", "dismissed by earlier reviews")):
        if result.status_count(status):
            print("         %d %s" % (result.status_count(status), label))
    print()
    shown = result.open_findings[: args.top]
    for finding in shown:
        print("%-8s %-9s %s:%d" % (finding.severity.upper(), finding.cwe or "-",
                                   _printable(finding.file), finding.line))
        print("         %s  (confidence %d%%, %s)" % (
            _printable(finding.title), round(finding.confidence * 100),
            "+".join(finding.engines)))
        print("         %s%s   id %s" % (
            finding.tier, ": " + _printable("; ".join(finding.evidence))
            if finding.evidence else "", finding.fingerprint))
        if finding.ai_verdict:
            print("         AI: %s" % finding.ai_verdict.replace("_", " "))
    if len(result.open_findings) > len(shown):
        print("... %d more in the report" % (len(result.open_findings) - len(shown)))

    formats = [f for f in args.format.split(",") if f.strip()]
    if formats:
        written = write_reports(result, args.out, formats)
        print()
        for fmt, path in written.items():
            print("Report (%s): %s" % (fmt, path))

    if args.fail_on:
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= limit for f in result.open_findings):
            return 1
    return 0


# ------------------------------------------------------------------ config / doctor
def cmd_config(args: argparse.Namespace) -> int:
    import getpass

    from .ai.providers import PRESETS, LLMConfig, env_file, load_config, make_client, save_config

    config = load_config()
    if args.show or not (args.provider or args.model or args.base_url or args.set_key):
        print("Provider : %s (%s)" % (config.preset, PRESETS[config.preset]["label"]))
        print("Address  : %s" % config.resolved_base_url())
        print("Model    : %s" % (config.model or "(not set)"))
        print("API key  : %s" % ("set" if config.api_key else "not set"))
        print("Stored in: %s" % env_file())
        print("\nProviders: %s" % ", ".join(PRESETS))
        print("Example  : python -m sca config --provider openai --model <model-name>")
        return 0
    provider = (args.provider or config.preset).lower()
    if provider not in PRESETS:
        print("Unknown provider. Choose one of: %s" % ", ".join(PRESETS), file=sys.stderr)
        return 2
    changed = provider != config.preset
    new = LLMConfig(preset=provider,
                    base_url=args.base_url or ("" if changed else config.base_url),
                    api_key="" if changed else config.api_key,
                    model=args.model or ("" if changed else config.model))
    needs_key = PRESETS[provider]["kind"] != "ollama"
    if needs_key and (args.set_key or not new.api_key):
        key = getpass.getpass("API key for %s (input is hidden, Enter to skip): "
                              % PRESETS[provider]["label"]).strip()
        if key:
            new.api_key = key
    path = save_config(new)
    print("Saved to %s (this file is git-ignored; do not share it)." % path)
    client = make_client(new)
    ready, message = client.check()
    print("Connection: %s" % ("ready" if ready else "NOT ready - " + message))
    if ready and not new.model:
        names = client.models()
        if names:
            print("Available models: %s" % ", ".join(names[:30]))
    return 0 if ready else 1


def _print_mobile_tools() -> None:
    """The "Mobile apps" part of doctor: the built-in decoders and checks, then the optional
    tools that app packages can use (--apk-tools)."""
    from .flutter import checks, tools

    print("Mobile apps")
    print("  [ok] checks     %d Flutter/Android checks of manifests, network security, signing, "
          "build and dependencies (built in)" % len(checks.CHECKS))
    print("  [ok] decoders   APK, AAB and split APK sets are decoded without other tools "
          "(built in)")
    hints = tools.hints()
    for name, path in tools.availability().items():
        print("  [%s] %-10s %s" % ("ok" if path else "--", name, path if path else
                                   "not found - " + hints.get(name, "optional")))


def cmd_doctor(args: argparse.Namespace) -> int:
    from .ai.classifier import SKLEARN_AVAILABLE
    from .ai.providers import PRESETS, load_config, make_client
    from .engines import external
    from .engines.rules_engine import load_rules

    rules = load_rules()
    learned = sum(1 for r in rules if r.origin == "learned")
    print("Secure Code Analyzer %s on Python %s" % (__version__, sys.version.split()[0]))
    print()
    print("Static engines")
    from . import rulebook
    counts = rulebook.summary()
    origins = counts["by_origin"]
    print("  [ok] rules      %d of %d rules active (%d built in, %d imported, %d learned, "
          "%d your own; %d are credential formats)"
          % (counts["enabled"], counts["total"], origins["builtin"]["enabled"],
             origins["imported"]["enabled"], origins["learned"]["enabled"],
             origins["custom"]["enabled"], counts["secret"]))
    print("  [ok] ast        Python taint analysis, inter-procedural within a file (built in)")
    print("  [ok] taint-lite input tracing for JS, PHP, Java, Go, C#, Ruby, C, Dart (built in)")
    print("  [ok] c-memory   C/C++ double free, use after free, leaks, overflowing sizes, "
          "bounds (built in)")
    print("  [ok] secrets    key formats + entropy (built in)")
    tools = external.availability()
    hints = {"bandit": "pip install bandit",
             "semgrep": "optional: install Opengrep (github.com/opengrep/opengrep) or Semgrep",
             "gitleaks": "optional: install from github.com/gitleaks/gitleaks"}
    for name, ok in tools.items():
        print("  [%s] %-10s %s" % ("ok" if ok else "--", name, "available" if ok
                                   else "not found - " + hints.get(name, "optional")))
    print()
    _print_mobile_tools()
    print()
    print("AI components")
    print("  [%s] ML classifier (scikit-learn)%s" % (
        "ok" if SKLEARN_AVAILABLE else "--",
        "" if SKLEARN_AVAILABLE else " - pip install scikit-learn"))
    config = load_config()
    client = make_client(config)
    ready, message = client.check()
    print("  [%s] LLM provider: %s, model %s" % ("ok" if ready else "--",
                                                PRESETS[config.preset]["label"],
                                                client.model or "(not set)"))
    if not ready:
        print("       %s" % message)
        print("       set it up with: python -m sca config --provider <name> --model <model>")
    try:
        import fpdf  # noqa: F401
        print("  [ok] PDF export (fpdf2)")
    except ImportError:
        print("  [--] PDF export - pip install fpdf2")
    return 0


# ------------------------------------------------------------------ learning
def _print_candidates(candidates: List[Dict[str, Any]]) -> None:
    for c in candidates:
        failed = [x for x in (c.get("validation") or {}).get("checks", []) if not x["passed"]]
        print("%-22s %-14s %-9s %s" % (c["id"], c["status"], c.get("cwe", ""), c.get("title", "")))
        for check in failed:
            print("      failed %s: %s" % (check["name"], check["detail"]))


def cmd_learn(args: argparse.Namespace) -> int:
    from .flutter import AppError
    from .learn import loop
    from .pipeline import ScanOptions, scan_project
    from .storage import Storage

    if not (args.path or args.bootstrap or args.from_feedback):
        print("Give a project folder or app package, or --bootstrap <language>, or "
              "--from-feedback.", file=sys.stderr)
        return 2
    client = _client(args)
    if client is None:
        return 2
    storage = Storage()
    created: List[Dict[str, Any]] = []
    auto_approved: List[str] = []
    if args.path:
        options = ScanOptions(use_llm=True, llm_deep_scan=True,
                              llm_deep_max_files=args.max_files, llm_max_findings=args.llm_max,
                              use_c_memory=not args.no_c_memory, save=False,
                              **_llm_settings(args))
        try:
            report = loop.learn_until_stable(
                args.path, client, storage,
                lambda: scan_project(args.path, options, _progress(args), storage),
                rounds=args.rounds, approve=args.auto_approve, max_candidates=args.max_rules,
                progress=_progress(args))
        except (FileNotFoundError, AppError) as exc:
            print("Error: %s" % _printable(exc), file=sys.stderr)
            return 2
        for entry in report:
            print("Round %d: %d candidate(s), %d passed validation, %d activated. AI: %s" % (
                entry["round"], len(entry["created"]), entry["pending"],
                len(entry["approved"]), entry["llm"]))
            created += entry["created"]
            auto_approved += entry["approved"]
        last = report[-1]
        if not last["created"]:
            print("Nothing new to learn from this project: the rules cover what the AI found.")
        elif last["pending"] and not args.auto_approve and args.rounds > 1:
            print("Stopped after round %d: approve the candidates, then run the command again "
                  "(or use --auto-approve) so the next round can look for more." % last["round"])
    if args.from_feedback:
        created += loop.learn_from_feedback(client, storage, args.max_rules)
    if args.bootstrap:
        cwes = [c for c in args.cwe.split(",") if c] if args.cwe else None
        if args.bootstrap.lower() == "all":
            gaps = loop.all_gaps(cwes=cwes)
            total = sum(len(v) for v in gaps.values())
            print("Coverage gaps: %d weaknesses in %d languages (up to %d AI requests)."
                  % (total, len(gaps), 2 * total))
            created += loop.bootstrap_all(client, storage, cwes=cwes, progress=_progress(args))
        else:
            try:
                created += loop.bootstrap(client, storage, args.bootstrap, cwes,
                                          _progress(args))
            except ValueError as exc:
                print("Error: %s. Run `python -m sca coverage` for the list." % exc,
                      file=sys.stderr)
                return 2

    pending = [c for c in created if c["status"] == "pending"]
    print("\n%d candidate(s) proposed: %d passed validation, %d rejected automatically."
          % (len(created), len(pending), len(created) - len(pending)))
    _print_candidates(created)
    still_pending = [c["id"] for c in storage.list_candidates("pending")]
    if auto_approved:
        print("\nActivated automatically: %s" % ", ".join(auto_approved))
    if still_pending:
        print("\n%d candidate(s) are waiting for your approval." % len(still_pending))
        print("Review them:  python -m sca rules show <id>")
        print("Approve    :  python -m sca rules approve <id>   (or: approve all)")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .engines.rules_engine import load_rules
    from .learn import feedback, store
    from .storage import Storage

    storage = Storage()
    action = args.action
    if action == "list":
        status = None if args.status == "all" else args.status
        candidates = storage.list_candidates(status)
        if not candidates:
            print("No candidates with status '%s'." % args.status)
        _print_candidates(candidates)
        learned = store.read_learned()
        print("\nActive learned rules: %d" % len(learned))
        for rule in learned:
            print("  %-22s %-9s %s" % (rule["id"], rule.get("cwe", ""), rule.get("title", "")))
        return 0
    if action == "stats":
        stats = storage.rule_stats()
        confidences = {r.id: r.confidence for r in load_rules()}
        if not stats:
            print("No reviewer feedback yet. Mark findings with: python -m sca feedback fp|tp <id>")
            return 0
        print("%-24s %4s %4s  %-10s %s" % ("Rule", "TP", "FP", "Confidence", "State"))
        for rule_id, s in sorted(stats.items(), key=lambda kv: -kv[1]["fp"]):
            base = confidences.get(rule_id, 0.6)
            print("%-24s %4d %4d  %.2f->%.2f %s" % (
                rule_id, s["tp"], s["fp"], base,
                feedback.adjusted_confidence(base, s["tp"], s["fp"]),
                "QUARANTINED" if feedback.is_quarantined(base, s["tp"], s["fp"]) else "active"))
        return 0
    if action in RULEBOOK_ACTIONS:
        return _rulebook_action(args, storage)
    if not args.ids:
        print("Give a candidate id.", file=sys.stderr)
        return 2
    ids = args.ids
    if action == "show" and storage.get_candidate(ids[0]) is None:
        return _rulebook_action(args, storage)       # not a candidate: show the rule itself
    if action == "approve" and ids == ["all"]:
        ids = [c["id"] for c in storage.list_candidates("pending")]
    code = 0
    for candidate_id in ids:
        try:
            if action == "show":
                candidate = storage.get_candidate(candidate_id)
                if candidate is None:
                    raise KeyError("No candidate with id %s" % candidate_id)
                print(json.dumps(candidate, indent=2, ensure_ascii=False))
            elif action == "approve":
                store.approve(storage, candidate_id)
                print("Approved %s. It is active from the next scan." % candidate_id)
            elif action == "reject":
                store.reject(storage, candidate_id)
                print("Rejected %s." % candidate_id)
            elif action == "remove":
                removed = store.remove_learned_rule(candidate_id)
                print("Removed %s." % candidate_id if removed
                      else "No learned rule with id %s." % candidate_id)
        except (KeyError, ValueError) as exc:
            print("Error: %s" % str(exc).strip("'\""), file=sys.stderr)
            code = 1
    return code


RULEBOOK_ACTIONS = ("catalog", "enable", "disable", "reset", "delete", "edit", "new",
                    "template", "test", "export", "import")


def _print_rule(rule) -> None:
    import yaml
    data = rule.as_dict()
    state = "enabled" if rule.enabled else "DISABLED"
    print("%s  [%s, %s%s]" % (rule.id, rule.origin, state, ", edited by you" if rule.edited else ""))
    if rule.source:
        print("source: %s%s" % (rule.source, " (%s licence, %s)" % (rule.license, rule.url)
                                if rule.license else ""))
    if rule.note:
        print("note: %s" % rule.note)
    keep = ("title", "kind", "languages", "files", "cwe", "severity", "confidence", "pattern",
            "exclude", "ignore_case", "message", "fix", "keywords", "entropy", "extra_excludes",
            "examples_vulnerable", "examples_safe", "file")
    print(yaml.safe_dump({k: data[k] for k in keep if data.get(k) not in ("", [], 0.0, False)},
                         sort_keys=False, allow_unicode=True, width=1000).rstrip())


def _files_to_test(path: str) -> List[Any]:
    """The files `rules test` reads: those of a folder or a file, or for an app package the
    decoded files that the pattern rules read in a scan."""
    from .flutter.context import RULES_ORIGINS
    from .pipeline import decode_app, is_app_target
    from .walker import walk_project

    target = Path(path).expanduser()
    if is_app_target(target):
        return [sf for sf in decode_app(target, False).files if sf.origin in RULES_ORIGINS]
    return list(walk_project(path))


def _rulebook_action(args: argparse.Namespace, storage) -> int:
    """Everything that manages the rule set itself (see sca/rulebook.py)."""
    import yaml
    from . import rulebook
    from .flutter import AppError

    action, ids = args.action, args.ids
    try:
        if action == "catalog":
            rules = rulebook.list_rules(
                origin=args.origin, language=args.lang, cwe=args.cwe, text=args.search or "",
                enabled=False if args.disabled else None)
            print("%-34s %-9s %-8s %-9s %-8s %s" % ("Rule", "Origin", "State", "Weakness",
                                                    "Severity", "Title"))
            for rule in rules:
                print("%-34s %-9s %-8s %-9s %-8s %s" % (
                    rule.id[:34], rule.origin, ("on" if rule.enabled else "off")
                    + ("*" if rule.edited else ""), rule.cwe, rule.severity, rule.title[:60]))
            counts = rulebook.summary()
            print("\n%d shown. In total %d rules, %d active (* = edited by you)."
                  % (len(rules), counts["total"], counts["enabled"]))
            return 0
        if action == "template":
            print(rulebook.TEMPLATE, end="")
            return 0
        if action == "export":
            text = rulebook.export_yaml(ids or None, args.origin)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
                print("Wrote %s" % args.output)
            else:
                print(text, end="")
            return 0
        if not ids and action in ("enable", "disable") and (
                args.origin or args.lang or args.cwe or args.search):
            # no id given: act on every rule that matches the filters
            ids = [r.id for r in rulebook.list_rules(origin=args.origin, language=args.lang,
                                                     cwe=args.cwe, text=args.search or "")]
            changed = rulebook.set_enabled_many(ids, action == "enable")
            print("%s %d of %d matching rule(s)." % (
                "Enabled" if action == "enable" else "Disabled", changed, len(ids)))
            return 0
        if not ids:
            print("Give a rule id (or a file for new / import).", file=sys.stderr)
            return 2
        if action in ("new", "import"):
            added, problems = rulebook.import_yaml(Path(ids[0]).read_text(encoding="utf-8"),
                                                   storage)
            for rule_id in added:
                print("Added %s. It is active from the next scan." % rule_id)
                for warning in rulebook.check(rulebook.get(rule_id).as_dict(), storage,
                                              rule_id)["warnings"]:
                    print("  warning: %s" % warning)
            for problem in problems:
                print("Error: %s" % problem, file=sys.stderr)
            return 1 if problems else 0
        if action == "show":
            for rule_id in ids:
                _print_rule(rulebook.get(rule_id))
            return 0
        if action == "edit":
            changes: Dict[str, Any] = {}
            for item in args.set or []:
                key, _, value = item.partition("=")
                key = key.strip()
                if key == "files":      # globs such as **/web/index.html are not YAML
                    changes[key] = [p.strip().strip("'\"") for p in value.strip(" []").split(",")
                                    if p.strip().strip("'\"")]
                    continue
                changes[key] = yaml.safe_load(value) if key in (
                    "languages", "confidence", "ignore_case", "enabled") else value
            if not changes:
                print("Nothing to change. Use --set field=value, for example "
                      "--set severity=low --set confidence=0.4", file=sys.stderr)
                return 2
            result = rulebook.update(ids[0], changes, storage)
            print("Updated %s." % ids[0])
            for warning in result["warnings"]:
                print("  warning: %s" % warning)
            return 0
        if action == "test":
            rule = rulebook.get(ids[0])
            if len(ids) < 2:
                print("Give a file or folder to test the rule on.", file=sys.stderr)
                return 2
            hits = skipped = 0
            for sf in _files_to_test(ids[1]):
                if not rule.applies_to(sf.rel):
                    skipped += 1
                    continue
                for number, line in enumerate(sf.lines, start=1):
                    if rule.matches(line):
                        hits += 1
                        print("%s:%d  %s" % (sf.rel, number, _printable(line.strip()[:140])))
            print("%d line(s) matched by %s." % (hits, rule.id))
            if skipped:
                print("%d file(s) not read: the rule only reads files that match %s."
                      % (skipped, ", ".join(rule.files)))
            return 0
        for rule_id in ids:
            if action == "enable":
                rulebook.set_enabled(rule_id, True)
                print("Enabled %s." % rule_id)
            elif action == "disable":
                rulebook.set_enabled(rule_id, False)
                print("Disabled %s. It no longer takes part in scans." % rule_id)
            elif action == "reset":
                print("Restored %s to its original definition." % rule_id
                      if rulebook.reset(rule_id) else "%s was not changed." % rule_id)
            elif action == "delete":
                rulebook.delete(rule_id)
                print("Deleted %s." % rule_id)
    except (rulebook.RuleError, OSError, AppError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    return 0


def cmd_feedback(args: argparse.Namespace) -> int:
    from .storage import Storage

    storage = Storage()
    if args.verdict == "list":
        rows = storage.feedback_rows()
        if not rows:
            print("No feedback recorded yet.")
        for row in rows:
            print("%s  %-2s  %-9s %s  %s" % (row["fingerprint"], row["verdict"], row["cwe"],
                                             row["file"], (row["snippet"] or "")[:70]))
        return 0
    if not args.id:
        print("Give the finding id printed by `scan` (the 16-character id).", file=sys.stderr)
        return 2
    if args.verdict == "clear":
        storage.clear_feedback(args.id)
        print("Cleared.")
        return 0
    for row in storage.list_scans(30):
        scan = storage.load_scan(row["id"])
        match = next((f for f in scan.findings if f.fingerprint.startswith(args.id)), None)
        if match is not None:
            storage.set_feedback(match, args.verdict)
            print("Recorded: %s is a %s (%s:%d %s)." % (
                match.fingerprint, "false positive" if args.verdict == "fp" else "real finding",
                match.file, match.line, match.title))
            print("Later scans apply this verdict and adjust the confidence of rule(s): %s"
                  % ", ".join(match.rule_ids))
            return 0
    print("No finding with id %s in the saved scans. Run a scan first (without --no-save)."
          % args.id, file=sys.stderr)
    return 1


def cmd_coverage(args: argparse.Namespace) -> int:
    from .cwe import info
    from .learn.loop import coverage_matrix

    matrix = coverage_matrix()
    cwes = sorted({c for row in matrix.values() for c in row}, key=lambda c: int(c.split("-")[1]))
    print("Active pattern rules per language and weakness (rules for \"any\" language, rules "
          "for named files only and credential formats are not counted):\n")
    print("%-12s %5s  %s" % ("Language", "Rules", "Weaknesses covered"))
    for language, row in matrix.items():
        covered = ", ".join("%s(%d)" % (c.replace("CWE-", ""), row[c]) for c in cwes if row.get(c))
        if language == "python":
            covered = "AST taint engine" + (" + " + covered if covered else "")
        print("%-12s %5d  %s" % (language, sum(row.values()), covered or "- none yet -"))
    print("\nNumbers are CWE ids:")
    for c in cwes:
        print("  %-9s %s" % (c, info(c)["name"]))
    print("\nFill gaps with:  python -m sca learn --bootstrap <language>")
    return 0


# ------------------------------------------------------------------ flutter (app packages)
FLUTTER_ROWS = 100           # rows of each list printed by `flutter info`; --json prints all
_UNSAFE_PATH = re.compile(r'[\x00-\x1f\x7f\\:*?"<>|]')
_RESERVED_NAME = re.compile(r"(?i)(con|prn|aux|nul|com\d|lpt\d|conin\$|conout\$)(\..*)?\Z")


def output_path(folder: Path, rel: str) -> Optional[Path]:
    """Where `flutter decode` writes a virtual file: folder/rel, or None when rel is not a
    plain relative path that stays inside folder (absolute, a drive, '..', a name Windows
    reserves or changes, or characters it refuses)."""
    parts = rel.split("/")
    if not rel or len(rel) > 400 or _UNSAFE_PATH.search(rel) or any(
            part in ("", ".", "..") or part != part.rstrip(". ") or _RESERVED_NAME.match(part)
            for part in parts):
        return None
    target = folder.joinpath(*parts)
    try:
        target.resolve().relative_to(folder.resolve())
    except (OSError, ValueError):
        return None
    return target


def _decode(ctx: Any, out: Optional[str]) -> int:
    """Write every virtual file of an app (or the placeholders of a project) and facts.json
    into an empty folder."""
    if not out:
        print("Give the output folder with --out FOLDER (it must be empty).", file=sys.stderr)
        return 2
    folder = Path(out).expanduser().resolve()
    if folder.exists() and (not folder.is_dir() or any(folder.iterdir())):
        print("Error: %s is not an empty folder." % folder, file=sys.stderr)
        return 2
    folder.mkdir(parents=True, exist_ok=True)
    written, problems = 0, []
    outputs = [(sf.rel, sf.text) for sf in ctx.files] + [
        ("facts.json", json.dumps(ctx.facts, indent=2, ensure_ascii=False) + "\n")]
    for rel, text in outputs:
        target = output_path(folder, rel)
        if target is None:
            problems.append("%s (not a safe file name)" % rel)
            continue
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            problems.append("%s (%s)" % (rel, exc.strerror or exc))
            continue
        written += 1
    print("Wrote %d %s to %s" % (written, "file" if written == 1 else "files", folder))
    for problem in problems[:20]:
        print("  not written: %s" % _printable(problem))
    if len(problems) > 20:
        print("  and %d more not written" % (len(problems) - 20))
    return 1 if problems else 0


def _print_facts(facts: Dict[str, Any]) -> None:
    from .report.html_report import app_overview, app_tables

    width = max([len(label) for label, _ in app_overview(facts)] + [8])
    for label, text in app_overview(facts):
        print("%-*s  %s" % (width, label, text))
    for title, columns, rows in app_tables(facts):
        print("\n%s (%d)" % (title, len(rows)))
        for row in rows[:FLUTTER_ROWS]:
            more = ", ".join("%s: %s" % (column.lower(), cell)
                             for column, cell in zip(columns[1:], row[1:]) if cell)
            print("  %s%s" % (row[0], "  (%s)" % more if more else ""))
        if len(rows) > FLUTTER_ROWS:
            print("  and %d more (--json prints all)" % (len(rows) - FLUTTER_ROWS))


def _print_apis(apis: Dict[str, Any]) -> None:
    """The API and key inventory for a terminal: summary, alerts, then every list."""
    from .report.html_report import api_alerts, api_summary, api_tables

    print("APIs and keys: %s" % _printable(api_summary(apis)))
    print("Keys are masked; no address was contacted.")
    alerts = api_alerts(apis)
    if alerts:
        print("\nAlerts (%d)" % len(alerts))
        for level, text in alerts:
            print("  %-7s %s" % (level.upper(), _printable(text)))
    for title, columns, rows in api_tables(apis):
        print("\n%s (%d)" % (title, len(rows)))
        for row in rows[:FLUTTER_ROWS]:
            more = "; ".join("%s: %s" % (column.lower(), cell)
                             for column, cell in zip(columns[1:], row[1:]) if cell)
            print("  %s%s" % (_printable(row[0]), "  (%s)" % _printable(more) if more else ""))
        if len(rows) > FLUTTER_ROWS:
            print("  and %d more (--json prints all)" % (len(rows) - FLUTTER_ROWS))
    truncated = apis.get("truncated")
    if isinstance(truncated, dict) and truncated:
        print("\nLists cut to keep the facts small: %s" % ", ".join(
            "%s +%s" % item for item in truncated.items()))


def cmd_flutter(args: argparse.Namespace) -> int:
    from .flutter import AppError
    from .pipeline import inspect_mobile

    if args.action == "tools":
        _print_mobile_tools()
        return 0
    if not args.path:
        print("Give an app package (.apk, .aab, .apks, .xapk, .apkm) or a project folder.",
              file=sys.stderr)
        return 2
    try:
        ctx, _files, findings, note = inspect_mobile(
            args.path, args.apk_tools, [d for d in args.exclude.split(",") if d],
            key_rules=args.action in ("apis", "info", "decode"))
    except (FileNotFoundError, AppError) as exc:
        print("Error: %s" % _printable(exc), file=sys.stderr)
        return 2
    if ctx is None:
        print("Error: %s holds neither a Flutter app nor an Android project." % args.path,
              file=sys.stderr)
        return 2
    if args.action == "decode":
        return _decode(ctx, args.out)
    if args.action == "deps":
        issues = [f for f in findings if f.rule_id.startswith("FLUTTER-PUB-")]
        if args.json:
            print(json.dumps({"packages": ctx.facts.get("packages") or [],
                              "issues": [f.to_dict() for f in issues]},
                             indent=2, ensure_ascii=False))
            return 0
        packages = [p for p in ctx.facts.get("packages") or [] if isinstance(p, dict)]
        print("%d packages" % len(packages))
        width = min(40, max([len(str(p.get("name", ""))) for p in packages] + [10]))
        for item in packages:
            where = [str(item[key]) for key in ("source", "dependency") if item.get(key)]
            if item.get("found_in"):
                where.append("found in %s" % item["found_in"])
            print("  %-*s %-14s %s" % (width, _printable(item.get("name", "")),
                                       _printable(item.get("version") or "unknown"),
                                       _printable(", ".join(where))))
        print("\n%d dependency issues" % len(issues))
        for finding in issues:
            print("  %-8s %-15s %s  (%s:%d)" % (finding.severity.upper(), finding.rule_id,
                                                _printable(finding.title),
                                                _printable(finding.file), finding.line))
        return 0
    if args.action == "apis":
        apis = ctx.facts.get("apis")
        if not isinstance(apis, dict):
            print("Error: the API inventory could not be built: %s" % _printable(note),
                  file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(apis, indent=2, ensure_ascii=False))
            return 0
        _print_apis(apis)
        return 0
    if args.json:
        print(json.dumps(ctx.facts, indent=2, ensure_ascii=False))
        return 0
    _print_facts(ctx.facts)
    if isinstance(ctx.facts.get("apis"), dict):
        from .report.html_report import api_summary
        print("\nAPIs and keys: %s\n  (flutter apis PATH lists them with their places)"
              % api_summary(ctx.facts["apis"]))
    print("\nThe Flutter/Android checks found %d weaknesses; scan the target for the full "
          "report." % len(findings))
    if "not checked" in note or not note.startswith("ok") or "API inventory failed" in note:
        print("Note: %s" % _printable(note))
    return 0


# ------------------------------------------------------------------ history / train / ui
def cmd_history(args: argparse.Namespace) -> int:
    from .storage import Storage

    rows = Storage().list_scans(args.limit)
    if not rows:
        print("No scans saved yet.")
        return 0
    print("%-5s %-19s %-6s %-5s %-4s %-4s %-4s %-4s %s" % (
        "ID", "Date", "Score", "Grade", "Crit", "High", "Med", "Low", "Target"))
    for row in rows:
        print("%-5d %-19s %-6d %-5s %-4d %-4d %-4d %-4d %s" % (
            row["id"], row["started_at"], row["score"], row["grade"], row["critical"],
            row["high"], row["medium"], row["low"], row["target"]))
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from .ai import classifier as clf
    from .ai.seed_corpus import build_corpus

    if not clf.SKLEARN_AVAILABLE:
        print("scikit-learn is not installed: pip install scikit-learn", file=sys.stderr)
        return 2
    if args.dataset:
        texts, labels = clf.load_dataset(args.dataset, args.limit)
        source = "%s (%d samples)" % (Path(args.dataset).name, len(texts))
    else:
        texts, labels = build_corpus()
        source = "built-in synthetic corpus (%d samples)" % len(texts)
    if len(set(labels)) < 2 or len(texts) < 20:
        print("Dataset needs both labels and at least 20 samples (got %d)." % len(texts),
              file=sys.stderr)
        return 2
    print("Training on %s: %d vulnerable, %d safe" % (source, sum(labels),
                                                      len(labels) - sum(labels)))
    model, metrics = clf.train_and_evaluate(texts, labels, source)
    print(json.dumps(metrics, indent=2))
    if not args.dataset:
        print("Note: these numbers come from synthetic data and are optimistic. "
              "Do not report them as research results.")
    final = clf.VulnerabilityClassifier.train(texts, labels, source)
    final.save(args.out)
    print("Model saved to %s" % args.out)
    print("Use it with: python -m sca scan <folder> --ml-model %s" % args.out)
    if args.show_features:
        for side, items in final.top_features().items():
            print("\nStrongest '%s' features:" % side)
            for name, weight in items:
                print("  %+.3f  %s" % (weight, name))
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    import threading
    import webbrowser

    url = "http://localhost:%d" % args.port
    # headless: Streamlit does not ask first-time questions in the terminal; we open the
    # browser ourselves. address=localhost: the dashboard is not reachable from the network.
    cmd = [sys.executable, "-m", "streamlit", "run", str(ROOT / "app.py"),
           "--server.port", str(args.port), "--server.address", "localhost",
           "--server.headless", "true", "--browser.gatherUsageStats", "false"]
    print("Starting the dashboard at %s  (press Ctrl+C to stop)" % url)
    if not args.no_browser:
        threading.Timer(3.0, webbrowser.open, [url]).start()
    try:
        return subprocess.call(cmd, cwd=str(ROOT))
    except KeyboardInterrupt:
        return 0


def _add_flutter_options(parser: argparse.ArgumentParser, default: Any = None) -> None:
    """The options of `flutter`. default=argparse.SUPPRESS leaves an option that is not given
    out of the result (for the parsers of the actions, see build_parser)."""
    def given(value: Any) -> Any:
        return value if default is None else default

    parser.add_argument("--out", default=given(None),
                        help="decode: an empty folder for the decoded files")
    parser.add_argument("--json", action="store_true", default=given(False),
                        help="info, deps, apis: print JSON")
    parser.add_argument("--apk-tools", action="store_true", default=given(False),
                        help="also use jadx and apksigner when they are installed")
    parser.add_argument("--exclude", default=given(""),
                        help="projects: comma list of folder names to skip")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca", description="Secure Code Analyzer: static + AI vulnerability scanner "
                                "for source code and Android/Flutter app packages that "
                                "learns new rules")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a project folder or an app package")
    scan.add_argument("path", help="folder, file or app package (.apk, .aab, .apks, .xapk, "
                                   ".apkm)")
    scan.add_argument("--out", default="reports", help="report folder (default: reports)")
    scan.add_argument("--format", default="html,json",
                      help="comma list of: html, json, sarif, pdf (default: html,json)")
    scan.add_argument("--lang", choices=["en", "ar"], default="en",
                      help="language of explanations")
    scan.add_argument("--exclude", default="", help="comma list of folder names to skip")
    scan.add_argument("--top", type=int, default=25, help="findings to print (default 25)")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                      help="exit with code 1 if a finding of this severity or higher exists")
    scan.add_argument("--strict", action="store_true",
                      help="count only findings confirmed by independent evidence; the rest "
                           "go to 'needs review'")
    scan.add_argument("--skip-tests", action="store_true",
                      help="do not scan test code (tests/, test_*.py, *.spec.js ...)")
    scan.add_argument("--quiet", action="store_true", help="no progress messages")
    scan.add_argument("--no-save", action="store_true", help="do not store in history")
    scan.add_argument("--no-feedback", action="store_true",
                      help="ignore earlier reviewer verdicts and rule track records")
    for name in ("rules", "ast", "secrets", "bandit", "semgrep", "gitleaks", "ml"):
        scan.add_argument("--no-%s" % name, action="store_true", help="disable the %s engine" % name)
    scan.add_argument("--semgrep-config", default="auto", help="Semgrep/Opengrep rule config")
    scan.add_argument("--ml-model", help="path to a model trained with 'sca train'")
    scan.add_argument("--llm", action="store_true", help="review findings with the AI provider")
    scan.add_argument("--deep", action="store_true",
                      help="also let the AI audit whole files (slower; implies --llm)")
    scan.add_argument("--llm-max", type=int, default=30, help="max findings the AI reviews")
    scan.add_argument("--deep-max-files", type=int, default=10,
                      help="files the AI audits in a deep scan (default 10)")
    scan.add_argument("--llm-timeout", type=int, default=180,
                      help="seconds to wait for one AI answer (default 180)")
    scan.add_argument("--no-taint-lite", action="store_true",
                      help="do not trace user input for JS, PHP, Java, Go, C#, Ruby, C, Dart")
    scan.add_argument("--no-c-memory", action="store_true",
                      help="skip the C/C++ memory checks (double free, use after free, ...)")
    scan.add_argument("--no-flutter", action="store_true",
                      help="skip the Flutter/Android checks (manifest, network security, "
                           "signing, build, dependencies); a source project then also has no "
                           "app facts and no API and key inventory")
    scan.add_argument("--apk-tools", action="store_true",
                      help="app packages: also decompile the app's classes with jadx and "
                           "verify the signature with apksigner, when they are installed")
    _add_llm_arguments(scan)
    scan.set_defaults(func=cmd_scan)

    config = sub.add_parser("config", help="choose the AI provider and store the API key")
    config.add_argument("--provider")
    config.add_argument("--model")
    config.add_argument("--base-url")
    config.add_argument("--set-key", action="store_true", help="ask for a new API key")
    config.add_argument("--show", action="store_true")
    config.set_defaults(func=cmd_config)

    learn = sub.add_parser("learn", help="let the AI propose new rules")
    learn.add_argument("path", nargs="?", help="project folder or app package to learn from")
    learn.add_argument("--bootstrap", metavar="LANGUAGE",
                       help="write rules for the weaknesses this language has no rule for; "
                            "'all' does every language that has a gap")
    learn.add_argument("--rounds", type=int, default=1,
                       help="repeat deep scan + learning until a round finds nothing new, "
                            "at most this many times (needs --auto-approve to continue "
                            "past the first round)")
    learn.add_argument("--cwe", default="", help="with --bootstrap: comma list of CWE ids")
    learn.add_argument("--from-feedback", action="store_true",
                       help="propose exclusions for findings you marked as false positives")
    learn.add_argument("--auto-approve", action="store_true",
                       help="activate validated rules learned from real code without asking "
                            "(bootstrap rules and exclusions still wait for you)")
    learn.add_argument("--max-files", type=int, default=10, help="files the AI audits")
    learn.add_argument("--max-rules", type=int, default=20, help="candidates per run")
    learn.add_argument("--llm-max", type=int, default=60, help="max findings the AI reviews")
    learn.add_argument("--no-c-memory", action="store_true",
                       help="skip the C/C++ memory checks in the scans of the learning loop")
    learn.add_argument("--quiet", action="store_true")
    _add_llm_arguments(learn)
    learn.set_defaults(func=cmd_learn)

    rules = sub.add_parser(
        "rules", help="review proposed rules and manage the whole rule set",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""Proposed rules (candidates from the AI):
  list                    candidates waiting for approval (--status all for every one)
  show ID                 a candidate, or any rule of the rule set
  approve ID... | all     make a validated candidate active
  reject ID...            discard a candidate
  stats                   how each rule did in your reviews

The rule set:
  catalog                 every rule (--origin, --lang, --cwe, --search, --disabled)
  enable ID... / disable ID...
                          without an id: every rule matching --origin/--lang/--cwe/--search
  edit ID --set field=value [--set ...]    fields: title, languages, files, cwe,
                          severity, confidence, pattern, exclude, ignore_case, message,
                          fix (files: file name patterns separated by commas, e.g.
                          --set "files=**/web/index.html, *.sh"; empty = every file)
  reset ID...             undo your changes to a rule that ships with the tool
  template                print an empty rule to fill in
  new FILE.yaml           add your own rule(s) from a file (same as import)
  test ID PATH            show the lines of a file, folder or app package that a rule
                          marks (only in the files the rule reads)
  delete ID...            remove one of your own or learned rules (remove = same)
  export [ID...]          print rules as YAML (--origin custom, -o FILE)
  import FILE.yaml        add rules exported from another computer""")
    rules.add_argument("action", choices=["list", "show", "approve", "reject", "remove", "stats"]
                       + list(RULEBOOK_ACTIONS), metavar="action")
    rules.add_argument("ids", nargs="*", help="rule or candidate id(s), or a file")
    rules.add_argument("--status", default="pending",
                       choices=["pending", "approved", "rejected", "rejected_auto", "all"])
    rules.add_argument("--origin", choices=["builtin", "imported", "learned", "custom"])
    rules.add_argument("--lang", help="catalog: only rules for this language")
    rules.add_argument("--cwe", help="catalog: only rules for this weakness, e.g. CWE-89")
    rules.add_argument("--search", help="catalog: text in the id, title or expression")
    rules.add_argument("--disabled", action="store_true", help="catalog: only disabled rules")
    rules.add_argument("--set", action="append", metavar="FIELD=VALUE", help="edit: a change")
    rules.add_argument("-o", "--output", help="export: write to this file")
    rules.set_defaults(func=cmd_rules)

    feedback = sub.add_parser("feedback", help="tell the tool whether a finding is real")
    feedback.add_argument("verdict", choices=["fp", "tp", "clear", "list"])
    feedback.add_argument("id", nargs="?", help="finding id printed by scan")
    feedback.set_defaults(func=cmd_feedback)

    coverage = sub.add_parser("coverage", help="rules per language and weakness")
    coverage.set_defaults(func=cmd_coverage)

    mobile = sub.add_parser(
        "flutter", help="look inside an app package or a Flutter/Android project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""Look inside an app package (.apk, .aab, .apks, .xapk, .apkm) or a
Flutter/Android project folder. An app is decoded and read, never installed or run.
  info PATH               package, versions, build mode, signing, permissions, components
  decode PATH --out DIR   write the decoded files and facts.json into an empty folder
  deps PATH               the Dart packages and their known weaknesses
  apis PATH               every server address, API call, API path and key, with the
                          file and line of each place, and the alerts about them
  tools                   which optional tools (jadx, apksigner ...) are installed
The options can come before or after the action and the path.""")
    # One parser per action, so that options may come between the action and the path
    # (flutter info --json app.apk). The options are also accepted before the action
    # (flutter --json info app.apk); an action leaves them as they are unless it is given
    # them itself (default SUPPRESS).
    _add_flutter_options(mobile)
    actions = mobile.add_subparsers(dest="action", metavar="action",
                                    help="info, decode, deps, apis or tools")
    actions.required = True
    for name, text in (("info", "package, versions, build mode, signing, permissions, "
                                "components"),
                       ("decode", "write the decoded files and facts.json into an empty "
                                  "folder (--out DIR)"),
                       ("deps", "the Dart packages and their known weaknesses"),
                       ("apis", "server addresses, API calls, API paths and keys, with their "
                                "places and alerts"),
                       ("tools", "which optional tools (jadx, apksigner ...) are installed")):
        action = actions.add_parser(name, help=text, description=text)
        if name != "tools":
            action.add_argument("path", nargs="?", help="app package or project folder")
        _add_flutter_options(action, argparse.SUPPRESS)
    mobile.set_defaults(func=cmd_flutter, path=None)

    doctor = sub.add_parser("doctor", help="check which components are available")
    doctor.set_defaults(func=cmd_doctor)

    history = sub.add_parser("history", help="list previous scans")
    history.add_argument("--limit", type=int, default=20)
    history.set_defaults(func=cmd_history)

    train = sub.add_parser("train", help="train the ML classifier")
    train.add_argument("--dataset", help="JSON Lines file with code/label (or func/target)")
    train.add_argument("--limit", type=int, default=0, help="use only the first N samples")
    train.add_argument("--out", default=str(ROOT / "data" / "model.joblib"))
    train.add_argument("--show-features", action="store_true")
    train.set_defaults(func=cmd_train)

    ui = sub.add_parser("ui", help="start the web dashboard")
    ui.add_argument("--port", type=int, default=8501)
    ui.add_argument("--no-browser", action="store_true", help="do not open the browser")
    ui.set_defaults(func=cmd_ui)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _safe_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except BrokenPipeError:          # output piped into `head` or a closed pager
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
