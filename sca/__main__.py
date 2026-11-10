"""Command line interface.

    python -m sca scan <folder> [--llm] [--deep] [--format html,json,sarif,pdf]
    python -m sca doctor              # show which engines and AI components are available
    python -m sca history             # list previous scans
    python -m sca train --dataset data.jsonl --out data/model.joblib
    python -m sca ui                  # start the web dashboard
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .models import SEVERITIES, SEVERITY_RANK

ROOT = Path(__file__).resolve().parent.parent


def _safe_stdout() -> None:
    # Windows consoles often use a legacy code page; never crash on a character
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def cmd_scan(args: argparse.Namespace) -> int:
    from .pipeline import ScanOptions, run_scan
    from .report import write_reports

    options = ScanOptions(
        use_rules=not args.no_rules, use_ast=not args.no_ast, use_secrets=not args.no_secrets,
        use_bandit=not args.no_bandit, use_semgrep=not args.no_semgrep,
        use_gitleaks=not args.no_gitleaks, semgrep_config=args.semgrep_config,
        exclude_dirs=[d for d in args.exclude.split(",") if d],
        use_ml=not args.no_ml, ml_model_path=args.ml_model,
        use_llm=args.llm or args.deep, llm_host=args.llm_host, llm_model=args.model,
        llm_max_findings=args.llm_max, llm_deep_scan=args.deep, lang=args.lang,
        save=not args.no_save,
    )

    def progress(message: str, fraction: float) -> None:
        if not args.quiet:
            print("[%3d%%] %s" % (round(fraction * 100), message), file=sys.stderr)

    try:
        result = run_scan(args.path, options, progress)
    except FileNotFoundError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2

    counts = result.counts()
    print()
    print("Secure Code Analyzer %s" % __version__)
    print("Target : %s" % result.target)
    print("Scanned: %d files, %d lines in %.1f s" % (result.files_scanned,
                                                     result.lines_scanned,
                                                     result.duration_seconds))
    print("Engines: %s" % ", ".join(result.engines_used))
    for name, note in result.engine_notes.items():
        if not note.startswith("ok"):
            print("  - %s: %s" % (name, note))
    for name, note in result.ai.items():
        print("AI %-4s: %s" % (name, note))
    print()
    print("Score  : %d / 100   Grade %s" % (result.score, result.grade))
    print("Open   : " + "   ".join("%s %d" % (s, counts[s]) for s in SEVERITIES))
    hidden = len(result.findings) - len(result.open_findings)
    if hidden:
        print("         %d more judged likely false positives by the AI review" % hidden)
    print()
    shown = result.open_findings[: args.top]
    for finding in shown:
        print("%-8s %-9s %s:%d" % (finding.severity.upper(), finding.cwe or "-",
                                   finding.file, finding.line))
        print("         %s  (confidence %d%%, %s)" % (
            finding.title, round(finding.confidence * 100), "+".join(finding.engines)))
        if finding.ai_verdict:
            print("         LLM: %s" % finding.ai_verdict.replace("_", " "))
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


def cmd_doctor(args: argparse.Namespace) -> int:
    from .ai.classifier import SKLEARN_AVAILABLE
    from .ai.llm import OllamaClient
    from .engines import external
    from .engines.rules_engine import load_rules

    print("Secure Code Analyzer %s on Python %s" % (__version__, sys.version.split()[0]))
    print()
    print("Static engines")
    print("  [ok] rules      %d rules loaded" % len(load_rules()))
    print("  [ok] ast        Python taint analysis (built in)")
    print("  [ok] secrets    key formats + entropy (built in)")
    tools = external.availability()
    hints = {"bandit": "pip install bandit",
             "semgrep": "optional: install Opengrep (github.com/opengrep/opengrep) or Semgrep",
             "gitleaks": "optional: install from github.com/gitleaks/gitleaks"}
    for name, ok in tools.items():
        print("  [%s] %-10s %s" % ("ok" if ok else "--", name, "available" if ok
                                   else "not found - " + hints[name]))
    print()
    print("AI components")
    print("  [%s] ML classifier (scikit-learn)%s" % (
        "ok" if SKLEARN_AVAILABLE else "--",
        "" if SKLEARN_AVAILABLE else " - pip install scikit-learn"))
    client = OllamaClient(args.llm_host)
    if client.available():
        models = client.models()
        print("  [ok] Ollama at %s" % args.llm_host)
        print("       models: %s" % (", ".join(models) or "none - run: ollama pull qwen2.5-coder:7b"))
    else:
        print("  [--] Ollama not reachable at %s" % args.llm_host)
        print("       install from https://ollama.com then run: ollama pull qwen2.5-coder:7b")
    try:
        import fpdf  # noqa: F401
        print("  [ok] PDF export (fpdf2)")
    except ImportError:
        print("  [--] PDF export - pip install fpdf2")
    return 0


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca", description="Secure Code Analyzer: local static + AI vulnerability scanner")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a project folder")
    scan.add_argument("path", help="project folder (or a single file)")
    scan.add_argument("--out", default="reports", help="report folder (default: reports)")
    scan.add_argument("--format", default="html,json",
                      help="comma list of: html, json, sarif, pdf (default: html,json)")
    scan.add_argument("--lang", choices=["en", "ar"], default="en",
                      help="language of explanations")
    scan.add_argument("--exclude", default="", help="comma list of folder names to skip")
    scan.add_argument("--top", type=int, default=25, help="findings to print (default 25)")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                      help="exit with code 1 if a finding of this severity or higher exists")
    scan.add_argument("--quiet", action="store_true", help="no progress messages")
    scan.add_argument("--no-save", action="store_true", help="do not store in history")
    for name in ("rules", "ast", "secrets", "bandit", "semgrep", "gitleaks", "ml"):
        scan.add_argument("--no-%s" % name, action="store_true", help="disable the %s engine" % name)
    scan.add_argument("--semgrep-config", default="auto", help="Semgrep/Opengrep rule config")
    scan.add_argument("--ml-model", help="path to a model trained with 'sca train'")
    scan.add_argument("--llm", action="store_true", help="review findings with a local LLM")
    scan.add_argument("--deep", action="store_true",
                      help="also let the LLM audit whole files (slower; implies --llm)")
    scan.add_argument("--model", default="qwen2.5-coder:7b", help="Ollama model name")
    scan.add_argument("--llm-host", default="http://localhost:11434")
    scan.add_argument("--llm-max", type=int, default=30, help="max findings the LLM reviews")
    scan.set_defaults(func=cmd_scan)

    doctor = sub.add_parser("doctor", help="check which components are available")
    doctor.add_argument("--llm-host", default="http://localhost:11434")
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
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
