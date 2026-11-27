"""Run reproducible real-APK scans through the same pipeline as the dashboard.

Detailed artifacts contain original evidence and stay under the local data directory.
Console output contains only counts, timings and tool coverage notes.
"""
from __future__ import annotations

import argparse
from collections import Counter
import faulthandler
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detector_identity(code_root):
    """A resume must not silently reuse results from older detectors or local overrides."""
    paths = [p for p in (code_root / "sca").rglob("*")
             if p.is_file() and p.suffix in {".py", ".yaml"}
             and "node_modules" not in p.parts and "__pycache__" not in p.parts]
    from sca.engines.rules_engine import learned_dir
    local = learned_dir()
    entries = [(p.relative_to(code_root).as_posix(), file_sha256(p)) for p in sorted(paths)]
    entries += [("local/" + p.name, file_sha256(p)) for p in sorted(local.glob("*.yaml"))]
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def input_identity(app, detector_hash, use_tools):
    return {"schema": 1, "detectors_sha256": detector_hash,
            "apk_tools": bool(use_tools), "ml": False, "llm": False, "feedback": False,
            "input_apks": [{"name": p.name, "bytes": p.stat().st_size,
                            "sha256": file_sha256(p)} for p in sorted(app.glob("*.apk"))]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--code-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--database", type=Path)
    parser.add_argument("--tools", action="store_true")
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.code_root.resolve()))
    from sca.pipeline import ScanOptions, scan_project
    from sca.presentation import view_result
    from sca.storage import Storage

    args.output.mkdir(parents=True, exist_ok=True)
    store = Storage(str(args.database)) if args.database else None
    options = ScanOptions(use_ml=False, use_llm=False, use_feedback=False,
                          apk_tools=args.tools, keep_decoded=True, save=store is not None)
    apps = [path for path in sorted(args.inputs.iterdir()) if path.is_dir()
            and any(path.glob("*.apk")) and (not args.only or path.name in args.only)]
    summary = []
    detector_hash = detector_identity(args.code_root.resolve())
    for app in apps:
        identity = input_identity(app, detector_hash, args.tools)
        record_path = args.output / (app.name + ".summary.json")
        if args.resume and record_path.exists():
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if record.get("status") == "ok" and record.get("identity") == identity:
                summary.append(record)
                continue
        print(json.dumps({"app": app.name, "event": "started", "external_tools": args.tools}), flush=True)
        start = time.monotonic()
        last_progress = [0.0]
        def progress(message, fraction):
            now = time.monotonic()
            if getattr(message, "kind", "") == "step" or now - last_progress[0] >= 30:
                print(json.dumps({"app": app.name, "event": "progress", "fraction": round(fraction, 3),
                                  "stage": str(message), "elapsed_seconds": round(now - start, 1)}), flush=True)
                last_progress[0] = now
        try:
            with open(args.output / (app.name + ".diagnostics.log"), "w", encoding="utf-8") as diagnostics:
                faulthandler.dump_traceback_later(120, repeat=True, file=diagnostics)
                try:
                    result, files = scan_project(str(app), options, progress=progress, storage=store)
                finally:
                    faulthandler.cancel_dump_traceback_later()
            write_json(args.output / (app.name + ".report.json"), view_result(result).to_dict())
            hits = [{"file": sf.rel, "line": line, "rule": rule, "value": value,
                     "origin": sf.origin, "title": title, "severity": severity}
                    for sf in files for line, rule, value, title, severity in sf.secret_hits]
            write_json(args.output / (app.name + ".hits.json"), hits)
            with gzip.open(args.output / (app.name + ".sources.json.gz"), "wt", encoding="utf-8") as out:
                json.dump({sf.rel: {"origin": sf.origin, "language": sf.language,
                                   "lines": sf.lines, "derivation": sf.derivation}
                           for sf in files}, out, ensure_ascii=False)
            apis = result.visible_apis or result.app.get("apis", {})
            record = {
                "app": app.name, "status": "ok", "scan_id": result.scan_id,
                "target": str(app), "input_apks": len(list(app.glob("*.apk"))),
                "package": result.app.get("package"), "framework": result.app.get("framework"),
                "build_mode": result.app.get("build_mode"), "files": len(files),
                "origins": dict(Counter(sf.origin or "source" for sf in files)),
                "findings": len(result.findings), "open_findings": len(result.open_findings),
                "keys": len(apis.get("keys", [])), "distinct_secret_hits": len({h["value"] for h in hits}),
                "endpoints": len(apis.get("endpoints", [])), "paths": len(apis.get("paths", [])),
                "calls": len(apis.get("calls", [])), "inventory_limits": apis.get("truncated", {}),
                "engine_notes": result.engine_notes, "warnings": result.app.get("warnings", []),
                "duration_seconds": round(time.monotonic() - start, 2),
                "settings": {"ml": False, "llm": False, "feedback": False, "apk_tools": args.tools},
            }
        except Exception as exc:
            record = {"app": app.name, "status": "error", "error": str(exc),
                      "duration_seconds": round(time.monotonic() - start, 2)}
        record["identity"] = identity
        write_json(record_path, record)
        summary.append(record)
        print(json.dumps({key: record[key] for key in ("app", "status", "files", "findings", "keys",
                                                       "endpoints", "duration_seconds") if key in record}), flush=True)
        write_json(args.output / "summary.json", summary)
    write_json(args.output / "summary.json", summary)
    return int(any(item["status"] != "ok" for item in summary))


if __name__ == "__main__":
    raise SystemExit(main())
