"""Rebuild derived runtime inventories from preserved journals; preview unless --apply.

No application or device is contacted. Session IDs, events, capture times, tool
versions and raw JSONL files remain unchanged. Every updated archive and report
is backed up first. Run after the capture batch has stopped writing these files.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import gc
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import zlib

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from sca.dynamic import analyze_events, validate_capture
from sca.dynamic import capture as backend
from sca.storage import MAX_DYNAMIC_SESSION_BYTES, Storage
from tools.audit_dynamic_apps import compare_observations, write_json
from tools.verify_dynamic_audit import verify_locations


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def decode_payload(payload: bytes) -> dict:
    if len(payload) > MAX_DYNAMIC_SESSION_BYTES:
        raise ValueError("Archive exceeds its compressed size limit")
    inflater = zlib.decompressobj()
    raw = inflater.decompress(payload, MAX_DYNAMIC_SESSION_BYTES + 1)
    if (len(raw) > MAX_DYNAMIC_SESSION_BYTES or inflater.unconsumed_tail
            or not inflater.eof or inflater.unused_data):
        raise ValueError("Invalid or oversized archive")
    return json.loads(raw)


def reanalyze_capture(original: dict, decoded_files, *, scan_id: int,
                      journal_sha256: str, analyzed_at: str, analyzer_sha256: str) -> dict:
    # Bad historical derived records must not prevent rebuilding from valid raw events.
    raw_only = deepcopy(original)
    raw_only["observations"] = []
    revised = validate_capture(raw_only)
    warnings = []
    revised["observations"] = analyze_events(revised["events"], decoded_files,
                                             session_id=revised["session_id"], limitations=warnings)
    revised["limitations"] = list(dict.fromkeys([*revised["limitations"], *warnings]))
    callback_errors = []
    for capability in revised["capabilities"]:
        name = capability["name"]
        if not capability["available"] and name.startswith("hook_callback"):
            error = {"stage": "historical_capture_hook", "api": name,
                     "message": capability.get("detail", "Hook callback failed during capture")}
            if error not in revised["errors"]:
                callback_errors.append(error)
    revised["errors"].extend(callback_errors)
    impaired = bool(warnings or revised["errors"] or revised.get("detached_reason"))
    impaired |= revised.get("coverage", {}).get("profile") == "warm_launch_attach"
    impaired |= any(not c["available"] and ("limit" in c["name"] or c["name"] == "native_observer")
                    for c in revised["capabilities"])
    if revised["status"] == "completed" and impaired:
        revised["status"] = "partial"
    # Never upgrade a failed/partial run: later parsing cannot restore missing execution.
    previous = original.get("analysis_revision", {})
    revised["analysis_revision"] = {
        "tool": "tools/reanalyze_dynamic_audit.py", "analyzed_at": analyzed_at,
        "analyzer_sha256": analyzer_sha256, "source_scan_id": scan_id,
        "journal_sha256": journal_sha256, "raw_events_unchanged": True,
        "original_status": previous.get("original_status", original["status"]),
        "original_observation_count": previous.get("original_observation_count", len(original.get("observations", []))),
        "derived_warning_count": len(warnings),
        "invalid_host_events": sum(warning.startswith("Invalid host") for warning in warnings),
        "note": "Only derived observations were rebuilt. Runtime coverage and original collector version were not upgraded.",
    }
    if revised["events"] != original["events"]:
        raise ValueError("Reanalysis changed raw runtime events")
    verified = verify_locations(revised, decoded_files)
    if verified["issues"]:
        raise ValueError("Derived event/source provenance failed verification: " + "; ".join(verified["issues"]))
    return validate_capture(revised)


def artifact(root: Path, filename: str, session_id: str, expected_name: str) -> Path:
    path = Path(filename).resolve(strict=True)
    if not path.is_relative_to(root.resolve()) or path.parent.name != session_id or path.name != expected_name:
        raise ValueError("Session artifact is outside the selected audit or has an unexpected location")
    return path


def backup_bytes(folder: Path, name: str, data: bytes) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (name + "." + sha256(data)[:20] + ".bak")
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(data)
    elif path.read_bytes() != data:
        raise ValueError("Existing backup does not match the expected original bytes")
    return path


def matching_report(path: Path, session_id: str, events: list) -> tuple[bytes, dict] | None:
    if not path.is_file():
        return None
    raw = path.read_bytes()
    report = json.loads(raw)
    if report.get("session_id") != session_id:
        return None
    if report.get("events") != events:
        raise ValueError("Matching session report contains different raw events")
    return raw, report


def migrate_session(store: Storage, root: Path, capture_id: int, *, apply: bool = False) -> dict:
    with sqlite3.connect(store.path) as connection:
        row = connection.execute("SELECT scan_id, payload FROM dynamic_sessions WHERE id = ?", (capture_id,)).fetchone()
    if row is None:
        raise ValueError("Dynamic archive does not exist")
    scan_id, old_payload = row
    original = decode_payload(old_payload)
    session_id = original["session_id"]
    journal = artifact(root, original["artifacts"]["events_file"], session_id, "events.jsonl")
    report_path = artifact(root, original["artifacts"]["report_file"], session_id, "report.json")
    journal_bytes = journal.read_bytes()
    journal_events = [json.loads(line) for line in journal_bytes.decode("utf-8").splitlines()]
    if journal_events != original["events"]:
        raise ValueError("Archive events differ from the original on-disk JSONL journal")
    stored_report = matching_report(report_path, session_id, original["events"])
    if stored_report is None:
        raise ValueError("Per-session report has a different session identifier")
    scan = store.load_scan(scan_id)
    if scan is None:
        raise ValueError("Linked static scan is unavailable")
    if scan.app.get("package") and scan.app["package"] != original["package"]:
        raise ValueError("Runtime package differs from the linked static scan")
    revised = reanalyze_capture(original, scan.decoded_files, scan_id=scan_id,
                               journal_sha256=sha256(journal_bytes),
                               analyzed_at=datetime.now(timezone.utc).isoformat(),
                               analyzer_sha256=sha256(Path(backend.__file__).read_bytes()))
    raw = encode(revised)
    if len(raw) > MAX_DYNAMIC_SESSION_BYTES:
        raise ValueError("Reanalyzed archive exceeds its size limit")
    comparison = compare_observations(revised, {"app": {"apis": scan.visible_apis}})
    app_folder = report_path.parent.parent
    canonical_path = app_folder / "capture.json"
    canonical = matching_report(canonical_path, session_id, original["events"])
    summary_path = app_folder / "summary.json"
    summary_bytes = summary_path.read_bytes() if summary_path.is_file() else None
    summary = json.loads(summary_bytes) if summary_bytes is not None else {}
    canonical_summary = bool(canonical and summary.get("session_id") == session_id)
    result = {"capture_id": capture_id, "scan_id": scan_id, "session_id": session_id,
              "mode": "apply" if apply else "preview", "status_before": original["status"],
              "status_after": revised["status"], "events": len(revised["events"]),
              "observations_before": len(original.get("observations", [])),
              "observations_after": len(revised["observations"]),
              "invalid_host_events": revised["analysis_revision"]["invalid_host_events"],
              "canonical_match": bool(canonical), "journal_sha256": sha256(journal_bytes)}
    if not apply:
        return result
    backups = root / "reanalysis-backups" / f"{capture_id}-{session_id}"
    backup_bytes(backups, "archive.payload.zlib", old_payload)
    backup_bytes(backups, "session.report.json", stored_report[0])
    file_replacements = [(report_path, stored_report[0], revised)]
    comparison_paths = [report_path.parent / "comparison.json"]
    if canonical:
        backup_bytes(backups, "canonical.capture.json", canonical[0])
        file_replacements.append((canonical_path, canonical[0], revised))
        comparison_paths.append(app_folder / "comparison.json")
    if canonical_summary:
        previous_summary = summary_bytes
        backup_bytes(backups, "canonical.summary.json", previous_summary)
        summary.update(status=revised["status"], events=len(revised["events"]),
                       observations=len(revised["observations"]),
                       kinds=dict(Counter(item["kind"] for item in revised["observations"])),
                       comparison_counts=comparison["counts"], errors=revised["errors"],
                       capabilities=revised["capabilities"], limitations=revised["limitations"],
                       analysis_revision=revised["analysis_revision"])
        file_replacements.append((summary_path, previous_summary, summary))
    for path in comparison_paths:
        if path.exists():
            backup_bytes(backups, "comparison-" + path.parent.name + ".json", path.read_bytes())
    # Compare-and-swap protects a capture being concurrently edited by another process.
    with sqlite3.connect(store.path, timeout=15) as connection:
        changed = connection.execute(
            "UPDATE dynamic_sessions SET status = ?, event_count = ?, observation_count = ?, payload = ? "
            "WHERE id = ? AND scan_id = ? AND payload = ?",
            (revised["status"], len(revised["events"]), len(revised["observations"]),
             zlib.compress(raw), capture_id, scan_id, old_payload)).rowcount
        if changed != 1:
            raise ValueError("Archive changed during reanalysis; no update was applied")
    # The database is authoritative; atomic artifact writes may be retried from it.
    for path, expected, value in file_replacements:
        if path.read_bytes() != expected:
            raise ValueError("Archive updated, but an artifact changed concurrently; rerun after capture writers stop")
        write_json(path, value)
    for path in comparison_paths:
        write_json(path, comparison)
    if journal.read_bytes() != journal_bytes:
        raise ValueError("Raw journal changed concurrently; review this session before using it")
    result["backup_directory"] = str(backups.resolve())
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--database", type=Path, default=REPO / "data/sca.db")
    parser.add_argument("--capture-id", type=int, action="append", dest="capture_ids")
    parser.add_argument("--apply", action="store_true", help="update backed-up derived results; default only previews")
    args = parser.parse_args()
    root = args.directory.resolve(strict=True)
    store = Storage(str(args.database))
    with sqlite3.connect(store.path) as connection:
        capture_ids = args.capture_ids or [row[0] for row in connection.execute("SELECT id FROM dynamic_sessions ORDER BY id")]
    results = []
    for capture_id in capture_ids:
        try:
            result = migrate_session(store, root, capture_id, apply=args.apply)
            result["result"] = "updated" if args.apply else "previewed"
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, zlib.error) as exc:
            result = {"capture_id": capture_id, "result": "failed", "error": f"{type(exc).__name__}: {exc}"}
        results.append(result)
        print(json.dumps(result, ensure_ascii=True), flush=True)
        gc.collect()
    if args.apply:
        inventory = json.loads((root / "input_inventory.json").read_text(encoding="utf-8"))
        summaries = []
        for app in inventory["apps"]:
            path = root / app["app"] / "summary.json"
            if path.exists():
                summaries.append(json.loads(path.read_text(encoding="utf-8")))
        aggregate = root / "summary.json"
        if aggregate.exists():
            backup_bytes(root / "reanalysis-backups", "aggregate.summary.json", aggregate.read_bytes())
        write_json(aggregate, summaries)
        write_json(root / "reanalysis.json", {"method": "Derived analysis rebuilt from unchanged original raw journals.", "sessions": results})
    return int(any(item["result"] == "failed" for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
