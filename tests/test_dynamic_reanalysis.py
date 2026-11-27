"""Historical repair changes derived records only; tests never contact a device."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from sca.decoded import DecodedFile
from sca.dynamic import analyze_events
from sca.models import ScanResult
from sca.storage import Storage
from tools.reanalyze_dynamic_audit import migrate_session, reanalyze_capture


def capture(session_id="older", bad_host=False):
    event = {"id": 1, "session_id": session_id, "type": "observation", "kind": "host",
             "value": "api.example.test", "api": "fixture.getaddrinfo", "details": {}, "stack": [],
             "timestamp": "2026-11-27T00:00:00Z", "pid": 123, "tid": 123}
    report = {"schema_version": 1, "session_id": session_id, "package": "fixture.runtime.app",
              "serial": "fixture-device", "started_at": event["timestamp"], "ended_at": event["timestamp"],
              "status": "completed", "events": [event], "observations": analyze_events([event], session_id=session_id),
              "capabilities": [], "errors": [], "limitations": ["Existing capture limitation"],
              "tool_versions": {"agent_sha256": "original-collector-hash"}}
    if bad_host:
        # Model the historical collector bug without putting fabricated data in the application.
        report["events"][0]["value"] += "\x00unrelated-memory"
        report["observations"][0]["value"] = report["events"][0]["value"]
    return report


def revise(report, files=None):
    return reanalyze_capture(report, files or {}, scan_id=7, journal_sha256="raw-journal-hash",
                             analyzed_at="2026-11-27T01:00:00Z", analyzer_sha256="new-analyzer-hash")


def test_invalid_host_is_removed_only_from_derived_inventory_with_truthful_partial_status():
    original = capture(bad_host=True)
    snapshot = deepcopy(original)
    revised = revise(original)
    assert revised["observations"] == []
    assert revised["status"] == "partial"
    assert revised["events"] == snapshot["events"]
    assert original == snapshot
    assert revised["tool_versions"] == snapshot["tool_versions"]
    assert revised["started_at"] == snapshot["started_at"]
    assert revised["analysis_revision"]["invalid_host_events"] == 1
    assert revised["limitations"][0] == "Existing capture limitation"


def test_legacy_callback_error_and_failed_status_are_not_upgraded():
    report = capture()
    report["capabilities"] = [{"name": "hook_callback", "available": False, "detail": "TypeError from old hook"}]
    revised = revise(report)
    assert revised["status"] == "partial"
    assert revised["errors"][0]["stage"] == "historical_capture_hook"
    revised_again = revise(revised)
    assert len(revised_again["errors"]) == 1
    report["status"] = "failed"
    assert revise(report)["status"] == "failed"


def test_exact_source_coordinates_are_rebuilt_from_linked_archive():
    files = {"Network.java": DecodedFile("java", "decompiled", 1, ('String host = "api.example.test";',))}
    revised = revise(capture(), files)
    location = revised["observations"][0]["locations"][0]
    line = files["Network.java"].lines[0]
    assert line[location["column"] - 1:location["end_column"] - 1] == "api.example.test"
    assert location["verified"] is True
    assert revised["status"] == "completed"


def save_capture(store, scan_id, root, report):
    folder = root / "01_fixture" / report["session_id"]
    folder.mkdir(parents=True)
    report["artifacts"] = {"events_file": str(folder / "events.jsonl"), "report_file": str(folder / "report.json")}
    (folder / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in report["events"]), encoding="utf-8")
    (folder / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return store.save_dynamic_session(scan_id, report)


def test_preview_is_read_only_and_apply_preserves_raw_journal_latest_capture_and_archive_ids(tmp_path):
    root = tmp_path / "audit"
    store = Storage(str(tmp_path / "scan.db"))
    scan_id = store.save_scan(ScanResult("fixture.apk", app={"package": "fixture.runtime.app"}))
    older = capture("older", bad_host=True)
    old_id = save_capture(store, scan_id, root, older)
    newer = capture("newer")
    new_id = save_capture(store, scan_id, root, newer)
    canonical = root / "01_fixture/capture.json"
    canonical.write_text(json.dumps(newer), encoding="utf-8")
    (root / "01_fixture/summary.json").write_text(json.dumps({"session_id": "newer", "capture_id": new_id}), encoding="utf-8")
    journal = Path(older["artifacts"]["events_file"])
    before = {"journal": journal.read_bytes(), "canonical": canonical.read_bytes(),
              "archive": store.load_dynamic_session(old_id), "report": Path(older["artifacts"]["report_file"]).read_bytes()}
    preview = migrate_session(store, root, old_id)
    assert preview["status_after"] == "partial"
    assert store.load_dynamic_session(old_id) == before["archive"]
    assert Path(older["artifacts"]["report_file"]).read_bytes() == before["report"]
    assert not (root / "reanalysis-backups").exists()
    result = migrate_session(store, root, old_id, apply=True)
    assert result["canonical_match"] is False
    assert journal.read_bytes() == before["journal"]
    assert canonical.read_bytes() == before["canonical"]
    repaired = store.load_dynamic_session(old_id)
    assert repaired["status"] == "partial"
    assert repaired["events"] == older["events"]
    assert repaired["observations"] == []
    assert store.load_dynamic_session(new_id)["status"] == "completed"
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dynamic_sessions").fetchone()[0] == 2
    assert list(Path(result["backup_directory"]).glob("archive.payload.zlib.*.bak"))


def test_journal_archive_disagreement_aborts_before_any_write(tmp_path):
    store = Storage(str(tmp_path / "scan.db"))
    scan_id = store.save_scan(ScanResult("fixture.apk"))
    root = tmp_path / "audit"
    report = capture()
    capture_id = save_capture(store, scan_id, root, report)
    Path(report["artifacts"]["events_file"]).write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="differ from"):
        migrate_session(store, root, capture_id, apply=True)
    assert store.load_dynamic_session(capture_id)["observations"] == report["observations"]
    assert not (root / "reanalysis-backups").exists()


def test_matching_canonical_summary_comparison_and_report_are_updated_together(tmp_path):
    store = Storage(str(tmp_path / "scan.db"))
    scan_id = store.save_scan(ScanResult("fixture.apk"))
    root = tmp_path / "audit"
    report = capture(bad_host=True)
    capture_id = save_capture(store, scan_id, root, report)
    folder = root / "01_fixture"
    (folder / "capture.json").write_text(json.dumps(report), encoding="utf-8")
    (folder / "summary.json").write_text(json.dumps({"session_id": "older", "capture_id": capture_id,
                                                    "status": "completed", "observations": 1}), encoding="utf-8")
    result = migrate_session(store, root, capture_id, apply=True)
    assert result["canonical_match"] is True
    canonical = json.loads((folder / "capture.json").read_text(encoding="utf-8"))
    per_session = json.loads(Path(report["artifacts"]["report_file"]).read_text(encoding="utf-8"))
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
    assert canonical == per_session
    assert canonical["events"] == report["events"]
    assert summary["status"] == "partial"
    assert summary["observations"] == 0
    assert summary["capture_id"] == capture_id
    assert json.loads((folder / "comparison.json").read_text(encoding="utf-8"))["observations"] == []
