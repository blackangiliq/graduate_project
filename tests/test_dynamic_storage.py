"""Runtime archives keep complete evidence separate from static/AI analysis JSON."""
import json
import sqlite3
import zlib

import pytest

from sca import storage as module
from sca.dynamic import analyze_events
from sca.models import ScanResult
from sca.storage import Storage


def capture():
    event = {"id": 1, "session_id": "unit_session", "type": "observation", "kind": "url",
             "value": "https://runtime-test.example/api?api_key=unit-full-value-1234567890",
             "api": "unit-api", "details": {}, "stack": [], "pid": 123, "tid": 124,
             "timestamp": "2026-11-27T00:00:00+00:00"}
    return {"schema_version": 1, "session_id": "unit_session", "package": "test.runtime.app",
            "serial": "unit-device", "started_at": event["timestamp"], "ended_at": event["timestamp"],
            "status": "completed", "events": [event], "observations": analyze_events([event], session_id="unit_session"),
            "errors": [], "capabilities": [], "limitations": []}


def test_archive_roundtrip_full_values_and_scope(tmp_path):
    store = Storage(str(tmp_path / "scans.db"))
    scan_id = store.save_scan(ScanResult("unit.apk"))
    payload = capture()
    session_id = store.save_dynamic_session(scan_id, payload)
    rows = store.list_dynamic_sessions(scan_id)
    assert rows[0]["capture_id"] == session_id
    assert "events" not in rows[0] and "payload" not in rows[0]
    restored = store.load_dynamic_session(session_id, scan_id=scan_id)
    assert restored["events"] == payload["events"]
    assert restored["observations"] == payload["observations"]
    assert store.load_dynamic_session(session_id, scan_id=scan_id + 1) is None
    with sqlite3.connect(store.path) as db:
        static_json = db.execute("SELECT result_json FROM scans").fetchone()[0]
    assert "unit-full-value" not in static_json
    store.delete_scan(scan_id)
    assert store.list_dynamic_sessions(scan_id) == []
    assert store.load_dynamic_session(session_id) is None


def test_runtime_orphan_invalid_and_oversize_rejected(tmp_path, monkeypatch):
    store = Storage(str(tmp_path / "scans.db"))
    with pytest.raises(ValueError, match="does not exist"):
        store.save_dynamic_session(999, capture())
    scan_id = store.save_scan(ScanResult("unit.apk"))
    malformed = capture()
    malformed["observations"][0]["evidence"]["line"] = 2
    with pytest.raises(ValueError):
        store.save_dynamic_session(scan_id, malformed)
    monkeypatch.setattr(module, "MAX_DYNAMIC_SESSION_BYTES", 20)
    with pytest.raises(ValueError, match="size limit"):
        store.save_dynamic_session(scan_id, capture())


@pytest.mark.parametrize("suffix", [b"trailing-data", b""])
def test_runtime_archive_decompression_bounded(tmp_path, monkeypatch, suffix):
    store = Storage(str(tmp_path / "scans.db"))
    scan_id = store.save_scan(ScanResult("unit.apk"))
    session_id = store.save_dynamic_session(scan_id, capture())
    payload = zlib.compress(json.dumps(capture()).encode()) + suffix
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE dynamic_sessions SET payload = ? WHERE id = ?", (payload, session_id))
    if not suffix:
        monkeypatch.setattr(module, "MAX_DYNAMIC_SESSION_BYTES", len(payload) + 1)
    with pytest.raises(ValueError, match="Invalid or oversized"):
        store.load_dynamic_session(session_id)
