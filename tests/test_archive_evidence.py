"""Saved scans reopen their original local evidence without changing analysis identity."""
import json
import sqlite3
import zlib

import pytest

from sca import storage as storage_module
from sca.decoded import build_previews
from sca.models import Finding, ScanResult
from sca.presentation import finding_text, view_result
from sca.storage import Storage
from sca.walker import SourceFile, mask_secret


@pytest.fixture
def scanned(tmp_path):
    value = "local-archive-value-" + "aB0123456789" * 30
    path = tmp_path / "settings.py"
    text = f'# إعدادات محلية\nAPI_SECRET = "{value}"\n'
    path.write_text(text, encoding="utf-8")
    source = SourceFile(path, path.name, "python", text, secret_values=[value])
    finding = Finding("SECRET-HARDCODED-001", "Hard-coded secret", path.name, 2,
                      cwe="CWE-798", snippet=source.line_text(2),
                      context=source.context(2), engines=["secrets"])
    result = ScanResult(str(path), started_at="2026-11-26 12:00:00", findings=[finding],
                        files_scanned=1, lines_scanned=2, score=79, grade="C")
    result.decoded_files = build_previews([source], source_root=tmp_path)
    result.visible_apis = {
        "values_visible": True, "summary": {"keys": 1},
        "keys": [{"value": value, "rule_id": finding.rule_id,
                  "locations": [{"file": path.name, "line": 2}]}],
        "endpoints": [{"url": "https://archive-unit.example/status?token=" + value,
                       "locations": [{"file": path.name, "line": 2}]}],
    }
    return result, path, value


def test_archive_roundtrip_preserves_values_locations_and_feedback_identity(scanned, tmp_path):
    result, path, value = scanned
    store = Storage(str(tmp_path / "history.sqlite"))
    fingerprint = result.findings[0].fingerprint
    store.set_feedback(result.findings[0], "tp")
    scan_id = store.save_scan(result)
    path.write_text("print('changed after scanning')", encoding="utf-8")

    restored = Storage(store.path).load_scan(scan_id)

    assert restored.scan_id == scan_id
    assert restored.decoded_files[path.name].lines == result.decoded_files[path.name].lines
    assert restored.decoded_files[path.name].original is None
    assert restored.credential_evidence is None
    assert restored.visible_apis == result.visible_apis
    assert value in finding_text(restored, restored.findings[0])
    assert "changed after scanning" not in finding_text(restored, restored.findings[0])
    assert restored.findings[0].fingerprint == fingerprint
    assert restored.findings[0].snippet == result.findings[0].snippet
    assert mask_secret(value) in restored.findings[0].snippet
    assert store.feedback_map() == {fingerprint: "tp"}
    assert view_result(restored).findings[0].fingerprint == fingerprint
    assert value in json.dumps(view_result(restored).to_dict())
    assert store.count_scans() == 1 and store.list_scans()[0]["score"] == 79


def test_archive_payload_is_separate_explicit_compressed_json(scanned, tmp_path):
    result, path, value = scanned
    store = Storage(str(tmp_path / "history.sqlite"))
    scan_id = store.save_scan(result)
    with sqlite3.connect(store.path) as conn:
        result_json, = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        payload, = conn.execute("SELECT payload FROM scan_evidence WHERE scan_id = ?", (scan_id,)).fetchone()
    assert value not in result_json
    assert isinstance(payload, bytes)
    data = json.loads(zlib.decompress(payload))
    assert data["version"] == 1
    assert set(data) == {"version", "decoded_files", "visible_apis"}
    assert set(data["decoded_files"][path.name]) == {"language", "origin", "source_line_count", "lines"}
    assert value in data["decoded_files"][path.name]["lines"][1]
    assert "original" not in data["decoded_files"][path.name]
    assert str(path) not in json.dumps(data)


def test_existing_database_without_evidence_table_remains_readable(tmp_path):
    database = tmp_path / "legacy.sqlite"
    old = ScanResult("old/base.apk", findings=[Finding("R1", "Old result", "AndroidManifest.xml", 7,
                                                      snippet='value="[redacted]"')])
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, started_at TEXT, "
                     "duration_seconds REAL, files_scanned INTEGER, lines_scanned INTEGER, score INTEGER, "
                     "grade TEXT, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, "
                     "info INTEGER, result_json TEXT)")
        conn.execute("INSERT INTO scans (id, target, started_at, result_json) VALUES (1, ?, ?, ?)",
                     (old.target, old.started_at, json.dumps(old.to_dict())))
    store = Storage(str(database))
    restored = store.load_scan(1)
    assert restored.findings[0].snippet == old.findings[0].snippet
    assert not restored.decoded_files and not restored.visible_apis
    assert "archived evidence" not in restored.engine_notes
    assert store.count_scans() == 1
    assert store.load_scan(999) is None


@pytest.mark.parametrize("payload", [
    b"not compressed evidence",
    zlib.compress(b'{"version":1,"decoded_files":{},"visible_apis":{}}')[:-2],
    zlib.compress(b'{"version":1,"decoded_files":{},"visible_apis":{}}') + b"trailing bytes",
    zlib.compress(b'{"version":2,"decoded_files":{},"visible_apis":{}}'),
    zlib.compress(b'{"version":1,"decoded_files":{"file":[]},"visible_apis":{}}'),
    zlib.compress(b'{"version":1,"decoded_files":{},"visible_apis":{"keys":"broken"}}'),
    zlib.compress(b"[" * 2000 + b"0" + b"]" * 2000),
])
def test_corrupt_evidence_falls_back_to_saved_analysis(scanned, tmp_path, payload):
    result, _, _ = scanned
    store = Storage(str(tmp_path / "history.sqlite"))
    scan_id = store.save_scan(result)
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE scan_evidence SET payload = ? WHERE scan_id = ?", (payload, scan_id))
    restored = store.load_scan(scan_id)
    assert restored.findings[0].fingerprint == result.findings[0].fingerprint
    assert not restored.decoded_files and not restored.visible_apis
    assert restored.engine_notes["archived evidence"].startswith("unavailable:")


def test_archive_encode_limit_keeps_scan_and_records_missing_evidence(scanned, tmp_path, monkeypatch):
    result, _, _ = scanned
    monkeypatch.setattr(storage_module, "MAX_ARCHIVE_EVIDENCE_BYTES", 256)
    store = Storage(str(tmp_path / "history.sqlite"))
    scan_id = store.save_scan(result)
    restored = store.load_scan(scan_id)
    assert not restored.decoded_files and not restored.visible_apis
    assert "size limit" in restored.engine_notes["archived evidence"]
    assert restored.findings[0].fingerprint == result.findings[0].fingerprint


@pytest.mark.parametrize("compressed", [True, False])
def test_archive_decode_limits_compressed_and_expanded_bytes(scanned, tmp_path, monkeypatch, compressed):
    result, _, _ = scanned
    store = Storage(str(tmp_path / "history.sqlite"))
    scan_id = store.save_scan(result)
    payload = zlib.compress(b"x" * 4096) if compressed else b"x" * 4096
    with sqlite3.connect(store.path) as conn:
        conn.execute("UPDATE scan_evidence SET payload = ? WHERE scan_id = ?", (payload, scan_id))
    monkeypatch.setattr(storage_module, "MAX_ARCHIVE_EVIDENCE_BYTES", 256)
    restored = store.load_scan(scan_id)
    assert not restored.decoded_files and not restored.visible_apis
    assert "size limit" in restored.engine_notes["archived evidence"]


def test_deleting_scan_deletes_only_its_evidence(scanned, tmp_path):
    result, _, _ = scanned
    store = Storage(str(tmp_path / "history.sqlite"))
    first, second = store.save_scan(result), store.save_scan(result)
    store.delete_scan(first)
    assert store.load_scan(first) is None
    assert store.load_scan(second).visible_apis == result.visible_apis
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT scan_id FROM scan_evidence").fetchall() == [(second,)]
