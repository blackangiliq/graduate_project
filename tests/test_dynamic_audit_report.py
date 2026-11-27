"""Reports show captured values and failures without trusting application strings as HTML."""
import json

from tools.render_dynamic_audit import render_report


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_full_values_and_runtime_evidence_are_escaped_without_truncation(tmp_path):
    value = "FixtureOnly_" + "a" * 300 + "<script>alert(1)</script>"
    put(tmp_path / "input_inventory.json", {"apps": [{"app": "test", "package": "test.app"}]})
    put(tmp_path / "test/summary.json", {"session_id": "run-1", "status": "partial"})
    put(tmp_path / "test/capture.json", {"session_id": "run-1", "events": [{"value": value}],
                                        "observations": [{"id": "key", "kind": "credential", "value": value,
                                                          "evidence": {"file": "_runtime/run-1/events.jsonl", "line": 1}}]})
    report = render_report(tmp_path)
    assert "FixtureOnly_" + "a" * 300 in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
    assert "<script>alert(1)</script>" not in report
    assert "_runtime/run-1/events.jsonl:1" in report
    assert "partial" in report


def test_failed_retry_does_not_relabel_old_values_as_new_runtime_evidence(tmp_path):
    put(tmp_path / "input_inventory.json", {"apps": [{"app": "test", "package": "test.app"}]})
    put(tmp_path / "test/summary.json", {"status": "install_failed", "install": {"errors": ["ABI mismatch"]}})
    put(tmp_path / "test/capture.json", {"session_id": "old-run", "events": [],
                                        "observations": [{"id": "old", "value": "OLD_CAPTURE_SENTINEL"}]})
    report = render_report(tmp_path)
    assert "install_failed" in report
    assert "ABI mismatch" in report
    assert "OLD_CAPTURE_SENTINEL" not in report
    assert "/capture.json" not in report


def test_inventory_without_device_run_is_not_presented_as_successful(tmp_path):
    put(tmp_path / "input_inventory.json", {"apps": [{"app": "test", "package": "test.app"}]})
    report = render_report(tmp_path)
    assert "not_captured" in report
    assert "0 حدث" in report
