"""Evidence integrity tests. Fixtures are used only here, never as capture fallbacks."""
import json
import sys
import threading
import types

import pytest

from sca.decoded import DecodedFile
from sca.dynamic import CaptureOptions, analyze_events, evidence_lines, run_capture, validate_capture
from sca.dynamic import capture as backend


def event(kind="url", value="https://api.example.test/v1", **kwargs):
    return {"type": "observation", "id": 1, "kind": kind, "value": value,
            "api": "fixture.test", "details": {}, "stack": [], "timestamp": "2026-01-01T00:00:00Z",
            "pid": 100, "tid": 101, **kwargs}


def test_generated_header_keeps_complete_value_and_actual_event_location():
    value = "Bearer FixtureOnly_" + "a9B2c8D3" * 40
    rows = analyze_events([event("header", value, details={"name": "Authorization"})], session_id="test")
    row = next(item for item in rows if item["value"] == value)
    assert row["confidence"] == "candidate"
    assert row["vulnerability_confirmed"] is False
    assert row["locations"] == []
    assert row["evidence"] == {"file": "_runtime/test/events.jsonl", "line": 1}
    assert "[redacted]" not in row["value"]


def test_overlapping_url_host_and_query_token_all_have_exact_columns():
    token = "FixtureOnlyTokenA1B2C3"
    url = "https://api.example.test/v1?api_key=" + token
    text = 'String endpoint = "' + url + '";'
    files = {"Main.java": DecodedFile("java", "decompiled", 1, (text,))}
    rows = analyze_events([event(value=url), event("host", "api.example.test", id=2)], files)
    for value in [url, "api.example.test", token]:
        item = next(item for item in rows if item["value"] == value)
        site = item["locations"][0]
        assert site["column"] == text.index(value) + 1
        assert site["end_column"] == site["column"] + len(value)
        assert site["verified"] is True


def test_runtime_stack_line_is_not_reused_as_jadx_line():
    files = {"jadx/com/example/Main.java": DecodedFile("java", "decompiled", 3,
              ("class Main {", "  public void fetch() {", "  }"))}
    rows = analyze_events([event(stack=[{"class_name": "com.example.Main", "method": "fetch", "line": 718}])], files)
    assert rows[0]["locations"][0]["line"] == 2
    assert rows[0]["locations"][0]["relation"] == "class_method"
    assert rows[0]["locations"][0]["verified"] is False
    assert rows[0]["stack"][0]["line"] == 718


def test_provider_key_classification_reuses_secret_engine_without_false_vulnerability():
    key = "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"
    rows = analyze_events([event("decoded_text", json.dumps({"api_key": key}))])
    item = next(item for item in rows if item["value"] == key)
    assert item["details"]["rule_id"] == "SECRET-GOOGLE-001"
    assert item["label"] == "Google API key"
    assert item["vulnerability_confirmed"] is False


def test_crypto_key_and_duplicate_header_event_provenance():
    events = [event("crypto_key", "0a0b0c0d", details={"encoding": "hex", "stage": "generated"}),
              event("header", "FixtureToken123", id=2), event("header", "FixtureToken123", id=3)]
    rows = analyze_events(events, session_id="keys")
    assert rows[0]["details"]["stage"] == "generated"
    header = next(item for item in rows if item["kind"] == "credential")
    assert header["event_ids"] == [2, 3]
    assert [site["line"] for site in header["evidence_locations"]] == [2, 3]


def test_http1_url_derivation_and_body_credentials_are_labeled():
    payload = 'POST /token HTTP/1.1\r\nHost: api.example.test\r\nAuthorization: Bearer FixtureOnly1\r\n\r\n{"access_token":"FixtureOnly2"}'
    rows = analyze_events([event("transport_text", payload)])
    url = next(item for item in rows if item["kind"] == "url")
    assert url["value"] == "https://api.example.test/token"
    assert "Host header" in url["details"]["derivation"]
    assert {"Bearer FixtureOnly1", "FixtureOnly2"} <= {item["value"] for item in rows}


def test_oversized_value_is_rejected_with_explicit_limitation():
    limitations = []
    assert analyze_events([event("header", "A" * (backend.MAX_VALUE_CHARS + 1))], limitations=limitations) == []
    assert "budget" in limitations[0]


@pytest.mark.parametrize("host", ["api.example.test\x00UnrelatedMemory", "api.example.test\ufffdgarbage",
    "api.example.test " + "x" * 500, "https://api.example.test/v1", "bad host", "-bad.example"])
def test_invalid_native_host_memory_never_becomes_valid_inventory(host):
    limitations = []
    assert analyze_events([event("host", host)], limitations=limitations) == []
    assert limitations[0].startswith("Invalid host value")


@pytest.mark.parametrize("host", ["api.example.test", "api.example.test.", "localhost", "192.0.2.1", "2001:db8::1"])
def test_real_hostname_or_ip_remains_complete(host):
    assert analyze_events([event("host", host)])[0]["value"] == host


@pytest.mark.parametrize("kwargs", [{"package": "com.example;rm"}, {"serial": ""},
    {"duration_seconds": 301}, {"frida_host": "192.0.2.10:27042"}, {"max_events": 10001}])
def test_explicit_capture_bounds(kwargs):
    args = {"package": "com.example.app", "serial": "emulator-5590", **kwargs}
    with pytest.raises(ValueError):
        CaptureOptions(**args)


def fake_frida(monkeypatch, *, failure=False, crash=False, events=None, capabilities=None):
    monkeypatch.setattr(backend, "_verify_forward", lambda options: None)
    monkeypatch.setattr(backend, "_frida_call", lambda frida, function, timeout=20: function())
    # Import the submodule explicitly: package exports a same-named probe function.
    import importlib
    env = importlib.import_module("sca.dynamic.environment")
    monkeypatch.setattr(env, "launch_target", lambda *args: {"success": False, "errors": ["fixture failed"]}, raising=False)
    state = {"killed": [], "resumed": [], "detached": False}
    class Script:
        def on(self, name, callback):
            self.callback = callback
        def load(self):
            self.callback({"type": "send", "payload": {"type": "capability", "name": "java_bridge", "available": True}}, None)
            for item in capabilities or []:
                self.callback({"type": "send", "payload": {"type": "capability", **item}}, None)
            for item in events or [event()]:
                self.callback({"type": "send", "payload": item}, None)
        def unload(self):
            pass
    class Session:
        def on(self, name, callback):
            state["detach_callback"] = callback
        def create_script(self, *args, **kwargs):
            state["script_source"] = args[0]
            return Script()
        def detach(self):
            state["detached"] = True
            state["detach_callback"]("application-requested", None)
    class Device:
        def spawn(self, argv):
            if failure:
                raise RuntimeError("fixture unavailable process")
            return 42
        def attach(self, pid):
            return Session()
        def enumerate_applications(self, **kwargs):
            state["identifiers"] = kwargs.get("identifiers")
            return [types.SimpleNamespace(identifier="com.example.app", pid=42),
                    types.SimpleNamespace(identifier="com.other.app", pid=43)]
        def resume(self, pid):
            state["resumed"].append(pid)
            if crash:
                state["detach_callback"]("process-terminated", "fixture app crash")
        def kill(self, pid):
            state["killed"].append(pid)
    module = types.SimpleNamespace(__version__="test", get_device_manager=lambda: types.SimpleNamespace(add_remote_device=lambda _: Device()))
    monkeypatch.setitem(sys.modules, "frida", module)
    return state


def test_capture_journal_roundtrip_and_cleanup(monkeypatch, tmp_path):
    state = fake_frida(monkeypatch)
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    assert report["status"] == "completed"
    assert report["detached_reason"] is None
    assert state["resumed"] == state["killed"] == [42]
    assert state["detached"]
    assert tuple(open(report["artifacts"]["events_file"], encoding="utf-8").read().splitlines()) == evidence_lines(report)
    assert validate_capture(report)["observations"][0]["value"] == "https://api.example.test/v1"


def test_failed_capture_has_no_fabricated_data(monkeypatch, tmp_path):
    fake_frida(monkeypatch, failure=True)
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    assert report["status"] == "failed"
    assert report["events"] == report["observations"] == []
    assert "unavailable process" in report["errors"][0]["message"]
    validate_capture(report)


def test_early_crash_retains_observed_evidence_and_marks_partial(monkeypatch, tmp_path):
    fake_frida(monkeypatch, crash=True)
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    assert report["status"] == "partial"
    assert report["events"]
    assert report["detached_reason"] == "process-terminated"
    assert report["coverage"]["observed_seconds"] < 1
    validate_capture(report)


def test_event_budget_never_truncates_retained_values(monkeypatch, tmp_path):
    value = "FixtureFullValue" * 100
    fake_frida(monkeypatch, events=[event("header", value), event("header", "AnotherFixture", id=2)])
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1, max_events=1), tmp_path)
    assert report["status"] == "partial"
    assert len(report["events"]) == 1 and report["events"][0]["value"] == value
    assert any("Event count limit" in item for item in report["limitations"])


def test_report_validation_rejects_broken_provenance_and_forged_verdict(monkeypatch, tmp_path):
    fake_frida(monkeypatch, crash=True)
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    broken = json.loads(json.dumps(report))
    broken["observations"][0]["evidence"]["line"] = 9999
    with pytest.raises(ValueError, match="journal"):
        validate_capture(broken)
    broken = json.loads(json.dumps(report))
    broken["observations"][0]["vulnerability_confirmed"] = True
    with pytest.raises(ValueError, match="verdict"):
        validate_capture(broken)


def test_hook_callback_error_is_partial_but_optional_class_absence_is_not(monkeypatch, tmp_path):
    fake_frida(monkeypatch, capabilities=[{"name": "hook_callback:test.api", "available": False,
        "detail": "fixture callback failure"}, {"name": "optional.class", "available": False, "detail": "not loaded"}])
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    assert report["status"] == "partial"
    assert report["errors"] == [{"stage": "hook", "api": "test.api", "message": "fixture callback failure"}]


def test_spawn_failure_fallback_identifies_package_and_preserves_preexisting_process(monkeypatch, tmp_path):
    state = fake_frida(monkeypatch, failure=True)
    import importlib
    env = importlib.import_module("sca.dynamic.environment")
    monkeypatch.setattr(env, "launch_target", lambda *args: {"success": True, "activity": "com.example.app/Main"})
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    assert report["status"] == "partial"
    assert report["coverage"]["profile"] == "warm_launch_attach"
    assert state["identifiers"] == ["com.example.app"]
    assert state["resumed"] == state["killed"] == []
    assert report["events"]


def test_attach_uses_application_identifier_and_never_resumes_or_kills(monkeypatch, tmp_path):
    state = fake_frida(monkeypatch)
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1, spawn=False), tmp_path)
    assert report["status"] == "completed"
    assert report["coverage"]["profile"] == "attached_process"
    assert state["identifiers"] == ["com.example.app"]
    assert state["resumed"] == state["killed"] == []


def test_forward_verification_rejects_different_device_on_same_port(monkeypatch):
    import importlib
    env = importlib.import_module("sca.dynamic.environment")
    monkeypatch.setattr(env, "find_adb", lambda _: "adb")
    monkeypatch.setattr(backend.subprocess, "run", lambda *args, **kwargs:
        types.SimpleNamespace(returncode=0, stdout="emulator-5582 tcp:37042 tcp:27042\n"))
    with pytest.raises(RuntimeError, match="selected device"):
        backend._verify_forward(CaptureOptions("com.example.app", "emulator-5590"))


def test_native_operation_is_cancelled_after_deadline():
    ended = threading.Event()
    class Cancellation:
        is_cancelled = False
        def cancel(self):
            self.is_cancelled = True
            ended.set()
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    with pytest.raises(TimeoutError, match="exceeded"):
        backend._frida_call(types.SimpleNamespace(Cancellable=Cancellation), lambda: ended.wait(1), timeout=.02)


def test_pid_zero_metadata_falls_back_to_corroborated_native_process(monkeypatch):
    import importlib
    env = importlib.import_module("sca.dynamic.environment")
    monkeypatch.setattr(env, "find_adb", lambda _: "adb")
    monkeypatch.setattr(backend, "_frida_call", lambda frida, function, timeout=20: function())
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        data = b"42 43\n" if "pidof" in args else b"com.example.app\0" if "/proc/42/cmdline" in args else b"com.example.app:service\0"
        return types.SimpleNamespace(returncode=0, stdout=data)
    monkeypatch.setattr(backend.subprocess, "run", run)
    device = types.SimpleNamespace(
        enumerate_applications=lambda **kwargs: [types.SimpleNamespace(identifier="com.example.app", pid=0)],
        enumerate_processes=lambda: [types.SimpleNamespace(pid=42), types.SimpleNamespace(pid=43)])
    details = {}
    options = CaptureOptions("com.example.app", "emulator-5590")
    assert backend._running_pid(None, device, options.package, options, details) == 42
    assert details["method"] == "adb_pidof_proc_cmdline_and_frida_process"
    assert all(command[:3] == ["adb", "-s", "emulator-5590"] for command in calls)


@pytest.mark.parametrize("cmdline,visible", [(b"com.other.app\0", True), (b"com.example.app:service\0", True),
    (b"com.example.app\0", False)])
def test_pid_fallback_never_attaches_unverified_or_wrong_process(monkeypatch, cmdline, visible):
    import importlib
    env = importlib.import_module("sca.dynamic.environment")
    monkeypatch.setattr(env, "find_adb", lambda _: "adb")
    monkeypatch.setattr(backend, "_frida_call", lambda frida, function, timeout=20: function())
    monkeypatch.setattr(backend.subprocess, "run", lambda args, **kwargs:
        types.SimpleNamespace(returncode=0, stdout=b"42\n" if "pidof" in args else cmdline))
    device = types.SimpleNamespace(enumerate_applications=lambda **kwargs: [],
        enumerate_processes=lambda: [types.SimpleNamespace(pid=42)] if visible else [])
    options = CaptureOptions("com.example.app", "emulator-5590")
    with pytest.raises(RuntimeError, match="uniquely verified"):
        backend._running_pid(None, device, options.package, options)


def test_native_hook_configuration_preserves_packaged_bundle_sizes():
    enabled = backend._agent_source(True)
    disabled = backend._agent_source(False)
    assert "SCA_NATIVE_HOOKS_ENABLED_1" in enabled
    assert "SCA_NATIVE_HOOKS_ENABLED_1" not in disabled
    assert "SCA_NATIVE_HOOKS_ENABLED_0" in disabled
    assert len(enabled.encode("utf-8")) == len(disabled.encode("utf-8"))
    assert enabled.split("✄", 1)[0] == disabled.split("✄", 1)[0]


def test_native_disabled_capture_is_explicit_without_automatic_crash_claim(monkeypatch, tmp_path):
    state = fake_frida(monkeypatch, crash=True, capabilities=[{"name": "native_observer", "available": False,
        "detail": "Disabled by capture option"}])
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1, native_hooks=False), tmp_path)
    assert report["status"] == "partial"  # Actual crash remains recorded in this mode.
    assert report["options"]["native_hooks"] is False
    assert report["coverage"]["native_hooks_requested"] is False
    assert "SCA_NATIVE_HOOKS_ENABLED_0" in state["script_source"]
    assert report["tool_versions"]["agent_sha256"] != report["tool_versions"]["configured_agent_sha256"]
    assert any("does not establish" in warning for warning in report["limitations"])


def test_report_validation_rejects_mismatched_journal_event_id(monkeypatch, tmp_path):
    fake_frida(monkeypatch, crash=True, events=[event(), event("host", "other.example.test", id=2)])
    report = run_capture(CaptureOptions("com.example.app", "emulator-5590", duration_seconds=1), tmp_path)
    report["observations"][0]["evidence"]["line"] = 2
    with pytest.raises(ValueError, match="disagree"):
        validate_capture(report)
