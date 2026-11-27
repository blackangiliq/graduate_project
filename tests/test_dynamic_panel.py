"""Runtime UI tests use explicit fixtures; production observations come from capture records."""
from copy import deepcopy
from html import unescape
import json

import pytest

from sca.decoded import DecodedFile
from sca.models import ScanResult
from sca.ui.dynamic_panel import _evidence_event, _verified_locations
from sca.ui.i18n import AR

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

FILE = "jadx/com/example/RuntimeFixture.java"
URL = "https://runtime-fixture.example/api?sample=1&mode=full"
TOKEN = "fixture-runtime-token-" + "Q7" * 35
SCRIPT = '''
import streamlit as st
from sca.ui.dynamic_panel import render_dynamic
from sca.ui.i18n import AR

def run_capture(request):
    st.session_state["requests"] = [*st.session_state.get("requests", []), request]
    if st.session_state.get("capture_error"):
        raise RuntimeError(st.session_state["capture_error"])
    capture = st.session_state.get("next_capture")
    if capture:
        st.session_state["captures"] = [capture, *st.session_state.get("captures", [])]
    return capture

def open_source(path, line):
    st.session_state["opened"] = (path, line)

def load_capture(capture_id):
    st.session_state["loaded_capture_ids"] = [*st.session_state.get("loaded_capture_ids", []), capture_id]
    return st.session_state.get("archived_captures", {}).get(capture_id)

def reconnect(serial):
    st.session_state["reconnect_requests"] = [*st.session_state.get("reconnect_requests", []), serial]
    if st.session_state.get("reconnect_error"):
        raise RuntimeError(st.session_state["reconnect_error"])
    return st.session_state.get("reconnect_result", {"success": True})

translation = (lambda text: AR.get(text, text)) if st.session_state.get("arabic") else (lambda text: text)
render_dynamic(st.session_state.get("result"), translation,
    environment=st.session_state.get("environment", {}),
    sessions=st.session_state.get("captures", []),
    on_run=run_capture, on_open_source=open_source, on_load=load_capture,
    on_reconnect=reconnect if st.session_state.get("reconnect_enabled") else None)
'''


def _result(value=URL):
    lines = ("class RuntimeFixture {", f'  String endpoint = "{value}";', "}")
    return ScanResult("runtime-fixture.apk", scan_id=123,
                      app={"package": "com.example.runtimefixture"},
                      decoded_files={FILE: DecodedFile("java", "decompiled", 3, lines)})


def _capture():
    return {
        "schema_version": 1, "session_id": "ui-fixture", "capture_id": 7,
        "package": "com.example.runtimefixture", "serial": "fixture-emulator-5554",
        "started_at": "2026-01-01T12:00:00Z", "ended_at": "2026-01-01T12:00:30Z",
        "status": "completed", "errors": [], "limitations": ["Only visited paths were observed."],
        "capabilities": [{"name": "java.net.URL", "available": True, "detail": "Fixture hook installed"}],
        "events": [
            {"id": "event-1", "kind": "url", "value": URL, "api": "java.net.URL.$init"},
            {"id": "event-2", "kind": "credential", "value": TOKEN, "api": "Request.header"},
        ],
        "observations": [
            {"id": "obs-1", "kind": "url", "value": URL, "confidence": "observed",
             "api": "java.net.URL.$init", "timestamp": "2026-01-01T12:00:01Z", "pid": 5432, "tid": 555,
             "event_ids": ["event-1"], "evidence": {"file": "_runtime/ui-fixture/events.jsonl", "line": 1},
             "locations": [{"file": FILE, "line": 2, "column": 22, "end_column": 22 + len(URL),
                            "verified": True, "relation": "exact_literal"}],
             "stack": [{"class_name": "com.example.RuntimeFixture", "method": "connect",
                        "file_name": "RuntimeFixture.java", "line": 923}]},
            {"id": "obs-2", "kind": "credential", "value": TOKEN, "confidence": "candidate",
             "api": "Request.header", "timestamp": "2026-01-01T12:00:02Z", "event_ids": ["event-2"],
             "evidence": {"file": "_runtime/ui-fixture/events.jsonl", "line": 2}, "locations": [],
             "stack": [{"class_name": "com.example.RuntimeFixture", "method": "authenticate",
                        "file_name": "RuntimeFixture.java", "line": 2001}]},
        ],
    }


def _environment(available=True):
    return {"available": available, "reasons": [] if available else ["Frida server is not reachable."],
            "devices": [{"serial": "fixture-emulator-5554", "state": "device", "name": "Fixture emulator"}],
            "capabilities": {"adb": True, "frida_client": available}}


def _app(captures=(), environment=None, result=None):
    app = AppTest.from_string(SCRIPT, default_timeout=15)
    app.session_state["result"] = result or _result()
    app.session_state["environment"] = environment or _environment()
    app.session_state["captures"] = list(captures)
    app.run()
    assert not app.exception
    return app


def _selectbox(app, label):
    return next(control for control in app.selectbox if control.label == label)


def _button(app, label):
    return next(control for control in app.button if control.label == label)


def test_capture_is_disabled_with_actual_prerequisite_reason_and_no_fake_data():
    app = _app(environment=_environment(False))
    assert _button(app, "Start runtime capture").disabled
    assert any("Frida server is not reachable." == w.value for w in app.warning)
    assert any("No runtime capture has been recorded" in info.value for info in app.info)
    assert not app.metric and not app.code


def test_selected_offline_device_does_not_enable_capture():
    environment = _environment()
    environment["devices"].append({"serial": "fixture-offline", "state": "unauthorized"})
    app = _app(environment=environment)
    _selectbox(app, "Android device").select("fixture-offline").run()
    assert not app.exception
    assert _button(app, "Start runtime capture").disabled
    assert any("not connected or authorized" in warning.value for warning in app.warning)


def test_run_sends_selected_device_duration_and_preserves_failed_empty_capture():
    app = _app()
    failed = {**_capture(), "events": [], "observations": [], "status": "failed",
              "errors": ["Target process exited before hooks were installed."]}
    app.session_state["next_capture"] = failed
    next(n for n in app.number_input if n.label == "Capture duration (seconds)").set_value(45)
    _button(app, "Start runtime capture").click().run()
    assert not app.exception
    assert app.session_state["requests"] == [{"package": "com.example.runtimefixture",
        "serial": "fixture-emulator-5554", "duration_seconds": 45, "spawn": True, "native_hooks": True}]
    assert app.session_state["runtime_capture_in_progress"] is False
    assert any(error.value == "Capture failed" for error in app.error)
    assert any("Target process exited" in error.value for error in app.error)
    assert any("not evidence" in info.value for info in app.info)
    assert [metric.value for metric in app.metric] == ["0", "0", "0"]


def test_runtime_observation_row_opens_full_generated_value_without_fake_source_location():
    app = _app([_capture()])
    grid = next(grid for grid in app.dataframe if "Full observed value" in grid.value.columns)
    states = app._tree.get_widget_states()
    states.widgets.add(id=grid.proto.id, string_value=json.dumps({"selection": {"rows": [1]}}))
    app._run(states)
    assert not app.exception
    assert any(code.value == TOKEN for code in app.code)
    assert any("No exact source line was verified" in info.value for info in app.info)
    assert not any('aria-current="location"' in element.proto.body for element in app.get("html"))
    assert any("line 2" in caption.value and "events.jsonl" in caption.value for caption in app.caption)
    assert any("not JADX line numbers" in caption.value for caption in app.caption)
    assert any("does not by itself prove" in caption.value for caption in app.caption)
    assert not any(button.label == "Browse decoded files" for button in app.button)


def test_exact_literal_opens_verified_file_and_keeps_full_long_value_and_exports(monkeypatch):
    value = "RuntimeFixture9" * 1400 + "<script>literal</script> & end"
    result, capture = _result(value), _capture()
    capture["events"][0]["value"] = value
    capture["observations"][0]["value"] = value
    capture["observations"][0]["locations"][0]["end_column"] = 22 + len(value)
    downloads = {}
    original = st.download_button

    def download(label, data, *args, **kwargs):
        downloads[label] = data
        return original(label, data, *args, **kwargs)

    monkeypatch.setattr(st, "download_button", download)
    app = _app([capture], result=result)
    assert any(code.value == value for code in app.code)
    markup = next(element.proto.body for element in app.get("html")
                  if 'aria-current="location"' in element.proto.body)
    assert value in unescape(markup)
    assert "<script>" not in markup and "&lt;script&gt;" in markup
    assert any("does not prove that this line generated" in caption.value for caption in app.caption)
    assert json.loads(downloads["Download runtime capture JSON"])["observations"][0]["value"] == value
    assert json.loads(downloads["Download runtime events JSONL"].splitlines()[0])["value"] == value
    _button(app, "Browse decoded files").click().run()
    assert not app.exception
    assert app.session_state["opened"] == (FILE, 2)
    assert app.session_state["decoded_files_pending_column"] == 22


def test_search_and_type_filter_use_full_observation_values():
    app = _app([_capture()])
    next(text for text in app.text_input if text.label == "Search runtime values, APIs or locations").input(TOKEN[-50:]).run()
    assert not app.exception
    assert any(code.value == TOKEN for code in app.code)
    assert any("Showing 1 of 2" in caption.value for caption in app.caption)
    _selectbox(app, "Observation type").select("url").run()
    assert not app.exception
    assert any("No recorded values match" in info.value for info in app.info)


def test_unverifiable_source_claims_never_become_clickable_line_links():
    result, capture = _result(), _capture()
    candidate = capture["observations"][1]
    candidate["locations"] = [
        {"file": FILE, "line": 2, "column": 22, "relation": "exact_literal", "verified": True},
        {"file": FILE, "line": 2001, "relation": "class_method", "verified": True},
    ]
    assert _verified_locations(candidate, result) == []
    app = _app([capture])
    _selectbox(app, "Open recorded value").select(1).run()
    assert not app.exception
    assert any("possible code associations, not verified source lines" in caption.value for caption in app.caption)
    assert not any(button.label == "Browse decoded files" for button in app.button)


def test_event_lookup_uses_actual_record_identity_when_no_line_exists():
    capture = _capture()
    item = {**capture["observations"][1], "evidence": {"line": 999}}
    assert _evidence_event(capture, item) == (2, capture["events"][1])
    assert _evidence_event(capture, {"event_ids": ["missing"]}) == (0, None)


def test_imported_partial_capture_and_callback_failures_are_explicit():
    capture = {**_capture(), "status": "partial", "imported_external": True,
               "errors": ["Native TLS library was not observed."]}
    app = _app([capture])
    assert any("did not independently witness" in info.value for info in app.info)
    assert any("Partial capture" in warning.value for warning in app.warning)
    app.session_state["capture_error"] = "Frida attach failed: process no longer exists"
    _button(app, "Start runtime capture").click().run()
    assert not app.exception
    assert any("Runtime capture could not finish" in error.value for error in app.error)
    assert any("process no longer exists" in code.value for code in app.code)
    assert app.session_state["runtime_capture_in_progress"] is False
    assert len(app.session_state["captures"]) == 1


def test_arabic_panel_formats_evidence_and_metadata_without_losing_values():
    app = _app([_capture()])
    app.session_state["arabic"] = True
    app.run()
    assert not app.exception
    assert any(code.value == URL for code in app.code)
    assert any("التحليل الديناميكي" == heading.value for heading in app.subheader)


def test_explicit_source_column_identifies_second_literal_occurrence():
    value = URL
    line = f'first="{value}"; second="{value}";'
    result = _result()
    result.decoded_files[FILE] = DecodedFile("java", "decompiled", 1, (line,))
    column = line.rindex(value) + 1
    item = {"value": value, "locations": [{"file": FILE, "line": 1, "column": column,
             "end_column": 999, "relation": "exact_literal", "verified": True}]}
    verified = _verified_locations(item, result)
    assert verified[0]["column"] == column
    assert verified[0]["end_column"] == column + len(value)
    for invalid in [0, 2, True, "1"]:
        changed = deepcopy(item)
        changed["locations"][0]["line"] = invalid
        assert not _verified_locations(changed, result)


def test_archive_loads_only_selected_session_and_never_reports_missing_payload_as_empty():
    capture = _capture()
    metadata = {key: value for key, value in capture.items() if key not in {"events", "observations"}}
    app = _app([metadata])
    assert any("summary is not a complete capture" in warning.value for warning in app.warning)
    assert not app.metric
    app.session_state["archived_captures"] = {capture["capture_id"]: capture}
    app.run()
    assert not app.exception
    assert any(code.value == URL for code in app.code)
    assert app.session_state["loaded_capture_ids"] == [7, 7]


def test_hook_coverage_and_every_repeated_occurrence_remain_inspectable():
    capture = _capture()
    second_event = {**capture["events"][0], "id": "event-3", "timestamp": "2026-01-01T12:00:25Z"}
    capture["events"].append(second_event)
    item = capture["observations"][0]
    item["event_ids"].append("event-3")
    item["occurrence_count"] = 2
    item["evidence_locations"] = [item["evidence"], {**item["evidence"], "line": 3}]
    capture["capabilities"].append({"name": "SSL_write", "available": False, "detail": "Symbol not loaded"})
    app = _app([capture])
    capabilities = next(grid.value for grid in app.dataframe if "Capability" in grid.value.columns)
    assert capabilities["Status"].tolist() == ["Hook available", "Hook unavailable"]
    assert capabilities["Details"].tolist() == ["Fixture hook installed", "Symbol not loaded"]
    _selectbox(app, "Recorded event occurrence").select(1).run()
    assert not app.exception
    assert any("events.jsonl" in caption.value and "line 3" in caption.value for caption in app.caption)
    assert any("event-3" in code.value and "12:00:25Z" in code.value for code in app.code)


@pytest.mark.parametrize("profile,label", [
    ("startup", "Startup instrumentation"),
    ("attached_process", "Attached running process"),
    ("warm_launch_attach", "Attached after launch"),
])
def test_capture_profile_and_actual_recording_duration_are_explicit(profile, label):
    capture = _capture()
    capture["coverage"] = {"profile": profile, "observed_seconds": 12.345,
                           "requested_seconds": 30, "ui_exploration": False}
    app = _app([capture])
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Capture profile"] == label
    assert metrics["Observed duration (seconds)"] == "12.345"
    assert metrics["Requested duration (seconds)"] == "30"
    assert any("not a measure of screen or code coverage" in caption.value for caption in app.caption)
    assert any("No automated screen exploration" in caption.value for caption in app.caption)


def test_absent_or_invalid_coverage_duration_is_not_fabricated_as_zero():
    capture = _capture()
    capture["coverage"] = {"profile": "startup", "observed_seconds": True}
    app = _app([capture])
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Observed duration (seconds)"] == "Not recorded"
    assert metrics["Requested duration (seconds)"] == "Not recorded"


def test_arabic_translates_fixed_runtime_limits_and_keeps_unknown_diagnostics():
    from sca.dynamic.capture import _LIMITATIONS
    capture = _capture()
    capture["limitations"] = [*_LIMITATIONS, "Fixture custom diagnostic remains verbatim."]
    capture["coverage"] = {"profile": "warm_launch_attach", "observed_seconds": 0,
                           "requested_seconds": 30, "ui_exploration": False}
    app = _app([capture])
    app.session_state["arabic"] = True
    app.run()
    assert not app.exception
    warnings = [warning.value for warning in app.warning]
    assert all(AR[limitation] in warnings for limitation in _LIMITATIONS)
    assert "Fixture custom diagnostic remains verbatim." in warnings
    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics[AR["Capture profile"]] == AR["Attached after launch"]
    assert metrics[AR["Observed duration (seconds)"]] == "0"


def test_reconnect_only_calls_selected_device_after_explicit_click_even_if_preflight_failed():
    environment = _environment(False)
    environment["devices"].append({"serial": "fixture-second-5556", "state": "device"})
    app = _app(environment=environment)
    assert not any(button.label == "Reconnect lab observer" for button in app.button)
    app.session_state["reconnect_enabled"] = True
    app.run()
    _selectbox(app, "Android device").select("fixture-second-5556").run()
    assert "reconnect_requests" not in app.session_state
    assert not _button(app, "Reconnect lab observer").disabled
    assert _button(app, "Start runtime capture").disabled
    _button(app, "Reconnect lab observer").click().run()
    assert not app.exception
    assert app.session_state["reconnect_requests"] == ["fixture-second-5556"]
    assert "requests" not in app.session_state
    assert any("Lab observer reconnected" in success.value for success in app.success)


@pytest.mark.parametrize("exception", [False, True])
def test_reconnect_failure_is_explicit_without_starting_a_capture(exception):
    app = _app(environment=_environment(False))
    app.session_state["reconnect_enabled"] = True
    if exception:
        app.session_state["reconnect_error"] = "Fixture device disconnected"
    else:
        app.session_state["reconnect_result"] = {"success": False, "errors": ["Fixture device disconnected"]}
    app.run()
    _button(app, "Reconnect lab observer").click().run()
    assert not app.exception
    assert any("could not be reconnected" in error.value for error in app.error)
    assert any("Fixture device disconnected" in code.value for code in app.code)
    assert not app.success
    assert "requests" not in app.session_state


def test_reconnect_is_disabled_without_a_device_or_during_a_capture():
    app = _app(environment={"available": False, "devices": [], "reasons": ["No device"]})
    app.session_state["reconnect_enabled"] = True
    app.run()
    assert _button(app, "Reconnect lab observer").disabled
    app.session_state["environment"] = _environment()
    app.session_state["runtime_capture_in_progress"] = True
    app.run()
    assert _button(app, "Reconnect lab observer").disabled
    assert _button(app, "Start runtime capture").disabled
    assert "reconnect_requests" not in app.session_state


def test_native_observation_remains_enabled_unless_explicitly_unchecked():
    app = _app()
    native = next(box for box in app.checkbox if box.label == "Observe native DNS and TLS calls")
    assert native.value is True
    native.uncheck()
    _button(app, "Start runtime capture").click().run()
    assert not app.exception
    assert app.session_state["requests"][0]["native_hooks"] is False


def test_requested_java_only_mode_is_visible_in_saved_capture_coverage():
    capture = _capture()
    capture["options"] = {"native_hooks": False}
    app = _app([capture])
    assert any("Java-only observation requested" in text.value for text in app.text)
    assert any("Native DNS, socket and TLS observation was disabled" in warning.value for warning in app.warning)
