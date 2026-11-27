"""Exercise the dashboard's real persistence/import callbacks with isolated fixtures."""
from importlib import import_module
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sca.decoded import DecodedFile
from sca.dynamic import analyze_events
from sca.models import ScanResult
from sca.storage import Storage
from sca.ui.i18n import AR

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FILE = "jadx/com/example/DynamicDashboardFixture.java"
PACKAGE = "com.example.dynamicdashboardfixture"
URL = "https://dynamic-dashboard-fixture.example/api/session?mode=fixture"
TOKEN = "integration-fixture-token-" + "Ab9" * 20


def _result():
    lines = ("class DynamicDashboardFixture {", f' String url = "{URL}";', "}")
    return ScanResult("fixture-upload.apk", app={"kind": "apk", "package": PACKAGE, "name": "UI fixture"},
                      started_at="2026-01-01T00:00:00Z", files_scanned=1, lines_scanned=3,
                      decoded_files={FILE: DecodedFile("java", "decompiled", 3, lines)})


def _capture(result, *, session_id="dashboard-fixture"):
    events = [
        {"id": 1, "type": "observation", "kind": "url", "value": URL, "api": "java.net.URL.$init",
         "timestamp": "2026-01-01T00:01:01Z", "stack": [], "details": {}},
        {"id": 2, "type": "observation", "kind": "header", "value": TOKEN, "api": "Request.header",
         "timestamp": "2026-01-01T00:01:02Z", "stack": [], "details": {"name": "Authorization"}},
    ]
    return {"schema_version": 1, "session_id": session_id, "package": PACKAGE,
            "serial": "fixture-emulator-5554", "started_at": "2026-01-01T00:01:00Z",
            "ended_at": "2026-01-01T00:01:30Z", "status": "completed", "events": events,
            "observations": analyze_events(events, result.decoded_files, session_id=session_id),
            "capabilities": [{"name": "java.net.URL", "available": True, "detail": "Fixture metadata"}],
            "errors": [], "limitations": ["Only fixture events are supplied by this test."], "artifacts": {}}


@pytest.fixture(autouse=True)
def isolated_dashboard(tmp_path, monkeypatch):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    st.cache_resource.clear()
    st.cache_data.clear()
    environment = import_module("sca.dynamic.environment")
    monkeypatch.setattr(environment, "environment", lambda: {
        "available": False, "devices": [], "reasons": ["UI test has no live Android device."]})
    # An unintended real capture/installation must fail the test instead of touching a device.
    def forbidden(*args, **kwargs):
        raise AssertionError("This integration test must not access a live Android device")
    monkeypatch.setattr(environment, "install_target", forbidden)
    monkeypatch.setattr(environment, "forward_frida", forbidden)
    monkeypatch.setattr(import_module("sca.dynamic"), "run_capture", forbidden)
    yield
    st.cache_resource.clear()
    st.cache_data.clear()


def _app(result, arabic=False):
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=40)
    app.session_state["result"] = result
    if arabic:
        app.session_state["ui_lang"] = "العربية"
    app.run()
    assert not app.exception
    return app


def _tab(app, arabic=False):
    label = AR["Runtime analysis"] if arabic else "Runtime analysis"
    return next(tab for tab in app.tabs if tab.label == label)


def _upload_fixture(monkeypatch, payload):
    original = st.file_uploader
    state = {"payload": json.dumps(payload).encode("utf-8")}

    def upload(label, *args, **kwargs):
        if label in {"Runtime capture JSON", AR["Runtime capture JSON"]}:
            value = state["payload"]
            return SimpleNamespace(name="fixture-capture.json", size=len(value), getvalue=lambda: value)
        return original(label, *args, **kwargs)

    monkeypatch.setattr(st, "file_uploader", upload)
    return state


@pytest.mark.parametrize("arabic", [False, True])
def test_full_dashboard_loads_archive_metadata_and_opens_verified_source(arabic, monkeypatch):
    result = _result()
    storage = Storage()
    scan_id = storage.save_scan(result)
    capture_id = storage.save_dynamic_session(scan_id, _capture(result))
    loaded_ids = []
    original = Storage.load_dynamic_session

    def load(storage, capture_id, **kwargs):
        loaded_ids.append((capture_id, kwargs.get("scan_id")))
        return original(storage, capture_id, **kwargs)

    monkeypatch.setattr(Storage, "load_dynamic_session", load)
    app = _app(storage.load_scan(scan_id), arabic)
    tab = _tab(app, arabic)
    assert loaded_ids == [(capture_id, scan_id)]
    assert any(code.value == URL for code in tab.code)
    browse = AR["Browse decoded files"] if arabic else "Browse decoded files"
    next(button for button in tab.button if button.label == browse).click().run()
    assert not app.exception
    file_tab = next(tab for tab in app.tabs if tab.label == (AR["Decoded files"] if arabic else "Decoded files"))
    file_label = AR["Decoded file"] if arabic else "Decoded file"
    line_label = AR["Jump to line"] if arabic else "Jump to line"
    assert next(control for control in file_tab.selectbox if control.label == file_label).value == FILE
    assert next(control for control in file_tab.number_input if control.label == line_label).value == 2
    assert any(URL in code.value for code in file_tab.code)


def test_import_into_unsaved_local_scan_survives_changed_widget_prefix_and_archive_reload(monkeypatch):
    result = _result()
    _upload_fixture(monkeypatch, _capture(result))
    app = _app(result)
    assert result.scan_id is None
    next(button for button in _tab(app).button if button.label == "Import capture").click().run()
    assert not app.exception
    assert result.scan_id is not None
    assert any(code.value == URL for code in _tab(app).code)
    storage = Storage()
    sessions = storage.list_dynamic_sessions(result.scan_id)
    assert len(sessions) == 1
    assert "events" not in sessions[0]
    saved = storage.load_dynamic_session(sessions[0]["capture_id"], scan_id=result.scan_id)
    assert saved["imported_external"] is True
    assert any(item["value"] == TOKEN for item in saved["observations"])
    app.run()
    assert not app.exception
    assert any(code.value == URL for code in _tab(app).code)
    app.session_state["result"] = storage.load_scan(result.scan_id)
    app.run()
    assert not app.exception
    assert any(code.value == URL for code in _tab(app).code)
    assert len(storage.list_dynamic_sessions(result.scan_id)) == 1


@pytest.mark.parametrize("arabic", [False, True])
def test_hosted_import_persists_in_session_without_local_db_or_filename_cross_contamination(monkeypatch, arabic):
    monkeypatch.setenv("SCA_HOSTED", "1")
    result = _result()
    _upload_fixture(monkeypatch, _capture(result))
    app = _app(result, arabic)
    t = lambda value: AR[value] if arabic else value
    tab = _tab(app, arabic)
    assert next(button for button in tab.button if button.label == t("Start runtime capture")).disabled
    assert not any(button.label == t("Reconnect lab observer") for button in tab.button)
    next(button for button in tab.button if button.label == t("Import capture")).click().run()
    assert not app.exception
    assert any(code.value == URL for code in _tab(app, arabic).code)
    assert any(t("Imported evidence: this dashboard did not independently witness the capture.") == info.value
               for info in _tab(app, arabic).info)
    app.run()
    assert not app.exception
    assert any(code.value == URL for code in _tab(app, arabic).code)
    assert result.scan_id is None and Storage().count_scans() == 0
    # A fresh scan may use exactly the same upload filename and Android package.
    # Its runtime evidence must start empty rather than inherit the previous scan.
    app.session_state["result"] = _result()
    app.run()
    assert not app.exception
    assert not _tab(app, arabic).metric
    assert not any(code.value == URL for code in _tab(app, arabic).code)
    assert any(t("No runtime capture has been recorded for this scan yet.") == info.value
               for info in _tab(app, arabic).info)


@pytest.mark.parametrize("spawn", [True, False], ids=["install-and-restart", "attach-existing"])
def test_local_capture_callback_uses_requested_mode_and_archives_observations(monkeypatch, spawn):
    result = _result()
    environment = import_module("sca.dynamic.environment")
    calls = []
    monkeypatch.setattr(environment, "environment", lambda: {"available": True, "reasons": [],
        "devices": [{"serial": "fixture-emulator-5554", "state": "device", "name": "Fixture"}]})

    def install(target, serial):
        calls.append(("install", target, serial))
        return {"success": True, "errors": [], "output": "Fixture installation", "apks": []}

    def forward(serial):
        calls.append(("forward", serial))
        return "127.0.0.1:37042"

    def capture(options, output_dir, decoded_files):
        calls.append(("capture", options, Path(output_dir), decoded_files))
        return _capture(result)

    monkeypatch.setattr(environment, "install_target", install)
    monkeypatch.setattr(environment, "forward_frida", forward)
    monkeypatch.setattr(import_module("sca.dynamic"), "run_capture", capture)
    app = _app(result)
    next(control for control in _tab(app).selectbox if control.label == "Capture mode").select("spawn" if spawn else "attach")
    if not spawn:
        next(box for box in _tab(app).checkbox if box.label == "Observe native DNS and TLS calls").uncheck()
    next(control for control in _tab(app).number_input if control.label == "Capture duration (seconds)").set_value(60)
    next(button for button in _tab(app).button if button.label == "Start runtime capture").click().run()
    assert not app.exception
    capture_call = next(call for call in calls if call[0] == "capture")
    assert capture_call[1].spawn is spawn
    assert capture_call[1].native_hooks is spawn  # this fixture exercises both explicit hook modes
    assert capture_call[1].duration_seconds == 60
    assert capture_call[1].package == PACKAGE
    assert capture_call[1].serial == "fixture-emulator-5554"
    assert bool([call for call in calls if call[0] == "install"]) is spawn
    assert result.scan_id is not None
    sessions = Storage().list_dynamic_sessions(result.scan_id)
    assert len(sessions) == 1
    saved = Storage().load_dynamic_session(sessions[0]["capture_id"])
    assert ("installation" in saved) is spawn
    app.run()
    assert not app.exception
    assert any(code.value == URL for code in _tab(app).code)
    assert len([call for call in calls if call[0] == "capture"]) == 1


def test_import_rejects_another_package_without_creating_scan_or_capture(monkeypatch):
    result = _result()
    capture = _capture(result)
    capture["package"] = "com.example.otherfixture"
    _upload_fixture(monkeypatch, capture)
    app = _app(result)
    next(button for button in _tab(app).button if button.label == "Import capture").click().run()
    assert not app.exception
    assert any("does not match the selected scan" in code.value for code in _tab(app).code)
    assert Storage().count_scans() == 0
    assert not _tab(app).metric


def test_local_reconnect_refreshes_cached_preflight_without_installing_or_capturing(monkeypatch):
    environment = import_module("sca.dynamic.environment")
    calls = {"preflight": 0, "serials": []}

    def preflight():
        calls["preflight"] += 1
        return {"available": bool(calls["serials"]), "reasons": [] if calls["serials"] else ["Fixture observer offline"],
                "devices": [{"serial": "fixture-emulator-5554", "state": "device", "name": "Fixture"}]}

    def reconnect(serial):
        calls["serials"].append(serial)
        return {"success": True}

    monkeypatch.setattr(environment, "environment", preflight)
    monkeypatch.setattr(environment, "restart_lab_observer", reconnect, raising=False)
    app = _app(_result())
    assert calls == {"preflight": 1, "serials": []}
    assert next(button for button in _tab(app).button if button.label == "Start runtime capture").disabled
    next(button for button in _tab(app).button if button.label == "Reconnect lab observer").click().run()
    assert not app.exception
    assert calls == {"preflight": 2, "serials": ["fixture-emulator-5554"]}
    assert not next(button for button in _tab(app).button if button.label == "Start runtime capture").disabled
    assert any("Device status has been refreshed" in message.value for message in _tab(app).success)
    assert Storage().count_scans() == 0
