"""Exercise selecting an Android split set through the local and hosted dashboards."""
from pathlib import Path

import pytest

from flutter_kit import build_apk, split_apk

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


@pytest.mark.parametrize("hosted", [False, True])
def test_scan_workspace_selects_all_uploaded_parts(tmp_path, monkeypatch, hosted):
    if not hasattr(AppTest, "file_uploader"):
        pytest.skip("file upload simulation requires a newer Streamlit")
    monkeypatch.setenv("SCA_HOSTED", "1" if hosted else "0")
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    monkeypatch.delenv("SCA_SCAN_ROOT", raising=False)
    st.cache_resource.clear()
    app = AppTest.from_file(str(APP), default_timeout=180).run()
    assert not app.exception
    tabs = {tab.label: tab for tab in app.tabs}
    assert tabs["Scan input"].file_uploader(key="app_upload")
    assert not app.sidebar.file_uploader
    assert "Scan settings" in tabs
    if not hosted:
        assert tabs["Samples"].button
        assert not app.session_state["target"]
    pieces = split_apk(build_apk(abis=("arm64-v8a", "x86_64")))
    uploads = [(name + ".apk", content, "application/vnd.android.package-archive")
               for name, content in pieces.items()]
    assert len(uploads) == 3
    app.file_uploader(key="app_upload").set_value(uploads).run()
    assert not app.exception
    if not hosted:
        assert Path(app.session_state["target"]).suffix == ".apks"
    next(b for b in app.button if b.label == "Run scan").click().run()
    assert not app.exception
    result = app.session_state["result"]
    assert {m["name"] for m in result.app["apk_members"]} == {name for name, _, _ in uploads}
    members = result.app["apk_members"]
    assert all(m["status"] in ("read", "partial") for m in members)
    assert all(m["reason"] for m in members if m["status"] == "partial")
    if hosted:
        assert result.scan_id is None
    else:
        assert Path(result.target).is_file()
        assert not app.session_state["scan_workspace_open"]
        next(b for b in app.button if b.label == "Use this path for a new scan").click().run()
        assert not app.exception
        assert app.text_input(key="target").value == result.target
        assert app.session_state["scan_workspace_open"]
        assert app.session_state["scan_workspace_tab_en"] == "Scan input"
