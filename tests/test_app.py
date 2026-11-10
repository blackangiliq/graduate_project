"""Runs the Streamlit dashboard headlessly: start page, a full scan of the sample, and
loading a scan from history. Fails if the app raises any exception."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def button(app: AppTest, label: str):
    return next(b for b in app.button if b.label == label)


def test_dashboard_scan_flow():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception
    assert any("Scan a project to begin" in h.value for h in app.header)

    button(app, "Run scan").click().run()          # no folder chosen yet
    assert any("Choose a project folder" in e.value for e in app.error)

    button(app, "Use sample").click().run()
    assert app.session_state["target"].endswith("vulnerable_app")
    button(app, "Run scan").click().run()
    assert not app.exception
    result = app.session_state["result"]
    assert result.grade == "F" and len(result.findings) > 50
    labels = [m.label for m in app.metric]
    assert "Security score (grade F)" in labels and "Critical" in labels
    assert len(app.expander) >= 50                  # one per finding in the Findings tab

    # switch explanations to Arabic and rerun: must not raise
    app.radio[0].set_value("العربية").run()
    assert not app.exception

    load = button(app, "Load this scan")
    load.click().run()
    assert not app.exception


def test_dashboard_rejects_missing_folder():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    app.text_input[0].set_value(str(ROOT / "no-such-folder")).run()
    button(app, "Run scan").click().run()
    assert any("does not exist" in e.value for e in app.error)
