"""Runs the Streamlit dashboard headlessly: start page, a full scan of the sample, reviews,
the Learning tab, and loading a scan from history. Fails if the app raises any exception."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    import streamlit as st
    st.cache_resource.clear()
    st.cache_data.clear()


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
    assert "Learned rules" in labels and "Waiting for approval" in labels
    assert any("weaknesses without a rule in" in c.value for c in app.caption)
    assert len(app.expander) >= 50                  # one per finding in the Findings tab

    # review the first finding as a false positive, then take it back
    first = result.findings[0]
    open_before = len(result.open_findings)
    next(b for b in app.button if b.key == "fp_0").click().run()
    assert not app.exception
    assert first.status == "dismissed" and len(result.open_findings) == open_before - 1
    assert "Your reviews" in [m.label for m in app.metric]
    next(b for b in app.button if b.key == "tp_1").click().run()
    assert result.findings[1].tier == "confirmed"
    assert not app.exception

    # switch explanations to Arabic and rerun: must not raise
    app.radio[0].set_value("العربية").run()
    assert not app.exception

    button(app, "Load this scan").click().run()
    assert not app.exception


def test_dashboard_strict_mode_and_remembered_reviews():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    button(app, "Use sample").click().run()
    button(app, "Run scan").click().run()
    next(b for b in app.button if b.key == "fp_0").click().run()
    dismissed = app.session_state["result"].findings[0].fingerprint

    strict = next(c for c in app.checkbox if c.label.startswith("Strict mode"))
    strict.check().run()
    button(app, "Run scan").click().run()
    assert not app.exception
    result = app.session_state["result"]
    assert result.status_count("needs_review") > 0
    assert all(f.tier == "confirmed" for f in result.open_findings)
    again = next(f for f in result.findings if f.fingerprint == dismissed)
    assert again.status == "dismissed"              # the review was remembered


def test_dashboard_api_provider_settings():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    provider = next(s for s in app.selectbox if s.label == "AI provider")
    provider.set_value("openai").run()
    assert not app.exception
    assert any(t.label == "API key" for t in app.text_input)
    assert any("sent to api.openai.com" in w.value for w in app.warning)
    assert any("not ready: no API key is set" in c.value for c in app.caption)
    review = next(c for c in app.checkbox if c.label == "AI review of findings")
    assert review.disabled                          # nothing is sent without a key


def test_dashboard_rejects_missing_folder():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    app.text_input[0].set_value(str(ROOT / "no-such-folder")).run()
    button(app, "Run scan").click().run()
    assert any("does not exist" in e.value for e in app.error)


def test_dashboard_learning_flow():
    """Deep scan with a (scripted) AI provider, learn a rule, approve it in the Learning tab."""
    from test_learning import Teacher, serve

    from sca.ai.providers import LLMConfig, save_config
    from sca.learn import store
    from sca.storage import Storage

    Teacher.log = []
    server, url = serve(Teacher)
    try:
        save_config(LLMConfig(preset="ollama", base_url=url, model="teacher:1"))
        app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180)
        app.run()
        assert any("AI provider ready: teacher:1" in c.value for c in app.caption)
        review = next(c for c in app.checkbox if c.label == "AI review of findings")
        assert review.value and not review.disabled
        next(c for c in app.checkbox if c.label.startswith("Deep scan")).check().run()
        button(app, "Use sample").click().run()
        button(app, "Run scan").click().run()
        assert not app.exception
        result = app.session_state["result"]
        assert any(f.engines == ["llm"] and f.tier == "confirmed" for f in result.findings)
        assert "deep scan added 1 (1 verified)" in result.ai["llm"]

        button(app, "Learn from this scan").click().run()
        assert not app.exception
        pending = Storage().list_candidates("pending")
        assert [c["cwe"] for c in pending] == ["CWE-120"]
        assert any("Waiting for your approval (1)" in h.value for h in app.subheader)
        assert store.read_learned() == []                      # not active before approval

        next(b for b in app.button if b.key == "approve_" + pending[0]["id"]).click().run()
        assert not app.exception
        assert [r["id"] for r in store.read_learned()] == [pending[0]["id"]]
        assert any("Learned rules (1)" in h.value for h in app.subheader)

        # the next scan, with the AI switched off, finds the weakness through the learned rule
        next(c for c in app.checkbox if c.label == "AI review of findings").uncheck().run()
        button(app, "Run scan").click().run()
        assert not app.exception
        result = app.session_state["result"]
        assert any(f.engines == ["learned"] and "memcpy" in f.snippet for f in result.findings)
        assert result.ai["llm"] == "disabled"
    finally:
        server.shutdown()
