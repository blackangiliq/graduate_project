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
    assert "درجة الأمان (التقدير F)" in [m.label for m in app.metric]   # the whole UI switches
    assert any(b.label == "ابدأ الفحص" for b in app.button)

    button(app, "حمّل هذا الفحص").click().run()                          # "Load this scan"
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
    app.sidebar.text_input[0].set_value(str(ROOT / "no-such-folder")).run()
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


def test_rules_tab_controls_the_rule_set(tmp_path, monkeypatch):
    from sca import rulebook
    from sca.engines import rules_engine
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception
    labels = [m.label for m in app.metric]
    assert "All rules" in labels and "Imported" in labels and "Your own" in labels

    first = rules_engine.all_rules()[0]                     # the rule shown in the details
    next(b for b in app.button if b.key == "rule_off_" + first.id).click().run()
    assert not app.exception and not rulebook.get(first.id).enabled
    assert any("Disabled %s." % first.id in s.value for s in app.success)
    next(b for b in app.button if b.key == "rule_on_" + first.id).click().run()
    assert rulebook.get(first.id).enabled

    # edit it through the form, then restore the original
    app.selectbox(key="rule_severity_" + first.id).set_value("low")
    button(app, "Save changes").click().run()
    assert not app.exception
    assert rulebook.get(first.id).severity == "low" and rulebook.get(first.id).edited
    next(b for b in app.button if b.key == "rule_reset_" + first.id).click().run()
    assert rulebook.get(first.id).severity == first.severity

    # write a new rule: first an invalid one, then a valid one
    app.text_input(key="new_id").set_value("UI-RULE-001")
    app.text_input(key="new_title").set_value("eval of request data")
    app.multiselect(key="new_languages").set_value(["javascript"])
    app.text_input(key="new_cwe").set_value("CWE-95")
    app.text_area(key="new_pattern").set_value("eval((")
    button(app, "Save the rule").click().run()
    assert any("Not saved" in e.value for e in app.error)
    assert rules_engine.get_rule("UI-RULE-001") is None
    app.text_area(key="new_pattern").set_value(r"\beval\(\s*req\.")
    app.text_area(key="new_vulnerable").set_value("eval(req.body.code)")
    button(app, "Check the rule").click().run()
    assert any("passed every check" in s.value for s in app.success)
    button(app, "Save the rule").click().run()
    assert not app.exception
    assert rulebook.get("UI-RULE-001").origin == "custom"

    # try an expression
    app.text_area(key="try_pattern_").set_value(r"\beval\(")
    app.text_area(key="try_code_").set_value("x = 1\neval(data)\n")
    button(app, "Run the expression").click().run()
    assert any(">>   2  eval(data)" in c.value for c in app.code)


def test_guide_tab_shows_every_setting_diagram_and_reference_in_both_languages():
    from sca.ui import texts
    from sca.ui.i18n import AR
    images = ROOT / "docs" / "images"
    for item in texts.DIAGRAMS:                             # each diagram exists twice
        assert (images / ("%s.png" % item["name"])).is_file(), item["name"]
        assert (images / ("%s.ar.png" % item["name"])).is_file(), item["name"]
        assert item["text_en"] and item["text_ar"]
    for key, item in texts.SETTINGS.items():                # each setting is explained twice
        assert all(item["label"]) and all(item["help"]), key
    for english, arabic in AR.items():                      # placeholders survive translation
        assert english.count("%") == arabic.count("%"), english

    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception
    shown = " ".join(m.value for m in app.markdown)
    assert "Choose the project." in shown and "What a rule is" in shown
    assert "owasp.org/Top10" in shown and "python -m sca rules catalog" in " ".join(
        c.value for c in app.code)
    app.radio[0].set_value("العربية").run()
    assert not app.exception
    shown = " ".join(m.value for m in app.markdown)
    assert "اختر المشروع." in shown and "ما هي القاعدة؟" in shown and "حلقة التعلّم" in " ".join(
        h.value for h in app.subheader)
