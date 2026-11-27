"""Runs the Streamlit dashboard headlessly: start page, a full scan of the sample, reviews,
the Learning tab, loading a scan from history, a Flutter project and an uploaded app file.
Fails if the app raises any exception. Also checks that every text has its Arabic version."""
import ast
import hashlib
import os
import re
import zipfile
from collections import Counter
from io import BytesIO
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
# a conversion specifier of %-formatting: %s, %d, %.1f, %%
SPECIFIER = re.compile(r"%[-#0 +]*\d*(?:\.\d+)?[a-zA-Z%]")
PROPER_NAMES = {"JSON", "SARIF", "APK"}         # shown as they are in both languages
FLUTTER_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="tiny" android:debuggable="true"
        android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="tiny" android:host="open" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")       # test_introduction_pages shows it
    import streamlit as st
    st.cache_resource.clear()
    st.cache_data.clear()


def button(app: AppTest, label: str):
    return next(b for b in app.button if b.label == label)


def checkbox(app: AppTest, label: str):
    return next(c for c in app.checkbox if c.label.startswith(label))


def flutter_project(folder: Path) -> Path:
    """A tiny Flutter app: pubspec, Dart code and a debuggable Android manifest."""
    files = {
        "pubspec.yaml": "name: tiny_app\npublish_to: none\nversion: 1.0.0+3\nenvironment:\n"
                        "  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  flutter:\n    sdk: flutter\n",
        "lib/main.dart": "const api = 'http://api.tiny.example/v1/login';\n\n"
                         "void main() {\n  print(api);\n}\n",
        "android/app/build.gradle.kts": 'android {\n    namespace = "com.example.tiny"\n'
                                        '    defaultConfig {\n'
                                        '        applicationId = "com.example.tiny"\n'
                                        '        minSdk = 21\n        targetSdk = 34\n    }\n}\n',
        "android/app/src/main/AndroidManifest.xml": FLUTTER_MANIFEST,
    }
    for rel, text in files.items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_text(text, encoding="utf-8")
    return folder


def dashboard_texts():
    """(file, line, text) of every t("...") call with a literal text in the dashboard."""
    for path in [ROOT / "app.py"] + sorted((ROOT / "sca" / "ui").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "t" and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                yield path.name, node.lineno, node.args[0].value


def untranslated_steps(steps):
    """Templates and word arguments of scan messages that have no Arabic entry."""
    from sca.ui.i18n import AR
    missing = [s.template for s in steps
               if SPECIFIER.sub("", s.template).strip(" :-,") and s.template not in AR]
    missing += [s.args[1] for s in steps if s.template == "%s: skipped - %s"
                and s.args[1] not in AR]
    return missing


def test_splash_and_introduction_pages(monkeypatch):
    monkeypatch.delenv("SCA_SKIP_INTRO")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception
    shown = " ".join(m.value for m in app.markdown)
    assert "sca-splash" in shown and "Welcome to Secure Code Analyzer" in shown
    assert not any("Scan a project to begin" in h.value for h in app.header)   # not yet
    for title in ("How a scan works", "22 programming languages", "How a finding is decided",
                  "Start scanning"):
        button(app, "Next →").click().run()
        assert not app.exception
        assert any(title in h.value for h in app.header), title
        if title == "22 programming languages":           # the language cards and the app card
            cards = " ".join(m.value for m in app.markdown)
            assert "<b>Dart</b>" in cards and "Rules + input tracing + app checks" in cards
            assert "<b>Android apps</b>" in cards and ">.apk<" in cards
    assert "sca-splash" not in " ".join(m.value for m in app.markdown)   # once per session
    assert any(b.key == "intro_flutter_sample" for b in app.button)

    next(b for b in app.button if b.key == "intro_ar").click().run()      # language switch
    assert any("ابدأ الفحص" in h.value for h in app.header)
    next(b for b in app.button if b.key == "intro_sample").click().run()  # try the sample
    assert not app.exception
    assert app.session_state["target"].endswith("vulnerable_app")
    assert any("افحص مشروعاً للبدء" in h.value for h in app.header)        # the dashboard

    next(b for b in app.button if b.label == "اعرض المقدمة").click().run()  # open it again
    assert any("مرحباً بك" in m.value for m in app.markdown)


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
    assert not any("\u2066" in c.value for c in app.caption)   # isolates are for Arabic only
    # what the scan did, step by step, stays on the Dashboard tab
    assert any(e.label == "What the scan did, step by step" for e in app.expander)
    assert any("**\u25b8** Pattern rules: checking every line" in m.value for m in app.markdown)
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
    # right to left, but "0 / 100" must not read "100 / 0", and the scanned path must not
    # carry the file count away from its word
    css = next(m.value for m in app.markdown if "<style>" in m.value)
    assert "direction: ltr" in css.split('[data-testid="stMetricValue"]', 1)[1]
    assert any(c.value.startswith("\u2066") and "vulnerable\\_app\u2069 - " in c.value
               for c in app.caption)                  # the path is escaped for Markdown
    assert any(e.label == "\u0645\u0627\u0630\u0627 \u0641\u0639\u0644 \u0627\u0644\u0641\u062d\u0635\u060c \u062e\u0637\u0648\u0629 \u0628\u062e\u0637\u0648\u0629" for e in app.expander)
    assert any("\u0642\u0648\u0627\u0639\u062f \u0627\u0644\u0623\u0646\u0645\u0627\u0637: \u0645\u0637\u0627\u0628\u0642\u0629 \u0643\u0644 \u0633\u0637\u0631" in m.value for m in app.markdown)

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


def test_filters_show_all_severities_and_statuses_and_can_be_reset():
    from sca.models import Finding, ScanResult
    items = [
        Finding("TEST-A", "First", "a.xml", 1, severity="high"),
        Finding("TEST-B", "Second", "b.xml", 2, severity="info", status="needs_review"),
        Finding("TEST-C", "Third", "c.xml", 3, severity="low", status="dismissed"),
    ]
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state["result"] = ScanResult(target="sample", findings=items)
    app.run()
    assert not app.exception
    assert any(c.value == "3 of 3 findings." for c in app.caption)

    def widget(widgets, label):
        return next(w for w in widgets if w.label == label)

    widget(app.selectbox, "Show").set_value("open")
    widget(app.multiselect, "Severity").set_value(["high"])
    widget(app.multiselect, "File").set_value(["a.xml"])
    widget(app.text_input, "Search (title, CWE, code)").set_value("First").run()
    assert any("Showing 1 of 3 findings. The filters hide 2." in i.value for i in app.info)
    widget(app.text_input, "Search (title, CWE, code)").set_value("no matches").run()
    assert any("Showing 0 of 3 findings" in i.value for i in app.info)
    button(app, "Show all findings").click().run()
    assert not app.exception
    assert any(c.value == "3 of 3 findings." for c in app.caption)
    table = next(d.value for d in app.dataframe if "Tier" in d.value.columns)
    assert list(table["Title"]) == ["First", "Second", "Third"]
    assert table["Status"].nunique() == 3


def test_base_apk_with_adjacent_splits_has_a_scope_note(tmp_path):
    base = tmp_path / "base.apk"
    base.touch()
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    app.text_input(key="target").set_value(str(base)).run()
    assert any("An app file" in c.value for c in app.caption)
    (tmp_path / "split_config.ar.apk").touch()
    app.run()
    include = checkbox(app, "Include adjacent APK parts")
    assert include.value
    assert any(c.value == "APK files selected: 2" for c in app.caption)
    include.uncheck().run()
    assert any("An app file" in c.value for c in app.caption)


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
    app.text_input(key="target").set_value(str(ROOT / "no-such-folder")).run()
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
        # the C/C++ memory checks find the memcpy themselves; off, so the AI can teach it
        next(c for c in app.checkbox if c.label == "C/C++ memory checks").uncheck().run()
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


def test_rules_are_easy_to_find_with_their_file_types_and_file():
    from sca.walker import rule_extensions
    assert rule_extensions(["java"])[0] == sorted(
        [".java", ".jsp", ".jspf", ".jspx", ".kt", ".kts", ".scala", ".groovy"])
    assert ".php" in rule_extensions(["javascript"])[1]           # <script> inside pages
    assert rule_extensions(["any"]) == (["*"], [])

    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    next(b for b in app.button if b.label == "Open the rules").click().run()
    assert not app.exception
    assert app.session_state["main_tabs_en"] == "Rules"           # the Rules tab is open
    assert any(m.value.startswith("**Applies to:** `.") for m in app.markdown)   # file types
    assert any(c.value.startswith("Defined in sca/rules/") for c in app.caption)


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
    assert all(english in AR for english in ("Flutter and APK", "Dart and Flutter rules (%d)"))
    assert any("يُبلَّغ عن الثغرة" in limit[1] for limit in texts.LIMITS)

    from sca.flutter.checks import CHECKS
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception
    shown = " ".join(m.value for m in app.markdown)
    assert "Choose the project." in shown and "What a rule is" in shown
    assert "What is analysed" in shown and "kernel_blob.bin" in shown      # Flutter and APK
    assert "owasp.org/Top10" in shown and "mas.owasp.org" in shown
    assert "python -m sca rules catalog" in " ".join(c.value for c in app.code)
    checks = next(d.value for d in app.dataframe if "Runs on" in d.value.columns)
    assert list(checks["Check"]) == [check.id for check in CHECKS]
    dart = next(d.value for d in app.dataframe if list(d.value.columns)[:3] == [
        "Rule", "Title", "Kind"])
    kinds = dict(zip(dart["Rule"], dart["Kind"]))
    assert len(dart) >= 45 and set(dart["Rule"].str.split("-").str[0]) == {"DART", "FLUTTER"}
    assert kinds["DART-SECRET-001"] == kinds["DART-SECRET-003"] == "credential format"
    assert kinds["DART-TLS-001"] == "Dart code"
    assert kinds["FLUTTER-WEB-001"] == kinds["FLUTTER-FIREBASE-001"] == "Files around the app"
    counted = Counter(kinds.values())
    assert any(c.value.startswith("%d pattern rules for Dart code, %d pattern rules for the "
                                  "files around a Flutter app" % (counted["Dart code"],
                                                                  counted["Files around the app"]))
               and "and %d credential formats" % counted["credential format"] in c.value
               for c in app.caption)
    app.radio[0].set_value("العربية").run()
    assert not app.exception
    shown = " ".join(m.value for m in app.markdown)
    assert "اختر المشروع." in shown and "ما هي القاعدة؟" in shown and "حلقة التعلّم" in " ".join(
        h.value for h in app.subheader)
    assert "ما الذي يُحلَّل؟" in shown
    checks = next(d.value for d in app.dataframe if "يعمل على" in d.value.columns)
    assert list(checks["العنوان"]) == [check.title_ar for check in CHECKS]


def test_arabic_texts_keep_their_placeholders():
    """The same conversion specifiers in the same order: otherwise formatting an Arabic
    message raises, and a scan fails in Arabic only."""
    from sca.ui.i18n import AR
    for english, arabic in AR.items():
        assert SPECIFIER.findall(english) == SPECIFIER.findall(arabic), english


def test_every_dashboard_text_has_an_arabic_entry():
    from sca.flutter.checks import CHECKS
    from sca.pipeline import ENGINE_TEXT
    from sca.ui import app_panel
    from sca.ui.i18n import AR
    texts = list(dashboard_texts())
    assert len(texts) > 400                          # the scan of the code found the calls
    assert [item for item in texts if item[2] not in AR and item[2] not in PROPER_NAMES] == []
    # values of the app facts that the panel shows translated, and the Flutter stage
    words = (list(app_panel.KINDS.values()) + list(app_panel.COMPONENTS.values())
             + list(app_panel.FOUND_IN.values()) + list(app_panel.DEPENDENCIES.values())
             + list(app_panel.BUILD_MODES) + list(app_panel.FLAG_WORDS)
             + list(ENGINE_TEXT["flutter"]))
    assert [word for word in words if word not in AR] == []
    assert all(check.title and check.title_ar for check in CHECKS)


def test_app_panel_flag_texts():
    from sca.ui import app_panel
    from sca.ui.i18n import AR

    def arabic(text):
        return AR.get(text, text)

    assert app_panel.flag_text("allowed (network security config)", arabic) \
        == "مسموح (إعدادات أمان الشبكة)"
    assert app_panel.flag_text("allowed (default for targetSdk 27)", arabic) \
        == "مسموح (القيمة الافتراضية مع targetSdk 27)"
    assert app_panel.flag_text("yes (default), with backup rules", arabic) \
        == "نعم (القيمة الافتراضية)، مع قواعد للنسخ الاحتياطي"
    assert app_panel.flag_text("not allowed (android:usesCleartextTraffic)", arabic) \
        == "غير مسموح (android:usesCleartextTraffic)"
    assert app_panel.flag_text("@xml/network_security_config", arabic) \
        == "@xml/network_security_config"
    assert app_panel.flag_text("a, b (c", str) == "a, b (c"          # kept as it is


def test_dashboard_scans_a_flutter_project(tmp_path):
    folder = flutter_project(tmp_path / "tiny_app")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180)
    app.run()
    assert checkbox(app, "Flutter / Android checks").value
    tools = checkbox(app, "Decompile and verify app files (jadx, apksigner)")
    assert not tools.value                                  # optional tools stay off
    app.text_input(key="target").set_value(str(folder)).run()
    assert any("A Flutter project" in c.value for c in app.caption)
    button(app, "Run scan").click().run()
    assert not app.exception
    result = app.session_state["result"]
    assert result.app["kind"] == "flutter-project" and result.app["package"] == "com.example.tiny"
    assert {"ANDROID-MANIFEST-001", "ANDROID-MANIFEST-007"} <= {f.rule_id for f in result.findings}
    assert untranslated_steps(result.steps) == []
    # the app panel, the OWASP Mobile charts and the tags of each finding
    assert any(e.label.startswith("Flutter project: tiny") for e in app.expander)
    metrics = {m.label: m.value for m in app.metric}
    assert "**Package:** com.example.tiny" in [m.value for m in app.markdown]
    assert metrics["Min / target SDK"] == "21 / 34"
    assert metrics["Version"] == "1.0.0 (3)" and metrics["Platforms"] == "android"
    assert any(s.value == "By OWASP Mobile Top 10 (2024)" for s in app.subheader)
    assert any("M5 Insecure Communication" in m.value and "MASVS-NETWORK" in m.value
               for m in app.markdown)
    permissions = next(d.value for d in app.dataframe if "Dangerous" in d.value.columns)
    assert permissions.to_dict("records") == [{"Permission": "android.permission.CAMERA",
                                               "Dangerous": "yes"}]

    app.radio[0].set_value("العربية").run()
    assert not app.exception
    assert any(e.label.startswith("مشروع Flutter: ") for e in app.expander)
    labels = {m.label for m in app.metric}
    assert {"الإصدار", "المنصّات", "SDK الأدنى / المستهدف"} <= labels
    assert any(m.value.startswith("**الحزمة:**") for m in app.markdown)
    assert any(s.value == "حسب فئات OWASP Mobile Top 10 (2024)" for s in app.subheader)
    permissions = next(d.value for d in app.dataframe if "خطرة" in d.value.columns)
    assert list(permissions["خطرة"]) == ["نعم"]

    checkbox(app, "فحوص Flutter و Android").uncheck().run()    # the switch of the engine
    button(app, "ابدأ الفحص").click().run()
    assert not app.exception
    result = app.session_state["result"]
    assert result.app == {} and not any(f.rule_id.startswith("ANDROID-") for f in result.findings)
    assert any(s.args == ("Flutter/Android checks", "switched off") for s in result.steps)
    assert not any(e.label.startswith("مشروع Flutter") for e in app.expander)


def test_dashboard_scans_an_uploaded_app_file(tmp_path):
    if not hasattr(AppTest, "file_uploader"):
        pytest.skip("this Streamlit version cannot upload files in AppTest")
    from flutter_kit import build_apk
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180)
    app.run()
    broken = tmp_path / "broken.apk"
    broken.write_bytes(b"not a zip archive")
    app.text_input(key="target").set_value(str(broken)).run()
    button(app, "Run scan").click().run()
    assert any("not a readable app package" in e.value for e in app.error)

    # an upload that is not a ZIP archive is refused and not kept
    uploads = tmp_path / "data" / "uploads"
    app.file_uploader(key="app_upload").set_value(("junk.apk", b"not a zip", "x")).run()
    assert not app.exception
    assert app.session_state["target"] == ""                # never scan the previous input by mistake
    assert any("not a readable app package" in c.value and "junk.apk" in c.value
               for c in app.warning)
    assert not uploads.exists() or list(uploads.iterdir()) == []

    data = build_apk()
    app.file_uploader(key="app_upload").set_value(          # a name in Arabic letters
        ("تطبيق.apk", data, "application/vnd.android.package-archive")).run()
    assert not app.exception
    target = Path(app.session_state["target"])
    assert target == tmp_path / "data" / "uploads" / (
        "%s-app.apk" % hashlib.sha256(data).hexdigest()[:12])
    assert target.read_bytes() == data
    assert any("An app file" in c.value for c in app.caption)
    # the same app under another name is the same file and the same target (History)
    app.file_uploader(key="app_upload").set_value(("second name.apk", data, "x")).run()
    assert app.session_state["target"] == str(target)
    assert [p.name for p in uploads.iterdir()] == [target.name]
    button(app, "Run scan").click().run()
    assert not app.exception
    result = app.session_state["result"]
    assert result.app["kind"] == "apk" and result.app["build_mode"] == "release"
    assert "ANDROID-SIGN-001" in {f.rule_id for f in result.findings}
    assert untranslated_steps(result.steps) == []
    assert any(s.args == ("Bandit", "not used for app packages") for s in result.steps)
    assert any(e.label == "Flutter app: com.example.kitapp" for e in app.expander)
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Build mode"] == "release" and metrics["Version"] == "1.2.3 (7)"
    details = next(d.value for d in app.dataframe if "Fact" in d.value.columns)
    assert dict(zip(details["Fact"], details["Value"]))["Size"] == \
        "%d KB" % round(len(data) / 1000)                    # decimal units, as in the docs
    certificates = next(d.value for d in app.dataframe if "Issuer" in d.value.columns)
    assert list(certificates["Android debug certificate"]) == ["yes"]
    assert any(c.value.startswith("Signature schemes: v2. The signature is not verified")
               for c in app.caption)

    app.radio[0].set_value("العربية").run()
    assert not app.exception
    assert any(e.label.startswith("تطبيق Flutter: ") for e in app.expander)
    assert {m.label: m.value for m in app.metric}["نوع البناء"] == "إصدار (release)"
    details = next(d.value for d in app.dataframe if "المعلومة" in d.value.columns)
    assert dict(zip(details["المعلومة"], details["القيمة"]))["النوع"] == "تطبيق Android (APK)"
    assert any(c.value.startswith("مخططات التوقيع: v2.") for c in app.caption)


def flutter_zip(folder: Path) -> bytes:
    with BytesIO() as buffer:
        with zipfile.ZipFile(buffer, "w") as archive:
            for file in folder.rglob("*"):
                if file.is_file():
                    archive.write(file, file.relative_to(folder.parent).as_posix())
        return buffer.getvalue()


@pytest.mark.parametrize("hosted_mode", [False, True])
def test_dashboard_scans_an_uploaded_source_zip(tmp_path, monkeypatch, hosted_mode):
    if not hasattr(AppTest, "file_uploader"):
        pytest.skip("this Streamlit version cannot upload files in AppTest")
    if hosted_mode:
        monkeypatch.setenv("SCA_HOSTED", "1")
        monkeypatch.delenv("SCA_SCAN_ROOT", raising=False)
    source = flutter_project(tmp_path / "tiny")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180).run()
    app.file_uploader(key="app_upload").set_value(
        ("flutter.zip", flutter_zip(source), "application/zip")).run()
    button(app, "Run scan").click().run()
    assert not app.exception
    assert any("use unencrypted" in error.value for error in app.error)
    result = app.session_state["result"]
    assert result.app["kind"] == "flutter-project"
    assert any(f.file == "android/app/src/main/AndroidManifest.xml" for f in result.findings)
    if hosted_mode:
        assert result.target == "flutter.zip" and result.scan_id is None
        assert not (tmp_path / "data").exists()
        assert result.decoded_files and all(f.original is None for f in result.decoded_files.values())
        labels = {tab.label for tab in app.tabs}
        assert {"Dashboard", "Findings", "Source files", "Reports", "Guide"} <= labels
        assert {"Rules", "Learning", "History"}.isdisjoint(labels)
    else:
        assert Path(result.target).suffix == ".zip" and result.scan_id is not None


def test_dashboard_hosted_accepts_a_scoped_path_and_apk(tmp_path, monkeypatch):
    if not hasattr(AppTest, "file_uploader"):
        pytest.skip("this Streamlit version cannot upload files in AppTest")
    from flutter_kit import build_apk

    projects = tmp_path / "projects"
    flutter_project(projects / "tiny")
    monkeypatch.setenv("SCA_HOSTED", "1")
    monkeypatch.setenv("SCA_SCAN_ROOT", str(projects))
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180).run()
    app.radio(key="scan_input").set_value("path").run()
    app.text_input(key="server_path").set_value("tiny").run()
    button(app, "Run scan").click().run()
    assert not app.exception
    assert app.session_state["result"].target == "tiny"
    assert app.session_state["result"].app["kind"] == "flutter-project"

    app.text_input(key="server_path").set_value("..").run()
    button(app, "Run scan").click().run()
    assert any("inside the server project directory" in error.value for error in app.error)

    app.radio(key="scan_input").set_value("upload").run()
    app.file_uploader(key="app_upload").set_value(
        ("app.apk", build_apk(), "application/vnd.android.package-archive")).run()
    button(app, "Run scan").click().run()
    assert not app.exception
    assert app.session_state["result"].target == "app.apk"
    assert app.session_state["result"].app["kind"] == "apk"
    assert not (tmp_path / "data").exists()


def test_workspace_names_the_kind_of_folder_without_walking_it(tmp_path):
    """A pure Dart package is not a Flutter project; an Android project gets its caption."""
    dart = tmp_path / "dart_cli"
    (dart / "bin").mkdir(parents=True)
    (dart / "pubspec.yaml").write_text("name: dart_cli\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\n"
                                       "dependencies:\n  http: ^1.1.0\n", encoding="utf-8")
    droid = tmp_path / "droid"
    (droid / "app" / "src" / "main").mkdir(parents=True)
    (droid / "app" / "src" / "main" / "AndroidManifest.xml").write_text(FLUTTER_MANIFEST,
                                                                        encoding="utf-8")
    (droid / "app" / "build.gradle").write_text("plugins { id 'com.android.application' }\n",
                                                encoding="utf-8")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    for folder, expected in ((dart, None), (droid, "An Android project"),
                             (flutter_project(tmp_path / "tiny"), "A Flutter project")):
        app.text_input(key="target").set_value(str(folder)).run()
        assert not app.exception
        captions = [c.value for c in app.caption
                    if "project:" in c.value or "app file:" in c.value]
        if expected is None:
            assert captions == [], folder.name
        else:
            assert len(captions) == 1 and captions[0].startswith(expected), captions
    app.radio[0].set_value("العربية").run()
    assert any(c.value.startswith("مشروع Flutter") for c in app.caption)


def test_texts_of_a_scan_are_shown_as_text_not_as_markdown():
    """Titles, file names, descriptions and facts can quote the scanned app: in labels,
    captions and metrics they must not become links, images or formatting."""
    from sca.models import Finding, ScanResult
    link = "![x](http://evil.example/x.png) [click](http://evil.example)"
    finding = Finding(rule_id="ANDROID-X", title="Exported receiver: " + link,
                      file="lib/a_b_*c*.dart", line=3, severity="high", cwe="CWE-99999",
                      confidence=0.8, engines=["flutter"], snippet="x",
                      description="Quoted " + link, fix="Fix " + link,
                      ai_verdict="true_positive", ai_model="m", ai_explanation="AI " + link)
    facts = {"kind": "apk", "flutter": False, "package": "com.a_b " + link,
             "version_name": "1.0", "min_sdk_note": link, "build_mode": "unknown",
             "signing": {"schemes": ["v2 " + link], "certificates": []}}
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.session_state["result"] = ScanResult(target="C:/apps/[a](http://evil.example).apk",
                                             app=facts, findings=[finding])
    app.run()
    assert not app.exception
    shown = ([e.label for e in app.expander] + [m.value for m in app.markdown]
             + [c.value for c in app.caption] + [i.value for i in app.info]
             + [str(m.value) for m in app.metric])
    quoted = [text for text in shown if "evil.example" in text]
    assert len(quoted) >= 8
    assert [text for text in quoted if re.search(r"(?<!\\)\]\(", text)] == []
    label = next(e.label for e in app.expander if e.label.startswith("HIGH"))
    assert label == ("HIGH | Exported receiver: !\\[x\\](http:⁠//evil.example/x.png) "
                     "\\[click\\](http:⁠//evil.example) | lib/a\\_b\\_\\*c\\*.dart:3")
    # the facts of an Android app without Flutter: no build mode, no Dart packages
    assert "Build mode" not in {m.label for m in app.metric}
    assert not [m.value for m in app.markdown if m.value.startswith("**Dart packages (")]


@pytest.mark.skipif(not os.environ.get("SCA_FLUTTER_PROBE_DIR"),
                    reason="set SCA_FLUTTER_PROBE_DIR to the APKs built from "
                           "samples/flutter_apk_probe")
def test_dashboard_scans_the_real_probe_apks():
    folder = Path(os.environ["SCA_FLUTTER_PROBE_DIR"])
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=300)
    app.run()
    expected = {"ANDROID-SIGN-001", "ANDROID-NSC-001", "ANDROID-FILEPROVIDER-001",
                "ANDROID-MANIFEST-005", "ANDROID-MANIFEST-007"}
    for name, mode, also in (("release.apk", "release", "FLUTTER-APP-003"),
                             ("debug.apk", "debug", "FLUTTER-APP-001"),
                             ("release.aab", "release", "FLUTTER-APP-007")):
        app.text_input(key="target").set_value(str(folder / name)).run()
        button(app, "Run scan").click().run()
        assert not app.exception, name
        result = app.session_state["result"]
        assert result.app["build_mode"] == mode, name
        assert expected | {also} <= {f.rule_id for f in result.findings}, name
        assert untranslated_steps(result.steps) == [], name
        assert any(e.label.startswith("Flutter app: com.example.flutter") for e in app.expander)
        assert any(s.value == "By OWASP Mobile Top 10 (2024)" for s in app.subheader)
    if os.environ.get("SCA_JADX"):                  # the optional tools on the release APK
        checkbox(app, "Decompile and verify app files").check().run()
        app.text_input(key="target").set_value(str(folder / "release.apk")).run()
        button(app, "Run scan").click().run()
        assert not app.exception
        result = app.session_state["result"]
        assert result.app["tools"]["jadx"].startswith("ok")
        details = next(d.value for d in app.dataframe if "Fact" in d.value.columns)
        assert "jadx" in set(details["Fact"])
