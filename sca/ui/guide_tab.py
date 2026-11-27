"""The Guide tab of the dashboard: instructions, every setting, rule writing, Flutter and
APK analysis, the diagrams with their explanation, references and limits - in English or
Arabic."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Dict

import pandas as pd
import streamlit as st

from .. import rulebook
from ..cwe import MASVS_GROUPS, MOBILE_TOP10_2024
from ..engines import rules_engine
from ..flutter.checks import AREAS, CHECKS, TARGETS
from . import texts

ROOT = Path(__file__).resolve().parent.parent.parent
IMAGES = ROOT / "docs" / "images"
IMAGE_LINE = re.compile(r"^\s*!\[([^\]]*)\]\(([^)\s]+)\)\s*$")
# the rules of sca/rules/dart.yaml and sca/rules/flutter.yaml, shown on the Flutter page
MOBILE_RULES = ("DART-", "FLUTTER-")
DOCUMENTS = [
    ("docs/VALIDATION_2026_11_27.md", "التحقق والمقارنة المستقلة للتطبيقات", "Independent application validation"),
    ("docs/UPSTREAM_RULES_2026_11_27.md", "مصادر القواعد وتوسعتها", "Upstream rule sources and expansion"),
    ("docs/DYNAMIC_ANALYSIS.md", "التحليل أثناء التشغيل وإعداد Windows", "Runtime analysis and Windows setup"),
    ("docs/EXTERNAL_ENGINES.md", "التحقق بمحركات خارجية", "External engine validation"),
    ("docs/GUIDE_AR.md", "الدليل الكامل بالعربية", "Complete guide (Arabic)"),
    ("docs/SUPERVISOR_AR.md", "وثيقة المشرف", "Supervisor document (Arabic)"),
    ("docs/DIAGRAMS_AR.md", "شرح المخططات مع مثال رقمي", "Diagrams walk-through (Arabic)"),
    ("docs/DIAGRAMS.md", "شرح المخططات بالإنجليزية", "Diagrams explained (English)"),
    ("docs/RULES.md", "دليل القواعد (عربي وإنجليزي)", "Rules guide (English and Arabic)"),
    ("evaluation/owasp_benchmark.md", "نتائج OWASP Benchmark لكل فئة",
     "OWASP Benchmark results per category"),
    ("evaluation/results.md", "نتائج التقييم على العيّنات", "Evaluation on the samples"),
    ("README.md", "ملف README بالإنجليزية", "README (English)"),
    ("docs/ARCHITECTURE.md", "المعمارية بالإنجليزية", "Architecture (English)"),
    ("docs/THESIS_OUTLINE_AR.md", "هيكل بحث التخرج", "Thesis outline (Arabic)"),
    ("docs/FLUTTER_AR.md", "تحليل Flutter و APK بالعربية", "Flutter and APK analysis (Arabic)"),
    ("docs/FLUTTER.md", "تحليل Flutter و APK بالإنجليزية", "Flutter and APK analysis (English)"),
]


def show_markdown(path: Path) -> None:
    """Render a Markdown file of the repository, with its images."""
    chunk = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = IMAGE_LINE.match(line)
        if not match:
            chunk.append(line)
            continue
        if chunk:
            st.markdown("\n".join(chunk))
            chunk = []
        image = (path.parent / match.group(2)).resolve()
        if image.is_file():
            st.image(str(image), caption=match.group(1) or None)
    if chunk:
        st.markdown("\n".join(chunk))


def _image(name: str, lang: str, caption: str = "") -> None:
    """Show a diagram in the wanted language; fall back to the other language."""
    names = ["%s.ar.png" % name, "%s.png" % name]
    for candidate in names if lang == "ar" else names[::-1]:
        if (IMAGES / candidate).is_file():
            st.image(str(IMAGES / candidate), caption=caption or None)
            return


def render(t: Callable[[str], str], lang: str, wide: Dict) -> None:
    index = 1 if lang == "ar" else 0
    start, settings, rules, flutter, diagrams, cli, refs, docs = st.tabs([
        t("Quick start"), t("Every setting"), t("Writing rules"), t("Flutter and APK"),
        t("Diagrams"), t("Command line"), t("References and limits"), t("Full documents")])

    with start:
        st.subheader(t("How to use the tool"))
        for number, step in enumerate(texts.QUICK_START, start=1):
            st.markdown("%d. %s" % (number, step[index]))
        shot = IMAGES / "dashboard.png"
        if shot.is_file():
            st.image(str(shot), caption=t("The dashboard after scanning the sample application"))
        st.subheader(t("What each tab is for"))
        st.table(pd.DataFrame([{t("Tab"): tab[index], t("What it shows"): tab[2 + index]}
                               for tab in texts.TABS]))
        _image("usage", lang, t("The steps as a diagram"))

    with settings:
        st.caption(t("The help next to each scan setting explains what it does."))
        groups: Dict[str, list] = {}
        for item in texts.SETTINGS.values():
            groups.setdefault(item["group"][index], []).append(item)
        for group, items in groups.items():
            st.markdown("#### %s" % group)
            st.table(pd.DataFrame([{t("Setting"): i["label"][index],
                                    t("What it does"): i["help"][index]} for i in items]))

    with rules:
        counts = rulebook.summary()
        origins = counts["by_origin"]
        st.subheader(t("The rule set today"))
        st.table(pd.DataFrame([
            {t("Origin"): t("Built in"), t("Rules"): origins["builtin"]["total"],
             t("Active"): origins["builtin"]["enabled"],
             t("Where they come from"): t("Written and tested with this tool, per language.")},
            {t("Origin"): t("Imported"), t("Rules"): origins["imported"]["total"],
             t("Active"): origins["imported"]["enabled"],
             t("Where they come from"): t("Converted from Microsoft DevSkim (code patterns) and "
                                          "Gitleaks (credential formats), both MIT licensed. "
                                          "Each rule was checked automatically and measured on "
                                          "2.4 million lines of well-known open-source code; "
                                          "noisy ones ship switched off.")},
            {t("Origin"): t("Learned"), t("Rules"): origins["learned"]["total"],
             t("Active"): origins["learned"]["enabled"],
             t("Where they come from"): t("Proposed by the AI, validated automatically, "
                                          "approved by you in the Learning tab.")},
            {t("Origin"): t("Your own"), t("Rules"): origins["custom"]["total"],
             t("Active"): origins["custom"]["enabled"],
             t("Where they come from"): t("Written by you in the Rules tab or in a YAML file.")},
        ]))
        st.markdown(texts.RULE_GUIDE_AR if lang == "ar" else texts.RULE_GUIDE_EN)
        st.markdown("#### %s" % t("An empty rule to start from"))
        st.code(rulebook.TEMPLATE, language="yaml")
        _image("rules", lang)

    with flutter:
        _flutter(t, index, wide)

    with diagrams:
        st.caption(t("Seven diagrams explain the project from the general picture to the "
                     "details. Each one starts with what it means."))
        both = st.checkbox(t("Show each diagram in both languages"), key="guide_both")
        for item in texts.DIAGRAMS:
            st.subheader(item["title_ar"] if lang == "ar" else item["title_en"])
            st.markdown(item["text_ar"] if lang == "ar" else item["text_en"])
            _image(item["name"], lang)
            if both:
                other = "en" if lang == "ar" else "ar"
                st.markdown(item["text_ar"] if other == "ar" else item["text_en"])
                _image(item["name"], other)
            st.divider()

    with cli:
        st.caption(t("Everything the dashboard does can also be done from a terminal, in the "
                     "project folder."))
        for command, en, ar in texts.CLI:
            st.markdown(ar if lang == "ar" else en)
            st.code(command, language="bash")

    with refs:
        st.subheader(t("References"))
        for title, url, en, ar in texts.REFERENCES:
            st.markdown("- [%s](%s) - %s" % (title, url, ar if lang == "ar" else en))
        st.subheader(t("Limits"))
        for limit in texts.LIMITS:
            st.markdown("- %s" % limit[index])

    with docs:
        st.caption(t("The documents of the repository, readable here with their images."))
        available = [d for d in DOCUMENTS if (ROOT / d[0]).is_file()]
        names = {d[0]: d[1] if lang == "ar" else d[2] for d in available}
        chosen = st.selectbox(t("Document"), list(names), key="guide_doc_" + lang,
                              format_func=names.get)
        if chosen in names:
            show_markdown(ROOT / chosen)


def _flutter(t: Callable[[str], str], index: int, wide: Dict) -> None:
    """What the Flutter / Android analysis reads, with its checks and rules as tables
    built from the code, so that they cannot drift from it."""
    st.markdown(texts.FLUTTER_GUIDE_AR if index else texts.FLUTTER_GUIDE_EN)
    st.markdown("#### %s" % (t("Checks of the Flutter / Android engine (%d)") % len(CHECKS)))
    st.caption(t("Severity and confidence are the defaults: a finding can lower them, for "
                 "example when a setting is only implied by a default."))
    st.dataframe(pd.DataFrame([{
        t("Check"): check.id, t("Title"): check.title_ar if index else check.title,
        "CWE": check.cwe, t("Severity"): t(check.severity.capitalize()),
        t("Confidence"): check.confidence, t("Area"): AREAS[check.area][index],
        t("Runs on"): TARGETS[check.target][index]} for check in CHECKS]),
        hide_index=True, **wide)
    rules = [rule for rule in rules_engine.all_rules() if rule.id.startswith(MOBILE_RULES)]
    secret = [rule for rule in rules if rule.kind == "secret"]
    dart = [rule for rule in rules if rule.kind != "secret" and rule.id.startswith("DART-")]
    around = [rule for rule in rules if rule.kind != "secret" and rule not in dart]
    st.markdown("#### %s" % (t("Dart and Flutter rules (%d)") % len(rules)))
    st.caption(t("%d pattern rules for Dart code, %d pattern rules for the files around a "
                 "Flutter app (CI build scripts, Firebase Security Rules, web/index.html) and "
                 "%d credential formats, which the secrets engine runs. Like every rule, they "
                 "can be read, changed or switched off in the Rules tab.")
               % (len(dart), len(around), len(secret)))
    kinds = [(dart, t("Dart code")), (around, t("Files around the app")),
             (secret, t("credential format"))]
    st.dataframe(pd.DataFrame([{
        t("Rule"): rule.id, t("Title"): rule.title, t("Kind"): kind, "CWE": rule.cwe,
        t("Severity"): t(rule.severity.capitalize()),
        t("State"): t("on") if rule.enabled else t("off")}
        for group, kind in kinds for rule in group]), hide_index=True, **wide)
    st.markdown("#### %s" % t("OWASP Mobile Top 10 (2024) and MASVS"))
    st.caption(t("The findings of a mobile app are tagged with one risk and one MASVS group, "
                 "chosen from their CWE. The mapping is the project's own, not an official "
                 "OWASP one."))
    left, right = st.columns(2)
    left.dataframe(pd.DataFrame([{t("Risk"): risk, t("Name"): names[index]}
                                 for risk, names in MOBILE_TOP10_2024.items()]),
                   hide_index=True, **wide)
    right.dataframe(pd.DataFrame([{t("Group"): group, t("Name"): names[index]}
                                  for group, names in MASVS_GROUPS.items()]),
                    hide_index=True, **wide)
