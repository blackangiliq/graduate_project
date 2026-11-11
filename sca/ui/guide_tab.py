"""The Guide tab of the dashboard: instructions, every setting, rule writing, the diagrams
with their explanation, references and limits - in English or Arabic."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Dict

import pandas as pd
import streamlit as st

from .. import rulebook
from . import texts

ROOT = Path(__file__).resolve().parent.parent.parent
IMAGES = ROOT / "docs" / "images"
IMAGE_LINE = re.compile(r"^\s*!\[([^\]]*)\]\(([^)\s]+)\)\s*$")
DOCUMENTS = [
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
    start, settings, rules, diagrams, cli, refs, docs = st.tabs([
        t("Quick start"), t("Every setting"), t("Writing rules"), t("Diagrams"),
        t("Command line"), t("References and limits"), t("Full documents")])

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
        st.caption(t("Every control of the sidebar, what it does and when to change it. The "
                     "same text appears as the (?) tooltip next to each control."))
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
