"""The splash screen and the introduction pages shown when the dashboard is opened.

The splash is a full-screen overlay drawn with CSS only: it plays once per browser session
and fades out by itself, so it never blocks the app. The introduction pages follow; they
explain how a scan works, which languages are covered and how a finding is decided. Every
number on them (languages, file types, rules) is computed from the code, so the pages
cannot drift from the tool. Set SCA_SKIP_INTRO=1 to open the dashboard directly.
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path
from typing import Dict, List, Tuple

import streamlit as st

from .. import __version__
from ..engines import rules_engine, secrets, taint_lite
from ..flutter import APP_SUFFIXES
from ..flutter.checks import CHECKS
from ..pipeline import ENGINE_TEXT
from ..walker import CODE_LANGUAGES, LANG_BY_EXT, RULE_LANGUAGE

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ROOT / "docs" / "images"
LABS = ROOT / "infected_project"
PAGES = 5
IMAGE_WIDE = ({"width": "stretch"} if inspect.signature(st.image).parameters["width"].default
              == "content" else {"use_container_width": True})
BUTTON_WIDE = ({"width": "stretch"} if "width" in inspect.signature(st.button).parameters
               else {"use_container_width": True})

NAMES = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
         "php": "PHP", "java": "Java", "kotlin": "Kotlin", "scala": "Scala",
         "groovy": "Groovy", "c": "C", "cpp": "C++", "csharp": "C#", "go": "Go",
         "ruby": "Ruby", "rust": "Rust", "swift": "Swift", "dart": "Dart", "shell": "Shell",
         "powershell": "PowerShell", "perl": "Perl", "lua": "Lua", "elixir": "Elixir",
         "sql": "SQL"}
# languages whose findings can be traced back to user input (taint_lite sources)
TRACED = {language for language in CODE_LANGUAGES
          if RULE_LANGUAGE.get(language, language) in taint_lite.SOURCES}

SHIELD = ('<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">'
          '<path d="M32 4 8 13v17c0 15 10 26 24 30 14-4 24-15 24-30V13Z" fill="#ff4b4b"/>'
          '<path d="M32 9 13 16.5v13.6c0 12 8 21 19 24.4V9Z" fill="#ff7a7a"/>'
          '<path d="m22 32 7 7 14-15" fill="none" stroke="#fff" stroke-width="5" '
          'stroke-linecap="round" stroke-linejoin="round"/></svg>')

SPLASH_CSS = (
    "<style>"
    "@keyframes sca-out{to{opacity:0;visibility:hidden}}"
    "@keyframes sca-pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}"
    "@keyframes sca-bar{from{width:0}to{width:100%}}"
    "@keyframes sca-up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}"
    ".sca-splash{position:fixed;inset:0;z-index:1000000;display:flex;flex-direction:column;"
    "align-items:center;justify-content:center;gap:14px;color:#fff;text-align:center;"
    "background:radial-gradient(circle at 50% 38%,#26324f 0%,#0b0f1a 72%);"
    "animation:sca-out .7s ease 2.6s forwards}"
    ".sca-splash svg{width:120px;height:120px;animation:sca-pulse 1.6s ease-in-out infinite}"
    ".sca-splash .t{font-size:2.5rem;font-weight:700;animation:sca-up .8s ease both}"
    ".sca-splash .s{opacity:.85;font-size:1.05rem;animation:sca-up .8s ease .25s both}"
    ".sca-splash .bar{width:280px;height:4px;border-radius:2px;margin-top:10px;"
    "background:rgba(255,255,255,.15);overflow:hidden}"
    ".sca-splash .bar i{display:block;height:100%;background:#ff4b4b;"
    "animation:sca-bar 2.4s ease forwards}"
    ".sca-splash .v{opacity:.55;font-size:.8rem}"
    "</style>")

PAGE_CSS = (
    "<style>"
    "[data-testid='stSidebar'],[data-testid='stSidebarCollapsedControl'],"
    "[data-testid='stExpandSidebarButton']{display:none}"
    ".sca-hero{display:flex;align-items:center;gap:18px}"
    ".sca-hero svg{width:64px;height:64px;flex:none}"
    ".sca-dots{letter-spacing:6px;font-size:1.1rem;opacity:.8}"
    ".sca-stat{border-radius:12px;padding:14px 10px;text-align:center;"
    "background:rgba(255,75,75,.09);border:1px solid rgba(255,75,75,.35)}"
    ".sca-stat b{display:block;font-size:2rem;color:#ff4b4b}"
    ".sca-card{border-radius:10px;padding:10px 12px;margin-bottom:10px;min-height:112px;"
    "border:1px solid rgba(128,128,128,.35)}"
    ".sca-card b{font-size:1.05rem}.sca-card small{opacity:.75}"
    ".sca-chip{display:inline-block;margin:2px 4px 2px 0;padding:0 7px;border-radius:9px;"
    "font-size:.78rem;background:rgba(128,128,128,.18);direction:ltr;unicode-bidi:isolate}"
    "</style>")


def _(lang: str, en: str, ar: str) -> str:
    return ar if lang == "ar" else en


def active() -> bool:
    """True while the introduction is shown (the first visit of a browser session)."""
    if os.environ.get("SCA_SKIP_INTRO") == "1":
        return False
    return st.session_state.setdefault("intro_page", 1) is not None


def reopen() -> None:
    st.session_state["intro_page"] = 1


def _finish(target: str = "") -> None:
    st.session_state["intro_page"] = None
    if target:
        st.session_state["target"] = target


MAIN_TABS_KEY = "main_tabs_"        # + language: the state of the dashboard's tabs


def open_rules(lang: str) -> None:
    """Close the introduction and open the Rules tab (view, edit and write rules)."""
    st.session_state["intro_page"] = None
    st.session_state[MAIN_TABS_KEY + lang] = "القواعد" if lang == "ar" else "Rules"


def _go(page: int) -> None:
    st.session_state["intro_page"] = page


def _set_lang(value: str) -> None:
    st.session_state["ui_lang"] = value


def _image(name: str, lang: str, caption: str = "") -> None:
    path = IMAGES / ("%s.ar.png" % name if lang == "ar" else "%s.png" % name)
    if not path.is_file():
        path = IMAGES / ("%s.png" % name)
    if path.is_file():
        st.image(str(path), caption=caption or None, **IMAGE_WIDE)


def labs() -> List[str]:
    """The training labs downloaded into infected_project (see fetch_labs.py)."""
    if not LABS.is_dir():
        return []
    return sorted(p.name for p in LABS.iterdir() if p.is_dir() and not p.name.startswith(".")
                  and p.name not in ("reports", "__pycache__"))


def facts() -> Dict[str, int]:
    rules = rules_engine.all_rules()
    return {"languages": len(CODE_LANGUAGES), "extensions": len(LANG_BY_EXT),
            "rules": sum(1 for r in rules if r.enabled),
            "secrets": sum(1 for r in rules if r.enabled and r.kind == "secret")
                       + len(secrets.KNOWN_FORMATS),
            "checks": len(CHECKS), "engines": len(ENGINE_TEXT), "traced": len(TRACED)}


def language_table() -> List[Tuple[str, str, int, str]]:
    """(name, extensions, active pattern rules, depth) for every code language."""
    rules = rules_engine.load_rules()
    by_language: Dict[str, List[str]] = {}
    for ext, language in LANG_BY_EXT.items():
        by_language.setdefault(language, []).append(ext)
    rows = []
    for language in CODE_LANGUAGES:
        count = len(rules_engine.rules_for(RULE_LANGUAGE.get(language, language), rules))
        if language == "python":
            depth = "ast"
        elif language in ("c", "cpp"):
            depth = "memory"
        elif language == "dart":
            depth = "flutter"
        elif language in TRACED:
            depth = "traced"
        else:
            depth = "rules"
        rows.append((NAMES.get(language, language), " ".join(sorted(by_language.get(language, []))),
                     count, depth))
    return rows


# ---------------------------------------------------------------------------- drawing
def splash(lang: str) -> None:
    """The splash overlay. Shown once per browser session; it removes itself with CSS."""
    if st.session_state.get("splash_shown"):
        return
    st.session_state["splash_shown"] = True
    st.markdown(SPLASH_CSS + '<div class="sca-splash">%s<div class="t">Secure Code Analyzer</div>'
                '<div class="s">%s</div><div class="bar"><i></i></div><div class="v">v%s</div>'
                '</div>' % (SHIELD, _(lang, "Finding security weaknesses in source code and "
                                            "Android apps",
                                      "كشف الثغرات الأمنية في الكود المصدري وتطبيقات Android"),
                            __version__),
                unsafe_allow_html=True)


def render(lang: str) -> None:
    splash(lang)
    st.markdown(PAGE_CSS, unsafe_allow_html=True)
    page = st.session_state.get("intro_page") or 1

    top = st.columns([6, 1, 1, 1])
    top[0].markdown('<span class="sca-dots">%s</span> &nbsp; %s' % (
        " ".join("●" if i == page else "○" for i in range(1, PAGES + 1)),
        _(lang, "Page %d of %d", "الصفحة %d من %d") % (page, PAGES)), unsafe_allow_html=True)
    top[1].button("English", key="intro_en", on_click=_set_lang, args=("English",), **BUTTON_WIDE)
    top[2].button("العربية", key="intro_ar", on_click=_set_lang, args=("العربية",), **BUTTON_WIDE)
    top[3].button(_(lang, "Skip", "تخطَّ"), key="intro_skip", on_click=_finish, **BUTTON_WIDE)

    (_welcome, _how, _languages, _mechanism, _start)[page - 1](lang)

    st.divider()
    nav = st.columns([1, 4, 1])
    if page > 1:
        nav[0].button(_(lang, "← Back", "→ السابق"), key="intro_back", on_click=_go,
                      args=(page - 1,), **BUTTON_WIDE)
    if page < PAGES:
        nav[2].button(_(lang, "Next →", "التالي ←"), key="intro_next", type="primary",
                      on_click=_go, args=(page + 1,), **BUTTON_WIDE)
    else:
        nav[2].button(_(lang, "Start scanning", "ابدأ الفحص"), key="intro_start", type="primary",
                      on_click=_finish, **BUTTON_WIDE)


def _welcome(lang: str) -> None:
    numbers = facts()
    st.markdown('<div class="sca-hero">%s<div><h1 style="margin:0">%s</h1>%s</div></div>' % (
        SHIELD, _(lang, "Welcome to Secure Code Analyzer", "مرحباً بك في Secure Code Analyzer"),
        _(lang, "Intelligent source code vulnerability detection and security assessment",
          "منصة ذكية لكشف الثغرات في الكود المصدري وتقييم أمانه")), unsafe_allow_html=True)
    st.write("")
    st.markdown(_(lang,
        "The tool reads the source code of a project and finds security weaknesses before "
        "the code is released: SQL injection, cross-site scripting, command injection, "
        "leaked passwords and keys, weak cryptography, memory errors in C, and more. For each "
        "one it shows the line, explains the danger and proposes a fix. It also reads Flutter "
        "and Android projects and app files (APK, AAB). **Your code is never run, and the "
        "static scan needs neither internet nor AI.**",
        "تقرأ الأداة الكود المصدري للمشروع وتكتشف الثغرات الأمنية قبل نشره: حقن SQL و XSS "
        "وحقن الأوامر وكلمات المرور والمفاتيح المكشوفة والتشفير الضعيف وأخطاء الذاكرة في C "
        "وغيرها. تعرض لكل ثغرة السطر وتشرح خطورتها وتقترح الإصلاح. وتقرأ أيضاً مشاريع "
        "Flutter و Android وملفات التطبيقات (APK و AAB). **لا يُنفَّذ كودك أبداً، والفحص "
        "الستاتيكي لا يحتاج إنترنت ولا ذكاءً اصطناعياً.**"))
    cols = st.columns(4)
    for col, (value, en, ar) in zip(cols, [
            (numbers["languages"], "programming languages", "لغة برمجة"),
            (numbers["extensions"], "file types", "نوع ملف"),
            (numbers["rules"] + numbers["checks"], "active rules and app checks",
             "قاعدة وفحص فعّال"),
            (numbers["engines"], "static analysis engines", "محركات تحليل ستاتيكي")]):
        col.markdown('<div class="sca-stat"><b>%d</b>%s</div>' % (value, _(lang, en, ar)),
                     unsafe_allow_html=True)
    st.write("")
    _image("overview", lang, _(lang, "How the parts of the tool fit together",
                               "كيف تترابط أجزاء الأداة"))


def _how(lang: str) -> None:
    numbers = facts()
    st.header(_(lang, "How a scan works", "كيف يعمل الفحص"))
    st.caption(_(lang, "While the scan runs you see each of these steps live, with what it "
                       "found and the file being read.",
                 "أثناء الفحص ترى كل خطوة من هذه الخطوات لحظة تنفيذها، مع ما وجدته والملف "
                 "الذي يُقرأ."))
    steps = [
        ("Collect the files", "جمع الملفات",
         "%d file types in %d languages; libraries, builds and binary files are skipped. An "
         "app file (APK, AAB) is decoded first." % (numbers["extensions"], numbers["languages"]),
         "%d نوع ملف في %d لغة؛ تُتجاوز المكتبات وملفات البناء والملفات الثنائية. أما ملف "
         "التطبيق (APK أو AAB) فيُفكّ أولاً." % (numbers["extensions"], numbers["languages"])),
        ("Look for secrets", "البحث عن الأسرار",
         "%d key formats (AWS, GitHub, Stripe ...) and the randomness of values."
         % numbers["secrets"],
         "%d صيغة مفاتيح (AWS و GitHub و Stripe ...) وعشوائية القيم." % numbers["secrets"]),
        ("Match the rules", "مطابقة القواعد",
         "Every line against the %d active rules of its language, and %d checks of the "
         "settings of Android and Flutter apps." % (numbers["rules"], numbers["checks"]),
         "كل سطر مقابل القواعد الفعّالة (%d) الخاصة بلغته، و %d فحصاً لإعدادات تطبيقات "
         "Android و Flutter." % (numbers["rules"], numbers["checks"])),
        ("Follow the data", "تتبّع البيانات",
         "Python syntax trees, C/C++ memory checks, and user input traced in %d languages."
         % numbers["traced"],
         "شجرة بايثون النحوية، وفحوص الذاكرة في C/C++، وتتبّع مدخلات المستخدم في %d لغة."
         % numbers["traced"]),
        ("Merge the evidence", "دمج الأدلة",
         "Duplicates removed, engines combined, each finding mapped to CWE and OWASP.",
         "إزالة التكرار وجمع أدلة المحركات وربط كل نتيجة بـ CWE و OWASP."),
        ("Second opinion (ML)", "رأي ثانٍ (تعلّم آلي)",
         "A trained classifier scores how likely each finding is real.",
         "مصنِّف مدرَّب يقدّر احتمال أن تكون كل نتيجة حقيقية."),
        ("AI review (optional)", "مراجعة الذكاء الاصطناعي (اختيارية)",
         "Later: a local or cloud model reviews findings and teaches new rules.",
         "لاحقاً: نموذج محلي أو سحابي يراجع النتائج ويعلّم الأداة قواعد جديدة."),
        ("Score and report", "التقييم والتقرير",
         "Risk per finding, a project score 0-100 with a grade, and HTML/PDF/JSON/SARIF reports.",
         "خطورة كل نتيجة ودرجة للمشروع من 0 إلى 100 مع تقدير، وتقارير HTML و PDF و JSON و SARIF."),
    ]
    cols = st.columns(4)
    for index, (en, ar, d_en, d_ar) in enumerate(steps):
        cols[index % 4].markdown('<div class="sca-card"><b>%d. %s</b><br><small>%s</small></div>'
                                 % (index + 1, _(lang, en, ar), _(lang, d_en, d_ar)),
                                 unsafe_allow_html=True)
    _image("pipeline", lang, _(lang, "The full pipeline", "مسار الفحص كاملاً"))


def _languages(lang: str) -> None:
    numbers = facts()
    st.header(_(lang, "%d programming languages", "%d لغة برمجة") % numbers["languages"])
    st.caption(_(lang,
        "Server pages and templates are included: JSP is checked with the Java rules, EJS "
        "with the JavaScript rules, ASP.NET pages with the C# rules, and the <script> code "
        "inside PHP, ERB, JSP, ASP.NET and HTML pages with the JavaScript rules as well. "
        "Configuration files (YAML, JSON, XML, .env, Web.config) are checked for secrets and "
        "insecure settings. For Flutter and Android apps the manifest, Gradle, Info.plist and "
        "pubspec files are checked too, and app files are decoded (last card).",
        "صفحات الخادم والقوالب مشمولة: JSP بقواعد Java، و EJS بقواعد JavaScript، وصفحات ASP.NET "
        "بقواعد C#، وكود <script> داخل صفحات PHP و ERB و JSP و ASP.NET و HTML بقواعد JavaScript "
        "أيضاً. وتُفحص ملفات الإعداد (YAML و JSON و XML و .env و Web.config) بحثاً عن الأسرار "
        "والإعدادات غير الآمنة. ولتطبيقات Flutter و Android تُفحص أيضاً ملفات manifest و "
        "Gradle و Info.plist و pubspec، وتُفكّ ملفات التطبيقات (البطاقة الأخيرة)."))
    depth = {"ast": ("Data flow (AST) + Bandit", "تتبّع البيانات (AST) + Bandit"),
             "memory": ("Memory checks + input tracing", "فحوص الذاكرة + تتبّع المدخلات"),
             "traced": ("Rules + input tracing", "قواعد + تتبّع المدخلات"),
             "flutter": ("Rules + input tracing + app checks",
                         "قواعد + تتبّع المدخلات + فحوص التطبيق"),
             "rules": ("Rules + secrets", "قواعد + أسرار")}
    st.button(_(lang, "View and edit the rules of each language",
                "اعرض قواعد كل لغة وعدّلها"), key="intro_rules", on_click=open_rules,
              args=(lang,), type="primary")
    cards = [(name, _(lang, "%d rules", "%d قاعدة") % count, extensions.split(),
              _(lang, *depth[level])) for name, extensions, count, level in language_table()]
    cards.append((_(lang, "Android apps", "تطبيقات Android"),
                  _(lang, "%d checks", "%d فحصاً") % numbers["checks"], list(APP_SUFFIXES),
                  _(lang, "Decoded and read, never run", "تُفكّ وتُقرأ ولا تُشغَّل")))
    cols = st.columns(4)
    for index, (name, count, extensions, level) in enumerate(cards):
        chips = "".join('<span class="sca-chip">%s</span>' % ext for ext in extensions)
        cols[index % 4].markdown(
            '<div class="sca-card"><b>%s</b> &nbsp;<small>%s</small><br>%s<br><small>%s</small>'
            '</div>' % (name, count, chips, level), unsafe_allow_html=True)


def _mechanism(lang: str) -> None:
    st.header(_(lang, "How a finding is decided", "كيف تُحسم النتيجة"))
    left, right = st.columns(2)
    with left:
        st.markdown(_(lang,
            "1. **A source** is where outside data enters: a request parameter, a cookie, a "
            "file that is read.\n"
            "2. **A sink** is where that data becomes dangerous: an SQL query, a shell "
            "command, an HTML page, a file path, `memcpy`.\n"
            "3. When the path from source to sink is **traced**, or the weakness is a property "
            "of the line itself (a weak algorithm, a hard-coded key), the finding is "
            "**confirmed**. Otherwise it is **probable** and waits for a review.\n"
            "4. Every finding has a risk from 0 to 10; together they give the project score "
            "and grade. **Strict mode** counts only confirmed findings.\n"
            "5. Your reviews teach the tool: dismissed findings stay dismissed and rules that "
            "keep producing false alarms lose confidence.",
            "1. **المصدر** هو مكان دخول البيانات الخارجية: معامل في الطلب، أو كوكي، أو ملف يُقرأ.\n"
            "2. **المصبّ** هو المكان الذي تصبح فيه هذه البيانات خطرة: استعلام SQL، أو أمر نظام، "
            "أو صفحة HTML، أو مسار ملف، أو `memcpy`.\n"
            "3. عندما يُتتبَّع المسار من المصدر إلى المصبّ، أو تكون الثغرة صفةً في السطر نفسه "
            "(خوارزمية ضعيفة أو مفتاح مكتوب في الكود)، تصبح النتيجة **مؤكَّدة**. وإلا فهي "
            "**محتملة** وتنتظر المراجعة.\n"
            "4. لكل نتيجة خطورة من 0 إلى 10، ومنها تُحسب درجة المشروع وتقديره. "
            "**الوضع الصارم** يعدّ المؤكَّدة فقط.\n"
            "5. مراجعاتك تعلّم الأداة: النتيجة المستبعدة تبقى مستبعدة، والقاعدة التي تكثر "
            "إنذاراتها الكاذبة تفقد ثقتها."))
    with right:
        _image("taint", lang, _(lang, "Tracing user input to a dangerous call",
                                "تتبّع مدخلات المستخدم حتى الاستدعاء الخطر"))
    _image("finding-status", lang, _(lang, "The life of a finding", "حالات النتيجة"))


def _start(lang: str) -> None:
    st.header(_(lang, "Start scanning", "ابدأ الفحص"))
    left, right = st.columns([3, 2])
    with left:
        st.markdown(_(lang,
            "1. In **Scan input**, choose a folder or file or upload the package.\n"
            "2. Keep the static engines on and press **Run scan**: each step appears live.\n"
            "3. Read the score on the **Dashboard**, each issue with its fix under "
            "**Findings**, and download the report under **Reports**.\n"
            "4. Mark findings as real or false: the tool learns from your reviews.\n"
            "5. Later, connect an AI provider in **Scan settings** for reviews, deep "
            "scans and new rules.",
            "1. من تبويب **مصدر الفحص** اختر المجلد أو الملف أو ارفع الحزمة.\n"
            "2. أبقِ المحركات الستاتيكية مفعّلة واضغط **ابدأ الفحص**: تظهر كل خطوة مباشرةً.\n"
            "3. اقرأ الدرجة في **اللوحة**، وكل ثغرة مع إصلاحها في **النتائج**، ونزّل التقرير من "
            "**التقارير**.\n"
            "4. علِّم النتائج بأنها حقيقية أو كاذبة: الأداة تتعلم من مراجعاتك.\n"
            "5. لاحقاً اربط مزوّد ذكاء اصطناعي من **خيارات الفحص** للمراجعة والفحص "
            "العميق وتعلّم قواعد جديدة."))
        st.write("")
        sample = str(ROOT / "samples" / "vulnerable_app")
        st.button(_(lang, "Try it on the sample project", "جرّبها على المشروع التجريبي"),
                  key="intro_sample", on_click=_finish, args=(sample,), **BUTTON_WIDE)
        flutter_sample = str(ROOT / "samples" / "flutter_vulnerable_app")
        st.button(_(lang, "Try it on the Flutter sample", "جرّبها على عيّنة Flutter"),
                  key="intro_flutter_sample", on_click=_finish, args=(flutter_sample,),
                  **BUTTON_WIDE)
        available = labs()
        if available:
            st.caption(_(lang, "%d deliberately vulnerable training labs are in the "
                               "infected_project folder:",
                         "يوجد %d مختبراً ضعيفاً عمداً للتدريب في مجلد infected_project:")
                       % len(available))
            chosen = st.selectbox(_(lang, "Training lab", "مختبر تدريبي"), available,
                                  key="intro_lab")
            st.button(_(lang, "Scan this lab", "افحص هذا المختبر"), key="intro_lab_go",
                      on_click=_finish, args=(str(LABS / chosen),), **BUTTON_WIDE)
    with right:
        _image("ui-arabic" if lang == "ar" else "dashboard", "en",
               _(lang, "The dashboard after a scan", "اللوحة بعد الفحص"))
