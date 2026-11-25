"""Secure Code Analyzer - web dashboard.

Start it with:   python -m sca ui      (or double-click run.bat / run.sh)
The dashboard is only reachable from this computer (localhost).
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from sca import __version__, scoring
from sca.ai.classifier import SKLEARN_AVAILABLE
from sca.ai.llm import DEFAULT_MODEL
from sca.ai.providers import PRESETS, LLMConfig, load_config, make_client, save_config
from sca.cwe import MASVS_GROUPS, MOBILE_TOP10_2024, info as cwe_info, masvs_name, mobile_name
from sca.engines import external
from sca.engines.rules_engine import load_rules
from sca.flutter import APP_SUFFIXES, AppError, is_app_package
from sca.flutter import tools as app_tools
from sca.flutter import zipread
from sca.flutter.pubspec import parse_pubspec
from sca.learn import feedback as feedback_module
from sca import rulebook
from sca.learn import loop, store
from sca.models import SEVERITIES, ScanResult
from sca.pipeline import ScanOptions, run_scan
from sca.report.html_report import render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import to_sarif
from sca.storage import Storage, data_dir
from sca.ui import app_panel, guide_tab, intro, rules_tab, texts
from sca.ui.i18n import AR
from sca.walker import CODE_LANGUAGES, strip_bidi

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "samples" / "vulnerable_app"
FLUTTER_SAMPLE = ROOT / "samples" / "flutter_vulnerable_app"
SEV_COLOR = {"critical": "#9b1c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d5f8a",
             "info": "#5f5e5a"}
CODE_LANG = {"python": "python", "javascript": "javascript", "typescript": "typescript",
             "php": "php", "java": "java", "c": "c", "cpp": "cpp", "csharp": "csharp",
             "go": "go", "config": "yaml", "shell": "bash", "html": "html", "ruby": "ruby",
             "kotlin": "kotlin", "rust": "rust", "swift": "swift", "powershell": "powershell",
             "dart": "dart"}
UPLOAD_NAME = re.compile(r"[^A-Za-z0-9._-]+")
STATUS_LABEL = {"open": "Open", "needs_review": "Needs review",
                "likely_false_positive": "Likely false positives (AI)",
                "dismissed": "Dismissed by you"}

st.set_page_config(page_title="Secure Code Analyzer", page_icon=":shield:", layout="wide")

# Streamlit renamed the "fill the available width" option; support old and new versions.
WIDE = ({"width": "stretch"} if "width" in inspect.signature(st.button).parameters
        else {"use_container_width": True})
# Newer Streamlit can keep the bars of a chart in data order (older ones sort them by name).
CHART_ORDER = {"sort": False} if "sort" in inspect.signature(st.bar_chart).parameters else {}


# ------------------------------------------------------------------ helpers
def ui_lang() -> str:
    return "ar" if st.session_state.get("ui_lang") == "العربية" else "en"


def ltr(text: str) -> str:
    """In Arabic, wrap a path in a Unicode left-to-right isolate (U+2066 ... U+2069) so that
    it does not pull the numbers after it into its own left-to-right run."""
    return "\u2066%s\u2069" % text if ui_lang() == "ar" else text


def t(text: str) -> str:
    """The text in the language of the dashboard (English is the source language)."""
    return AR.get(text, text) if ui_lang() == "ar" else text


MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~$])")
# where Markdown would turn an address or an e-mail into a link: after the ':' of '://',
# before '@' and after 'www'. An invisible WORD JOINER (U+2060) there stops it; a backslash
# escape does not (Streamlit's Markdown still links "https\://...").
AUTOLINK = re.compile(r"(?i)(?<=:)(?=//)|(?=@)|(?<=\bwww)(?=\.)")


def plain(text: str) -> str:
    """Escape Markdown, so that a path such as C:\\my_app\\*.py is shown as it is, and keep an
    address or e-mail of a scanned app from becoming a link."""
    return AUTOLINK.sub("\u2060", MARKDOWN_SPECIAL.sub(r"\\\1", text))


def untrusted(text: str) -> str:
    """Text of a scanned project or app (a title, a file name, a quoted value) for a place
    that renders Markdown, a label included: shown as it is, without links, images or
    formatting, and without the Unicode controls that would show it in another order."""
    return plain(strip_bidi(str(text)))


def scan_text(message: str) -> str:
    """A progress message of the scan (sca.pipeline.Message) in the dashboard language.
    The values are translated too when they are known words; paths are kept left to right."""
    template = getattr(message, "template", None)
    if template is None:
        return t(str(message))
    values = tuple((t(v) if v in AR else ltr(v)) if isinstance(v, str) else v
                   for v in message.args)
    return t(template) % values


def step_line(message: str) -> str:
    """One line of the scan log in Markdown: a stage that starts (bold arrow), or what the
    stage found (grey, with a mark: found, skipped or failed)."""
    text = plain(scan_text(message))
    if getattr(message, "kind", "step") != "result":
        return "**▸** " + text
    template = getattr(message, "template", "")
    mark = "–" if "skipped" in template else "✗" if "failed" in template else "✓"
    return ":gray[%s %s]" % (mark, text)


def show_steps(messages) -> None:
    """The scan log: each stage with what it found, one block per stage."""
    block: list = []
    for message in messages:
        if getattr(message, "kind", "step") != "result" and block:
            st.markdown("  \n".join(block))
            block = []
        block.append(step_line(message))
    if block:
        st.markdown("  \n".join(block))


def tframe(*args, **kwargs) -> pd.DataFrame:
    """A table whose column headers are shown in the language of the dashboard."""
    return pd.DataFrame(*args, **kwargs).rename(columns=t)


def opt(key: str) -> dict:
    """label= and help= of a sidebar control, from the shared settings table."""
    label, help_text = texts.setting(key, ui_lang())
    return {"label": label, "help": help_text}


RTL_CSS = """<style>
[data-testid="stMarkdownContainer"], [data-testid="stCaptionContainer"],
[data-testid="stWidgetLabel"], [data-testid="stMetric"], [data-testid="stAlert"],
[data-testid="stTable"] td, [data-testid="stTable"] th, h1, h2, h3, h4 {
    direction: rtl; text-align: right; }
[data-testid="stMarkdownContainer"] pre, [data-testid="stMarkdownContainer"] code,
[data-testid="stCode"] { direction: ltr; text-align: left; unicode-bidi: plaintext; }
/* A metric value is a number or "a / b". Right to left, "0 / 100" would read "100 / 0",
   so lay the value out left to right, still aligned on the right like its label. */
[data-testid="stMetricValue"],
[data-testid="stMetricValue"] [data-testid="stMarkdownContainer"] {
    direction: ltr; text-align: right; }
</style>"""


def run_dialog(call: str) -> str:
    """Open a dialog of the operating system (in a separate process so that it cannot
    interfere with the web server) and return the path it printed. The child prints UTF-8,
    so a path with Arabic letters survives a console that uses another code page."""
    code = ("import tkinter as tk\nfrom tkinter import filedialog\nroot = tk.Tk()\n"
            "root.withdraw()\nroot.attributes('-topmost', True)\n"
            "print(filedialog.%s or '')" % call)
    try:
        out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                             encoding="utf-8", errors="replace", timeout=600,
                             env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        return out.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return ""


def pick_folder() -> str:
    return run_dialog("askdirectory(title='Choose the project folder')")


def pick_app() -> str:
    patterns = " ".join("*" + suffix for suffix in APP_SUFFIXES)
    return run_dialog("askopenfilename(title='Choose the app file', filetypes=[('Android app', "
                      "%r), ('All files', '*.*')])" % patterns)


def browse_clicked() -> None:
    chosen = pick_folder()
    if chosen:
        st.session_state["target"] = chosen
    else:
        st.session_state["browse_note"] = t("No folder was chosen (or the folder dialog is not "
                                            "available here). You can paste the path instead.")


def browse_app_clicked() -> None:
    chosen = pick_app()
    if chosen:
        st.session_state["target"] = chosen
    else:
        st.session_state["browse_note"] = t("No app file was chosen (or the file dialog is not "
                                            "available here). You can paste the path instead.")


def app_uploaded() -> None:
    """Keep an uploaded app file under data/uploads, named after its content: the same app
    uploaded again, under any name, is the same file and the same scan target (one line in
    History). A file that is not a ZIP archive is refused and not kept."""
    uploaded = st.session_state.get("app_upload")
    if uploaded is None:
        return
    original = Path(uploaded.name.replace("\\", "/"))
    suffix = original.suffix.lower()
    if suffix not in APP_SUFFIXES:
        st.session_state["browse_note"] = t("Only app files (.apk, .aab, .apks, .xapk, .apkm) "
                                            "can be uploaded.")
        return
    data = uploaded.getvalue()
    if not is_zip_data(data):           # checked before anything is written
        st.session_state["browse_note"] = t(
            "This file is not a readable app package (it is not a ZIP archive): %s") \
            % plain(original.name)
        return
    digest = hashlib.sha256(data).hexdigest()[:12]
    folder = data_dir() / "uploads"
    kept = sorted(p for p in folder.glob("%s-*%s" % (digest, suffix))
                  if p.is_file() and p.suffix == suffix) if folder.is_dir() else []
    if kept:                            # uploaded before, perhaps under another name
        st.session_state["target"] = str(kept[0])
        return
    # only safe characters in the stored name; a name of other letters (Arabic) becomes "app"
    stem = UPLOAD_NAME.sub("_", original.stem).strip("._")[:60] or "app"
    path = folder / ("%s-%s%s" % (digest, stem, suffix))
    partial = folder / (".%s.part" % digest)      # a half-written file never becomes a target
    try:
        folder.mkdir(parents=True, exist_ok=True)
        partial.write_bytes(data)
        os.replace(partial, path)
    except OSError as exc:
        st.session_state["browse_note"] = t("The upload could not be saved: %s") % plain(str(exc))
        try:
            partial.unlink()
        except OSError:
            pass
        return
    st.session_state["target"] = str(path)


def is_zip_data(data: bytes) -> bool:
    """The check of sca.flutter.zipread.is_zip on bytes in memory: a ZIP header at the start,
    or an end of central directory record near the end (an archive with data in front)."""
    return (data[:4] in (zipread.LOCAL_SIG, zipread.EOCD_SIG)
            or zipread.EOCD_SIG in data[-(zipread.EOCD_SIZE + zipread.MAX_COMMENT):])


def use_sample() -> None:
    st.session_state["target"] = str(SAMPLE)


def use_flutter_sample() -> None:
    st.session_state["target"] = str(FLUTTER_SAMPLE)


PUBSPEC_LIMIT = 1_000_000      # a larger pubspec.yaml is not read by the sidebar


def target_note(target: str) -> str:
    """A caption under the path box: what kind of target it is. Only cheap checks, without
    walking the folder (the sidebar runs on every click): a pubspec.yaml that depends on the
    Flutter SDK, or the manifest of an Android module one level down (app/src/main/...,
    android/app/src/main/...) or of the folder itself."""
    try:
        path = Path(target).expanduser()
        if path.suffix.lower() in APP_SUFFIXES and path.is_file():
            return t("An app file: it is decoded and read, never installed or run.")
        if not path.is_dir():
            return ""
        pubspec = path / "pubspec.yaml"
        if pubspec.is_file() and pubspec.stat().st_size <= PUBSPEC_LIMIT and parse_pubspec(
                pubspec.read_text(encoding="utf-8", errors="replace")).is_flutter:
            return t("A Flutter project: the Flutter / Android checks run as well.")
        modules = [path / "android" / "app", path] + [
            manifest.parents[2] for manifest in path.glob("*/src/main/AndroidManifest.xml")]
        if any(android_module(module) for module in modules):
            return t("An Android project: the Flutter / Android checks run as well.")
    except Exception:                   # a caption is never worth an error in the sidebar
        pass
    return ""


def android_module(folder: Path) -> bool:
    """A Gradle module of an Android app or library: src/main/AndroidManifest.xml and a build
    file (what the Flutter / Android engine looks for)."""
    return (folder / "src" / "main" / "AndroidManifest.xml").is_file() and any(
        (folder / name).is_file() for name in ("build.gradle", "build.gradle.kts"))


def lab_chosen() -> None:
    name = st.session_state.get("lab_choice")
    if name:
        st.session_state["target"] = str(intro.LABS / name)


@st.cache_data(ttl=30, show_spinner=False)
def provider_models(preset: str, base_url: str, api_key: str):
    """(model names, is_local). Cached for 30 seconds."""
    client = make_client(LLMConfig(preset=preset, base_url=base_url, api_key=api_key,
                                   model="-", timeout=10))
    return client.models(), client.is_local


@st.cache_data(ttl=30, show_spinner=False)
def provider_ready(preset: str, base_url: str, api_key: str, model: str):
    return make_client(LLMConfig(preset=preset, base_url=base_url, api_key=api_key,
                                 model=model, timeout=10)).check()


@st.cache_data(ttl=30, show_spinner=False)
def mobile_tools() -> dict:
    """Which optional tools for app files are installed. Cached for 30 seconds."""
    found = app_tools.availability()
    return {name: bool(found.get(name)) for name in ("jadx", "apksigner")}


@st.cache_resource
def get_storage() -> Storage:
    return Storage()


def severity_badge(severity: str) -> str:
    return ("<span style='background:%s;color:#fff;border-radius:99px;padding:2px 10px;"
            "font-size:12px;font-weight:700;text-transform:uppercase'>%s</span>"
            % (SEV_COLOR[severity], severity))


def review(index: int, verdict: str) -> None:
    """The reviewer's decision on one finding: stored, applied now and in later scans."""
    result = st.session_state["result"]
    finding = result.findings[index]
    storage = get_storage()
    if verdict == "clear":
        storage.clear_feedback(finding.fingerprint)
        finding.user_verdict = ""
        if finding.status == "dismissed":
            finding.status = "open"
    elif verdict == "fp":
        storage.set_feedback(finding, "fp")
        finding.user_verdict, finding.status = "false_positive", "dismissed"
    else:
        storage.set_feedback(finding, "tp")
        finding.user_verdict, finding.status = "true_positive", "open"
        finding.confidence = max(finding.confidence, 0.97)
    scoring.assign_tier(finding)
    finding.risk_score = scoring.risk_score(finding)
    result.score, result.grade = scoring.project_score(result.findings, result.lines_scanned)
    apis = (getattr(result, "app", None) or {}).get("apis")
    if isinstance(apis, dict):       # a dismissed key leaves the inventory, a confirmed returns
        from sca.flutter.inventory import refresh_keys
        refresh_keys(apis, result.findings)


def decide(candidate_id: str, approve: bool) -> None:
    try:
        if approve:
            store.approve(get_storage(), candidate_id)
            st.session_state["learn_note"] = (t("Approved %s. It is active from the next scan.")
                                              % candidate_id)
        else:
            store.reject(get_storage(), candidate_id)
            st.session_state["learn_note"] = t("Rejected %s.") % candidate_id
    except (KeyError, ValueError) as exc:
        st.session_state["learn_note"] = str(exc)


def remove_rule(rule_id: str) -> None:
    store.remove_learned_rule(rule_id)
    st.session_state["learn_note"] = t("Removed learned rule %s.") % rule_id


# ------------------------------------------------------------------ sidebar
st.session_state.setdefault("target", "")
saved = load_config()
with st.sidebar:
    st.title("Secure Code Analyzer")
    st.radio("Language / اللغة", ["English", "العربية"], horizontal=True, key="ui_lang",
             help=texts.setting("ui_lang", "en")[1] + "\n\n" + texts.setting("ui_lang", "ar")[1])
    lang = ui_lang()
    if lang == "ar":
        st.markdown(RTL_CSS, unsafe_allow_html=True)
    st.caption(t("Static + AI vulnerability detection that learns - v%s") % __version__)

    st.subheader(t("1. Project folder or app"))
    st.text_input(key="target", placeholder=r"C:\projects\my-app", **opt("target"))
    chosen_target = st.session_state["target"].strip().strip('"')
    note = target_note(chosen_target) if chosen_target else ""
    if note:
        st.caption(note)
    col_a, col_b = st.columns(2)
    col_a.button(on_click=browse_clicked, **opt("browse"), **WIDE)
    col_b.button(on_click=use_sample, **opt("sample"), **WIDE)
    col_a.button(on_click=browse_app_clicked, **opt("browse_app"), **WIDE)
    col_b.button(on_click=use_flutter_sample, **opt("flutter_sample"), **WIDE)
    training_labs = intro.labs()
    if training_labs:
        st.selectbox(options=[""] + training_labs, key="lab_choice", on_change=lab_chosen,
                     format_func=lambda name: name or "-", **opt("lab"))
    with st.expander(t("Upload an app file")):
        st.file_uploader(type=[suffix.lstrip(".") for suffix in APP_SUFFIXES], key="app_upload",
                         on_change=app_uploaded, **opt("app_upload"))
    if st.session_state.get("browse_note"):
        st.caption(st.session_state.pop("browse_note"))

    st.subheader(t("2. Static engines"))
    tools = external.availability()
    missing = t(" (not installed)")
    counts = rulebook.summary()
    use_rules = st.checkbox(value=True, **opt("use_rules"))
    st.caption(t("%d active rules of %d - manage them in the Rules tab")
               % (counts["enabled"], counts["total"]))
    st.button(on_click=intro.open_rules, args=(lang,), **opt("open_rules"), **WIDE)
    use_ast = st.checkbox(value=True, **opt("use_ast"))
    use_secrets = st.checkbox(value=True, **opt("use_secrets"))
    use_bandit = st.checkbox("Bandit" + ("" if tools["bandit"] else missing),
                             value=tools["bandit"], disabled=not tools["bandit"],
                             help=opt("use_bandit")["help"])
    use_semgrep = st.checkbox("Opengrep / Semgrep" + ("" if tools["semgrep"] else missing),
                              value=tools["semgrep"], disabled=not tools["semgrep"],
                              help=opt("use_semgrep")["help"])
    use_gitleaks = st.checkbox("Gitleaks" + ("" if tools["gitleaks"] else missing),
                               value=tools["gitleaks"], disabled=not tools["gitleaks"],
                               help=opt("use_gitleaks")["help"])
    use_flutter = st.checkbox(value=True, **opt("use_flutter"))
    with st.expander(t("More engine options")):
        use_taint_lite = st.checkbox(value=True, **opt("use_taint_lite"))
        use_c_memory = st.checkbox(value=True, **opt("use_c_memory"))
        absent = [name for name, found in mobile_tools().items() if not found]
        if len(absent) == 2:
            tools_note = missing
        elif absent:
            tools_note = t(" (%s not installed)") % absent[0]
        else:
            tools_note = ""
        apk_tools = st.checkbox(opt("apk_tools")["label"] + tools_note, value=False,
                                disabled=len(absent) == 2, help=opt("apk_tools")["help"])
        exclude_dirs = st.text_input(placeholder="docs, third_party", **opt("exclude_dirs"))

    st.subheader(t("3. Artificial intelligence"))
    use_ml = st.checkbox(value=SKLEARN_AVAILABLE, disabled=not SKLEARN_AVAILABLE,
                         **opt("use_ml"))
    presets = list(PRESETS)
    preset = st.selectbox(options=presets, index=presets.index(saved.preset),
                          format_func=lambda key: PRESETS[key]["label"], **opt("provider"))
    same = preset == saved.preset
    base_url = st.text_input(
        key="base_url_%s" % preset,
        value=saved.base_url if same and saved.base_url else PRESETS[preset]["base_url"],
        **opt("base_url"))
    api_key = ""
    if PRESETS[preset]["kind"] != "ollama":
        api_key = st.text_input(
            type="password", key="api_key_%s" % preset,
            value=saved.api_key if same else os.environ.get(PRESETS[preset]["key_env"] or "-", ""),
            **opt("api_key"))
    models, is_local = provider_models(preset, base_url, api_key)
    default_model = saved.model if same and saved.model else (
        DEFAULT_MODEL if preset == "ollama" else "")
    if models:
        llm_model = st.selectbox(options=models, index=models.index(default_model)
                                 if default_model in models else 0, **opt("model"))
    else:
        llm_model = st.text_input(value=default_model, key="model_%s" % preset, **opt("model"))
    llm_ready, llm_message = provider_ready(preset, base_url, api_key, llm_model)
    if llm_ready:
        st.caption(t("AI provider ready: %s") % llm_model)
    else:
        st.caption(t("AI provider not ready: %s. The static scan works without it.")
                   % llm_message)
    if not is_local:
        st.warning(t("With this provider, the code under review is sent to %s. Secrets found "
                     "by the tool are masked first. Choose Ollama to keep everything on this "
                     "computer.") % (urlparse(base_url).hostname or base_url))
    use_llm = st.checkbox(value=llm_ready, disabled=not llm_ready, **opt("use_llm"))
    deep = st.checkbox(value=False, disabled=not llm_ready, **opt("deep"))
    llm_max = st.slider(min_value=5, max_value=200, value=30, step=5, disabled=not llm_ready,
                        **opt("llm_max"))
    with st.expander(t("More AI options")):
        deep_max_files = st.slider(min_value=1, max_value=50, value=10,
                                   disabled=not llm_ready, **opt("deep_max_files"))
        llm_timeout = st.slider(min_value=30, max_value=600, value=180, step=30,
                                disabled=not llm_ready, **opt("llm_timeout"))
    if st.button(**opt("save_ai"), **WIDE):
        path = save_config(LLMConfig(
            preset=preset, api_key=api_key, model=llm_model,
            base_url="" if base_url == PRESETS[preset]["base_url"] else base_url))
        st.caption(t("Saved to %s") % path)

    st.subheader(t("4. Precision"))
    strict = st.checkbox(value=False, **opt("strict"))
    skip_tests = st.checkbox(value=False, **opt("skip_tests"))
    use_feedback = st.checkbox(value=True, **opt("use_feedback"))

    st.subheader(t("5. Output"))
    save_scan = st.checkbox(value=True, **opt("save_scan"))
    run = st.button(type="primary", **opt("run"), **WIDE)
    st.button(on_click=intro.reopen, **opt("intro"), **WIDE)

# ------------------------------------------------------------------ splash and introduction
# Shown when the dashboard is opened: a splash, then the pages that explain the tool.
if intro.active():
    intro.render(lang)
    st.stop()

llm_config = LLMConfig(preset=preset, base_url=base_url, api_key=api_key, model=llm_model)

# ------------------------------------------------------------------ run a scan
# Messages and the progress bar of a scan live in this container. It exists in every run,
# so the tabs below keep their place on the page and the selected tab is not reset.
status_area = st.container()
if run:
    with status_area:
        target = st.session_state["target"].strip().strip('"')
        target_path = Path(target).expanduser()
        if not target:
            st.error(t("Choose a project folder or an app file first."))
        elif not target_path.exists():
            st.error(t("This path does not exist: %s") % plain(target))
        elif (target_path.is_file() and target_path.suffix.lower() in APP_SUFFIXES
              and not is_app_package(target_path)):
            st.error(t("This file is not a readable app package (it is not a ZIP archive): %s")
                     % plain(target))
        else:
            options = ScanOptions(
                use_rules=use_rules, use_ast=use_ast, use_secrets=use_secrets,
                use_bandit=use_bandit, use_semgrep=use_semgrep, use_gitleaks=use_gitleaks,
                use_ml=use_ml, use_llm=use_llm, llm_provider=preset, llm_base_url=base_url,
                llm_api_key=api_key, llm_model=llm_model, llm_max_findings=llm_max,
                llm_deep_scan=deep and use_llm, lang=lang, strict=strict,
                include_tests=not skip_tests, use_taint_lite=use_taint_lite,
                use_c_memory=use_c_memory, use_flutter=use_flutter, apk_tools=apk_tools,
                use_feedback=use_feedback, save=save_scan, llm_deep_max_files=deep_max_files,
                llm_timeout=llm_timeout,
                exclude_dirs=[d.strip() for d in exclude_dirs.split(",") if d.strip()])
            # What the scan is doing, while it does it: each step is added to this box as
            # it starts and when it ends, and the bar names the file being read.
            live = st.empty()
            box = live.status(t("Scanning %s") % plain(ltr(target)), expanded=True)
            bar = box.progress(0.0, text=t("Starting"))

            def on_progress(message: str, fraction: float) -> None:
                bar.progress(min(1.0, max(0.0, fraction)), text=plain(scan_text(message)))
                if getattr(message, "kind", "step") != "file":
                    box.markdown(step_line(message))

            try:
                st.session_state["result"] = run_scan(target, options, on_progress, get_storage())
                live.empty()     # the same steps stay on the Dashboard tab, see "scan_log"
                st.session_state["scan_log_open"] = True
            except AppError as exc:   # the file is not an app package that can be read
                bar.empty()
                box.update(label=t("The app file cannot be read: %s") % untrusted(exc),
                           state="error")
                st.error(t("The app file cannot be read: %s") % untrusted(exc))
            except Exception as exc:  # show the problem instead of a stack trace
                bar.empty()
                box.update(label=t("The scan failed: %s") % untrusted(exc), state="error")
                st.error(t("The scan failed: %s") % untrusted(exc))

result: ScanResult = st.session_state.get("result")

# ------------------------------------------------------------------ main area
# With a key, the open tab is remembered, and a button can open one (e.g. Open the rules).
TAB_STATE = ({"key": intro.MAIN_TABS_KEY + lang, "on_change": "rerun"}
             if "on_change" in inspect.signature(st.tabs).parameters else {})
tab_dash, tab_findings, tab_rules, tab_learn, tab_reports, tab_history, tab_guide = st.tabs(
    [t(name) for name in ("Dashboard", "Findings", "Rules", "Learning", "Reports", "History",
                          "Guide")], **TAB_STATE)

with tab_rules:
    rules_tab.render(get_storage(), t, WIDE)

with tab_guide:
    guide_tab.render(t, lang, WIDE)

with tab_dash:
    if result is None:
        st.header(t("Scan a project to begin"))
        st.write(t("Choose a folder or an app file (.apk, .aab) in the sidebar and press "
                   "**Run scan**. To see a full example, press **Use sample** first."))
        st.info(t("Static engines always run on this computer. The optional AI review uses the "
                "provider you choose: a local model (Ollama) or a cloud API."))
    else:
        counts = result.counts()
        st.caption(t("%s - %s - %d files, %d lines, %.1f s") % (
            ltr(untrusted(result.target)), result.started_at, result.files_scanned,
            result.lines_scanned, result.duration_seconds))
        if result.steps:   # open right after a scan; a scan loaded from history has no steps
            with st.expander(t("What the scan did, step by step"),
                             expanded=st.session_state.pop("scan_log_open", False)):
                show_steps(result.steps)
        app_facts = getattr(result, "app", None)    # a scan saved by an older version has none
        if app_facts:
            with st.expander(plain(app_panel.title(app_facts, t, ltr)), expanded=True):
                app_panel.render(app_facts, t, ltr, WIDE)
            apis = app_facts.get("apis")
            if isinstance(apis, dict):      # a scan saved by an older version has none
                with st.expander(app_panel.apis_title(apis, t), expanded=True):
                    app_panel.render_apis(apis, t, ltr, WIDE)
        cols = st.columns(6)
        cols[0].metric(t("Security score (grade %s)") % result.grade, "%d / 100" % result.score)
        for col, sev in zip(cols[1:], SEVERITIES[:4]):
            col.metric(t(sev.capitalize()), counts[sev])
        confirmed = sum(1 for f in result.open_findings if f.tier == "confirmed")
        cols[5].metric(t("Confirmed / open"), "%d / %d" % (confirmed, len(result.open_findings)))
        others = ["%d %s" % (result.status_count(s), t(STATUS_LABEL[s]).lower())
                  for s in ("needs_review", "likely_false_positive", "dismissed")
                  if result.status_count(s)]
        if others:
            st.caption(t("Not counted in the score: ") + ", ".join(others))

        left, right = st.columns(2)
        with left:
            st.subheader(t("By severity"))
            # the number prefix keeps the bars in severity order (charts sort labels by name)
            st.bar_chart(pd.DataFrame({"findings": [counts[s] for s in SEVERITIES]},
                                      index=["%d. %s" % (i, t(s.capitalize()))
                                             for i, s in enumerate(SEVERITIES, start=1)]),
                         horizontal=True, height=240)
        with right:
            st.subheader(t("By OWASP Top 10 category"))
            by_owasp = {}
            for f in result.open_findings:
                by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1
            if by_owasp:
                st.bar_chart(pd.DataFrame({"findings": by_owasp}), horizontal=True, height=240)
            else:
                st.write(t("No open findings."))

        if app_facts:
            risks = Counter(getattr(f, "owasp_mobile", "") for f in result.open_findings)
            groups = Counter(getattr(f, "masvs", "") for f in result.open_findings)
            by_risk = {"%s %s" % (risk, mobile_name(risk, lang)): risks[risk]
                       for risk in MOBILE_TOP10_2024 if risks[risk]}
            by_group = {"%s (%s)" % (masvs_name(group, lang), group): groups[group]
                        for group in MASVS_GROUPS if groups[group]}
            left, right = st.columns(2)
            for column, heading, counted in (
                    (left, t("By OWASP Mobile Top 10 (2024)"), by_risk),
                    (right, t("By MASVS group"), by_group)):
                with column:
                    st.subheader(heading)
                    if counted:   # M1 to M10 in their order, where Streamlit allows it
                        st.bar_chart(pd.DataFrame({"findings": list(counted.values())},
                                                  index=list(counted)),
                                     horizontal=True, height=240, **CHART_ORDER)
                    else:
                        st.write(t("No open findings."))

        left, right = st.columns(2)
        with left:
            st.subheader(t("Most affected files"))
            by_file = {}
            for f in result.open_findings:
                by_file[f.file] = by_file.get(f.file, 0) + 1
            top = sorted(by_file.items(), key=lambda kv: -kv[1])[:10]
            st.dataframe(tframe(top, columns=["File", "Findings"]), hide_index=True,
                         **WIDE)
        with right:
            st.subheader(t("Engines"))
            rows = [{"Engine": k, "Status": v} for k, v in result.engine_notes.items()]
            rows += [{"Engine": "AI: " + k, "Status": str(v)} for k, v in result.ai.items()]
            st.dataframe(tframe(rows), hide_index=True, **WIDE)

with tab_findings:
    if result is None:
        st.write(t("No scan yet."))
    elif not result.findings:
        st.success(t("No findings. A clean scan is not a proof of security."))
    else:
        f1, f2, f3, f4 = st.columns([2, 2, 2, 2])
        present = [s for s in STATUS_LABEL if result.status_count(s)] or ["open"]
        # labels are computed now, so they do not depend on when Streamlit formats them
        show_labels = {s: "%s (%d)" % (t(STATUS_LABEL[s]), result.status_count(s))
                       for s in present}
        show_labels["all"] = t("All")
        status_filter = f1.selectbox(t("Show"), present + ["all"], format_func=show_labels.get)
        if status_filter not in show_labels:
            status_filter = present[0]
        sev_filter = f2.multiselect(t("Severity"), SEVERITIES, default=SEVERITIES[:4])
        files = sorted({f.file for f in result.findings})
        file_filter = f3.multiselect(t("File"), files)
        text_filter = f4.text_input(t("Search (title, CWE, code)"))

        shown = []
        for index, f in enumerate(result.findings):
            if status_filter != "all" and f.status != status_filter:
                continue
            if f.severity not in sev_filter or (file_filter and f.file not in file_filter):
                continue
            haystack = " ".join([f.title, f.cwe, f.snippet, f.file,
                                 getattr(f, "owasp_mobile", ""), getattr(f, "masvs", "")]).lower()
            if text_filter and text_filter.lower() not in haystack:
                continue
            shown.append((index, f))

        st.caption(t("%d of %d findings. Your reviews are remembered: a finding you dismiss stays "
                   "dismissed in later scans, and each review adjusts the confidence of the "
                   "rule that produced it.") % (len(shown), len(result.findings)))
        table = tframe([{
            "Severity": f.severity, "Title": f.title, "File": f.file, "Line": f.line,
            "CWE": f.cwe, "Tier": f.tier, "Risk": f.risk_score,
            "Confidence %": round(f.confidence * 100), "Engines": ", ".join(f.engines),
            "ML %": None if f.ml_score is None else round(f.ml_score * 100),
            "AI": f.ai_verdict.replace("_", " "),
        } for _, f in shown])
        st.dataframe(table, hide_index=True, height=280, **WIDE)

        st.subheader(t("Details"))
        for position, (index, f) in enumerate(shown[:150]):
            # a label renders Markdown: the title can quote the app (a name, a URL)
            label = "%s | %s | %s:%d" % (f.severity.upper(), untrusted(f.title),
                                         untrusted(f.file), f.line)
            with st.expander(label, expanded=(position == 0)):
                kb = cwe_info(f.cwe, lang)
                tags = [f.owasp]
                risk, group = getattr(f, "owasp_mobile", ""), getattr(f, "masvs", "")
                if risk:
                    tags.append("%s %s" % (risk, mobile_name(risk, lang)))
                if group:
                    tags.append(group)
                st.markdown(severity_badge(f.severity) + "&nbsp; **%s** %s &nbsp;-&nbsp; %s"
                            % (f.cwe, kb["name"] if kb["name"] != f.cwe else "",
                               " &nbsp;-&nbsp; ".join(tag for tag in tags if tag)),
                            unsafe_allow_html=True)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric(t("Risk"), "%.1f / 10" % f.risk_score)
                c2.metric(t("Confidence"), "%d%%" % round(f.confidence * 100))
                c3.metric(t("ML score"), "-" if f.ml_score is None else
                          "%d%%" % round(f.ml_score * 100))
                c4.metric(t("AI verdict"), f.ai_verdict.replace("_", " ") or "-")
                if f.tier == "confirmed":
                    st.success(t("Confirmed: ") + "; ".join(f.evidence))
                else:
                    st.caption(t("Probable: a rule matched and no independent evidence confirms "
                               "it yet%s.") % (" (this file is test code)" if f.test_code else ""))
                st.code(f.context or f.snippet, language=CODE_LANG.get(f.language, "text"))
                st.caption(t("Flagged line: %d - found by: %s - rule: %s") % (
                    f.line, ", ".join(f.engines), ", ".join(f.rule_ids)))
                # the texts of the knowledge base are written with the tool; the texts of the
                # finding itself can quote the scanned code or app, so they are escaped
                description = kb["description"] or untrusted(f.description)
                fix = kb["fix"] or untrusted(f.fix)
                if f.description and f.description != kb["description"] and kb["description"] \
                        and lang == "en":
                    st.markdown(untrusted(f.description))
                if description:
                    st.markdown(t("**Why it matters**"))
                    st.markdown(description)
                if fix:
                    st.markdown(t("**How to fix**"))
                    st.markdown(fix)
                if f.ai_explanation or f.ai_fix:
                    st.markdown(t("**AI review** (%s)") % untrusted(f.ai_model or "model"))
                    if f.ai_explanation:
                        st.info(untrusted(f.ai_explanation))
                    if f.ai_fix:
                        st.code(f.ai_fix, language=CODE_LANG.get(f.language, "text"))
                if kb["url"]:
                    st.caption(t("Reference: %s") % kb["url"])
                b1, b2, b3, _ = st.columns([1, 1, 1, 2])
                b1.button(t("Real vulnerability"), key="tp_%d" % index, on_click=review,
                          args=(index, "tp"), disabled=f.user_verdict == "true_positive", **WIDE)
                b2.button(t("False positive"), key="fp_%d" % index, on_click=review,
                          args=(index, "fp"), disabled=f.user_verdict == "false_positive", **WIDE)
                if f.user_verdict:
                    b3.button(t("Clear my review"), key="clear_%d" % index, on_click=review,
                              args=(index, "clear"), **WIDE)
        if len(shown) > 150:
            st.caption(t("Showing the first 150. Use the filters, or download the full report."))

with tab_learn:
    storage = get_storage()
    if st.session_state.get("learn_note"):
        st.info(st.session_state.pop("learn_note"))
    all_rules = load_rules()
    stats = storage.rule_stats()
    confidences = {r.id: r.confidence for r in all_rules}
    quarantined = feedback_module.quarantined_rules(stats, confidences)
    pending = storage.list_candidates("pending")
    learned = store.read_learned()
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric(t("Active rules"), len(all_rules))
    m2.metric(t("Learned rules"), len(learned))
    m3.metric(t("Waiting for approval"), len(pending))
    m4.metric(t("Your reviews"), len(storage.feedback_rows()))
    m5.metric(t("Quarantined rules"), len(quarantined))
    st.caption(t("The AI proposes, the tool validates, you approve. A proposed rule becomes "
               "active only after it passes every automatic check and you approve it."))

    st.subheader(t("Teach the tool"))
    if not llm_ready:
        st.caption(t("Learning needs a working AI provider (section 3 of the sidebar)."))
    t1, t2, t3 = st.columns(3)
    with t1:
        st.markdown(t("**From the current scan**"))
        st.caption(t("Uses what the AI found or rejected in the last scan. Run the scan with "
                   "*AI review* and *Deep scan* switched on."))
        if st.button(t("Learn from this scan"), disabled=not llm_ready or result is None, **WIDE):
            with st.spinner(t("Proposing and validating rules")):
                created = loop.learn_from_scan(result, loop.load_files(result.target, apk_tools),
                                               make_client(llm_config), storage)
            ok = sum(1 for c in created if c["status"] == "pending")
            st.session_state["learn_note"] = t(
                "%d candidate(s) proposed: %d passed validation, %d rejected automatically."
            ) % (len(created), ok, len(created) - ok)
            st.rerun()
    with t2:
        st.markdown(t("**Fill gaps for a language**"))
        every = "all languages"
        language = st.selectbox(t("Language"), [every] + CODE_LANGUAGES)
        if language == every:
            gap_map = loop.all_gaps()
            gaps = [c for v in gap_map.values() for c in v]
            st.caption(t("%d weaknesses without a rule in %d languages (up to %d AI requests)")
                       % (len(gaps), len(gap_map), 2 * len(gaps)))
        else:
            gaps = loop.coverage_gaps(language)
            st.caption(t("Weaknesses without a rule: %s") % (", ".join(gaps) or "none"))
        if st.button(t("Write rules for the gaps"), disabled=not llm_ready or not gaps, **WIDE):
            with st.spinner(t("Asking the model for rules")):
                client = make_client(llm_config)
                created = (loop.bootstrap_all(client, storage) if language == every
                           else loop.bootstrap(client, storage, language))
            ok = sum(1 for c in created if c["status"] == "pending")
            st.session_state["learn_note"] = t(
                "%d candidate(s) proposed: %d passed validation, %d rejected automatically."
            ) % (len(created), ok, len(created) - ok)
            st.rerun()
    with t3:
        st.markdown(t("**From your false positives**"))
        st.caption(t("Proposes a narrow exclusion for each finding you dismissed, so the rule "
                   "stops reporting that kind of safe code."))
        if st.button(t("Learn exclusions"), disabled=not llm_ready, **WIDE):
            with st.spinner(t("Proposing and validating exclusions")):
                created = loop.learn_from_feedback(make_client(llm_config), storage)
            st.session_state["learn_note"] = t("%d exclusion(s) proposed.") % len(created)
            st.rerun()

    st.subheader(t("Waiting for your approval (%d)") % len(pending))
    if not pending:
        st.caption(t("Nothing is waiting."))
    for c in pending:
        kind = "Exclusion for %s" % c.get("target_rule") if c.get("kind") == "exclude" \
            else "New rule"
        with st.expander("%s | %s | %s | %s" % (untrusted(kind), ", ".join(c.get("languages", [])),
                                                untrusted(c.get("cwe", "")),
                                                untrusted(c.get("title", "")))):
            st.caption(t("%s - proposed by %s - origin: %s") % (c["id"], c.get("source", ""),
                                                             c.get("origin", "")))
            if c.get("origin") == "bootstrap":
                st.warning(t("Written from the model's own knowledge, without an example from a "
                           "real project. Its only evidence is the examples below."))
            if c.get("kind") == "exclude":
                st.markdown(t("**Lines matching this are skipped by the rule**"))
                st.code(c.get("exclude", ""), language="text")
            else:
                st.markdown(t("**Pattern**"))
                st.code(c.get("pattern", ""), language="text")
                if c.get("exclude"):
                    st.markdown(t("**Unless the line also matches**"))
                    st.code(c["exclude"], language="text")
            if c.get("message"):
                st.markdown(untrusted(c["message"]))
            evidence = (c.get("evidence") or {}).get("snippet")
            if evidence:
                # a file name of the scanned project, shown as code: no backtick may end it
                st.markdown(t("**Learned from** `%s`") % strip_bidi(
                    str(c["evidence"].get("file") or "your review")).replace("`", "'"))
                st.code(evidence, language="text")
            e1, e2 = st.columns(2)
            if c.get("examples_vulnerable"):
                e1.markdown(t("**Must match**"))
                e1.code("\n".join(c["examples_vulnerable"]), language="text")
            if c.get("examples_safe"):
                e2.markdown(t("**Must not match**"))
                e2.code("\n".join(c["examples_safe"]), language="text")
            report = c.get("validation") or {}
            st.markdown(t("**Automatic checks**"))
            st.dataframe(tframe([{"Check": x["name"],
                                        "Result": "passed" if x["passed"] else "FAILED",
                                        "Detail": x["detail"]} for x in report.get("checks", [])]),
                         hide_index=True, **WIDE)
            if report.get("project_matches"):
                st.markdown(t("**What it would flag in the scanned project (%d lines)**")
                            % report.get("match_count", 0))
                st.dataframe(tframe(report["project_matches"]), hide_index=True, **WIDE)
            a1, a2, _ = st.columns([1, 1, 3])
            a1.button(t("Approve"), key="approve_%s" % c["id"], type="primary", on_click=decide,
                      args=(c["id"], True), **WIDE)
            a2.button(t("Reject"), key="reject_%s" % c["id"], on_click=decide,
                      args=(c["id"], False), **WIDE)

    rejected = storage.list_candidates("rejected_auto")[:15]
    if rejected:
        with st.expander(t("Rejected automatically (%d most recent)") % len(rejected)):
            st.dataframe(tframe([{
                "Id": c["id"], "CWE": c.get("cwe", ""), "Pattern": c.get("pattern") or c.get("exclude", ""),
                "Failed checks": "; ".join("%s: %s" % (x["name"], x["detail"]) for x in
                                           (c.get("validation") or {}).get("checks", [])
                                           if not x["passed"])} for c in rejected]),
                hide_index=True, **WIDE)

    st.subheader(t("Learned rules (%d)") % len(learned))
    if learned:
        st.dataframe(tframe([{
            "Id": r["id"], "Languages": ", ".join(r.get("languages", [])), "CWE": r.get("cwe", ""),
            "Title": r.get("title", ""), "Pattern": r.get("pattern", ""),
            "Source": (r.get("learned") or {}).get("source", ""),
            "Approved": (r.get("learned") or {}).get("approved", "")} for r in learned]),
            hide_index=True, **WIDE)
        r1, r2 = st.columns([3, 1])
        chosen_rule = r1.selectbox(t("Remove a learned rule"), [r["id"] for r in learned],
                                   label_visibility="collapsed")
        r2.button(t("Remove rule"), on_click=remove_rule, args=(chosen_rule,), **WIDE)
    else:
        st.caption(t("No learned rules yet. They are stored in learned/rules.yaml."))

    st.subheader(t("Rule track record"))
    if stats:
        st.dataframe(tframe([{
            "Rule": rule_id, "Confirmed": s["tp"], "False positives": s["fp"],
            "Written confidence": confidences.get(rule_id, 0.6),
            "Adjusted confidence": round(feedback_module.adjusted_confidence(
                confidences.get(rule_id, 0.6), s["tp"], s["fp"]), 2),
            "State": "quarantined" if rule_id in quarantined else "active"}
            for rule_id, s in sorted(stats.items(), key=lambda kv: -kv[1]["fp"])]),
            hide_index=True, **WIDE)
    else:
        st.caption(t("No reviews yet. Use the buttons under each finding to confirm or dismiss it."))

    st.subheader(t("Coverage: rules per language and weakness"))
    matrix = loop.coverage_matrix()
    frame = pd.DataFrame(matrix).T.fillna(0).astype(int)
    frame = frame[sorted(frame.columns, key=lambda c: int(c.split("-")[1]))] if len(frame.columns) else frame
    frame.insert(0, "Rules", frame.sum(axis=1))
    st.dataframe(frame, **WIDE)
    st.caption(t("Python is analysed mainly by the AST taint engine; its few pattern rules "
               "are imported ones. Languages without rules are still covered by the AI deep "
               "scan, and by Opengrep/Semgrep when installed."))

with tab_reports:
    if result is None:
        st.write(t("No scan yet."))
    else:
        st.write(t("Download the results of the current scan."))
        d1, d2, d3, d4 = st.columns(4)
        d1.download_button(t("HTML report"), render_html(result), "sca-report.html", "text/html",
                           **WIDE)
        d2.download_button(t("JSON"), json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
                           "sca-report.json", "application/json", **WIDE)
        d3.download_button(t("SARIF"), json.dumps(to_sarif(result), indent=2, ensure_ascii=False),
                           "sca-report.sarif", "application/json", **WIDE)
        try:
            d4.download_button(t("PDF report"), render_pdf(result), "sca-report.pdf",
                               "application/pdf", **WIDE)
        except Exception as exc:
            d4.caption(t("PDF unavailable: %s") % exc)
        st.caption(t("The HTML report contains everything, including Arabic text. The PDF uses "
                   "built-in fonts and leaves non-Latin text out. SARIF can be uploaded to "
                   "GitHub code scanning or opened in VS Code."))

with tab_history:
    scans = get_storage().list_scans(200)
    if not scans:
        st.write(t("No saved scans yet."))
    else:
        frame = pd.DataFrame(scans)
        targets = sorted(frame["target"].unique())
        chosen = st.selectbox(t("Project"), targets, index=targets.index(result.target)
                              if result is not None and result.target in targets else 0)
        project = frame[frame["target"] == chosen].sort_values("id")
        st.subheader(t("Security score over time"))
        st.line_chart(project.set_index("started_at")[["score"]], height=220)
        st.dataframe(project[["id", "started_at", "score", "grade", "critical", "high",
                              "medium", "low", "files_scanned", "lines_scanned"]]
                     .sort_values("id", ascending=False), hide_index=True, **WIDE)
        scan_id = st.selectbox(t("Open a saved scan"), list(project["id"])[::-1])
        if st.button(t("Load this scan")):
            loaded = get_storage().load_scan(int(scan_id))
            if loaded is not None:
                st.session_state["result"] = loaded
                st.rerun()
