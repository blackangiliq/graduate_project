"""Secure Code Analyzer - web dashboard.

Start it locally with python -m sca ui, or use the container for browser uploads.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from contextlib import ExitStack
from functools import partial
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from sca import scoring, splitinput
from sca.ai.classifier import SKLEARN_AVAILABLE
from sca.ai.llm import DEFAULT_MODEL
from sca.ai.providers import PRESETS, LLMConfig, load_config, make_client, save_config
from sca.cwe import MASVS_GROUPS, MOBILE_TOP10_2024, info as cwe_info, masvs_name, mobile_name
from sca.engines import external
from sca.engines.rules_engine import load_rules
from sca.flutter import APP_SUFFIXES, AppError, is_app_package
from sca.flutter import tools as app_tools
from sca.flutter import zipread
from sca.flutter.checks import FIREBASE_NOTE, MAPS_CLIENT_FIX, MAPS_CLIENT_NOTE
from sca.flutter.context import APP_KINDS
from sca.flutter.pubspec import parse_pubspec
from sca.learn import feedback as feedback_module
from sca import rulebook
from sca.learn import loop, store
from sca.models import SEVERITIES, ScanResult
from sca.pipeline import ScanOptions, run_scan
from sca.report.html_report import render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import to_sarif
from sca.presentation import finding_focus, finding_text, view_result
from sca.sourcearchive import ArchiveError, MAX_EXPANDED_BYTES
from sca.storage import Storage, data_dir
from sca.ui import app_panel, decoded_panel, dynamic_panel, guide_tab, hosted, intro, rules_tab, texts
from sca.ui.i18n import AR
from sca.walker import CODE_LANGUAGES, strip_bidi

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "samples" / "vulnerable_app"
FLUTTER_SAMPLE = ROOT / "samples" / "flutter_vulnerable_app"
DEMO_APK = ROOT / "data" / "demo" / "secure-code-analyzer-demo.apk"
SEV_COLOR = {"critical": "#9b1c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d5f8a",
             "info": "#5f5e5a"}
CODE_LANG = {"python": "python", "javascript": "javascript", "typescript": "typescript",
             "php": "php", "java": "java", "c": "c", "cpp": "cpp", "csharp": "csharp",
             "go": "go", "config": "yaml", "shell": "bash", "html": "html", "ruby": "ruby",
             "kotlin": "kotlin", "rust": "rust", "swift": "swift", "powershell": "powershell",
             "dart": "dart"}
HOSTED = os.environ.get("SCA_HOSTED") == "1"
STATUS_LABEL = {"open": "Open", "needs_review": "Needs review",
                "likely_false_positive": "Likely false positives (AI)",
                "dismissed": "Dismissed by you"}

st.set_page_config(page_title="Secure Code Analyzer", page_icon=":shield:", layout="wide")

# Streamlit renamed the "fill the available width" option; support old and new versions.
WIDE = ({"width": "stretch"} if "width" in inspect.signature(st.button).parameters
        else {"use_container_width": True})
EXPANDER_EVENTS = "on_change" in inspect.signature(st.expander).parameters
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
    """Label and help text of a scan control, from the shared settings table."""
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
    patterns = " ".join("*" + suffix for suffix in hosted.UPLOAD_SUFFIXES)
    return run_dialog("askopenfilename(title='Choose a source ZIP or an Android app', filetypes=[('Source ZIP or Android app', "
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
    """Make the uploaded selection the local scan target, including split packages."""
    uploads = st.session_state.get("app_upload") or []
    if st.session_state.get("target") == st.session_state.pop("last_upload_path", None):
        st.session_state["target"] = ""
    if not uploads:
        return
    st.session_state["target"] = ""
    if len(uploads) > 1:
        try:
            with ExitStack() as buffers:
                items = [(f.name, buffers.enter_context(f.getbuffer())) for f in uploads]
                path = splitinput.store_uploads(items, data_dir() / "uploads", limit_bytes=200 << 20)
        except (ValueError, OSError) as error:
            st.session_state["browse_note"] = untrusted(t(str(error)))
            return
        st.session_state["target"] = st.session_state["last_upload_path"] = str(path)
        return
    uploaded = uploads[0]
    original = Path(uploaded.name.replace("\\", "/"))
    suffix = original.suffix.lower()
    if suffix not in hosted.UPLOAD_SUFFIXES:
        st.session_state["browse_note"] = t("Choose a source ZIP or an Android app package.")
        return
    data = uploaded.getvalue()
    if suffix == ".zip" and not zipfile.is_zipfile(BytesIO(data)):
        st.session_state["browse_note"] = t("This file is not a readable source ZIP: %s") \
            % untrusted(original.name)
        return
    if suffix != ".zip" and not is_zip_data(data):    # APK parser accepts some nonstandard ZIPs
        st.session_state["browse_note"] = t(
            "This file is not a readable app package (it is not a ZIP archive): %s") \
            % plain(original.name)
        return
    digest = hashlib.sha256(data).hexdigest()[:12]
    folder = data_dir() / "uploads"
    kept = sorted(p for p in folder.glob("%s-*%s" % (digest, suffix))
                  if p.is_file() and p.suffix == suffix) if folder.is_dir() else []
    if kept:                            # uploaded before, perhaps under another name
        st.session_state["target"] = st.session_state["last_upload_path"] = str(kept[0])
        return
    # only safe characters in the stored name; a name of other letters (Arabic) becomes "app"
    stem = hosted.UPLOAD_NAME.sub("_", original.stem).strip("._")[:60] or "app"
    path = folder / ("%s-%s%s" % (digest, stem, suffix))
    partial = None
    try:
        folder.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=folder, suffix=".part", delete=False) as staging:
            partial = Path(staging.name)
            staging.write(data)
        os.replace(partial, path)
    except OSError as exc:
        st.session_state["browse_note"] = t("The upload could not be saved: %s") % plain(str(exc))
        if partial is not None:
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                pass
        return
    st.session_state["target"] = st.session_state["last_upload_path"] = str(path)


def is_zip_data(data: bytes) -> bool:
    """The check of sca.flutter.zipread.is_zip on bytes in memory: a ZIP header at the start,
    or an end of central directory record near the end (an archive with data in front)."""
    return (data[:4] in (zipread.LOCAL_SIG, zipread.EOCD_SIG)
            or zipread.EOCD_SIG in data[-(zipread.EOCD_SIZE + zipread.MAX_COMMENT):])


def use_sample(path: Path = SAMPLE) -> None:
    st.session_state["target"] = str(path)


def use_flutter_sample() -> None:
    st.session_state["target"] = str(FLUTTER_SAMPLE)


PUBSPEC_LIMIT = 1_000_000      # a larger pubspec.yaml is not read for the input preview


def target_note(target: str) -> str:
    """A caption under the path box: what kind of target it is. Only cheap checks, without
    walking the folder (the dashboard runs on every click): a pubspec.yaml that depends on the
    Flutter SDK, or the manifest of an Android module one level down (app/src/main/...,
    android/app/src/main/...) or of the folder itself."""
    try:
        path = Path(target).expanduser()
        if path.suffix.lower() == ".zip" and path.is_file():
            return t("The scanner checks the ZIP contents to identify a source project or a split APK set.")
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
    except Exception:                   # a caption is never worth an error in the dashboard
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
    """Open the history schema, including separately stored original scan evidence."""
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
    from sca.flutter.inventory import refresh_keys
    for apis in ((getattr(result, "app", None) or {}).get("apis"),
                 getattr(result, "visible_apis", None)):
        if isinstance(apis, dict):  # a dismissed key leaves the inventory, a confirmed returns
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


# ------------------------------------------------------------------ scan workspace
if not HOSTED:
    st.session_state.setdefault("target", "")
    saved = load_config()
heading, language = st.columns([4, 1])
heading.title("Secure Code Analyzer")
language.radio("Language / اللغة", ["English", "العربية"], horizontal=True, key="ui_lang",
               help=texts.setting("ui_lang", "en")[1] + "\n\n" + texts.setting("ui_lang", "ar")[1])
lang = ui_lang()
if lang == "ar":
    st.markdown(RTL_CSS, unsafe_allow_html=True)

if not HOSTED and intro.active():
    intro.render(lang)
    st.stop()

workspace_tab_key = f"scan_workspace_tab_{lang}"
show_setup = st.session_state.pop("open_scan_setup_next", None)
if "key" in inspect.signature(st.expander).parameters:
    if show_setup is not None:
        st.session_state["scan_workspace_open"] = show_setup
    setup = st.expander(t("Scan workspace"), expanded=True, key="scan_workspace_open",
                        on_change="rerun")
else:  # Older Streamlit versions do not support controlling or nesting expanders.
    setup = st.container()
    setup.subheader(t("Scan workspace"))
setup_names = ["Scan input", "Scan settings"] if HOSTED else ["Scan input", "Samples", "Scan settings"]
workspace_navigation = {}
if "on_change" in inspect.signature(st.tabs).parameters:
    workspace_navigation = {"key": workspace_tab_key, "on_change": "rerun"}
    if show_setup:
        st.session_state[workspace_tab_key] = t("Scan input")
setup_tabs = dict(zip(setup_names, setup.tabs([t(name) for name in setup_names], **workspace_navigation)))
uploads = []
server_path = ""
scan_input = "upload"
with setup_tabs["Scan input"]:
    if HOSTED:
        if hosted.server_root() is not None:
            input_labels = {"upload": t("Upload file"), "path": t("Server path")}
            scan_input = st.radio(t("Scan input"), tuple(input_labels), horizontal=True,
                                  key="scan_input", format_func=input_labels.get)
        if scan_input == "path":
            server_path = st.text_input(
                t("Server path"), placeholder="apps/my-app",
                key="server_path", help=t("Enter a path inside the server project directory.")).strip()
        else:
            uploads = st.file_uploader(type=[suffix[1:] for suffix in hosted.UPLOAD_SUFFIXES],
                                       accept_multiple_files=True, key="app_upload", **opt("app_upload"))
            st.caption(t("One archive up to %d MiB, or up to %d MiB total for a split set. "
                         "Download the report before closing this session.") %
                       (hosted.MAX_UPLOAD_MIB, MAX_EXPANDED_BYTES >> 20))
    else:
        paths, upload_area = st.columns([1, 1])
        paths.text_input(key="target", placeholder=r"C:\projects\my-app", **opt("target"))
        chosen_target = st.session_state["target"].strip().strip('"')
        selected_path = Path(chosen_target).expanduser() if chosen_target else None
        col_a, col_b = paths.columns(2)
        col_a.button(on_click=browse_clicked, **opt("browse"), **WIDE)
        col_b.button(on_click=browse_app_clicked, **opt("browse_app"), **WIDE)
        upload_area.file_uploader(type=[suffix[1:] for suffix in hosted.UPLOAD_SUFFIXES],
                                  accept_multiple_files=True, key="app_upload",
                                  on_change=app_uploaded, **opt("app_upload"))
        split_paths = []
        if selected_path is not None:
            try:
                if selected_path.is_dir():
                    split_paths = splitinput.folder_apks(selected_path)
                elif selected_path.is_file() and selected_path.name.lower() in ("base.apk", "base-master.apk"):
                    siblings = splitinput.folder_apks(selected_path.parent)
                    if len(siblings) > 1:
                        include = paths.checkbox(t("Include adjacent APK parts (%d files)") % len(siblings),
                                                 value=True, key=f"include_splits_{selected_path}")
                        if include:
                            selected_path = selected_path.parent
                            split_paths = siblings
            except (ValueError, OSError) as exc:
                paths.warning(untrusted(t(str(exc))))
        if split_paths:
            paths.caption(t("APK files selected: %d") % len(split_paths))
            paths.text("  ·  ".join(strip_bidi(part.name) for part in split_paths))
        elif chosen_target:
            note = target_note(chosen_target)
            if note:
                paths.caption(note)
    if st.session_state.get("browse_note"):
        st.warning(st.session_state.pop("browse_note"))

if "Samples" in setup_tabs:
    with setup_tabs["Samples"]:
        col_a, col_b = st.columns(2)
        col_a.button(on_click=use_sample, **opt("sample"), **WIDE)
        col_b.button(on_click=use_flutter_sample, **opt("flutter_sample"), **WIDE)
        if DEMO_APK.is_file():
            st.button(t("Demo APK"), on_click=use_sample, args=(DEMO_APK,), **WIDE)
        training_labs = intro.labs()
        if training_labs:
            st.selectbox(options=[""] + training_labs, key="lab_choice", on_change=lab_chosen,
                         format_func=lambda name: name or "-", **opt("lab"))

settings = setup_tabs["Scan settings"]
with settings.expander(t("Static engines"), expanded=True):
    tools = external.availability()
    missing = t(" (not installed)")
    counts = rulebook.summary()
    use_rules = st.checkbox(value=True, **opt("use_rules"))
    st.caption(t("%d active rules of %d - manage them in the Rules tab")
               % (counts["enabled"], counts["total"]))
    if not HOSTED:
        st.button(on_click=intro.open_rules, args=(lang,), **opt("open_rules"), **WIDE)
    use_ast = st.checkbox(value=True, **opt("use_ast"))
    use_secrets = st.checkbox(value=True, **opt("use_secrets"))
    use_bandit = use_semgrep = use_gitleaks = False
    if not HOSTED:
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
with settings.expander(t("More engine options")):
    use_taint_lite = st.checkbox(value=True, **opt("use_taint_lite"))
    use_c_memory = st.checkbox(value=True, **opt("use_c_memory"))
    absent = [name for name, found in mobile_tools().items() if not found]
    if len(absent) == 2:
        tools_note = missing
    elif absent:
        tools_note = t(" (%s not installed)") % absent[0]
    else:
        tools_note = ""
    apk_tools = st.checkbox(opt("apk_tools")["label"] + tools_note,
                            value=HOSTED and len(absent) < 2,
                            disabled=len(absent) == 2, help=opt("apk_tools")["help"])
    exclude_dirs = st.text_input(placeholder="docs, third_party", **opt("exclude_dirs"))

if not HOSTED:
    with settings.expander(t("Artificial intelligence")):
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
        deep_max_files = st.slider(min_value=1, max_value=50, value=10,
                                   disabled=not llm_ready, **opt("deep_max_files"))
        llm_timeout = st.slider(min_value=30, max_value=600, value=180, step=30,
                                disabled=not llm_ready, **opt("llm_timeout"))
        if st.button(**opt("save_ai"), **WIDE):
            path = save_config(LLMConfig(
                preset=preset, api_key=api_key, model=llm_model,
                base_url="" if base_url == PRESETS[preset]["base_url"] else base_url))
            st.caption(t("Saved to %s") % path)

with settings.expander(t("Precision and output")):
    strict = st.checkbox(value=False, **opt("strict"))
    skip_tests = st.checkbox(value=False, **opt("skip_tests"))
    use_feedback = not HOSTED and st.checkbox(value=True, **opt("use_feedback"))

    save_scan = not HOSTED and st.checkbox(value=True, **opt("save_scan"))
    if not HOSTED:
        st.button(on_click=intro.reopen, **opt("intro"), **WIDE)

if not HOSTED:
    llm_config = LLMConfig(preset=preset, base_url=base_url, api_key=api_key, model=llm_model)
    target = str(selected_path) if selected_path is not None else ""
elif uploads:
    target = uploads[0].name if len(uploads) == 1 else t("%d selected APK files") % len(uploads)
else:
    target = server_path
if target:
    setup.caption(t("Selected input: %s") % ltr(untrusted(target)))
run = setup.button(type="primary", **opt("run"))

# ------------------------------------------------------------------ run a scan
# Messages and the progress bar of a scan live in this container. It exists in every run,
# so the tabs below keep their place on the page and the selected tab is not reset.
status_area = st.container()
if run:
    with status_area:
        target_path = None if HOSTED else Path(target).expanduser()
        if not target:
            if HOSTED:
                st.error(t("Enter a path inside the server project directory.") if scan_input == "path"
                         else t("Choose a source ZIP or an Android app package."))
            else:
                st.error(t("Choose a project folder, source ZIP or Android app package first."))
        elif HOSTED and len(uploads) == 1 and not (0 < uploads[0].size <= hosted.MAX_UPLOAD_MIB << 20):
            st.error(t("Choose a file between 1 byte and %d MiB.") % hosted.MAX_UPLOAD_MIB)
        elif HOSTED and len(uploads) > 1 and sum(f.size for f in uploads) > MAX_EXPANDED_BYTES:
            st.error(t("The selected APKs exceed the combined size limit."))
        elif target_path is not None and not target_path.exists():
            st.error(t("This path does not exist: %s") % plain(target))
        elif (target_path is not None and target_path.is_file()
              and target_path.suffix.lower() in APP_SUFFIXES
              and not is_app_package(target_path)):
            st.error(t("This file is not a readable app package (it is not a ZIP archive): %s")
                     % plain(target))
        else:
            options = ScanOptions(
                use_rules=use_rules, use_ast=use_ast, use_secrets=use_secrets,
                use_bandit=use_bandit, use_semgrep=use_semgrep, use_gitleaks=use_gitleaks,
                lang=lang, strict=strict,
                include_tests=not skip_tests, use_taint_lite=use_taint_lite,
                use_c_memory=use_c_memory, use_flutter=use_flutter, apk_tools=apk_tools,
                use_feedback=use_feedback, save=save_scan, use_ml=not HOSTED and use_ml,
                keep_decoded=True,
                exclude_dirs=[d.strip() for d in exclude_dirs.split(",") if d.strip()])
            if not HOSTED:
                options.use_llm = use_llm
                options.llm_provider, options.llm_base_url = preset, base_url
                options.llm_api_key, options.llm_model = api_key, llm_model
                options.llm_max_findings, options.llm_deep_scan = llm_max, deep and use_llm
                options.llm_deep_max_files, options.llm_timeout = deep_max_files, llm_timeout
            # What the scan is doing, while it does it: each step is added to this box as
            # it starts and when it ends, and the bar names the file being read.
            live = st.empty()
            box = live.status(t("Scanning %s") % ltr(untrusted(target)), expanded=True)
            bar = box.progress(0.0, text=t("Starting"))

            def on_progress(message: str, fraction: float) -> None:
                bar.progress(min(1.0, max(0.0, fraction)), text=plain(scan_text(message)))
                if getattr(message, "kind", "step") != "file":
                    box.markdown(step_line(message))

            def show_error(message: str) -> None:
                bar.empty()
                box.update(label=message, state="error")
                st.error(message)

            try:
                if HOSTED:
                    if uploads:
                        with ExitStack() as buffers:
                            items = [(f.name, buffers.enter_context(f.getbuffer())) for f in uploads]
                            scan = hosted.scan_uploads(items, options, on_progress)
                    else:
                        scan = hosted.scan_path(target, options, on_progress)
                else:
                    scan = run_scan(target, options, on_progress, get_storage())
                st.session_state["result"] = scan
                st.session_state.pop("finding_file_preview", None)
                live.empty()     # the same steps stay on the Dashboard tab, see "scan_log"
                st.session_state["scan_log_open"] = True
                if "key" in inspect.signature(st.expander).parameters:
                    st.session_state["open_scan_setup_next"] = False
                    st.rerun()
            except hosted.HostedBusy:
                show_error(t("The scanner is busy. Try again when the current scan finishes."))
            except hosted.HostedInputError as exc:
                show_error(t(str(exc)))
            except splitinput.SplitInputError as exc:
                show_error(untrusted(t(str(exc))))
            except ArchiveError as exc:
                show_error(t("The source ZIP cannot be read: %s") % untrusted(t(str(exc))))
            except AppError as exc:
                show_error(t("The app file cannot be read: %s") % untrusted(exc))
            except Exception as exc:
                show_error(t("The scan failed.") if HOSTED else
                           t("The scan failed: %s") % untrusted(exc))

result: ScanResult = st.session_state.get("result")
previews = result.decoded_files if result is not None else {}
local_source_view = not HOSTED and st.get_option("server.address") in {"localhost", "127.0.0.1", "::1"}

# ------------------------------------------------------------------ main area
# With a key, the open tab is remembered, and a button can open one (e.g. Open the rules).
TAB_STATE = ({"key": intro.MAIN_TABS_KEY + lang, "on_change": "rerun"}
             if "on_change" in inspect.signature(st.tabs).parameters else {})
tab_names = (("Dashboard", "Findings", "Runtime analysis", "Reports", "Guide") if HOSTED else
             ("Dashboard", "Findings", "Runtime analysis", "Rules", "Learning", "Reports", "History", "Guide"))
file_tab = "Decoded files" if result is not None and result.app.get("kind") in APP_KINDS else "Source files"
if result is not None and (previews or (not HOSTED and file_tab == "Decoded files")):
    tab_names = (*tab_names[:2], file_tab, *tab_names[2:])
tabs = dict(zip(tab_names, st.tabs([t(name) for name in tab_names], **TAB_STATE)))


def open_decoded(path: str, line: int) -> None:
    decoded_panel.jump_to(path, line)
    if TAB_STATE:
        st.session_state[intro.MAIN_TABS_KEY + lang] = t(file_tab)


def can_preview(path: str, line: int) -> bool:
    file = previews.get(path)
    if file is None or not isinstance(line, int) or line < 1:
        return False
    if local_source_view and getattr(file, "original", None) is not None:
        return line <= file.source_line_count
    return line <= len(file.lines)


@st.cache_data(ttl=5, show_spinner=False)
def runtime_environment():
    from sca.dynamic.environment import environment
    return environment()


def reconnect_runtime_observer(serial: str) -> dict:
    from sca.dynamic.environment import restart_lab_observer
    if HOSTED:
        raise ValueError("A local Android lab is required")
    try:
        return restart_lab_observer(serial)
    finally:
        runtime_environment.clear()


def run_runtime_capture(request: dict) -> dict:
    from sca.dynamic import CaptureOptions, run_capture
    from sca.dynamic.environment import install_target, forward_frida
    if HOSTED or result is None:
        raise ValueError("A local Android lab and a selected APK scan are required")
    if request.get("package") != result.app.get("package"):
        raise ValueError("Runtime package does not match the selected scan")
    storage = get_storage()
    if result.scan_id is None:
        result.scan_id = storage.save_scan(result)
    with st.status(t("Runtime capture setup"), expanded=True) as status:
        spawn = bool(request.get("spawn", True))
        installed = install_target(result.target, serial=request["serial"]) if spawn else None
        if installed is not None and not installed["success"]:
            raise ValueError("; ".join(installed["errors"]))
        endpoint = forward_frida(request["serial"])
        options = CaptureOptions(package=request["package"], serial=request["serial"],
                                 duration_seconds=request["duration_seconds"], frida_host=endpoint, spawn=spawn,
                                 native_hooks=bool(request.get("native_hooks", True)))
        capture = run_capture(options, data_dir() / "runtime" / str(result.scan_id),
                              decoded_files=result.decoded_files)
        if installed is not None:
            capture["installation"] = installed
        capture_id = storage.save_dynamic_session(result.scan_id, capture)
        capture.update(capture_id=capture_id, scan_id=result.scan_id)
        status.update(label=t("Runtime evidence"), state="error" if capture["status"] == "failed" else "complete")
    return capture


def hosted_runtime_scan_key() -> str:
    """Keep imports bound to this scan, even when another upload reuses its filename."""
    binding = st.session_state.get("runtime_import_scan_binding")
    if not binding or binding["result"] is not result:
        sequence = int(st.session_state.get("runtime_import_scan_sequence", 0)) + 1
        st.session_state["runtime_import_scan_sequence"] = sequence
        binding = {"result": result, "key": str(sequence)}
        st.session_state["runtime_import_scan_binding"] = binding
    return binding["key"]


def import_runtime_capture(payload: bytes, filename: str) -> dict:
    from sca.dynamic import validate_capture
    if result is None:
        raise ValueError("Select a scanned Android application first")
    if len(payload) > dynamic_panel.MAX_IMPORT_BYTES:
        raise ValueError("Runtime capture exceeds the import size limit")
    capture = validate_capture(json.loads(payload))
    if capture.get("package") != result.app.get("package"):
        raise ValueError("The imported package does not match the selected scan")
    capture["imported_external"] = True
    if HOSTED:
        st.session_state.setdefault("imported_runtime_sessions", {}).setdefault(hosted_runtime_scan_key(), []).insert(0, capture)
    else:
        storage = get_storage()
        if result.scan_id is None:
            result.scan_id = storage.save_scan(result)
        capture["capture_id"] = storage.save_dynamic_session(result.scan_id, capture)
        capture["scan_id"] = result.scan_id
    return capture


with tabs["Runtime analysis"]:
    if HOSTED:
        runtime_env = {"available": False, "reasons": [
            t("Live capture requires a connected Android lab. Import its capture JSON to inspect it here.")]}
        runtime_sessions = st.session_state.get("imported_runtime_sessions", {}).get(
            hosted_runtime_scan_key() if result else "", [])
    else:
        runtime_env = runtime_environment()
        runtime_sessions = get_storage().list_dynamic_sessions(result.scan_id) if result and result.scan_id else []
    dynamic_panel.render_dynamic(
        result, t, environment=runtime_env, sessions=runtime_sessions,
        on_run=None if HOSTED else run_runtime_capture,
        on_reconnect=None if HOSTED else reconnect_runtime_observer,
        on_import=import_runtime_capture if result and result.app.get("package") else None,
        on_load=None if HOSTED else lambda capture_id: get_storage().load_dynamic_session(
            capture_id, scan_id=result.scan_id if result else None),
        on_open_source=open_decoded)


def clear_finding_selection() -> None:
    st.session_state.pop("finding_file_preview", None)
    st.session_state["finding_table_version"] = st.session_state.get("finding_table_version", 0) + 1


def reset_finding_filters(prefix: str) -> None:
    st.session_state[prefix + "status"] = "all"
    st.session_state[prefix + "severity"] = list(SEVERITIES)
    st.session_state[prefix + "files"] = []
    st.session_state[prefix + "text"] = ""
    clear_finding_selection()


def browse_key_locations(keys, selected, pane) -> None:
    if selected is not None and 0 <= selected < len(keys):
        keys = [keys[selected]]
    locations = {}
    for key in keys:
        for address in key.get("locations", ()):
            path, line = address.get("file"), address.get("line")
            if can_preview(path, line):
                locations.setdefault((path, line), key)
    if locations:
        # Streamlit may format stored selections after this render's language
        # context has ended. Keep those labels identical to the rendered options.
        location_labels = {loc: "%s:%d · %s" % (
            strip_bidi(loc[0]), loc[1], strip_bidi(t(str(item.get("type", "")))))
            for loc, item in locations.items()}
        path, line = st.selectbox(t("Key location in decoded files"), list(locations),
                                  format_func=location_labels.get,
                                  key=f"preview_key_location_{selected}")
        key = locations[(path, line)]
        rule = key.get("rule_id", "")
        is_maps = rule == "SECRET-GOOGLE-001" and any(
            f.file == path and f.line <= line <= (f.end_line or f.line)
            and MAPS_CLIENT_NOTE in f.description for f in result.findings)
        credential = ("Google Maps Android client key" if is_maps else
                      decoded_panel.credential_kind(rule, key.get("cwe", "")))
        if line <= len(previews[path].lines) or (selected is not None and local_source_view
                                                 and getattr(previews[path], "original", None)):
            st.button(t("Open decoded location"), on_click=open_decoded, args=(path, line))
        with pane:
            if getattr(result, "visible_apis", None) and key.get("value"):
                st.caption(t("Detected value"))
                st.code(strip_bidi(str(key["value"])), language="text")
            decoded_panel.render_location(
                path, line, previews[path], t, on_open=open_decoded, key="browse_after_key_preview",
                credential=credential, rule=rule, evidence=result.credential_evidence,
                focus=str(key.get("value") or ""),
                show_original=local_source_view and selected is not None,
                member=result.app.get("apk_file_members", {}).get(path, ""))
    else:
        pane.info(t("This location is outside the available preview."))


def preview_finding(index: int, source: str) -> None:
    st.session_state["finding_file_preview"] = (index, source)


def browse_api_location(kind, item, pane) -> None:
    with pane:
        if item is None:
            st.caption(t("Select a row to see where it was found."))
            return
        field = {"endpoints": "url", "paths": "path", "calls": "target",
                 "config": "value", "env": "value"}[kind]
        value = item.get(field)
        if value:
            st.code(strip_bidi(str(value)), language="text")
        places = decoded_panel.api_locations(item, call=kind in {"calls", "env"})
        if not places:
            st.info(t("No file and line were recorded for this item."))
            return
        count = item.get("count")
        if isinstance(count, int) and len(places) < count:
            st.caption(t("%d recorded locations for %d occurrences.") % (len(places), count))
        path, line = places[0]
        prefix = f"api_preview_{kind}_{id(result)}"
        if len(places) > 1:
            def place_label(loc):
                address = "%s:%d" % (strip_bidi(loc[0]), loc[1])
                if kind == "calls":
                    return (t("Call site · %s") if loc == places[0]
                            else t("Target argument · %s")) % address
                return address

            place_labels = {loc: place_label(loc) for loc in places}
            path, line = st.selectbox(t("Recorded locations"), places, format_func=place_labels.get,
                                      key=f"{prefix}_places_{id(item)}")
        if not can_preview(path, line):
            st.code("%s:%d" % (strip_bidi(path), line), language="text")
            st.info(t("This location is outside the available preview.") if previews else
                    t("Run the scan again to view the file at this location."))
            return
        decoded_panel.render_location(path, line, previews[path], t, on_open=open_decoded,
                                      key=prefix, show_original=local_source_view,
                                      focus=str(value or ""),
                                      member=result.app.get("apk_file_members", {}).get(path, ""))


def render_finding_location(finding, key: str) -> None:
    kind = ("Google Maps Android client key" if MAPS_CLIENT_NOTE in finding.description else
            decoded_panel.credential_kind(finding.rule_id, finding.cwe))
    decoded_panel.render_location(finding.file, finding.line, previews[finding.file], t,
                                  on_open=open_decoded, key=key, credential=kind,
                                  show_original=local_source_view,
                                  rule=finding.rule_id, evidence=None if HOSTED else result.credential_evidence,
                                  focus=finding_focus(result, finding), column=getattr(finding, "column", 0),
                                  end_column=getattr(finding, "end_column", 0),
                                  member=result.app.get("apk_file_members", {}).get(finding.file, ""))


def select_finding_row(table_key: str, indices) -> None:
    row = app_panel.selected_table_row(st.session_state[table_key])
    if row is not None and 0 <= row < len(indices):
        preview_finding(indices[row], "table")
    else:
        st.session_state.pop("finding_file_preview", None)


def toggle_finding_detail(detail_key: str, index: int) -> None:
    if st.session_state[detail_key]:
        preview_finding(index, "detail")
    elif st.session_state.get("finding_file_preview") == (index, "detail"):
        st.session_state.pop("finding_file_preview", None)


if "Rules" in tabs:
    with tabs["Rules"]:
        rules_tab.render(get_storage(), t, WIDE)

with tabs["Guide"]:
    guide_tab.render(t, lang, WIDE)

with tabs["Dashboard"]:
    if result is None:
        st.header(t("Scan a project to begin"))
        st.write(t("Choose your files in **Scan input**, then press **Run scan**."))
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
        apis = getattr(result, "visible_apis", None) or (app_facts or {}).get("apis")
        if isinstance(apis, dict):      # a scan saved by an older version has none
            with st.expander(app_panel.apis_title(apis, t), expanded=True):
                app_panel.render_apis(apis, t, ltr, WIDE,
                                      key_locations=browse_key_locations if previews else None,
                                      api_location=browse_api_location)
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

if file_tab in tabs:
    with tabs[file_tab]:
        if previews:
            if file_tab == "Decoded files":
                st.caption(t("Positions refer to decoded files. Previews show the scanned text, "
                             "including credential values."))
            if any(len(file.lines) < file.source_line_count for file in previews.values()):
                st.caption(t("Some files exceed the session preview limit."))
            members_by_file = result.app.get("apk_file_members", {})
            decoded_panel.render(
                {path: decoded_panel.FileInfo(file.language, file.origin, len(file.lines),
                                             file.source_line_count, members_by_file.get(path, ""),
                                             getattr(file, "original", None) if local_source_view else None,
                                             file.derivation)
                 for path, file in previews.items()},
                lambda path, first, last: previews[path].lines[first - 1:last],
                t, scan_key=str(id(result)), wide=WIDE, source=file_tab == "Source files",
                tab_open=bool(TAB_STATE) and tabs[file_tab].open is True)
        else:
            st.info(t("Run the scan again to browse this package's decoded files."))

with tabs["Findings"]:
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
        prefix = f"finding_filter_{id(result)}_"
        status_filter = f1.selectbox(t("Show"), ["all", *present], format_func=show_labels.get,
                                     key=prefix + "status", on_change=clear_finding_selection)
        if status_filter not in show_labels:
            status_filter = "all"
        sev_filter = f2.multiselect(t("Severity"), SEVERITIES, default=SEVERITIES,
                                    key=prefix + "severity", on_change=clear_finding_selection)
        files = sorted({f.file for f in result.findings})
        file_filter = f3.multiselect(t("File"), files, key=prefix + "files",
                                     on_change=clear_finding_selection)
        text_filter = f4.text_input(t("Search (title, CWE, code)"), key=prefix + "text",
                                    on_change=clear_finding_selection)

        shown = []
        for index, f in enumerate(result.findings):
            if status_filter != "all" and f.status != status_filter:
                continue
            if f.severity not in sev_filter or (file_filter and f.file not in file_filter):
                continue
            haystack = " ".join([f.title, f.cwe, finding_text(result, f, context=False), f.file,
                                 getattr(f, "owasp_mobile", ""), getattr(f, "masvs", "")]).lower()
            if text_filter and text_filter.lower() not in haystack:
                continue
            shown.append((index, f))

        hidden = len(result.findings) - len(shown)
        if hidden:
            st.info(t("Showing %d of %d findings. The filters hide %d.") % (
                len(shown), len(result.findings), hidden))
        else:
            st.caption(t("%d of %d findings.") % (len(shown), len(result.findings)))
        if (hidden or status_filter != "all" or len(sev_filter) != len(SEVERITIES)
                or file_filter or text_filter):
            st.button(t("Show all findings"), on_click=reset_finding_filters, args=(prefix,))
        table = tframe([{
            "Severity": f.severity, "Title": f.title, "File": f.file, "Line": f.line,
            "CWE": f.cwe, "Tier": f.tier, "Risk": f.risk_score,
            "Status": t(STATUS_LABEL.get(f.status, f.status)),
            "Confidence %": round(f.confidence * 100), "Engines": ", ".join(f.engines),
            "ML %": None if f.ml_score is None else round(f.ml_score * 100),
            "AI": f.ai_verdict.replace("_", " "),
        } for _, f in shown])
        target = st.session_state.get("finding_file_preview")
        if previews:
            table_column, preview_column = st.columns([3, 2])
            with table_column:
                select_options = {}
                if app_panel.TABLE_SELECTION and shown:
                    version = st.session_state.get("finding_table_version", 0)
                    table_key = f"decoded_finding_rows_{id(result)}_{version}"
                    select_options = {
                        "key": table_key, "selection_mode": app_panel.SINGLE_SELECTION_MODE,
                        "on_select": partial(select_finding_row, table_key,
                                             [index for index, _ in shown]),
                    }
                if shown:
                    st.dataframe(table, hide_index=True, height=min(280, 50 + 35 * len(shown)),
                                 **WIDE, **select_options)
            with preview_column:
                selected = next((f for index, f in shown if target == (index, "table")), None)
                if selected is not None and can_preview(selected.file, selected.line):
                    render_finding_location(selected, "browse_after_finding_preview")
                elif selected is not None:
                    st.info(t("This location is outside the available preview."))
                elif shown:
                    st.info(t("Select a finding to preview its location."))
        elif shown:
            st.dataframe(table, hide_index=True, height=min(280, 50 + 35 * len(shown)), **WIDE)

        if shown:
            st.subheader(t("Details"))
        for position, (index, f) in enumerate(shown[:150]):
            # a label renders Markdown: the title can quote the app (a name, a URL)
            label = "%s | %s | %s:%d" % (f.severity.upper(), untrusted(f.title),
                                         untrusted(f.file), f.line)
            track_detail = EXPANDER_EVENTS and can_preview(f.file, f.line)
            detail_options = {}
            if track_detail:
                version = st.session_state.get("finding_table_version", 0)
                detail_key = f"finding_detail_{id(result)}_{version}_{index}"
                detail_options = {"key": detail_key, "on_change": toggle_finding_detail,
                                  "args": (detail_key, index)}
            with st.expander(label, expanded=(position == 0 and not track_detail), **detail_options):
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
                show_preview = target == (index, "detail") and can_preview(f.file, f.line)
                evidence, file_pane = st.columns([3, 2]) if show_preview else (st.container(), None)
                with evidence:
                    st.code(finding_text(result, f), language=CODE_LANG.get(f.language, "text"))
                    st.caption(t("Flagged line: %d - found by: %s - rule: %s") % (
                        f.line, ", ".join(f.engines), ", ".join(f.rule_ids)))
                    if not show_preview and can_preview(f.file, f.line):
                        st.button(t("Preview location"), key=f"preview_finding_{index}",
                                  on_click=preview_finding, args=(index, "detail"))
                if file_pane is not None:
                    with file_pane:
                        render_finding_location(f, f"browse_after_finding_{index}")
                # the texts of the knowledge base are written with the tool; the texts of the
                # finding itself can quote the scanned code or app, so they are escaped
                description = kb["description"] or untrusted(f.description)
                fix = kb["fix"] or untrusted(f.fix)
                if MAPS_CLIENT_NOTE in f.description:
                    description, fix = t(MAPS_CLIENT_NOTE), t(MAPS_CLIENT_FIX)
                elif FIREBASE_NOTE in f.description:
                    description = t("This value appears in Firebase client configuration. "
                                    "The file scan cannot establish access to project data.")
                    fix = t("Review the allowed apps and APIs in Google Cloud and verify the "
                            "project's Firebase Security Rules.")
                elif f.rule_id == "FLUTTER-PUB-001" and f.title.startswith("Possibly vulnerable dependency:"):
                    description = t("The package was found, but its version could not be matched "
                                    "to the affected versions in the advisory.")
                    fix = t("Check the resolved dependency version against the advisory before "
                            "classifying this as a vulnerability.")
                elif f.description and f.description != kb["description"] and kb["description"] \
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
                if not HOSTED:
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

def render_learning() -> None:
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
        st.caption(t("Choose a working AI provider in Scan settings to use learning."))
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

if "Learning" in tabs:
    with tabs["Learning"]:
        render_learning()

with tabs["Reports"]:
    if result is None:
        st.write(t("No scan yet."))
    else:
        st.write(t("Download the results of the current scan."))
        report_view = view_result(result)
        if not previews:
            st.info(t("This saved result has no original file snapshot. Rescan its input to display "
                      "and export the complete observed values."))
        d1, d2, d3, d4 = st.columns(4)
        d1.download_button(t("HTML report"), render_html(report_view), "sca-report.html", "text/html",
                           **WIDE)
        d2.download_button(t("JSON"), json.dumps(report_view.to_dict(), indent=2, ensure_ascii=False),
                           "sca-report.json", "application/json", **WIDE)
        d3.download_button(t("SARIF"), json.dumps(to_sarif(report_view), indent=2, ensure_ascii=False),
                           "sca-report.sarif", "application/json", **WIDE)
        try:
            d4.download_button(t("PDF report"), render_pdf(report_view), "sca-report.pdf",
                               "application/pdf", **WIDE)
        except Exception as exc:
            d4.caption(t("PDF unavailable: %s") % exc)
        st.caption(t("The HTML report contains everything, including Arabic text. The PDF uses "
                   "built-in fonts and leaves non-Latin text out. SARIF can be uploaded to "
                   "GitHub code scanning or opened in VS Code."))

def render_history() -> None:
    storage = get_storage()
    st.subheader(t("Scan archive"))
    st.caption(t("Archive database"))
    st.code(str(Path(storage.path).resolve()), language="text")
    if not storage.count_scans():
        st.write(t("No saved scans yet."))
        return
    search = st.text_input(t("Find scans by file name or path"), key="archive_search",
                           on_change=lambda: st.session_state.update(archive_page=1)).strip()
    total = storage.count_scans(search)
    if not total:
        st.info(t("No saved scans match this path."))
        return
    page_count = (total + 24) // 25
    page = 1
    if page_count > 1:
        if st.session_state.get("archive_page", 1) > page_count:
            st.session_state["archive_page"] = 1
        page = st.number_input(t("Archive page"), 1, page_count, key="archive_page")
    scans = storage.list_scans(25, search=search, offset=(page - 1) * 25)
    if not scans:
        return
    st.caption(t("%d saved scans · page %d of %d") % (total, page, page_count))
    st.dataframe(tframe([{"ID": s["id"], "Scan target": s["target"], "Started": s["started_at"],
                          "Score": s["score"], "Grade": s["grade"], "Files": s["files_scanned"],
                          "Critical": s["critical"], "High": s["high"]} for s in scans]),
                 hide_index=True, **WIDE)
    by_id = {s["id"]: s for s in scans}
    scan_id = st.selectbox(t("Open a saved scan"), list(by_id), format_func=lambda n:
                           f"#{n} · {by_id[n]['started_at']} · {strip_bidi(by_id[n]['target'])}")
    selected = by_id[scan_id]
    left, right = st.columns(2)
    left.button(t("Load this scan"), on_click=load_archived_scan, args=(scan_id,))
    right.button(t("Use this path for a new scan"), on_click=use_archived_path, args=(selected["target"],))
    st.caption(t("Saved results keep the locations recorded at scan time. A new scan of the "
                 "original path rebuilds file previews from the files currently on disk."))
    trend = storage.project_scores(selected["target"])
    if len(trend) > 1:
        st.subheader(t("Security score over time"))
        st.line_chart(pd.DataFrame(trend).set_index("started_at"), height=220)


def load_archived_scan(scan_id: int) -> None:
    loaded = get_storage().load_scan(scan_id)
    if loaded is not None:
        st.session_state["result"] = loaded
        clear_finding_selection()
        if TAB_STATE:
            st.session_state[intro.MAIN_TABS_KEY + lang] = t("Findings")


def use_archived_path(target: str) -> None:
    st.session_state["target"] = target
    st.session_state["open_scan_setup_next"] = True


if "History" in tabs:
    with tabs["History"]:
        render_history()
