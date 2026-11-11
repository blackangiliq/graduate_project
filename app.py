"""Secure Code Analyzer - web dashboard.

Start it with:   python -m sca ui      (or double-click run.bat / run.sh)
The dashboard is only reachable from this computer (localhost).
"""
from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from sca import __version__, scoring
from sca.ai.classifier import SKLEARN_AVAILABLE
from sca.ai.llm import DEFAULT_MODEL
from sca.ai.providers import PRESETS, LLMConfig, load_config, make_client, save_config
from sca.cwe import info as cwe_info
from sca.engines import external
from sca.engines.rules_engine import load_rules
from sca.learn import feedback as feedback_module
from sca import rulebook
from sca.learn import loop, store
from sca.models import SEVERITIES, ScanResult
from sca.pipeline import ScanOptions, run_scan
from sca.report.html_report import render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import to_sarif
from sca.storage import Storage
from sca.ui import guide_tab, rules_tab, texts
from sca.ui.i18n import AR
from sca.walker import CODE_LANGUAGES

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "samples" / "vulnerable_app"
SEV_COLOR = {"critical": "#9b1c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d5f8a",
             "info": "#5f5e5a"}
CODE_LANG = {"python": "python", "javascript": "javascript", "typescript": "typescript",
             "php": "php", "java": "java", "c": "c", "cpp": "cpp", "csharp": "csharp",
             "go": "go", "config": "yaml", "shell": "bash", "html": "html", "ruby": "ruby",
             "kotlin": "kotlin", "rust": "rust", "swift": "swift", "powershell": "powershell"}
STATUS_LABEL = {"open": "Open", "needs_review": "Needs review",
                "likely_false_positive": "Likely false positives (AI)",
                "dismissed": "Dismissed by you"}

st.set_page_config(page_title="Secure Code Analyzer", page_icon=":shield:", layout="wide")

# Streamlit renamed the "fill the available width" option; support old and new versions.
WIDE = ({"width": "stretch"} if "width" in inspect.signature(st.button).parameters
        else {"use_container_width": True})


# ------------------------------------------------------------------ helpers
def ui_lang() -> str:
    return "ar" if st.session_state.get("ui_lang") == "العربية" else "en"


def t(text: str) -> str:
    """The text in the language of the dashboard (English is the source language)."""
    return AR.get(text, text) if ui_lang() == "ar" else text


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
</style>"""


def pick_folder() -> str:
    """Open the operating system's folder dialog (in a separate process so that it cannot
    interfere with the web server) and return the chosen path."""
    code = ("import tkinter as tk\nfrom tkinter import filedialog\nroot = tk.Tk()\n"
            "root.withdraw()\nroot.attributes('-topmost', True)\n"
            "print(filedialog.askdirectory(title='Choose the project folder') or '')")
    try:
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             timeout=600)
        return out.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return ""


def browse_clicked() -> None:
    chosen = pick_folder()
    if chosen:
        st.session_state["target"] = chosen
    else:
        st.session_state["browse_note"] = t("No folder was chosen (or the folder dialog is not "
                                            "available here). You can paste the path instead.")


def use_sample() -> None:
    st.session_state["target"] = str(SAMPLE)


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

    st.subheader(t("1. Project folder"))
    st.text_input(key="target", placeholder=r"C:\projects\my-app", **opt("target"))
    col_a, col_b = st.columns(2)
    col_a.button(on_click=browse_clicked, **opt("browse"), **WIDE)
    col_b.button(on_click=use_sample, **opt("sample"), **WIDE)
    if st.session_state.get("browse_note"):
        st.caption(st.session_state.pop("browse_note"))

    st.subheader(t("2. Static engines"))
    tools = external.availability()
    missing = t(" (not installed)")
    counts = rulebook.summary()
    use_rules = st.checkbox(value=True, **opt("use_rules"))
    st.caption(t("%d active rules of %d - manage them in the Rules tab")
               % (counts["enabled"], counts["total"]))
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
    with st.expander(t("More engine options")):
        use_taint_lite = st.checkbox(value=True, **opt("use_taint_lite"))
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

llm_config = LLMConfig(preset=preset, base_url=base_url, api_key=api_key, model=llm_model)

# ------------------------------------------------------------------ run a scan
# Messages and the progress bar of a scan live in this container. It exists in every run,
# so the tabs below keep their place on the page and the selected tab is not reset.
status_area = st.container()
if run:
    with status_area:
        target = st.session_state["target"].strip().strip('"')
        if not target:
            st.error(t("Choose a project folder first."))
        elif not Path(target).expanduser().exists():
            st.error(t("This path does not exist: %s") % target)
        else:
            options = ScanOptions(
                use_rules=use_rules, use_ast=use_ast, use_secrets=use_secrets,
                use_bandit=use_bandit, use_semgrep=use_semgrep, use_gitleaks=use_gitleaks,
                use_ml=use_ml, use_llm=use_llm, llm_provider=preset, llm_base_url=base_url,
                llm_api_key=api_key, llm_model=llm_model, llm_max_findings=llm_max,
                llm_deep_scan=deep and use_llm, lang=lang, strict=strict,
                include_tests=not skip_tests, use_taint_lite=use_taint_lite,
                use_feedback=use_feedback, save=save_scan, llm_deep_max_files=deep_max_files,
                llm_timeout=llm_timeout,
                exclude_dirs=[d.strip() for d in exclude_dirs.split(",") if d.strip()])
            bar = st.progress(0.0, text="Starting")

            def on_progress(message: str, fraction: float) -> None:
                bar.progress(min(1.0, max(0.0, fraction)), text=message)

            try:
                st.session_state["result"] = run_scan(target, options, on_progress, get_storage())
            except Exception as exc:  # show the problem instead of a stack trace
                st.error(t("The scan failed: %s") % exc)
            bar.empty()

result: ScanResult = st.session_state.get("result")

# ------------------------------------------------------------------ main area
tab_dash, tab_findings, tab_rules, tab_learn, tab_reports, tab_history, tab_guide = st.tabs(
    [t(name) for name in ("Dashboard", "Findings", "Rules", "Learning", "Reports", "History",
                          "Guide")])

with tab_rules:
    rules_tab.render(get_storage(), t, WIDE)

with tab_guide:
    guide_tab.render(t, lang, WIDE)

with tab_dash:
    if result is None:
        st.header(t("Scan a project to begin"))
        st.write(t("Choose a folder in the sidebar and press **Run scan**. "
                 "To see a full example, press **Use sample** first."))
        st.info(t("Static engines always run on this computer. The optional AI review uses the "
                "provider you choose: a local model (Ollama) or a cloud API."))
    else:
        counts = result.counts()
        st.caption(t("%s - %s - %d files, %d lines, %.1f s") % (
            result.target, result.started_at, result.files_scanned, result.lines_scanned,
            result.duration_seconds))
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
            haystack = " ".join([f.title, f.cwe, f.snippet, f.file]).lower()
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
            label = "%s | %s | %s:%d" % (f.severity.upper(), f.title, f.file, f.line)
            with st.expander(label, expanded=(position == 0)):
                kb = cwe_info(f.cwe, lang)
                st.markdown(severity_badge(f.severity) + "&nbsp; **%s** %s &nbsp;-&nbsp; %s"
                            % (f.cwe, kb["name"] if kb["name"] != f.cwe else "", f.owasp),
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
                description = kb["description"] or f.description
                fix = kb["fix"] or f.fix
                if f.description and f.description != description and lang == "en":
                    st.write(f.description)
                if description:
                    st.markdown(t("**Why it matters**"))
                    st.write(description)
                if fix:
                    st.markdown(t("**How to fix**"))
                    st.write(fix)
                if f.ai_explanation or f.ai_fix:
                    st.markdown(t("**AI review** (%s)") % (f.ai_model or "model"))
                    if f.ai_explanation:
                        st.info(f.ai_explanation)
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
                created = loop.learn_from_scan(result, loop.load_files(result.target),
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
        with st.expander("%s | %s | %s | %s" % (kind, ", ".join(c.get("languages", [])),
                                                c.get("cwe", ""), c.get("title", ""))):
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
                st.write(c["message"])
            evidence = (c.get("evidence") or {}).get("snippet")
            if evidence:
                st.markdown(t("**Learned from** `%s`") % (c["evidence"].get("file") or "your review"))
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
