"""Secure Code Analyzer - web dashboard.

Start it with:   streamlit run app.py      (or double-click run.bat / run.sh)
Everything runs on this computer; the dashboard is only reachable from localhost.
"""
from __future__ import annotations

import inspect
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

from sca import __version__
from sca.ai.classifier import SKLEARN_AVAILABLE
from sca.ai.llm import DEFAULT_HOST, DEFAULT_MODEL, OllamaClient
from sca.cwe import info as cwe_info
from sca.engines import external
from sca.models import SEVERITIES, ScanResult
from sca.pipeline import ScanOptions, run_scan
from sca.report.html_report import render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import to_sarif
from sca.storage import Storage

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "samples" / "vulnerable_app"
SEV_COLOR = {"critical": "#9b1c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d5f8a",
             "info": "#5f5e5a"}
CODE_LANG = {"python": "python", "javascript": "javascript", "typescript": "typescript",
             "php": "php", "java": "java", "c": "c", "cpp": "cpp", "csharp": "csharp",
             "go": "go", "config": "yaml", "shell": "bash", "html": "html"}

st.set_page_config(page_title="Secure Code Analyzer", page_icon=":shield:", layout="wide")

# Streamlit renamed the "fill the available width" option; support old and new versions.
WIDE = ({"width": "stretch"} if "width" in inspect.signature(st.button).parameters
        else {"use_container_width": True})


# ------------------------------------------------------------------ helpers
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
        st.session_state["browse_note"] = ("No folder was chosen (or the folder dialog is not "
                                           "available here). You can paste the path instead.")


def use_sample() -> None:
    st.session_state["target"] = str(SAMPLE)


@st.cache_data(ttl=20, show_spinner=False)
def ollama_models(host: str):
    client = OllamaClient(host)
    if not client.available():
        return None
    return client.models()


@st.cache_resource
def get_storage() -> Storage:
    return Storage()


def severity_badge(severity: str) -> str:
    return ("<span style='background:%s;color:#fff;border-radius:99px;padding:2px 10px;"
            "font-size:12px;font-weight:700;text-transform:uppercase'>%s</span>"
            % (SEV_COLOR[severity], severity))


# ------------------------------------------------------------------ sidebar
st.session_state.setdefault("target", "")
with st.sidebar:
    st.title("Secure Code Analyzer")
    st.caption("Local static + AI vulnerability detection - v%s" % __version__)

    st.subheader("1. Project folder")
    st.text_input("Folder path", key="target", placeholder=r"C:\projects\my-app")
    col_a, col_b = st.columns(2)
    col_a.button("Browse...", on_click=browse_clicked, **WIDE)
    col_b.button("Use sample", on_click=use_sample, **WIDE,
                 help="Scan the deliberately vulnerable demo app that ships with the tool")
    if st.session_state.get("browse_note"):
        st.caption(st.session_state.pop("browse_note"))

    st.subheader("2. Static engines")
    tools = external.availability()
    use_rules = st.checkbox("Pattern rules (JS, PHP, Java, C/C++, Go, C#)", value=True)
    use_ast = st.checkbox("Python AST taint analysis", value=True)
    use_secrets = st.checkbox("Secrets detection", value=True)
    use_bandit = st.checkbox("Bandit" + ("" if tools["bandit"] else " (not installed)"),
                             value=tools["bandit"], disabled=not tools["bandit"])
    use_semgrep = st.checkbox("Opengrep / Semgrep" + ("" if tools["semgrep"] else
                                                      " (not installed)"),
                              value=tools["semgrep"], disabled=not tools["semgrep"])
    use_gitleaks = st.checkbox("Gitleaks" + ("" if tools["gitleaks"] else " (not installed)"),
                               value=tools["gitleaks"], disabled=not tools["gitleaks"])

    st.subheader("3. Artificial intelligence")
    use_ml = st.checkbox("ML classifier (second opinion)", value=SKLEARN_AVAILABLE,
                         disabled=not SKLEARN_AVAILABLE)
    llm_host = st.text_input("Ollama address", value=DEFAULT_HOST)
    models = ollama_models(llm_host)
    if models is None:
        st.caption("Ollama is not running. The scan works without it; to enable AI review "
                   "install Ollama from ollama.com and run `ollama pull %s`." % DEFAULT_MODEL)
        use_llm, deep, llm_model, llm_max = False, False, DEFAULT_MODEL, 30
    elif not models:
        st.caption("Ollama is running but has no model. Run `ollama pull %s`." % DEFAULT_MODEL)
        use_llm, deep, llm_model, llm_max = False, False, DEFAULT_MODEL, 30
    else:
        use_llm = st.checkbox("LLM review of findings", value=True)
        llm_model = st.selectbox("Model", models,
                                 index=models.index(DEFAULT_MODEL) if DEFAULT_MODEL in models else 0)
        llm_max = st.slider("Findings to review", 5, 200, 30, step=5,
                            help="Local models are slow; the most severe findings go first.")
        deep = st.checkbox("Deep scan (LLM audits whole files)", value=False,
                           help="Slower. Can find issues the static engines miss.")
    lang_label = st.radio("Explanation language", ["English", "العربية"], horizontal=True)
    lang = "ar" if lang_label != "English" else "en"

    run = st.button("Run scan", type="primary", **WIDE)

# ------------------------------------------------------------------ run a scan
if run:
    target = st.session_state["target"].strip().strip('"')
    if not target:
        st.error("Choose a project folder first.")
    elif not Path(target).expanduser().exists():
        st.error("This path does not exist: %s" % target)
    else:
        options = ScanOptions(
            use_rules=use_rules, use_ast=use_ast, use_secrets=use_secrets,
            use_bandit=use_bandit, use_semgrep=use_semgrep, use_gitleaks=use_gitleaks,
            use_ml=use_ml, use_llm=use_llm, llm_host=llm_host, llm_model=llm_model,
            llm_max_findings=llm_max, llm_deep_scan=deep, lang=lang)
        bar = st.progress(0.0, text="Starting")

        def on_progress(message: str, fraction: float) -> None:
            bar.progress(min(1.0, max(0.0, fraction)), text=message)

        try:
            st.session_state["result"] = run_scan(target, options, on_progress, get_storage())
        except Exception as exc:  # show the problem instead of a stack trace
            st.error("The scan failed: %s" % exc)
        bar.empty()

result: ScanResult = st.session_state.get("result")

# ------------------------------------------------------------------ main area
tab_dash, tab_findings, tab_reports, tab_history, tab_about = st.tabs(
    ["Dashboard", "Findings", "Reports", "History", "About"])

with tab_dash:
    if result is None:
        st.header("Scan a project to begin")
        st.write("Choose a folder in the sidebar and press **Run scan**. "
                 "To see a full example, press **Use sample** first.")
        st.info("The code never leaves this computer. Static engines run locally, and the "
                "optional AI review talks only to an Ollama model on localhost.")
    else:
        counts = result.counts()
        st.caption("%s - %s - %d files, %d lines, %.1f s" % (
            result.target, result.started_at, result.files_scanned, result.lines_scanned,
            result.duration_seconds))
        cols = st.columns(6)
        cols[0].metric("Security score (grade %s)" % result.grade, "%d / 100" % result.score)
        for col, sev in zip(cols[1:], SEVERITIES[:4]):
            col.metric(sev.capitalize(), counts[sev])
        cols[5].metric("Likely false positives",
                       len(result.findings) - len(result.open_findings))

        left, right = st.columns(2)
        with left:
            st.subheader("By severity")
            # the number prefix keeps the bars in severity order (charts sort labels by name)
            st.bar_chart(pd.DataFrame({"findings": [counts[s] for s in SEVERITIES]},
                                      index=["%d. %s" % (i, s.capitalize())
                                             for i, s in enumerate(SEVERITIES, start=1)]),
                         horizontal=True, height=240)
        with right:
            st.subheader("By OWASP Top 10 category")
            by_owasp = {}
            for f in result.open_findings:
                by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1
            if by_owasp:
                st.bar_chart(pd.DataFrame({"findings": by_owasp}), horizontal=True, height=240)
            else:
                st.write("No open findings.")

        left, right = st.columns(2)
        with left:
            st.subheader("Most affected files")
            by_file = {}
            for f in result.open_findings:
                by_file[f.file] = by_file.get(f.file, 0) + 1
            top = sorted(by_file.items(), key=lambda kv: -kv[1])[:10]
            st.dataframe(pd.DataFrame(top, columns=["File", "Findings"]), hide_index=True,
                         **WIDE)
        with right:
            st.subheader("Engines")
            rows = [{"Engine": k, "Status": v} for k, v in result.engine_notes.items()]
            rows += [{"Engine": "AI: " + k, "Status": str(v)} for k, v in result.ai.items()]
            st.dataframe(pd.DataFrame(rows), hide_index=True, **WIDE)

with tab_findings:
    if result is None:
        st.write("No scan yet.")
    elif not result.findings:
        st.success("No findings. A clean scan is not a proof of security.")
    else:
        f1, f2, f3, f4 = st.columns([2, 2, 2, 1])
        sev_filter = f1.multiselect("Severity", SEVERITIES, default=SEVERITIES[:4])
        files = sorted({f.file for f in result.findings})
        file_filter = f2.multiselect("File", files)
        text_filter = f3.text_input("Search (title, CWE, code)")
        show_fp = f4.checkbox("Show likely false positives", value=False)

        shown = []
        for f in result.findings:
            if f.severity not in sev_filter:
                continue
            if file_filter and f.file not in file_filter:
                continue
            if f.status != "open" and not show_fp:
                continue
            haystack = " ".join([f.title, f.cwe, f.snippet, f.file]).lower()
            if text_filter and text_filter.lower() not in haystack:
                continue
            shown.append(f)

        st.caption("%d of %d findings" % (len(shown), len(result.findings)))
        table = pd.DataFrame([{
            "Severity": f.severity, "Title": f.title, "File": f.file, "Line": f.line,
            "CWE": f.cwe, "Risk": f.risk_score, "Confidence %": round(f.confidence * 100),
            "Engines": ", ".join(f.engines),
            "ML %": None if f.ml_score is None else round(f.ml_score * 100),
            "LLM": f.ai_verdict.replace("_", " "),
        } for f in shown])
        st.dataframe(table, hide_index=True, **WIDE, height=280)

        st.subheader("Details")
        for index, f in enumerate(shown[:150]):
            label = "%s | %s | %s:%d" % (f.severity.upper(), f.title, f.file, f.line)
            with st.expander(label, expanded=(index == 0)):
                kb = cwe_info(f.cwe, lang)
                st.markdown(severity_badge(f.severity) + "&nbsp; **%s** %s &nbsp;-&nbsp; %s"
                            % (f.cwe, kb["name"] if kb["name"] != f.cwe else "", f.owasp),
                            unsafe_allow_html=True)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Risk", "%.1f / 10" % f.risk_score)
                c2.metric("Confidence", "%d%%" % round(f.confidence * 100))
                c3.metric("ML score", "-" if f.ml_score is None else
                          "%d%%" % round(f.ml_score * 100))
                c4.metric("LLM verdict", f.ai_verdict.replace("_", " ") or "-")
                st.code(f.context or f.snippet, language=CODE_LANG.get(f.language, "text"))
                st.caption("Flagged line: %d - found by: %s%s" % (
                    f.line, ", ".join(f.engines),
                    " - user input was traced to this line" if f.tainted else ""))
                description = kb["description"] or f.description
                fix = kb["fix"] or f.fix
                if description:
                    st.markdown("**Why it matters**")
                    st.write(description)
                if fix:
                    st.markdown("**How to fix**")
                    st.write(fix)
                if f.ai_explanation or f.ai_fix:
                    st.markdown("**AI review** (%s)" % (f.ai_model or "local model"))
                    if f.ai_explanation:
                        st.info(f.ai_explanation)
                    if f.ai_fix:
                        st.code(f.ai_fix, language=CODE_LANG.get(f.language, "text"))
                if kb["url"]:
                    st.caption("Reference: %s" % kb["url"])
        if len(shown) > 150:
            st.caption("Showing the first 150. Use the filters, or download the full report.")

with tab_reports:
    if result is None:
        st.write("No scan yet.")
    else:
        st.write("Download the results of the current scan.")
        d1, d2, d3, d4 = st.columns(4)
        d1.download_button("HTML report", render_html(result), "sca-report.html", "text/html",
                           **WIDE)
        d2.download_button("JSON", json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
                           "sca-report.json", "application/json", **WIDE)
        d3.download_button("SARIF", json.dumps(to_sarif(result), indent=2, ensure_ascii=False),
                           "sca-report.sarif", "application/json", **WIDE)
        try:
            d4.download_button("PDF report", render_pdf(result), "sca-report.pdf",
                               "application/pdf", **WIDE)
        except Exception as exc:
            d4.caption("PDF unavailable: %s" % exc)
        st.caption("The HTML report contains everything, including Arabic text. The PDF uses "
                   "built-in fonts and leaves non-Latin text out. SARIF can be uploaded to "
                   "GitHub code scanning or opened in VS Code.")

with tab_history:
    scans = get_storage().list_scans(200)
    if not scans:
        st.write("No saved scans yet.")
    else:
        frame = pd.DataFrame(scans)
        targets = sorted(frame["target"].unique())
        chosen = st.selectbox("Project", targets, index=targets.index(result.target)
                              if result is not None and result.target in targets else 0)
        project = frame[frame["target"] == chosen].sort_values("id")
        st.subheader("Security score over time")
        st.line_chart(project.set_index("started_at")[["score"]], height=220)
        st.dataframe(project[["id", "started_at", "score", "grade", "critical", "high",
                              "medium", "low", "files_scanned", "lines_scanned"]]
                     .sort_values("id", ascending=False), hide_index=True,
                     **WIDE)
        scan_id = st.selectbox("Open a saved scan", list(project["id"])[::-1])
        if st.button("Load this scan"):
            loaded = get_storage().load_scan(int(scan_id))
            if loaded is not None:
                st.session_state["result"] = loaded
                st.rerun()

with tab_about:
    st.markdown("""
### How it works

1. **Collect** - the source files of the chosen folder are read and their language detected.
2. **Detect** - several static engines look for weaknesses:
   pattern rules, a Python AST taint analysis, a secrets detector and, when installed,
   Bandit, Opengrep/Semgrep and Gitleaks.
3. **Merge** - the same issue found by several engines becomes one finding with a higher
   confidence.
4. **AI** - a machine-learning classifier gives a second opinion, and a local LLM (Ollama)
   can review each finding, explain it and propose a fix.
5. **Assess** - every finding gets a risk score, and the project gets a 0-100 score and a
   grade.

### Limits

- Static analysis cannot prove that code is secure. It misses logic flaws (for example
  missing access checks) and data flows that cross several functions or files.
- AI reviews can be wrong. A finding judged false by the LLM is kept and labelled, never
  deleted.
- The security score is a heuristic of this tool and not an official CVSS score.
""")
