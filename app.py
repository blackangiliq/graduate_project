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
from sca.learn import loop, store
from sca.models import SEVERITIES, ScanResult
from sca.pipeline import ScanOptions, run_scan
from sca.report.html_report import render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import to_sarif
from sca.storage import Storage
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
            st.session_state["learn_note"] = ("Approved %s. It is active from the next scan."
                                              % candidate_id)
        else:
            store.reject(get_storage(), candidate_id)
            st.session_state["learn_note"] = "Rejected %s." % candidate_id
    except (KeyError, ValueError) as exc:
        st.session_state["learn_note"] = str(exc)


def remove_rule(rule_id: str) -> None:
    store.remove_learned_rule(rule_id)
    st.session_state["learn_note"] = "Removed learned rule %s." % rule_id


# ------------------------------------------------------------------ sidebar
st.session_state.setdefault("target", "")
saved = load_config()
with st.sidebar:
    st.title("Secure Code Analyzer")
    st.caption("Static + AI vulnerability detection that learns - v%s" % __version__)

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
    use_rules = st.checkbox("Pattern rules (built-in + learned)", value=True)
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
    presets = list(PRESETS)
    preset = st.selectbox("AI provider", presets, index=presets.index(saved.preset),
                          format_func=lambda key: PRESETS[key]["label"])
    same = preset == saved.preset
    base_url = st.text_input(
        "API address", key="base_url_%s" % preset,
        value=saved.base_url if same and saved.base_url else PRESETS[preset]["base_url"])
    api_key = ""
    if PRESETS[preset]["kind"] != "ollama":
        api_key = st.text_input(
            "API key", type="password", key="api_key_%s" % preset,
            value=saved.api_key if same else os.environ.get(PRESETS[preset]["key_env"] or "-", ""),
            help="Kept in memory. Press 'Save AI settings' to store it in the .env file of "
                 "this project (git-ignored). It is never written to reports or the database.")
    models, is_local = provider_models(preset, base_url, api_key)
    default_model = saved.model if same and saved.model else (
        DEFAULT_MODEL if preset == "ollama" else "")
    if models:
        llm_model = st.selectbox("Model", models, index=models.index(default_model)
                                 if default_model in models else 0)
    else:
        llm_model = st.text_input("Model", value=default_model, key="model_%s" % preset,
                                  help="The model name exactly as the provider lists it.")
    llm_ready, llm_message = provider_ready(preset, base_url, api_key, llm_model)
    if llm_ready:
        st.caption("AI provider ready: %s" % llm_model)
    else:
        st.caption("AI provider not ready: %s. The static scan works without it." % llm_message)
    if not is_local:
        st.warning("With this provider, the code under review is sent to %s. Secrets found by "
                   "the tool are masked first. Choose Ollama to keep everything on this computer."
                   % (urlparse(base_url).hostname or base_url))
    use_llm = st.checkbox("AI review of findings", value=llm_ready, disabled=not llm_ready)
    deep = st.checkbox("Deep scan (AI audits whole files)", value=False, disabled=not llm_ready,
                       help="Slower and uses more requests. Finds issues the static engines "
                            "miss, which the tool can then turn into new rules.")
    llm_max = st.slider("Findings the AI reviews", 5, 200, 30, step=5, disabled=not llm_ready,
                        help="The most severe findings go first.")
    if st.button("Save AI settings", **WIDE):
        path = save_config(LLMConfig(
            preset=preset, api_key=api_key, model=llm_model,
            base_url="" if base_url == PRESETS[preset]["base_url"] else base_url))
        st.caption("Saved to %s" % path)
    lang_label = st.radio("Explanation language", ["English", "العربية"], horizontal=True)
    lang = "ar" if lang_label != "English" else "en"

    st.subheader("4. Precision")
    strict = st.checkbox("Strict mode (confirmed findings only)", value=False,
                         help="Counts a finding only when independent evidence supports it: "
                              "user input was traced to the line, the AI review confirmed "
                              "it, you confirmed it, or (for weaknesses that need no data "
                              "flow, such as a weak algorithm) two engines agree. Everything "
                              "else is kept under 'Needs review'.")

    skip_tests = st.checkbox("Skip test code", value=False,
                             help="Do not scan tests/, test_*.py, *.spec.js and similar. When "
                                  "they are scanned, findings in test code get a lower "
                                  "confidence and are never confirmed automatically.")

    run = st.button("Run scan", type="primary", **WIDE)

llm_config = LLMConfig(preset=preset, base_url=base_url, api_key=api_key, model=llm_model)

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
            use_ml=use_ml, use_llm=use_llm, llm_provider=preset, llm_base_url=base_url,
            llm_api_key=api_key, llm_model=llm_model, llm_max_findings=llm_max,
            llm_deep_scan=deep and use_llm, lang=lang, strict=strict,
            include_tests=not skip_tests)
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
tab_dash, tab_findings, tab_learn, tab_reports, tab_history, tab_about = st.tabs(
    ["Dashboard", "Findings", "Learning", "Reports", "History", "About"])

with tab_dash:
    if result is None:
        st.header("Scan a project to begin")
        st.write("Choose a folder in the sidebar and press **Run scan**. "
                 "To see a full example, press **Use sample** first.")
        st.info("Static engines always run on this computer. The optional AI review uses the "
                "provider you choose: a local model (Ollama) or a cloud API.")
    else:
        counts = result.counts()
        st.caption("%s - %s - %d files, %d lines, %.1f s" % (
            result.target, result.started_at, result.files_scanned, result.lines_scanned,
            result.duration_seconds))
        cols = st.columns(6)
        cols[0].metric("Security score (grade %s)" % result.grade, "%d / 100" % result.score)
        for col, sev in zip(cols[1:], SEVERITIES[:4]):
            col.metric(sev.capitalize(), counts[sev])
        confirmed = sum(1 for f in result.open_findings if f.tier == "confirmed")
        cols[5].metric("Confirmed / open", "%d / %d" % (confirmed, len(result.open_findings)))
        others = ["%d %s" % (result.status_count(s), STATUS_LABEL[s].lower())
                  for s in ("needs_review", "likely_false_positive", "dismissed")
                  if result.status_count(s)]
        if others:
            st.caption("Not counted in the score: " + ", ".join(others))

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
        f1, f2, f3, f4 = st.columns([2, 2, 2, 2])
        present = [s for s in STATUS_LABEL if result.status_count(s)] or ["open"]
        status_filter = f1.selectbox("Show", present + ["all"],
                                     format_func=lambda s: "All" if s == "all" else "%s (%d)" % (
                                         STATUS_LABEL[s], result.status_count(s)))
        sev_filter = f2.multiselect("Severity", SEVERITIES, default=SEVERITIES[:4])
        files = sorted({f.file for f in result.findings})
        file_filter = f3.multiselect("File", files)
        text_filter = f4.text_input("Search (title, CWE, code)")

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

        st.caption("%d of %d findings. Your reviews are remembered: a finding you dismiss stays "
                   "dismissed in later scans, and each review adjusts the confidence of the "
                   "rule that produced it." % (len(shown), len(result.findings)))
        table = pd.DataFrame([{
            "Severity": f.severity, "Title": f.title, "File": f.file, "Line": f.line,
            "CWE": f.cwe, "Tier": f.tier, "Risk": f.risk_score,
            "Confidence %": round(f.confidence * 100), "Engines": ", ".join(f.engines),
            "ML %": None if f.ml_score is None else round(f.ml_score * 100),
            "AI": f.ai_verdict.replace("_", " "),
        } for _, f in shown])
        st.dataframe(table, hide_index=True, height=280, **WIDE)

        st.subheader("Details")
        for position, (index, f) in enumerate(shown[:150]):
            label = "%s | %s | %s:%d" % (f.severity.upper(), f.title, f.file, f.line)
            with st.expander(label, expanded=(position == 0)):
                kb = cwe_info(f.cwe, lang)
                st.markdown(severity_badge(f.severity) + "&nbsp; **%s** %s &nbsp;-&nbsp; %s"
                            % (f.cwe, kb["name"] if kb["name"] != f.cwe else "", f.owasp),
                            unsafe_allow_html=True)
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Risk", "%.1f / 10" % f.risk_score)
                c2.metric("Confidence", "%d%%" % round(f.confidence * 100))
                c3.metric("ML score", "-" if f.ml_score is None else
                          "%d%%" % round(f.ml_score * 100))
                c4.metric("AI verdict", f.ai_verdict.replace("_", " ") or "-")
                if f.tier == "confirmed":
                    st.success("Confirmed: " + "; ".join(f.evidence))
                else:
                    st.caption("Probable: a rule matched and no independent evidence confirms "
                               "it yet%s." % (" (this file is test code)" if f.test_code else ""))
                st.code(f.context or f.snippet, language=CODE_LANG.get(f.language, "text"))
                st.caption("Flagged line: %d - found by: %s - rule: %s" % (
                    f.line, ", ".join(f.engines), ", ".join(f.rule_ids)))
                description = kb["description"] or f.description
                fix = kb["fix"] or f.fix
                if f.description and f.description != description and lang == "en":
                    st.write(f.description)
                if description:
                    st.markdown("**Why it matters**")
                    st.write(description)
                if fix:
                    st.markdown("**How to fix**")
                    st.write(fix)
                if f.ai_explanation or f.ai_fix:
                    st.markdown("**AI review** (%s)" % (f.ai_model or "model"))
                    if f.ai_explanation:
                        st.info(f.ai_explanation)
                    if f.ai_fix:
                        st.code(f.ai_fix, language=CODE_LANG.get(f.language, "text"))
                if kb["url"]:
                    st.caption("Reference: %s" % kb["url"])
                b1, b2, b3, _ = st.columns([1, 1, 1, 2])
                b1.button("Real vulnerability", key="tp_%d" % index, on_click=review,
                          args=(index, "tp"), disabled=f.user_verdict == "true_positive", **WIDE)
                b2.button("False positive", key="fp_%d" % index, on_click=review,
                          args=(index, "fp"), disabled=f.user_verdict == "false_positive", **WIDE)
                if f.user_verdict:
                    b3.button("Clear my review", key="clear_%d" % index, on_click=review,
                              args=(index, "clear"), **WIDE)
        if len(shown) > 150:
            st.caption("Showing the first 150. Use the filters, or download the full report.")

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
    m1.metric("Built-in rules", sum(1 for r in all_rules if r.origin == "builtin"))
    m2.metric("Learned rules", len(learned))
    m3.metric("Waiting for approval", len(pending))
    m4.metric("Your reviews", len(storage.feedback_rows()))
    m5.metric("Quarantined rules", len(quarantined))
    st.caption("The AI proposes, the tool validates, you approve. A proposed rule becomes "
               "active only after it passes every automatic check and you approve it.")

    st.subheader("Teach the tool")
    if not llm_ready:
        st.caption("Learning needs a working AI provider (section 3 of the sidebar).")
    t1, t2, t3 = st.columns(3)
    with t1:
        st.markdown("**From the current scan**")
        st.caption("Uses what the AI found or rejected in the last scan. Run the scan with "
                   "*AI review* and *Deep scan* switched on.")
        if st.button("Learn from this scan", disabled=not llm_ready or result is None, **WIDE):
            with st.spinner("Proposing and validating rules"):
                created = loop.learn_from_scan(result, loop.load_files(result.target),
                                               make_client(llm_config), storage)
            ok = sum(1 for c in created if c["status"] == "pending")
            st.session_state["learn_note"] = (
                "%d candidate(s) proposed: %d passed validation, %d rejected automatically."
                % (len(created), ok, len(created) - ok))
            st.rerun()
    with t2:
        st.markdown("**Fill gaps for a language**")
        language = st.selectbox("Language", CODE_LANGUAGES, index=CODE_LANGUAGES.index("ruby"))
        gaps = loop.coverage_gaps(language)
        st.caption("Weaknesses without a rule: %s" % (", ".join(gaps) or "none"))
        if st.button("Write rules for this language", disabled=not llm_ready or not gaps, **WIDE):
            with st.spinner("Asking the model for rules"):
                created = loop.bootstrap(make_client(llm_config), storage, language)
            ok = sum(1 for c in created if c["status"] == "pending")
            st.session_state["learn_note"] = (
                "%d candidate(s) proposed: %d passed validation, %d rejected automatically."
                % (len(created), ok, len(created) - ok))
            st.rerun()
    with t3:
        st.markdown("**From your false positives**")
        st.caption("Proposes a narrow exclusion for each finding you dismissed, so the rule "
                   "stops reporting that kind of safe code.")
        if st.button("Learn exclusions", disabled=not llm_ready, **WIDE):
            with st.spinner("Proposing and validating exclusions"):
                created = loop.learn_from_feedback(make_client(llm_config), storage)
            st.session_state["learn_note"] = "%d exclusion(s) proposed." % len(created)
            st.rerun()

    st.subheader("Waiting for your approval (%d)" % len(pending))
    if not pending:
        st.caption("Nothing is waiting.")
    for c in pending:
        kind = "Exclusion for %s" % c.get("target_rule") if c.get("kind") == "exclude" \
            else "New rule"
        with st.expander("%s | %s | %s | %s" % (kind, ", ".join(c.get("languages", [])),
                                                c.get("cwe", ""), c.get("title", ""))):
            st.caption("%s - proposed by %s - origin: %s" % (c["id"], c.get("source", ""),
                                                             c.get("origin", "")))
            if c.get("origin") == "bootstrap":
                st.warning("Written from the model's own knowledge, without an example from a "
                           "real project. Its only evidence is the examples below.")
            if c.get("kind") == "exclude":
                st.markdown("**Lines matching this are skipped by the rule**")
                st.code(c.get("exclude", ""), language="text")
            else:
                st.markdown("**Pattern**")
                st.code(c.get("pattern", ""), language="text")
                if c.get("exclude"):
                    st.markdown("**Unless the line also matches**")
                    st.code(c["exclude"], language="text")
            if c.get("message"):
                st.write(c["message"])
            evidence = (c.get("evidence") or {}).get("snippet")
            if evidence:
                st.markdown("**Learned from** `%s`" % (c["evidence"].get("file") or "your review"))
                st.code(evidence, language="text")
            e1, e2 = st.columns(2)
            if c.get("examples_vulnerable"):
                e1.markdown("**Must match**")
                e1.code("\n".join(c["examples_vulnerable"]), language="text")
            if c.get("examples_safe"):
                e2.markdown("**Must not match**")
                e2.code("\n".join(c["examples_safe"]), language="text")
            report = c.get("validation") or {}
            st.markdown("**Automatic checks**")
            st.dataframe(pd.DataFrame([{"Check": x["name"],
                                        "Result": "passed" if x["passed"] else "FAILED",
                                        "Detail": x["detail"]} for x in report.get("checks", [])]),
                         hide_index=True, **WIDE)
            if report.get("project_matches"):
                st.markdown("**What it would flag in the scanned project (%d lines)**"
                            % report.get("match_count", 0))
                st.dataframe(pd.DataFrame(report["project_matches"]), hide_index=True, **WIDE)
            a1, a2, _ = st.columns([1, 1, 3])
            a1.button("Approve", key="approve_%s" % c["id"], type="primary", on_click=decide,
                      args=(c["id"], True), **WIDE)
            a2.button("Reject", key="reject_%s" % c["id"], on_click=decide,
                      args=(c["id"], False), **WIDE)

    rejected = storage.list_candidates("rejected_auto")[:15]
    if rejected:
        with st.expander("Rejected automatically (%d most recent)" % len(rejected)):
            st.dataframe(pd.DataFrame([{
                "Id": c["id"], "CWE": c.get("cwe", ""), "Pattern": c.get("pattern") or c.get("exclude", ""),
                "Failed checks": "; ".join("%s: %s" % (x["name"], x["detail"]) for x in
                                           (c.get("validation") or {}).get("checks", [])
                                           if not x["passed"])} for c in rejected]),
                hide_index=True, **WIDE)

    st.subheader("Learned rules (%d)" % len(learned))
    if learned:
        st.dataframe(pd.DataFrame([{
            "Id": r["id"], "Languages": ", ".join(r.get("languages", [])), "CWE": r.get("cwe", ""),
            "Title": r.get("title", ""), "Pattern": r.get("pattern", ""),
            "Source": (r.get("learned") or {}).get("source", ""),
            "Approved": (r.get("learned") or {}).get("approved", "")} for r in learned]),
            hide_index=True, **WIDE)
        r1, r2 = st.columns([3, 1])
        chosen_rule = r1.selectbox("Remove a learned rule", [r["id"] for r in learned],
                                   label_visibility="collapsed")
        r2.button("Remove rule", on_click=remove_rule, args=(chosen_rule,), **WIDE)
    else:
        st.caption("No learned rules yet. They are stored in learned/rules.yaml.")

    st.subheader("Rule track record")
    if stats:
        st.dataframe(pd.DataFrame([{
            "Rule": rule_id, "Confirmed": s["tp"], "False positives": s["fp"],
            "Written confidence": confidences.get(rule_id, 0.6),
            "Adjusted confidence": round(feedback_module.adjusted_confidence(
                confidences.get(rule_id, 0.6), s["tp"], s["fp"]), 2),
            "State": "quarantined" if rule_id in quarantined else "active"}
            for rule_id, s in sorted(stats.items(), key=lambda kv: -kv[1]["fp"])]),
            hide_index=True, **WIDE)
    else:
        st.caption("No reviews yet. Use the buttons under each finding to confirm or dismiss it.")

    st.subheader("Coverage: rules per language and weakness")
    matrix = loop.coverage_matrix()
    frame = pd.DataFrame(matrix).T.fillna(0).astype(int)
    frame = frame[sorted(frame.columns, key=lambda c: int(c.split("-")[1]))] if len(frame.columns) else frame
    frame.insert(0, "Rules", frame.sum(axis=1))
    st.dataframe(frame, **WIDE)
    st.caption("Python is analysed by the AST taint engine and needs no pattern rules. "
               "Languages without rules are still covered by the AI deep scan, and by "
               "Opengrep/Semgrep when installed.")

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
                     .sort_values("id", ascending=False), hide_index=True, **WIDE)
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
2. **Detect** - static engines look for weaknesses: pattern rules (built-in and learned),
   a Python AST taint analysis that follows user input across functions, a secrets
   detector and, when installed, Bandit, Opengrep/Semgrep and Gitleaks.
3. **Refine** - for other languages a lightweight tracer checks whether user input reaches
   the flagged line; each rule's confidence is adjusted by its track record in your reviews.
4. **Merge** - the same issue found by several engines becomes one finding.
5. **AI** - a classifier gives a second opinion; the AI provider you chose can review each
   finding, explain it, propose a fix, and audit whole files.
6. **Assess** - findings are split into *confirmed* and *probable*; the project gets a
   0-100 score and a grade.
7. **Learn** - what the AI finds becomes a proposed rule, is validated automatically, and
   waits for your approval. Your reviews teach the tool which rules to trust.

### Limits

- No static analyzer can promise zero false alarms or zero missed vulnerabilities. Strict
  mode shows only findings backed by independent evidence, at the cost of moving the rest
  to *Needs review*.
- AI answers can be wrong. A finding judged false by the AI is kept and labelled, never
  deleted, and a rule written by the AI is never active before validation and approval.
- The security score is a heuristic of this tool and not an official CVSS score.
""")
