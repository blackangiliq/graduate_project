"""The Rules tab of the dashboard: full control of the rule set (see sca/rulebook.py)."""
from __future__ import annotations

from typing import Any, Callable, Dict, List

import pandas as pd
import streamlit as st
import yaml

from .. import rulebook
from ..cwe import info as cwe_info
from ..engines import rules_engine
from ..learn import feedback as feedback_module
from ..models import SEVERITIES
from ..storage import Storage

ORIGIN_LABEL = {"builtin": "Built in", "imported": "Imported", "learned": "Learned",
                "custom": "Your own"}
NOTE = "rules_note"


def _lines(text: str) -> List[str]:
    return [line for line in (text or "").splitlines() if line.strip()]


def _say(kind: str, message: str) -> None:
    st.session_state[NOTE] = (kind, message)


# ------------------------------------------------------------------ callbacks
def _toggle(rule_id: str, enabled: bool, t: Callable[[str], str]) -> None:
    try:
        rulebook.set_enabled(rule_id, enabled)
        _say("success", (t("Enabled %s.") if enabled else t("Disabled %s.")) % rule_id)
    except rulebook.RuleError as exc:
        _say("error", str(exc))


def _toggle_many(rule_ids: List[str], enabled: bool, t: Callable[[str], str]) -> None:
    changed = rulebook.set_enabled_many(rule_ids, enabled)
    _say("success", (t("Enabled %d rules.") if enabled else t("Disabled %d rules.")) % changed)


def _reset(rule_id: str, t: Callable[[str], str]) -> None:
    rulebook.reset(rule_id)
    for key in [k for k in st.session_state if k.startswith("rule_") and k.endswith(rule_id)]:
        del st.session_state[key]          # the form shows the original values again
    _say("success", t("Restored %s to its original definition.") % rule_id)


def _delete(rule_id: str, t: Callable[[str], str]) -> None:
    try:
        rulebook.delete(rule_id)
        _say("success", t("Deleted %s.") % rule_id)
    except rulebook.RuleError as exc:
        _say("error", str(exc))


def _drop_exclusion(rule_id: str, pattern: str, t: Callable[[str], str]) -> None:
    rulebook.remove_exclusion(rule_id, pattern)
    _say("success", t("Removed the exclusion from %s.") % rule_id)


def _form_values(prefix: str, suffix: str) -> Dict[str, Any]:
    state = st.session_state
    return {
        "title": state[prefix + "title" + suffix].strip(),
        "languages": list(state[prefix + "languages" + suffix]),
        "cwe": state[prefix + "cwe" + suffix].strip(),
        "severity": state[prefix + "severity" + suffix],
        "confidence": round(float(state[prefix + "confidence" + suffix]), 2),
        "pattern": state[prefix + "pattern" + suffix].strip(),
        "exclude": state[prefix + "exclude" + suffix].strip(),
        "ignore_case": bool(state[prefix + "ignore_case" + suffix]),
        "near": state[prefix + "near" + suffix].strip(),
        "within": int(state[prefix + "within" + suffix]),
        "requires_taint": bool(state[prefix + "requires_taint" + suffix]),
        "message": state[prefix + "message" + suffix].strip(),
        "fix": state[prefix + "fix" + suffix].strip(),
        "examples_vulnerable": _lines(state[prefix + "vulnerable" + suffix]),
        "examples_safe": _lines(state[prefix + "safe" + suffix]),
    }


def _save_edit(rule_id: str, storage: Storage, t: Callable[[str], str]) -> None:
    try:
        result = rulebook.update(rule_id, _form_values("rule_", "_" + rule_id), storage)
    except rulebook.RuleError as exc:
        _say("error", t("Not saved: %s") % exc)
        return
    _say("warning" if result["warnings"] else "success",
         t("Saved %s.") % rule_id + "".join("\n\n- " + w for w in result["warnings"]))


def _new_rule(storage: Storage, save: bool, t: Callable[[str], str]) -> None:
    raw = _form_values("new_", "")
    raw["id"] = st.session_state["new_id"].strip()
    if not save:
        st.session_state["new_check"] = rulebook.check(raw, storage)
        return
    try:
        result = rulebook.create(raw, storage)
    except rulebook.RuleError as exc:
        _say("error", t("Not saved: %s") % exc)
        return
    st.session_state.pop("new_check", None)
    st.session_state["rule_pick"] = raw["id"]
    _say("warning" if result["warnings"] else "success",
         t("Added %s. It is active from the next scan.") % raw["id"]
         + "".join("\n\n- " + w for w in result["warnings"]))


# ------------------------------------------------------------------ pieces
def _rule_fields(prefix: str, suffix: str, values: Dict[str, Any], t: Callable[[str], str],
                 secret: bool = False) -> None:
    """The editable fields of a rule. Used by the edit form and by the new-rule form."""
    st.text_input(t("Title"), value=values.get("title", ""), key=prefix + "title" + suffix,
                  help=t("Short description shown in the findings list."))
    c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
    c1.multiselect(t("Languages"), rulebook.LANGUAGES, default=values.get("languages") or [],
                   key=prefix + "languages" + suffix,
                   help=t("The languages the rule applies to. 'any' means every file. "
                          "TypeScript uses the JavaScript rules, C++ the C rules, and "
                          "Kotlin, Scala and Groovy the Java rules."))
    c2.text_input(t("Weakness (CWE)"), value=values.get("cwe", ""), key=prefix + "cwe" + suffix,
                  help=t("The kind of weakness as a CWE number, for example CWE-89 for SQL "
                         "injection. It decides the explanation, the fix text and the "
                         "OWASP category shown with the finding."))
    severity = values.get("severity", "medium")
    c3.selectbox(t("Severity"), SEVERITIES, key=prefix + "severity" + suffix,
                 index=SEVERITIES.index(severity) if severity in SEVERITIES else 2,
                 help=t("How bad the weakness is if it is real. It weighs on the score."))
    c4.slider(t("Confidence"), 0.0, 1.0, float(values.get("confidence", 0.6)), 0.05,
              key=prefix + "confidence" + suffix,
              help=t("How sure the rule is on its own, from 0 to 1. Lower it for a rule "
                     "that is often wrong; your reviews also move it automatically."))
    st.text_area(t("Pattern (regular expression that marks a vulnerable line)"),
                 value=values.get("pattern", ""), key=prefix + "pattern" + suffix, height=90,
                 help=t("Python regular-expression syntax. The rule reports a code line "
                        "when this matches it."))
    st.text_area(t("Exclude (optional: if this also matches, the line is ignored)"),
                 value=values.get("exclude", ""), key=prefix + "exclude" + suffix, height=70,
                 help=t("Use it to describe the safe variant of the same call, instead of "
                        "making the pattern complicated."))
    st.checkbox(t("Ignore upper/lower case"), value=bool(values.get("ignore_case")),
                key=prefix + "ignore_case" + suffix)
    n1, n2, n3 = st.columns([4, 1, 3])
    n1.text_input(t("Context (optional: must match a neighbouring line)"),
                  value=values.get("near", ""), key=prefix + "near" + suffix,
                  help=t("Use it when the pattern alone is ordinary code and the lines around "
                         "it make it a weakness, for example a random number used near the "
                         "word token."))
    n2.number_input(t("Within lines"), 0, 60, int(values.get("within", 5) or 0),
                    key=prefix + "within" + suffix,
                    help=t("How many lines above and below are searched for the context."))
    n3.checkbox(t("Only when user input is traced to the line"),
                value=bool(values.get("requires_taint")),
                key=prefix + "requires_taint" + suffix,
                help=t("For rules that name a common function (opening a file, running a "
                       "query): the rule stays silent unless a variable on the line was "
                       "filled from the request a few lines earlier."))
    st.text_area(t("Why it is dangerous (optional)"), value=values.get("message", ""),
                 key=prefix + "message" + suffix, height=70)
    st.text_area(t("How to fix it (optional)"), value=values.get("fix", ""),
                 key=prefix + "fix" + suffix, height=70)
    e1, e2 = st.columns(2)
    e1.text_area(t("Lines the rule must match (one per line)"),
                 value="\n".join(values.get("examples_vulnerable") or []),
                 key=prefix + "vulnerable" + suffix, height=110,
                 help=t("Checked every time the rule is saved, so a later edit cannot "
                        "silently break it."))
    e2.text_area(t("Lines the rule must NOT match (one per line)"),
                 value="\n".join(values.get("examples_safe") or []),
                 key=prefix + "safe" + suffix, height=110)
    if secret:
        st.caption(t("This is a credential format: it is run by the secrets engine, and "
                     "what it finds is masked in every report."))


def _show_check(result: Dict[str, Any], t: Callable[[str], str]) -> None:
    if result["errors"]:
        st.error(t("The rule cannot be saved:") + "".join("\n\n- " + e for e in result["errors"]))
    elif result["warnings"]:
        st.warning(t("The rule can be saved. Look at these points first:")
                   + "".join("\n\n- " + w for w in result["warnings"]))
    else:
        st.success(t("The rule passed every check."))


def _browse(storage: Storage, t: Callable[[str], str], wide: Dict[str, Any]) -> None:
    every = t("All")
    rules = rules_engine.all_rules()
    f1, f2, f3, f4, f5 = st.columns([2, 2, 2, 2, 3])
    origin_labels = {o: t(label) for o, label in ORIGIN_LABEL.items()}
    origin_labels[every] = every
    origin = f1.selectbox(t("Origin"), [every] + list(ORIGIN_LABEL),
                          format_func=origin_labels.get, key="rules_origin_" + every,
                          help=t("Built in: written with the tool. Imported: converted from "
                                 "DevSkim and Gitleaks. Learned: proposed by the AI and "
                                 "approved by you. Your own: written by you."))
    language = f2.selectbox(t("Language"), [every] + rulebook.LANGUAGES,
                            key="rules_language_" + every)
    cwes = sorted({r.cwe for r in rules if r.cwe}, key=lambda c: int(c.split("-")[1]))
    cwe = f3.selectbox(t("Weakness"), [every] + cwes, key="rules_cwe_" + every,
                       format_func=lambda c: c if c == every else "%s %s" % (
                           c, cwe_info(c)["name"] if cwe_info(c)["name"] != c else ""))
    states = [every, t("Enabled"), t("Disabled"), t("Edited by you"), t("Credential formats")]
    state = f4.selectbox(t("State"), states, key="rules_state_" + every)
    search = f5.text_input(t("Search (id, title, expression)"), key="rules_search")

    if origin not in origin_labels:
        origin = every
    shown = rulebook.list_rules(
        origin=None if origin == every else origin,
        language=None if language == every else language,
        cwe=None if cwe == every else cwe, text=search,
        enabled={states[1]: True, states[2]: False}.get(state),
        kind="secret" if state == states[4] else None)
    if state == states[3]:
        shown = [r for r in shown if r.edited]

    st.caption(t("%d of %d rules.") % (len(shown), len(rules)))
    if not shown:
        return
    st.dataframe(pd.DataFrame([{
        t("Rule"): r.id, t("State"): (t("on") if r.enabled else t("off"))
        + (" *" if r.edited else ""),
        t("Origin"): t(ORIGIN_LABEL[r.origin]), t("Languages"): ", ".join(r.languages),
        "CWE": r.cwe, t("Severity"): r.severity, t("Confidence"): r.confidence,
        t("Title"): r.title, t("Source"): r.source} for r in shown]),
        hide_index=True, height=min(300, 40 + 35 * len(shown)), **wide)
    st.download_button(t("Download these rules (YAML)"),
                       rulebook.export_yaml([r.id for r in shown]), "sca-rules.yaml",
                       "text/yaml", key="rules_download")

    with st.expander(t("Change all the rules shown (%d)") % len(shown)):
        st.caption(t("Applies to every rule in the table above. Use the filters first to "
                     "choose which ones."))
        m1, m2, _ = st.columns([1, 1, 3])
        m1.button(t("Enable all shown"), key="rules_enable_all", on_click=_toggle_many,
                  args=([r.id for r in shown], True, t), **wide)
        m2.button(t("Disable all shown"), key="rules_disable_all", on_click=_toggle_many,
                  args=([r.id for r in shown], False, t), **wide)

    st.subheader(t("Rule details"))
    ids = [r.id for r in shown]
    if st.session_state.get("rule_pick") not in ids:
        st.session_state["rule_pick"] = ids[0]
    titles = {r.id: "%s - %s" % (r.id, r.title) for r in shown}
    rule_id = st.selectbox(t("Choose a rule"), ids, key="rule_pick", format_func=titles.get)
    rule = next((r for r in shown if r.id == rule_id), shown[0])
    _details(rule, storage, t, wide)


def _details(rule: rules_engine.Rule, storage: Storage, t: Callable[[str], str],
             wide: Dict[str, Any]) -> None:
    shipped = rule.origin in ("builtin", "imported")
    badges = [t(ORIGIN_LABEL[rule.origin]), t("enabled") if rule.enabled else t("DISABLED")]
    if rule.edited:
        badges.append(t("edited by you"))
    if rule.kind == "secret":
        badges.append(t("credential format"))
    st.markdown("**%s** &nbsp; `%s`" % (rule.id, "` `".join(badges)))
    if rule.source:
        st.caption(t("Source: %s") % rule.source + (
            " - %s, %s" % (rule.license, rule.url) if rule.license else ""))
    if rule.note:
        st.info(rule.note)

    b1, b2, b3, _ = st.columns([1, 1, 1, 2])
    if rule.enabled:
        b1.button(t("Disable"), key="rule_off_" + rule.id, on_click=_toggle,
                  args=(rule.id, False, t), **wide,
                  help=t("The rule stays in the list but takes no part in scans."))
    else:
        b1.button(t("Enable"), key="rule_on_" + rule.id, type="primary", on_click=_toggle,
                  args=(rule.id, True, t), **wide)
    if shipped:
        b2.button(t("Restore original"), key="rule_reset_" + rule.id, on_click=_reset,
                  args=(rule.id, t), disabled=not rule.edited, **wide,
                  help=t("Undo every change you made to this rule."))
    else:
        b2.button(t("Delete rule"), key="rule_delete_" + rule.id, on_click=_delete,
                  args=(rule.id, t), **wide)

    stats = storage.rule_stats().get(rule.id)
    if stats:
        adjusted = feedback_module.adjusted_confidence(rule.confidence, stats["tp"], stats["fp"])
        st.caption(t("In your reviews: %d confirmed, %d false positives. Confidence used in "
                     "scans: %.2f%s") % (
            stats["tp"], stats["fp"], adjusted,
            t(" - QUARANTINED (not counted until you confirm one of its findings)")
            if feedback_module.is_quarantined(rule.confidence, stats["tp"], stats["fp"]) else ""))

    with st.form("rule_form_" + rule.id):
        _rule_fields("rule_", "_" + rule.id, rule.as_dict(), t, secret=rule.kind == "secret")
        st.form_submit_button(t("Save changes"), type="primary", on_click=_save_edit,
                              args=(rule.id, storage, t))
    if shipped:
        st.caption(t("This rule ships with the tool. Your changes are stored in "
                     "learned/edits.yaml and can be undone with 'Restore original'."))
        if rule.edited:
            with st.expander(t("The original definition")):
                st.code(yaml.safe_dump(rulebook.shipped_raw(rule.id), sort_keys=False,
                                       allow_unicode=True, width=100), language="yaml")
    if rule.extra_excludes:
        st.markdown("**%s**" % t("Approved exclusions of this rule"))
        for index, extra in enumerate(rule.extra_excludes):
            x1, x2 = st.columns([5, 1])
            x1.code(extra.pattern, language="text")
            x2.button(t("Remove"), key="rule_x_%s_%d" % (rule.id, index),
                      on_click=_drop_exclusion, args=(rule.id, extra.pattern, t), **wide)


def _new(storage: Storage, t: Callable[[str], str]) -> None:
    st.caption(t("Write your own rule. It is stored in learned/custom.yaml and takes part "
                 "in the next scan. The Guide tab explains every field."))
    with st.form("new_rule_form"):
        st.text_input(t("Rule id"), key="new_id", placeholder="MY-SQLI-001",
                      help=t("A unique name: letters, digits, '-', '_' or '.'."))
        _rule_fields("new_", "", {"severity": "medium", "confidence": 0.6}, t)
        c1, c2, _ = st.columns([1, 1, 3])
        c1.form_submit_button(t("Check the rule"), on_click=_new_rule, args=(storage, False, t),
                              help=t("Tests the rule without saving it."))
        c2.form_submit_button(t("Save the rule"), type="primary", on_click=_new_rule,
                              args=(storage, True, t))
    if "new_check" in st.session_state:
        _show_check(st.session_state["new_check"], t)
    st.download_button(t("Download an empty rule file (YAML template)"), rulebook.TEMPLATE,
                       "my-rule.yaml", "text/yaml", key="rules_template")


def _try(t: Callable[[str], str]) -> None:
    st.caption(t("See which lines an expression marks, before you put it in a rule. The "
                 "expression runs in a separate process with a time limit, so a bad one "
                 "cannot freeze the tool."))
    rules = rules_engine.all_rules()
    start = st.selectbox(t("Start from an existing rule (optional)"),
                         [""] + [r.id for r in rules], key="try_from")
    base = next((r for r in rules if r.id == start), None)
    pattern = st.text_area(t("Pattern"), value=base.pattern.pattern if base else "",
                           key="try_pattern_" + start, height=80)
    exclude = st.text_area(t("Exclude (optional)"), key="try_exclude_" + start, height=68,
                           value=base.exclude.pattern if base and base.exclude else "")
    ignore_case = st.checkbox(t("Ignore upper/lower case"), key="try_case_" + start,
                              value=bool(base and base.ignore_case))
    code = st.text_area(t("Code to test on (paste some lines)"), key="try_code_" + start,
                        height=200, value="\n".join(base.examples_vulnerable
                                                    + base.examples_safe) if base else "")
    if st.button(t("Run the expression"), type="primary", key="try_run"):
        if not pattern.strip() or not (code or "").strip():
            st.warning(t("Give an expression and some code."))
            return
        matched, error = rulebook.try_rule(pattern.strip(), exclude.strip(), ignore_case, code)
        if matched is None:
            st.error(t("The expression failed: %s") % error)
            return
        lines = code.splitlines()
        st.write(t("%d of %d lines matched.") % (len(matched), len(lines)))
        st.code("\n".join("%s %3d  %s" % (">>" if number in matched else "  ", number, line)
                          for number, line in enumerate(lines, start=1)), language="text")


def _transfer(storage: Storage, t: Callable[[str], str]) -> None:
    left, right = st.columns(2)
    with left:
        st.markdown("**%s**" % t("Export"))
        st.caption(t("Save rules to a file, to back them up or use them on another computer."))
        for origin in ("custom", "learned"):
            count = len(rulebook.list_rules(origin=origin))
            st.download_button(
                "%s (%d)" % (t("Your own rules") if origin == "custom" else t("Learned rules"),
                             count),
                rulebook.export_yaml(origin=origin), "sca-%s-rules.yaml" % origin, "text/yaml",
                key="export_" + origin, disabled=not count)
        st.download_button(t("Every rule (%d)") % len(rules_engine.all_rules()),
                           rulebook.export_yaml(), "sca-all-rules.yaml", "text/yaml",
                           key="export_all")
    with right:
        st.markdown("**%s**" % t("Import"))
        st.caption(t("Add rules from a YAML file. Each rule is checked first and is stored "
                     "as one of your own rules."))
        uploaded = st.file_uploader(t("Rule file (.yaml)"), type=["yaml", "yml"],
                                    key="rules_upload")
        if uploaded is not None and st.button(t("Import the rules"), key="rules_import"):
            added, problems = rulebook.import_yaml(
                uploaded.getvalue().decode("utf-8", errors="replace"), storage)
            if added:
                st.success(t("Added: %s") % ", ".join(added))
            for problem in problems:
                st.error(problem)


def render(storage: Storage, t: Callable[[str], str], wide: Dict[str, Any]) -> None:
    # the message area exists in every run, so the tabs below it keep their place and the
    # selected sub-tab is not reset when a message appears or disappears
    note_area = st.container()
    if st.session_state.get(NOTE):
        kind, message = st.session_state.pop(NOTE)
        with note_area:
            getattr(st, kind)(message)
    counts = rulebook.summary()
    origins = counts["by_origin"]
    cols = st.columns(6)
    cols[0].metric(t("All rules"), counts["total"])
    cols[1].metric(t("Active"), counts["enabled"])
    for col, origin in zip(cols[2:], ORIGIN_LABEL):
        col.metric(t(ORIGIN_LABEL[origin]), origins[origin]["total"],
                   help=t("%d of them active") % origins[origin]["enabled"])
    st.caption(t("Active / total") + ": " + " · ".join(
        "%s %d/%d" % (t(ORIGIN_LABEL[o]), origins[o]["enabled"], origins[o]["total"])
        for o in ORIGIN_LABEL) + " · " + t("Edited by you") + " %d" % counts["edited"])
    st.caption(t("Every rule the tool knows. Browse and filter them, read and change any "
                 "field, switch a rule off or on, write your own, and try an expression on "
                 "code. Nothing here needs the AI."))
    browse, new, tryit, transfer = st.tabs(
        [t("Browse and edit"), t("New rule"), t("Try an expression"), t("Import and export")])
    with browse:
        _browse(storage, t, wide)
    with new:
        _new(storage, t)
    with tryit:
        _try(t)
    with transfer:
        _transfer(storage, t)
