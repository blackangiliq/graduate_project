"""The app panel of the Dashboard tab: what a scan found out about a Flutter or Android app
file or project (ScanResult.app, written by sca.flutter).

It only shows facts. The weaknesses themselves are findings, so they count in the score, the
filters, the reviews and the reports. Every key of the facts is optional: an app file and a
source project have different ones, and a scan saved by an older version has none.
"""
from __future__ import annotations

import inspect
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, get_args

import pandas as pd
import streamlit as st
from streamlit.elements import arrow

from ..walker import strip_bidi

Text = Callable[[str], str]
ApiLocation = Callable[[str, Optional[Mapping[str, Any]], Any], None]
TABLE_SELECTION = "on_select" in inspect.signature(st.dataframe).parameters
# Streamlit added individual cell selection after its initial row selection support.
SINGLE_SELECTION_MODE = ("single-cell" if "single-cell" in get_args(getattr(arrow, "SelectionMode", None))
                         else "single-row")

PROJECT_KINDS = ("flutter-project", "android-project")
# Values the loaders and checks write into the facts, and the English text shown for them
# (each text has an Arabic entry in sca/ui/i18n.py)
KINDS = {"apk": "Android app (APK)", "aab": "Android App Bundle (AAB)",
         "apks": "Set of APK files (APKS, XAPK, APKM)", "flutter-project": "Flutter project",
         "android-project": "Android project"}
COMPONENTS = {"activity": "Activity", "activity-alias": "Activity alias", "service": "Service",
              "receiver": "Broadcast receiver", "provider": "Content provider"}
FOUND_IN = {"kernel": "Dart kernel (debug build)", "snapshot": "Dart snapshot (libapp.so)",
            "notices": "License notices (NOTICES.Z)", "plugin": "Plugin registration (DEX)"}
DEPENDENCIES = {"direct main": "Direct", "direct dev": "Development only",
                "direct overridden": "Overridden", "transitive": "Indirect"}
BUILD_MODES = ("debug", "profile", "release", "unknown")
# the words of the short flag texts ("allowed (network security config)", "yes (default)")
FLAG_WORDS = ("yes", "no", "unknown", "allowed", "not allowed", "allowed for some domains",
              "default", "network security config", "none")
FLUTTER_DEFAULT = " (the Flutter SDK default)"     # end of a project's min_sdk_note
MAX_ROWS = 300
# facts that only a Flutter app or project has; an Android app without Flutter does not show
# them (its build mode is "unknown" and it has no Dart packages)
FLUTTER_ONLY = ("build_mode", "dependency_issues", "packages", "plugins", "dart_sdk",
                "dart_version", "engine_revision", "snapshot_hash", "snapshot_features",
                "obfuscated", "obfuscation_note", "debug_symbols", "dart_sources")
_FLAG = re.compile(r"^(?P<head>[^(,]*?)(?: \((?P<why>[^()]*)\))?(?P<tail>, with backup rules)?$")
_TARGET_DEFAULT = re.compile(r"^default for targetSdk (\d+)$")
_MARKDOWN = re.compile(r"([\\`*_\[\]<>#|~$])")
# an invisible WORD JOINER (U+2060) after the ':' of '://', before '@' and after 'www' keeps
# Markdown from turning an address or e-mail into a link (a backslash escape does not)
_AUTOLINK = re.compile(r"(?i)(?<=:)(?=//)|(?=@)|(?<=\bwww)(?=\.)")


def plain(text: str) -> str:
    """Text of the app (a Gradle value, a name) escaped for Markdown, so that it is shown as
    it is and cannot add a link or an image."""
    return _AUTOLINK.sub("⁠", _MARKDOWN.sub(r"\\\1", text))   # and no autolinks


def title(facts: Mapping[str, Any], t: Text, ltr: Text) -> str:
    """The label of the panel, e.g. "Flutter app: com.example.app"."""
    if facts.get("kind") in PROJECT_KINDS:
        name = facts.get("name") or facts.get("package") or "-"
        label = t("Flutter project: %s") if facts.get("flutter") else t("Android project: %s")
    else:
        name = facts.get("package") or facts.get("name") or "-"
        label = t("Flutter app: %s") if facts.get("flutter") else t("Android app: %s")
    return label % ltr(str(name))


def render(facts: Mapping[str, Any], t: Text, ltr: Text, wide: Dict) -> None:
    """Draw the panel (call it inside an expander)."""
    is_app = facts.get("kind") not in PROJECT_KINDS
    flutter = facts.get("flutter") is not False        # also a scan saved without the fact
    if not flutter:
        facts = {key: value for key, value in facts.items() if key not in FLUTTER_ONLY}
    # The package name gets a line of its own: in a metric column it is cut off.
    # Metric values are Markdown too, so the texts of the app are escaped.
    st.markdown("**%s:** %s" % (t("Package"), ltr(plain(str(facts.get("package") or "-")))))
    metrics = [(t("Version"), plain(_version(facts)))]
    if not is_app:
        metrics.append((t("Platforms"),
                        plain(", ".join(map(str, facts.get("platforms") or [])) or "-")))
    elif flutter:
        metrics.append((t("Build mode"), t(str(facts.get("build_mode") or "unknown"))))
    metrics.append((t("Min / target SDK"), "%s / %s" % (_sdk(facts.get("min_sdk")),
                                                       _sdk(facts.get("target_sdk")))))
    for column, (label, value) in zip(st.columns(len(metrics)), metrics):
        column.metric(label, value)
    members = facts.get("apk_members")
    if members:
        st.subheader(t("APK files in this scan"))
        status_names = {"read": t("Read"), "partial": t("Partially read"), "skipped": t("Skipped")}
        role_names = {"base": t("Base APK"), "split": t("Split APK"), "alternative": t("Alternative APK")}
        read = sum(item.get("status") == "read" for item in members)
        st.caption(t("%d of %d APK files read without a reported input limit.") % (read, len(members)))
        st.dataframe(pd.DataFrame([{
            t("File"): strip_bidi(str(item.get("name", ""))),
            t("Package role"): role_names.get(item.get("role"), t("unknown")),
            t("Status"): status_names.get(item.get("status"), t("unknown")),
            t("Details"): t(str(item.get("reason") or "")),
        } for item in members]), hide_index=True, **wide)
    coverage = facts.get("analysis_coverage") or {}
    extraction = {label: facts[name] for name, label in (
        ("native_string_coverage", "Native library string coverage"),
        ("encoded_literal_coverage", "Base64 literal coverage"),
        ("complex_resources", "Complex Android resources")) if facts.get(name)}
    if extraction:
        with st.expander(t("Extraction coverage")):
            for label, detail in extraction.items():
                st.markdown("**%s**" % t(label))
                st.json(detail, expanded=False)
            st.caption(t("Read and omitted inputs, decoding budgets and derived-text counts "
                         "describe coverage; they do not prove that every vulnerability was found."))
    if coverage.get("pattern_long_lines"):
        st.info(t("%d long lines exceed the code-pattern analysis limit. Secrets and literal URLs "
                  "are checked separately; code vulnerability coverage is partial.") % coverage["pattern_long_lines"])
    java = facts.get("java_decompilation") or {}
    if java:
        st.caption(t("JADX loaded %d files. Scope: the base APK's manifest package and declared "
                     "components; limits: %d files and %d seconds. Other DEX contents are still "
                     "examined as extracted strings.") % (java.get("loaded_files", 0),
                     java.get("file_limit", 0), java.get("time_limit_seconds", 0)))
    notes = [_sdk_note(str(facts[key]), t) for key in ("min_sdk_note", "target_sdk_note")
             if facts.get(key)]
    if notes:
        st.caption(t("SDK levels set in Gradle: %s") % "; ".join(ltr(plain(n)) for n in notes))

    left, right = st.columns(2)
    with left:
        st.markdown("**%s**" % t("About the app"))
        _table(_details(facts, t), wide)
    with right:
        _permissions(facts, t, wide)
        _signing(facts, t, wide)
    components = [c for c in facts.get("components") or [] if isinstance(c, Mapping)]
    left, right = st.columns(2)
    with left:
        _components(components, t, wide)
    with right:
        _links(components, t, wide)
    # the API and key inventory (its own panel, see render_apis) replaces the plain list of
    # server addresses; a scan saved by an older version only has that list
    inventory = isinstance(facts.get("apis"), Mapping)
    if flutter and inventory:
        _packages(facts, is_app, t, wide)
    elif flutter:
        left, right = st.columns(2)
        with left:
            _packages(facts, is_app, t, wide)
        with right:
            _endpoints(facts, t, wide)
    elif not inventory:                 # no Dart packages in an app without Flutter
        _endpoints(facts, t, wide)
    _warnings(facts, t)


# ------------------------------------------------------------------ APIs and keys
# the English texts of the inventory (sca/flutter/inventory.py); each has an Arabic entry in
# sca/ui/i18n.py
ALERT_LABELS = {"cleartext": "no TLS", "tunnel": "tunnel", "webhook": "webhook",
                "telegram": "bot token", "secret_in_url": "key in the address",
                "password_in_url": "password in the address", "dev_host": "test server",
                "private_ip": "private IP", "ip_host": "IP address"}
CATEGORIES = {"tunnel": "Tunnel or test service", "webhook": "Webhook", "app": "App server",
              "backend": "Cloud backend", "api": "Third-party API",
              "sdk": "SDK, analytics or ads"}
CALL_KINDS = {"http": "HTTP request", "uri": "Address built with Uri", "websocket": "WebSocket",
              "graphql": "GraphQL", "annotation": "Retrofit/Chopper route",
              "base_url": "Base address"}
MAX_PLACES = 5
# the lists of the inventory, as the truncation note names them
LIST_NAMES = {"alerts": "Alerts", "keys": "Keys", "endpoints": "Server addresses",
              "hosts": "Hosts", "calls": "API calls", "paths": "API paths",
              "config": "Service IDs", "env": ".env entries"}


def apis_title(apis: Mapping[str, Any], t: Text) -> str:
    """The label of the APIs and keys panel."""
    summary = apis.get("summary") if isinstance(apis.get("summary"), Mapping) else {}
    alerts = summary.get("alerts") if isinstance(summary.get("alerts"), Mapping) else {}
    return t("APIs and keys: %d server addresses, %d keys, %d serious alerts") % (
        int(summary.get("endpoints") or 0), int(summary.get("keys") or 0),
        int(alerts.get("danger") or 0))


def places(item: Mapping[str, Any], limit: int = MAX_PLACES) -> str:
    """"file:line, file:line (+3)" of an item of the inventory."""
    locations = [loc for loc in item.get("locations") or [] if isinstance(loc, Mapping)]
    texts = ["%s:%s" % (loc.get("file", ""), loc.get("line", "")) if loc.get("line")
             else str(loc.get("file", "")) for loc in locations[:limit]]
    more = int(item.get("count") or len(locations)) - len(texts)
    return ", ".join(texts) + (" (+%d)" % more if more > 0 else "")


def alert_text(alert: Mapping[str, Any], t: Text) -> str:
    """An alert of the inventory in the language of the dashboard, its values (texts of the
    app) escaped for Markdown."""
    from sca.flutter.inventory import ALERTS

    code = str(alert.get("code", ""))
    args = alert.get("args") if isinstance(alert.get("args"), list) else []
    template = ALERTS.get(code)
    if template is None or template.count("%s") != len(args):
        return plain(str(alert.get("text", "")))
    values = tuple(plain(t(str(a)) if code == "key" and i == 0 else str(a))
                   for i, a in enumerate(args))
    return t(template) % values


def render_apis(apis: Mapping[str, Any], t: Text, ltr: Text, wide: Dict,
                key_locations: Optional[Callable[
                    [List[Mapping[str, Any]], Optional[int], Any], None]] = None,
                api_location: Optional[ApiLocation] = None
                ) -> None:
    """Draw the API and key inventory (call it inside an expander)."""
    summary = apis.get("summary") if isinstance(apis.get("summary"), Mapping) else {}
    values_visible = bool(apis.get("values_visible"))
    if values_visible:
        st.caption(t("Addresses, API calls, paths and keys observed in the scanned files, with "
                     "their recorded locations. Values are shown in full. No service was contacted."))
    else:
        st.caption(t("Every server address, API call, API path and key the analyzer found, with "
                     "the file and line of each place. Keys are masked. Nothing was contacted: "
                     "the addresses are only read."))
    metrics = [(t("Server addresses"), summary.get("endpoints", 0)),
               (t("Hosts"), summary.get("hosts", 0)),
               (t("Without TLS"), summary.get("cleartext", 0)),
               (t("Keys (secret)"), "%s (%s)" % (summary.get("keys", 0),
                                                 summary.get("secret_keys", 0))),
               (t("API calls"), summary.get("calls", 0)),
               (t("API paths"), summary.get("paths", 0))]
    for column, (label, value) in zip(st.columns(len(metrics)), metrics):
        column.metric(label, value)

    alerts = [a for a in apis.get("alerts") or [] if isinstance(a, Mapping)]
    if alerts:
        st.markdown("**%s**" % (t("Alerts (%d)") % len(alerts)))
        show = {"danger": st.error, "warning": st.warning, "info": st.info}
        for alert in alerts:
            show.get(str(alert.get("level")), st.info)(alert_text(alert, t))
    else:
        st.caption(t("No inventory alerts at the current thresholds."))

    keys = [k for k in apis.get("keys") or [] if isinstance(k, Mapping) and not k.get("dismissed")]
    endpoints = [e for e in apis.get("endpoints") or [] if isinstance(e, Mapping)]
    hosts = [h for h in apis.get("hosts") or [] if isinstance(h, Mapping)]
    calls = [c for c in apis.get("calls") or [] if isinstance(c, Mapping)]
    paths = [p for p in apis.get("paths") or [] if isinstance(p, Mapping)]
    config = [c for c in apis.get("config") or [] if isinstance(c, Mapping)]
    env = [e for e in apis.get("env") or [] if isinstance(e, Mapping)]
    tabs = st.tabs([t("Server addresses (%d)") % len(endpoints), t("Keys (%d)") % len(keys),
                    t("Hosts (%d)") % len(hosts), t("API calls (%d)") % len(calls),
                    t("API paths (%d)") % len(paths), t("Service IDs (%d)") % len(config),
                    t(".env entries (%d)") % len(env)])
    with tabs[0]:
        if any(e.get("requires_runtime_resolution") for e in endpoints):
            st.caption(t("URL templates are shown exactly as stored, including placeholders. "
                         "Their final addresses require runtime values; finding a literal "
                         "does not prove a network request occurred."))
        _api_rows("endpoints", endpoints, _endpoint_rows(endpoints, t), t, wide, api_location)
    with tabs[1]:
        if key_locations is not None and keys:
            key_table, preview = st.columns([3, 2])
            with key_table:
                selected = _key_rows(keys, t, wide, selectable=True, values_visible=values_visible)
                key_locations(keys, selected, preview)
        else:
            _key_rows(keys, t, wide, values_visible=values_visible)
    with tabs[2]:
        _rows([{t("Host"): str(h.get("host", "")), t("Service provider"): t(str(h.get("service") or "-")),
                t("Kind"): t(CATEGORIES.get(str(h.get("category")), str(h.get("category", "")))),
                t("Addresses"): int(h.get("endpoints") or 0),
                t("Without TLS"): yes_no(h.get("cleartext"), t),
                t("Alerts"): _alert_labels(h.get("alerts"), t)} for h in hosts], t, wide)
    with tabs[3]:
        st.caption(t("Calls found in source or decompiled code. Some compiled apps only expose "
                     "address and path strings."))
        call_rows = [{t("Method"): str(c.get("method", "")), t("Target"): str(c.get("target", "")),
                      t("Kind"): t(CALL_KINDS.get(str(c.get("kind")), str(c.get("kind", "")))),
                      t("Place"): places({"locations": [c]})} for c in calls]
        _api_rows("calls", calls, call_rows, t, wide, api_location)
    with tabs[4]:
        st.caption(t("Parts of addresses kept as texts, such as /api/v1/login: a compiled app "
                     "keeps them even when the full address is put together at run time."))
        path_rows = [{t("Path"): str(p.get("path", "")), t("Alerts"): _alert_labels(p.get("alerts"), t),
                      t("Places"): places(p)} for p in paths]
        _api_rows("paths", paths, path_rows, t, wide, api_location)
    with tabs[5]:
        _config_rows(apis, config, t, wide, api_location)
    with tabs[6]:
        _api_rows("env", env,
                  [{t("File"): str(e.get("file", "")), t("Line"): e.get("line", ""),
                    t("Name"): str(e.get("name", "")), t("Value"): str(e.get("value", "")),
                    t("Secret"): yes_no(e.get("secret"), t)} for e in env], t, wide, api_location)
    coverage = apis.get("coverage") or {}
    if coverage.get("context_lines_skipped"):
        st.info(t("%d long code lines were checked for literal URLs, but their API call expressions "
                  "could not be fully analyzed.") % coverage["context_lines_skipped"])
    truncated = apis.get("truncated")
    if isinstance(truncated, Mapping) and truncated:
        st.caption(t("Lists were cut to keep the report small: %s.") % ", ".join(
            "%s +%s" % (t(LIST_NAMES.get(str(key), str(key))), value)
            for key, value in truncated.items()))
    import json
    st.download_button(t("Download the inventory (JSON)"),
                       json.dumps(dict(apis), indent=2, ensure_ascii=False),
                       file_name="api-inventory.json", mime="application/json")


def _rows(rows: List[Dict[str, Any]], t: Text, wide: Dict) -> None:
    if not rows:
        st.caption(t("None."))
        return
    _table(rows, wide)


def _alert_labels(codes: Any, t: Text) -> str:
    return ", ".join(t(ALERT_LABELS.get(str(c), str(c))) for c in codes or []) or "-"


def selected_table_row(state: Mapping) -> Optional[int]:
    selection = state["selection"]
    cells = selection.get("cells", [])
    return cells[0][0] if cells else next(iter(selection.get("rows", [])), None)


def _selectable_table(rows: List[Dict[str, Any]], wide: Dict, key: str) -> Optional[int]:
    state = st.dataframe(pd.DataFrame(rows), hide_index=True, on_select="rerun",
                         selection_mode=SINGLE_SELECTION_MODE, key=key, **wide)
    return selected_table_row(state)


def _api_rows(kind: str, items: List[Mapping[str, Any]], rows: List[Dict[str, Any]], t: Text,
              wide: Dict, location: Optional[ApiLocation]) -> None:
    if not rows:
        st.caption(t("None."))
        return
    if location is None:
        st.dataframe(pd.DataFrame(rows), hide_index=True, **wide)
        return
    table, preview = st.columns([3, 2])
    key = f"decoded_inventory_{kind}_{id(items[0])}"
    with table:
        if TABLE_SELECTION:
            index = _selectable_table(rows, wide, key)
        else:
            st.dataframe(pd.DataFrame(rows), hide_index=True, **wide)
            index = st.selectbox(t(LIST_NAMES[kind]), range(len(rows)), index=None, key=key,
                                 format_func=lambda i: " · ".join(str(v) for v in rows[i].values()))
    item = items[index] if index is not None and 0 <= index < len(items) else None
    location(kind, item, preview)


def _key_rows(keys: List[Mapping[str, Any]], t: Text, wide: Dict, *, selectable: bool = False,
              values_visible: bool = False
              ) -> Optional[int]:
    if not keys:
        st.caption(t("None."))
        return None
    if values_visible:
        st.caption(t("Values are shown in full. The severity reflects the evidence in the scanned "
                     "files. Service permissions and restrictions require separate verification."))
    else:
        st.caption(t("Values are masked. The severity reflects the evidence in the scanned files. "
                     "Service permissions and restrictions require separate verification."))
    rows = []
    for k in keys:
        claims = k.get("claims") if isinstance(k.get("claims"), Mapping) else {}
        rows.append({
            t("Type"): t(str(k.get("type", ""))), t("Service provider"): t(str(k.get("service", ""))),
            t("Value") if values_visible else t("Value (masked)"): str(k.get("value") or "-"),
            t("Severity"): t(str(k.get("severity", "")).capitalize()),
            t("Public by design"): yes_no(k.get("public"), t),
            t("Places"): places(k),
            t("Details"): ", ".join("%s=%s" % item for item in claims.items())
            or str(k.get("used_by") or ""),
            t("What to do"): t(str(k.get("advice_text", "")))})
    if selectable and TABLE_SELECTION:
        return _selectable_table(rows[:MAX_ROWS], wide, f"decoded_inventory_keys_{id(keys[0])}")
    _table(rows, wide)
    return None


def _endpoint_rows(endpoints: List[Mapping[str, Any]], t: Text) -> List[Dict[str, Any]]:
    return [{t("Address"): str(e.get("url", "")), t("Service provider"): t(str(e.get("service") or "-")),
            t("Evidence"): t("URL template" if e.get("requires_runtime_resolution") else
                             "Host literal" if e.get("host_only") else "URL literal"),
            t("Kind"): t(CATEGORIES.get(str(e.get("category")), str(e.get("category", "")))),
            t("TLS"): "-" if e.get("host_only") else yes_no(not e.get("cleartext"), t),
            t("Alerts"): _alert_labels(e.get("alerts"), t),
            t("Times found"): int(e.get("count") or 0), t("Places"): places(e, 3)}
            for e in endpoints]


def _config_rows(apis: Mapping[str, Any], config: List[Mapping[str, Any]], t: Text,
                 wide: Dict, api_location: Optional[ApiLocation] = None) -> None:
    firebase = apis.get("firebase")
    if isinstance(firebase, Mapping) and firebase:
        labels = {"project_id": "Firebase project ID", "app_ids": "Firebase app ID",
                  "sender_id": "Firebase sender ID", "database_urls": "Realtime Database URL",
                  "storage_buckets": "Storage bucket", "auth_domain": "Firebase auth domain",
                  "api_keys": "Google API key"}
        st.markdown("**%s**" % t("Firebase project"))
        _table([{t("Fact"): t(labels.get(key, key)),
                 t("Value"): ", ".join(map(str, value)) if isinstance(value, list) else str(value)}
                for key, value in firebase.items()], wide)
    st.caption(t("Service configuration and credential candidates found in the files. "
                 "Client identifiers can be public; a name alone does not establish "
                 "privileges or exploitability. Select a value to inspect its source."))
    _api_rows("config", config,
              [{t("Name"): t(str(c.get("label", ""))), t("Value"): str(c.get("value", "")),
                t("Classification"): t({"credential_candidate": "Credential candidate; review required",
                                        "sdk_client_identifier": "SDK client identifier"}.get(
                                            str(c.get("classification", "")), "Service configuration")),
                t("Service provider"): t(str(c.get("service", ""))), t("Places"): places(c)}
               for c in config], t, wide, api_location)


# ------------------------------------------------------------------ values
def yes_no(value: Any, t: Text) -> str:
    if value is None:
        return t("unknown")
    return t("yes") if value else t("no")


def flag_text(value: Any, t: Text) -> str:
    """A short flag of the checks, such as "allowed (default for targetSdk 27)" or
    "yes (default), with backup rules", in the language of the dashboard: the known words
    are translated, anything else is kept as it is."""
    text = str(value)
    match = _FLAG.match(text)
    if not match:
        return text
    head, why, tail = match.group("head", "why", "tail")
    out = t(head)
    if why:
        number = _TARGET_DEFAULT.match(why)
        out += " (%s)" % (t("default for targetSdk %d") % int(number.group(1)) if number
                          else t(why))
    if tail:
        out += t(", with backup rules")
    return out


def _version(facts: Mapping[str, Any]) -> str:
    name, code = str(facts.get("version_name") or ""), str(facts.get("version_code") or "")
    if name and code:
        return "%s (%s)" % (name, code)
    return name or code or "-"


def _sdk(level: Any) -> str:
    return str(level) if isinstance(level, int) else "-"


def _sdk_note(note: str, t: Text) -> str:
    """"flutter.minSdkVersion (the Flutter SDK default)" with its explanation translated."""
    if note.endswith(FLUTTER_DEFAULT):
        return "%s (%s)" % (note[:-len(FLUTTER_DEFAULT)], t("the Flutter SDK default"))
    return note


def _short_list(items: Any, limit: int = 10) -> str:
    values = [str(item) for item in items or []]
    return ", ".join(values[:limit]) + (", ..." if len(values) > limit else "")


def _table(rows: List[Dict[str, Any]], wide: Dict) -> None:
    st.dataframe(pd.DataFrame(rows[:MAX_ROWS]), hide_index=True, **wide)


# ------------------------------------------------------------------ sections
def _details(facts: Mapping[str, Any], t: Text) -> List[Dict[str, str]]:
    """(fact, value) rows of everything that is a single value."""
    rows: List[Dict[str, str]] = []

    def add(label: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            rows.append({t("Fact"): label, t("Value"): str(value)})

    kind = str(facts.get("kind") or "")
    add(t("Type"), t(KINDS[kind]) if kind in KINDS else kind)
    add(t("Name"), facts.get("name"))
    size = facts.get("size_bytes")
    if isinstance(size, int):           # decimal units: 1 MB = 1,000,000 bytes
        add(t("Size"), t("%.1f MB") % (size / 1_000_000) if size >= 1_000_000
            else t("%d KB") % max(1, round(size / 1000)))
    add("SHA-256", facts.get("sha256"))
    if "flutter" in facts:
        add(t("Uses Flutter"), yes_no(facts.get("flutter"), t))
    add(t("Compile SDK"), facts.get("compile_sdk"))
    add(t("Dart SDK constraint"), facts.get("dart_sdk"))
    add(t("Debug manifests (not checked)"), _short_list(facts.get("debug_manifests")))
    add(t("ABIs"), _short_list(facts.get("abis")))
    add(t("Dart version"), facts.get("dart_version"))
    add(t("Flutter engine revision"), facts.get("engine_revision"))
    add(t("Snapshot hash"), facts.get("snapshot_hash"))
    add(t("Snapshot features"), facts.get("snapshot_features"))
    if "obfuscated" in facts:
        note = str(facts.get("obfuscation_note") or "")
        add(t("Dart code obfuscated"), yes_no(facts.get("obfuscated"), t)
            + (" - %s" % note if note else ""))
    if "debug_symbols" in facts:
        add(t("Debug symbols in libapp.so"), yes_no(facts.get("debug_symbols"), t))
    sources = facts.get("dart_sources")
    if isinstance(sources, Mapping) and facts.get("flutter"):
        files = sources.get("files") or []
        add(t("Dart source files recovered"), "%s%s" % (
            sources.get("recovered", 0), " (%s)" % _short_list(files, 5) if files else ""))
    dex = facts.get("dex")
    if isinstance(dex, Mapping):
        add(t("DEX files, classes, strings"), "%s, %s, %s" % (
            dex.get("files", 0), dex.get("classes", 0), dex.get("strings", 0)))
    add(t("Plugins"), _short_list(facts.get("plugins")))
    flags = facts.get("flags")
    if isinstance(flags, Mapping):
        for key, label in (("debuggable", t("Debuggable")), ("allow_backup", t("Backup allowed")),
                           ("cleartext", t("Cleartext HTTP")),
                           ("network_security_config", t("Network security config"))):
            if flags.get(key):
                add(label, flag_text(flags[key], t))
    if "dependency_issues" in facts:
        add(t("Dependency issues"), facts.get("dependency_issues"))
    tools = facts.get("tools")
    if isinstance(tools, Mapping):
        for name, note in tools.items():
            add(str(name), note)
    return rows


def _permissions(facts: Mapping[str, Any], t: Text, wide: Dict) -> None:
    permissions = [p for p in facts.get("permissions") or [] if isinstance(p, Mapping)]
    dangerous = sum(1 for p in permissions if p.get("dangerous"))
    st.markdown("**%s**" % (t("Permissions (%d, %d dangerous)") % (len(permissions), dangerous)))
    if not permissions:
        st.caption(t("None."))
        return
    _table([{t("Permission"): str(p.get("name", "")),
             t("Dangerous"): yes_no(p.get("dangerous"), t)}
            for p in sorted(permissions, key=lambda p: (not p.get("dangerous"),
                                                        str(p.get("name", ""))))], wide)


def _signing(facts: Mapping[str, Any], t: Text, wide: Dict) -> None:
    signing = facts.get("signing")
    if not isinstance(signing, Mapping):
        return
    st.markdown("**%s**" % t("Signing"))
    verified = signing.get("verified")
    if verified is None:
        sentence = t("Signature schemes: %s. The signature is not verified cryptographically "
                     "(apksigner did not run).")
    elif verified:
        sentence = t("Signature schemes: %s. apksigner verified the signature.")
    else:
        sentence = t("Signature schemes: %s. apksigner reports that the signature does not "
                     "verify.")
    st.caption(sentence % (plain(", ".join(map(str, signing.get("schemes") or [])))
                           or t("none (not signed)")))
    certificates = [c for c in signing.get("certificates") or [] if isinstance(c, Mapping)]
    if not certificates:
        return
    _table([{t("Subject"): str(c.get("subject", "")), t("Issuer"): str(c.get("issuer", "")),
             t("Valid"): "%s - %s" % (c.get("valid_from", ""), c.get("valid_to", "")),
             t("Key"): str(c.get("key", "")),
             t("Signature algorithm"): str(c.get("signature_algorithm", "")),
             t("Android debug certificate"): yes_no(c.get("debug"), t)}
            for c in certificates], wide)
    st.code("\n".join("SHA-256 %s" % c.get("sha256", "") for c in certificates),
            language="text")


def _components(components: List[Mapping[str, Any]], t: Text, wide: Dict) -> None:
    exported = sum(1 for c in components if c.get("exported"))
    st.markdown("**%s**" % (t("Components (%d, %d exported)") % (len(components), exported)))
    if not components:
        st.caption(t("None."))
        return
    kinds = {key: t(text) for key, text in COMPONENTS.items()}
    _table([{t("Type"): kinds.get(str(c.get("type")), str(c.get("type", ""))),
             t("Name"): str(c.get("name", "")), t("Exported"): yes_no(c.get("exported"), t),
             t("Permission"): str(c.get("permission") or "-"),
             t("Launcher"): yes_no(c.get("launcher"), t)}
            for c in sorted(components, key=lambda c: not c.get("exported"))], wide)


def _links(components: List[Mapping[str, Any]], t: Text, wide: Dict) -> None:
    links = [(str(link), str(c.get("name", ""))) for c in components
             for link in c.get("deep_links") or []]
    st.markdown("**%s**" % (t("Deep links (%d)") % len(links)))
    if not links:
        st.caption(t("None."))
        return
    _table([{t("Link"): link, t("Opens"): name} for link, name in links], wide)


def _packages(facts: Mapping[str, Any], is_app: bool, t: Text, wide: Dict) -> None:
    packages = [p for p in facts.get("packages") or [] if isinstance(p, Mapping)]
    st.markdown("**%s**" % (t("Dart packages (%d)") % len(packages)))
    if not packages:
        st.caption(t("None."))
        return
    if is_app:
        found = {key: t(text) for key, text in FOUND_IN.items()}
        _table([{t("Package"): str(p.get("name", "")),
                 t("Version"): str(p.get("version") or t("unknown")),
                 t("Found in"): found.get(str(p.get("found_in")), str(p.get("found_in", "")))}
                for p in packages], wide)
    else:
        kinds = {key: t(text) for key, text in DEPENDENCIES.items()}
        _table([{t("Package"): str(p.get("name", "")),
                 t("Version"): str(p.get("version") or t("unknown")),
                 t("Dependency"): kinds.get(str(p.get("dependency")),
                                            str(p.get("dependency", "")))}
                for p in packages], wide)


def _endpoints(facts: Mapping[str, Any], t: Text, wide: Dict) -> None:
    endpoints = [e for e in facts.get("endpoints") or [] if isinstance(e, Mapping)]
    cleartext = sum(1 for e in endpoints if e.get("cleartext"))
    st.markdown("**%s**" % (t("Server addresses in the code (%d, %d without TLS)")
                            % (len(endpoints), cleartext)))
    if not endpoints:
        st.caption(t("None."))
        return
    _table([{t("Address"): str(e.get("url", "")),
             t("Without TLS"): yes_no(e.get("cleartext"), t), t("File"): str(e.get("file", ""))}
            for e in sorted(endpoints, key=lambda e: not e.get("cleartext"))], wide)


def _warnings(facts: Mapping[str, Any], t: Text) -> None:
    warnings = [str(w) for w in facts.get("warnings") or []]
    if not warnings:
        return
    st.markdown("**%s**" % (t("Decoder warnings (%d)") % len(warnings)))
    st.caption(t("Parts of the app that could not be read as expected. Many unusual ones can "
                 "be a sign that the package was changed to hinder analysis."))
    st.code("\n".join(warnings[:50]), language="text")
