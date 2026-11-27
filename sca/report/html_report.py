"""Self-contained HTML report (one file, no internet needed, prints well to PDF).

For an app package or a Flutter/Android project the report also has an app card (the facts
of ScanResult.app) and the OWASP Mobile Top 10 (2024) and MASVS summaries. app_overview()
and app_tables() turn the facts into plain text rows; the PDF report and the command line
use them too.
"""
from __future__ import annotations

import json
import re
from html import escape
from typing import Any, Dict, List, Tuple

from .. import __version__
from ..cwe import MASVS_GROUPS, MOBILE_TOP10_2024, info, masvs_name, mobile_name
from ..models import SEVERITIES, Finding, ScanResult
from ..walker import strip_bidi

APP_ROWS = 25            # rows of each app list in the report; the rest is counted
KIND_TEXT = {"apk": "APK", "aab": "Android App Bundle (.aab)", "apks": "Split APK set",
             "flutter-project": "Flutter project", "android-project": "Android project"}
# facts that app_overview() and app_tables() show in their own way; any other key is shown
# as it is, so that no fact is left out
_SHOWN = {"kind", "name", "package", "version_name", "version_code", "min_sdk", "target_sdk",
          "compile_sdk", "min_sdk_note", "target_sdk_note", "size_bytes", "sha256", "flutter",
          "build_mode", "abis", "platforms", "dart_version", "dart_sdk", "engine_revision",
          "snapshot_hash", "snapshot_features", "obfuscated", "obfuscation_note",
          "debug_symbols", "dart_sources", "dex", "flutter_markers", "flags", "signing",
          "dependency_issues", "debug_manifests", "packages", "plugins", "permissions",
          "components", "endpoints", "tools", "warnings", "apis"}
API_ROWS = 60            # rows of each list of the API and key inventory in the report
API_PLACES = 5           # places named per item; the rest is counted
_CATEGORY_TEXT = {"tunnel": "tunnel or test service", "webhook": "webhook", "app": "app server",
                  "backend": "cloud backend", "api": "third-party API",
                  "sdk": "SDK, analytics or ads"}
_ALERT_LABEL = {"cleartext": "no TLS", "tunnel": "tunnel", "webhook": "webhook",
                "telegram": "bot token", "secret_in_url": "key in the address",
                "password_in_url": "password in the address", "dev_host": "test server",
                "private_ip": "private IP", "ip_host": "IP address"}
_FLAGS = (("debuggable", "Debuggable"), ("allow_backup", "Backup allowed"),
          ("cleartext", "Cleartext traffic"), ("network_security_config",
                                               "Network security config"))
_CONTROL = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")
_MAX_TEXT = 600

CSS = """
:root{--bg:#f6f5f1;--card:#fff;--ink:#1c1b19;--muted:#6b6a65;--line:#e2e0d8;--code:#f1efe8;
--critical:#9b1c1c;--high:#c2410c;--medium:#a16207;--low:#1d5f8a;--info:#5f5e5a;--ai:#4c3d99;
--ok:#15803d}
@media(prefers-color-scheme:dark){:root{--bg:#161614;--card:#1f1f1c;--ink:#ecebe6;--muted:#a09f98;
--line:#34332f;--code:#2a2925;--critical:#f87171;--high:#fb923c;--medium:#facc15;--low:#60a5fa;
--info:#a3a29b;--ai:#a99cf0;--ok:#4ade80}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,
"Segoe UI",Roboto,"Noto Sans Arabic",Tahoma,sans-serif}
main{max-width:1040px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:24px;margin:0 0 2px;letter-spacing:-.01em}
h2{font-size:17px;margin:34px 0 12px}
.sub{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:240px 1fr;gap:16px;margin-top:20px}
@media(max-width:720px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}
.score{text-align:center}
.score b{display:block;font-size:64px;line-height:1;font-weight:700;letter-spacing:-.03em}
.score span{font-size:13px;color:var(--muted)}
.grade{display:inline-block;margin-top:10px;padding:3px 14px;border-radius:99px;font-weight:700;
border:2px solid currentColor}
.sev-row{display:flex;gap:8px;flex-wrap:wrap}
.sev-box{flex:1;min-width:92px;border:1px solid var(--line);border-radius:8px;padding:10px 12px;
border-top:4px solid var(--c)}
.sev-box b{font-size:26px;display:block;line-height:1.1}
.sev-box span{font-size:12px;color:var(--muted);text-transform:capitalize}
.bar{display:flex;height:10px;border-radius:99px;overflow:hidden;margin:14px 0 4px;
background:var(--line)}
.bar i{display:block;background:var(--c)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
td,th{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}
td.n{text-align:right;font-variant-numeric:tabular-nums;width:60px}
ul.alerts{margin:0 0 8px;padding-left:20px;font-size:13.5px}ul.alerts li{margin:3px 0}
.filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.filters button{font:inherit;font-size:13px;padding:5px 12px;border-radius:99px;cursor:pointer;
border:1px solid var(--line);background:var(--card);color:var(--ink)}
.filters button.on{background:var(--ink);color:var(--bg);border-color:var(--ink)}
details.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--c);
border-radius:8px;margin-bottom:8px}
details.f.fp{opacity:.72}
summary{cursor:pointer;padding:11px 14px;display:flex;gap:10px;align-items:baseline;
flex-wrap:wrap;list-style:none}
summary::-webkit-details-marker{display:none}
.pill{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--c);
min-width:62px}
.t{font-weight:600;flex:1;min-width:200px}
.loc{font:12px ui-monospace,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere}
.body{padding:2px 14px 14px;border-top:1px solid var(--line)}
.meta{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0}
.tag{font-size:12px;padding:2px 9px;border-radius:99px;background:var(--code);color:var(--ink);
text-decoration:none}
.tag.ai{color:var(--ai);border:1px solid var(--ai);background:none}
.tag.ok{color:var(--ok);border:1px solid var(--ok);background:none}
pre{background:var(--code);border-radius:6px;padding:10px 12px;overflow-x:auto;margin:10px 0;
font:12.5px/1.5 ui-monospace,Consolas,monospace;direction:ltr;text-align:left}
pre .hit{background:color-mix(in srgb,var(--c) 22%,transparent);display:block}
.lbl{font-size:12px;font-weight:700;color:var(--muted);margin:12px 0 2px;text-transform:uppercase;
letter-spacing:.04em}
.aibox{border-left:3px solid var(--ai);padding:2px 0 2px 12px;margin-top:12px}
.aibox .lbl{color:var(--ai)}
p{margin:4px 0}
.note{font-size:12.5px;color:var(--muted);margin-top:28px;border-top:1px solid var(--line);
padding-top:12px}
.app h3{font-size:14px;margin:18px 0 6px}
.app td{overflow-wrap:anywhere}
.app .kv th{width:190px;color:var(--muted);font-weight:600;font-size:13px}
.app td.more{color:var(--muted);font-style:italic}
@media print{body{background:#fff}details.f{break-inside:avoid}.filters{display:none}
details.f>.body{display:block}}
"""

JS = """
document.querySelectorAll('.filters button').forEach(function(b){b.addEventListener('click',
function(){document.querySelectorAll('.filters button').forEach(function(x){
x.classList.remove('on')});b.classList.add('on');var s=b.dataset.sev;
document.querySelectorAll('details.f').forEach(function(d){
d.style.display=(s==='all'||(d.dataset.status==='open'&&d.dataset.sev===s)||d.dataset.status===s)?'':'none'})})});
window.addEventListener('beforeprint',function(){document.querySelectorAll('details.f')
.forEach(function(d){d.open=true})});
"""


STATUS_TEXT = {"open": "open", "needs_review": "needs review",
               "likely_false_positive": "likely false positive",
               "dismissed": "dismissed by the reviewer"}


# ------------------------------------------------------------------ app facts as text
def fact_text(value: Any, *, limit: int = _MAX_TEXT) -> str:
    """One fact as a short line of text: yes/no for booleans, lists joined by commas.
    Control characters, the bidirectional ones included, are removed (the facts come from an
    untrusted app)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        text = ", ".join(fact_text(item, limit=limit) for item in value)
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value)
    text = strip_bidi(_CONTROL.sub(" ", text)).strip()
    return text if not limit or len(text) <= limit else text[:limit] + "..."


def size_text(size: int) -> str:
    """A file size in decimal units, as the documents give them: "2.4 MB (2,400,000 bytes)"
    (1 MB = 1,000,000 bytes)."""
    if size >= 1_000_000:
        return "%.1f MB (%s bytes)" % (size / 1_000_000, format(size, ","))
    return "%d KB (%s bytes)" % (max(1, round(size / 1000)), format(size, ","))


def app_overview(facts: Dict[str, Any]) -> List[Tuple[str, str]]:
    """The single-value facts of an app or project as (label, text) rows, in a fixed order;
    facts that are absent or empty are left out."""
    rows: List[Tuple[str, str]] = []

    def add(label: str, value: Any) -> None:
        text = fact_text(value)
        if text:
            rows.append((label, text))

    kind = str(facts.get("kind") or "")
    add("Kind", KIND_TEXT.get(kind, kind))
    add("Name", facts.get("name"))
    add("Package", facts.get("package"))
    version = fact_text(facts.get("version_name"))
    if facts.get("version_code"):
        version = ("%s (code %s)" % (version, fact_text(facts["version_code"]))).strip()
    add("Version", version)
    levels = []
    for key, label in (("min_sdk", "min"), ("target_sdk", "target"), ("compile_sdk", "compile")):
        if key in facts:
            value = facts[key] if facts[key] is not None else facts.get(key + "_note") or "unknown"
            levels.append("%s %s" % (label, fact_text(value)))
    add("SDK levels", ", ".join(levels))
    if isinstance(facts.get("size_bytes"), int) and not isinstance(facts["size_bytes"], bool):
        add("Size", size_text(facts["size_bytes"]))
    add("SHA-256", facts.get("sha256"))
    if "flutter" in facts:
        add("Flutter", bool(facts["flutter"]))
    # an app or project without Flutter has no build mode and no Dart packages to report
    flutter_only = ("build_mode", "dependency_issues") if facts.get("flutter") is False else ()
    for key, label in (("build_mode", "Build mode"), ("abis", "ABIs"), ("platforms", "Platforms"),
                       ("dart_version", "Dart version"), ("dart_sdk", "Dart SDK"),
                       ("engine_revision", "Flutter engine revision"),
                       ("snapshot_hash", "Snapshot hash"),
                       ("snapshot_features", "Snapshot features")):
        if key not in flutter_only:
            add(label, facts.get(key))
    if "obfuscated" in facts:
        state = {True: "yes", False: "no"}.get(facts["obfuscated"], "unknown")
        note = fact_text(facts.get("obfuscation_note"))
        add("Dart obfuscation", "%s (%s)" % (state, note) if note else state)
    if "debug_symbols" in facts:
        add("Debug symbols in libapp.so", bool(facts["debug_symbols"]))
    sources = facts.get("dart_sources")
    if isinstance(sources, dict):
        add("Dart sources recovered", sources.get("recovered", 0))
    dex = facts.get("dex")
    if isinstance(dex, dict):
        add("DEX", ", ".join("%s %s" % (fact_text(dex[key]), one if dex[key] == 1 else key)
                             for key, one in (("files", "file"), ("classes", "class"),
                                              ("strings", "string")) if key in dex))
    markers = facts.get("flutter_markers")
    if isinstance(markers, dict):
        add("Flutter markers in DEX", [name for name, found in markers.items() if found])
    flags = facts.get("flags")
    if isinstance(flags, dict):
        for key, label in _FLAGS:
            add(label, flags.get(key))
    signing = facts.get("signing")
    if isinstance(signing, dict):
        add("Signature schemes", signing.get("schemes") or "none")
        if "verified" in signing:
            add("Signature verified by apksigner",
                {True: "yes", False: "no"}.get(signing["verified"], "not checked"))
    if "dependency_issues" in facts and "dependency_issues" not in flutter_only:
        add("Dependency issues", facts["dependency_issues"])
    add("Debug manifests (not checked)", facts.get("debug_manifests"))
    for key in sorted(set(facts) - _SHOWN):
        add(key.replace("_", " ").capitalize(), facts[key])
    return rows


def app_tables(facts: Dict[str, Any]) -> List[Tuple[str, List[str], List[List[str]]]]:
    """The list facts of an app or project as (title, column names, rows), every row in full;
    lists that are absent or empty are left out."""
    def items(key: str) -> List[Dict[str, Any]]:
        value = facts.get(key)
        return [item for item in value if isinstance(item, dict)] \
            if isinstance(value, list) else []

    def texts(key: str) -> List[List[str]]:
        value = facts.get(key)
        return [[fact_text(item)] for item in value] if isinstance(value, list) else []

    tables: List[Tuple[str, List[str], List[List[str]]]] = []
    signing = facts.get("signing") if isinstance(facts.get("signing"), dict) else {}
    certificates = [c for c in signing.get("certificates") or [] if isinstance(c, dict)]
    tables.append(("Signing certificates",
                   ["Subject", "Issuer", "SHA-256", "Valid", "Key", "Algorithm", "Debug"],
                   [[fact_text(c.get("subject")), fact_text(c.get("issuer")),
                     fact_text(c.get("sha256")),
                     "%s to %s" % (fact_text(c.get("valid_from")) or "?",
                                   fact_text(c.get("valid_to")) or "?"),
                     fact_text(c.get("key")), fact_text(c.get("signature_algorithm")),
                     fact_text(bool(c.get("debug")))] for c in certificates]))
    tables.append(("Permissions", ["Permission", "Dangerous"],
                   [[fact_text(p.get("name")), "yes" if p.get("dangerous") else ""]
                    for p in items("permissions")]))
    tables.append(("Components",
                   ["Type", "Name", "Exported", "Permission", "Launcher", "Deep links"],
                   [[fact_text(c.get("type")), fact_text(c.get("name")),
                     fact_text(c.get("exported")), fact_text(c.get("permission")),
                     "yes" if c.get("launcher") else "", fact_text(c.get("deep_links"))]
                    for c in items("components")]))
    if not isinstance(facts.get("apis"), dict):     # else the inventory lists them in full
        tables.append(("Endpoints", ["URL", "Cleartext", "File"],
                       [[fact_text(e.get("url")), "yes" if e.get("cleartext") else "",
                         fact_text(e.get("file"))] for e in items("endpoints")]))
    packages = items("packages")
    extra = [(key, label) for key, label in (("found_in", "Found in"),
                                             ("dependency", "Dependency"))
             if any(p.get(key) for p in packages)]
    tables.append(("Packages", ["Package", "Version", "Source"] + [label for _, label in extra],
                   [[fact_text(p.get("name")), fact_text(p.get("version")) or "unknown",
                     fact_text(p.get("source"))] + [fact_text(p.get(key)) for key, _ in extra]
                    for p in packages]))
    tables.append(("Plugins", ["Class"], texts("plugins")))
    sources = facts.get("dart_sources") if isinstance(facts.get("dart_sources"), dict) else {}
    files = sources.get("files") if isinstance(sources.get("files"), list) else []
    tables.append(("Recovered Dart sources", ["File"], [[fact_text(rel)] for rel in files]))
    tools = facts.get("tools") if isinstance(facts.get("tools"), dict) else {}
    tables.append(("Tools", ["Tool", "Note"],
                   [[fact_text(name), fact_text(note)] for name, note in tools.items()]))
    tables.append(("Warnings", ["Warning"], texts("warnings")))
    return [table for table in tables if table[2]]


def _places(item: Dict[str, Any]) -> str:
    locations = [loc for loc in item.get("locations") or [] if isinstance(loc, dict)]
    texts = ["%s:%s" % (fact_text(loc.get("file")), loc.get("line")) if loc.get("line")
             else fact_text(loc.get("file")) for loc in locations[:API_PLACES]]
    try:
        more = int(item.get("count") or len(locations)) - len(texts)
    except (TypeError, ValueError):
        more = 0
    return ", ".join(texts) + (" (+%d)" % more if more > 0 else "")


def _labels(codes: Any) -> str:
    return ", ".join(_ALERT_LABEL.get(str(code), fact_text(code))
                     for code in codes or []) if isinstance(codes, list) else ""


def api_summary(apis: Dict[str, Any]) -> str:
    """One line about the API and key inventory of an app or project."""
    summary = apis.get("summary") if isinstance(apis.get("summary"), dict) else {}

    def number(key: str) -> int:
        value = summary.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    return ("%d server addresses on %d hosts (%d without TLS), %d keys (%d secret, %d high or "
            "critical), %d API calls, %d API paths, %d service identifiers" % (
                number("endpoints"), number("hosts"), number("cleartext"), number("keys"),
                number("secret_keys"), number("high_keys"), number("calls"), number("paths"),
                number("config")))


def api_truncated(apis: Dict[str, Any]) -> str:
    """"" or the note that lists were cut to keep the facts small."""
    truncated = apis.get("truncated")
    if not isinstance(truncated, dict) or not truncated:
        return ""
    return "Lists cut to keep the facts small: %s." % ", ".join(
        "%s +%s" % (fact_text(name), fact_text(count)) for name, count in truncated.items())


def api_alerts(apis: Dict[str, Any]) -> List[Tuple[str, str]]:
    """The alerts of the inventory as (level, text): danger, warning or info."""
    out = []
    for alert in apis.get("alerts") or []:
        if isinstance(alert, dict):
            level = str(alert.get("level"))
            out.append((level if level in ("danger", "warning", "info") else "info",
                        fact_text(alert.get("text"))))
    return out


def api_tables(apis: Dict[str, Any]) -> List[Tuple[str, List[str], List[List[str]]]]:
    """The lists of the API and key inventory as (title, column names, rows); empty lists
    are left out."""
    def items(key: str) -> List[Dict[str, Any]]:
        value = apis.get(key)
        return [item for item in value if isinstance(item, dict)] \
            if isinstance(value, list) else []

    def value_text(value: Any) -> str:
        return fact_text(value, limit=0 if apis.get("values_visible") else _MAX_TEXT)

    tables: List[Tuple[str, List[str], List[List[str]]]] = []
    keys = []
    for k in items("keys"):
        if k.get("dismissed"):          # dismissed by the reviewer after the scan
            continue
        claims = k.get("claims") if isinstance(k.get("claims"), dict) else {}
        keys.append([fact_text(k.get("type")), fact_text(k.get("service")),
                     value_text(k.get("value")) or "-", fact_text(k.get("severity")),
                     "yes" if k.get("public") else "", _places(k),
                     ", ".join("%s=%s" % (fact_text(a), fact_text(b)) for a, b in claims.items())
                     or fact_text(k.get("used_by")), fact_text(k.get("advice_text"))])
    tables.append(("Keys, tokens and passwords" if apis.get("values_visible")
                   else "Keys, tokens and passwords (masked)",
                   ["Type", "Service", "Value", "Severity", "Public", "Places", "Details",
                    "What to do"], keys))
    tables.append(("Server addresses", ["Address", "Service", "Kind", "TLS", "Alerts", "Places"],
                   [[value_text(e.get("url")), fact_text(e.get("service")) or "-",
                     _CATEGORY_TEXT.get(str(e.get("category")), fact_text(e.get("category"))),
                     "-" if e.get("host_only") else "no" if e.get("cleartext") else "yes",
                     _labels(e.get("alerts")), _places(e)] for e in items("endpoints")]))
    tables.append(("Hosts", ["Host", "Service", "Kind", "Addresses", "Alerts"],
                   [[fact_text(h.get("host")), fact_text(h.get("service")) or "-",
                     _CATEGORY_TEXT.get(str(h.get("category")), fact_text(h.get("category"))),
                     fact_text(h.get("endpoints")), _labels(h.get("alerts"))]
                    for h in items("hosts")]))
    tables.append(("API calls in the code", ["Method", "Target", "Kind", "Place"],
                   [[fact_text(c.get("method")), value_text(c.get("target")),
                     fact_text(c.get("kind")), "%s:%s" % (fact_text(c.get("file")),
                                                          fact_text(c.get("line")))]
                    for c in items("calls")]))
    tables.append(("API paths", ["Path", "Alerts", "Places"],
                   [[value_text(p.get("path")), _labels(p.get("alerts")), _places(p)]
                    for p in items("paths")]))
    firebase = apis.get("firebase") if isinstance(apis.get("firebase"), dict) else {}
    tables.append(("Firebase project", ["Fact", "Value"],
                   [[key.replace("_", " "), value_text(value)] for key, value in firebase.items()]))
    tables.append(("Service identifiers", ["Name", "Value", "Service", "Places"],
                   [[fact_text(c.get("label")), value_text(c.get("value")),
                     fact_text(c.get("service")), _places(c)] for c in items("config")]))
    tables.append((".env entries", ["File", "Line", "Name", "Value"],
                   [[fact_text(e.get("file")), fact_text(e.get("line")), fact_text(e.get("name")),
                     value_text(e.get("value"))] for e in items("env")]))
    return [table for table in tables if table[2]]


def _apis_html(apis: Dict[str, Any]) -> str:
    level_color = {"danger": "critical", "warning": "medium", "info": "low"}
    alerts = "".join('<li style="color:var(--%s)">%s</li>' % (level_color[level], escape(text))
                     for level, text in api_alerts(apis))
    note = ("Original values are shown; no address was contacted." if apis.get("values_visible")
            else "Keys are masked; no address was contacted.")
    parts = ['<div class="sub">%s. %s</div>' % (escape(api_summary(apis)), escape(note))]
    if api_truncated(apis):
        parts.append('<div class="sub">%s</div>' % escape(api_truncated(apis)))
    if alerts:
        parts.append('<h3>Alerts</h3><ul class="alerts">%s</ul>' % alerts)
    for title, columns, rows in api_tables(apis):
        body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % escape(cell) for cell in row)
                       for row in rows[:API_ROWS])
        if len(rows) > API_ROWS:
            body += '<tr><td class="more" colspan="%d">and %d more</td></tr>' % (
                len(columns), len(rows) - API_ROWS)
        parts.append("<h3>%s (%d)</h3><table><tr>%s</tr>%s</table>" % (
            escape(title), len(rows), "".join("<th>%s</th>" % escape(c) for c in columns), body))
    return '<h2>APIs and keys</h2><div class="card app">%s</div>' % "".join(parts)


def _app_html(facts: Dict[str, Any]) -> str:
    if not facts.get("kind") and set(facts) <= {"apis"}:
        apis = facts.get("apis")
        return _apis_html(apis) if isinstance(apis, dict) else ""
    overview = "".join("<tr><th>%s</th><td>%s</td></tr>" % (escape(label), escape(text))
                       for label, text in app_overview(facts))
    parts = ['<table class="kv">%s</table>' % overview]
    for title, columns, rows in app_tables(facts):
        body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % escape(cell) for cell in row)
                       for row in rows[:APP_ROWS])
        if len(rows) > APP_ROWS:
            body += '<tr><td class="more" colspan="%d">and %d more</td></tr>' % (
                len(columns), len(rows) - APP_ROWS)
        parts.append("<h3>%s (%d)</h3><table><tr>%s</tr>%s</table>" % (
            escape(title), len(rows), "".join("<th>%s</th>" % escape(c) for c in columns), body))
    kind = facts.get("kind")
    title = "Mobile project" if kind in ("flutter-project", "android-project") else "App package"
    apis = facts.get("apis")
    return '<h2>%s</h2><div class="card app">%s</div>%s' % (
        title, "".join(parts), _apis_html(apis) if isinstance(apis, dict) else "")


def _mobile_html(result: ScanResult) -> str:
    """OWASP Mobile Top 10 (2024) and MASVS counts of the open findings."""
    risks: Dict[str, int] = {}
    groups: Dict[str, int] = {}
    for finding in result.open_findings:
        if finding.owasp_mobile:
            risks[finding.owasp_mobile] = risks.get(finding.owasp_mobile, 0) + 1
        if finding.masvs:
            groups[finding.masvs] = groups.get(finding.masvs, 0) + 1
    risk_rows = "".join('<tr><td>%s %s</td><td class="n">%d</td></tr>'
                        % (code, escape(mobile_name(code)), risks.get(code, 0))
                        for code in MOBILE_TOP10_2024)
    group_rows = "".join('<tr><td>%s (%s)</td><td class="n">%d</td></tr>'
                         % (code, escape(masvs_name(code)), groups.get(code, 0))
                         for code in MASVS_GROUPS)
    return ('<div class="grid" style="grid-template-columns:1fr 1fr">'
            '<div class="card"><h2 style="margin-top:0">OWASP Mobile Top 10 (2024)</h2>'
            '<table>%s</table></div>'
            '<div class="card"><h2 style="margin-top:0">MASVS groups</h2><table>%s</table></div>'
            '</div>' % (risk_rows, group_rows))


def _context_html(finding: Finding) -> str:
    if not finding.context:
        return escape(finding.snippet)
    out = []
    marker = "%4d |" % finding.line
    for row in finding.context.split("\n"):
        text = escape(row)
        out.append('<span class="hit">%s</span>' % text if row.startswith(marker) else text)
    return "\n".join(out).replace("</span>\n", "</span>")


def _finding_html(finding: Finding) -> str:
    kb = info(finding.cwe)
    tags = []
    if finding.cwe:
        tags.append('<a class="tag" href="%s">%s %s</a>'
                    % (escape(kb["url"]), escape(finding.cwe), escape(kb["name"])
                       if kb["name"] != finding.cwe else ""))
    if finding.owasp:
        tags.append('<span class="tag">%s</span>' % escape(finding.owasp))
    if finding.owasp_mobile:
        tags.append('<span class="tag">%s %s</span>' % (
            escape(finding.owasp_mobile), escape(mobile_name(finding.owasp_mobile))))
    if finding.masvs:
        tags.append('<span class="tag">%s</span>' % escape(finding.masvs))
    tags.append('<span class="tag">risk %.1f / 10</span>' % finding.risk_score)
    tags.append('<span class="tag">confidence %d%%</span>' % round(finding.confidence * 100))
    tags.append('<span class="tag">engines: %s</span>' % escape(", ".join(finding.engines)))
    if finding.tier == "confirmed":
        tags.append('<span class="tag ok">confirmed: %s</span>'
                    % escape("; ".join(finding.evidence)))
    elif finding.tier:
        tags.append('<span class="tag">probable: not independently confirmed</span>')
    if finding.ml_score is not None:
        tags.append('<span class="tag ai">ML %d%%</span>' % round(finding.ml_score * 100))
    if finding.ai_verdict:
        tags.append('<span class="tag ai">AI: %s</span>'
                    % escape(finding.ai_verdict.replace("_", " ")))
    if finding.user_verdict:
        tags.append('<span class="tag ok">reviewer: %s</span>'
                    % escape(finding.user_verdict.replace("_", " ")))
    parts = ['<div class="meta">%s</div>' % "".join(tags),
             "<pre>%s</pre>" % _context_html(finding)]
    if finding.description:
        parts.append('<div class="lbl">Why it matters</div><p dir="auto">%s</p>'
                     % escape(finding.description))
    if finding.fix:
        parts.append('<div class="lbl">How to fix</div><p dir="auto">%s</p>'
                     % escape(finding.fix))
    if finding.ai_explanation or finding.ai_fix:
        ai = ['<div class="aibox"><div class="lbl">AI review (%s)</div>'
              % escape(finding.ai_model or "model")]
        if finding.ai_explanation:
            ai.append('<p dir="auto">%s</p>' % escape(finding.ai_explanation))
        if finding.ai_fix:
            ai.append('<pre dir="auto">%s</pre>' % escape(finding.ai_fix))
        ai.append("</div>")
        parts.append("".join(ai))
    fp = finding.status != "open"
    return (
        '<details class="f%s" data-sev="%s" data-status="%s" style="--c:var(--%s)">'
        '<summary><span class="pill">%s</span><span class="t">%s%s</span>'
        '<span class="loc">%s:%d</span></summary><div class="body">%s</div></details>'
        % (" fp" if fp else "", finding.severity, finding.status, finding.severity,
           finding.severity, escape(finding.title),
           " (%s)" % STATUS_TEXT[finding.status] if fp else "",
           escape(finding.file), finding.line, "".join(parts))
    )


def render_html(result: ScanResult) -> str:
    counts = result.counts()
    total = sum(counts.values())
    grade_color = {"A": "ok", "B": "ok", "C": "medium", "D": "high", "F": "critical"}[
        result.grade]
    sev_boxes = "".join(
        '<div class="sev-box" style="--c:var(--%s)"><b>%d</b><span>%s</span></div>'
        % (s, counts[s], s) for s in SEVERITIES)
    bar = "".join('<i style="--c:var(--%s);width:%.2f%%"></i>' % (s, 100.0 * counts[s] / total)
                  for s in SEVERITIES if total and counts[s])

    by_owasp: Dict[str, int] = {}
    by_file: Dict[str, int] = {}
    for finding in result.open_findings:
        by_owasp[finding.owasp] = by_owasp.get(finding.owasp, 0) + 1
        by_file[finding.file] = by_file.get(finding.file, 0) + 1
    owasp_rows = "".join('<tr><td>%s</td><td class="n">%d</td></tr>' % (escape(k), v)
                         for k, v in sorted(by_owasp.items(), key=lambda kv: -kv[1]))
    file_rows = "".join('<tr><td class="loc">%s</td><td class="n">%d</td></tr>' % (escape(k), v)
                        for k, v in sorted(by_file.items(), key=lambda kv: -kv[1])[:10])
    engine_rows = "".join('<tr><td>%s</td><td>%s</td></tr>' % (escape(k), escape(v))
                          for k, v in result.engine_notes.items())
    engine_rows += "".join('<tr><td>AI: %s</td><td>%s</td></tr>' % (escape(k), escape(str(v)))
                           for k, v in result.ai.items())
    langs = ", ".join("%s (%d)" % (k, v) for k, v in
                      sorted(result.languages.items(), key=lambda kv: -kv[1]))
    fp_count = len(result.findings) - len(result.open_findings)
    other = ["%d %s" % (result.status_count(key), text) for key, text in STATUS_TEXT.items()
             if key != "open" and result.status_count(key)]
    confirmed = sum(1 for f in result.open_findings if f.tier == "confirmed")

    buttons: List[str] = ['<button class="on" data-sev="all">All (%d)</button>'
                          % len(result.findings)]
    buttons += ['<button data-sev="%s">%s (%d)</button>' % (s, s.capitalize(), counts[s])
                for s in SEVERITIES if counts[s]]
    buttons += ['<button data-sev="%s">%s (%d)</button>'
                % (key, text.capitalize(), result.status_count(key))
                for key, text in STATUS_TEXT.items()
                if key != "open" and result.status_count(key)]
    findings_html = "".join(_finding_html(f) for f in result.findings) or \
        '<div class="card">No findings. Remember that a clean scan is not a proof of security.</div>'

    html = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security report</title><style>%(css)s</style></head><body><main>
<h1>Secure Code Analyzer</h1>
<div class="sub">%(target)s</div>
<div class="sub">%(date)s &middot; %(files)d files &middot; %(lines)d lines &middot; %(duration).1f s
&middot; %(langs)s</div>
<div class="grid">
 <div class="card score"><span>Security score</span><b style="color:var(--%(gc)s)">%(score)d</b>
  <span>out of 100</span><br><span class="grade" style="color:var(--%(gc)s)">Grade %(grade)s</span></div>
 <div class="card"><div class="sev-row">%(sev_boxes)s</div><div class="bar">%(bar)s</div>
  <div class="sub">%(total)d open findings%(fp_note)s</div></div>
</div>
%(app)s
<div class="grid" style="grid-template-columns:1fr 1fr">
 <div class="card"><h2 style="margin-top:0">OWASP Top 10 (2021)</h2>
  <table>%(owasp_rows)s</table></div>
 <div class="card"><h2 style="margin-top:0">Most affected files</h2>
  <table>%(file_rows)s</table></div>
</div>
%(mobile)s
<h2>Findings</h2>
<div class="filters">%(buttons)s</div>
%(findings)s
<h2>Engines</h2>
<div class="card"><table><tr><th>Engine</th><th>Status</th></tr>%(engine_rows)s</table></div>
<div class="note">Generated by Secure Code Analyzer %(version)s. The security score is a heuristic
of this tool and not an official CVSS score. Static analysis can miss vulnerabilities and can report
false positives; AI reviews can be wrong. Verify findings before acting on them.</div>
</main><script>%(js)s</script></body></html>""" % {
        "css": CSS, "js": JS, "target": escape(result.target), "date": escape(result.started_at),
        "files": result.files_scanned, "lines": result.lines_scanned,
        "duration": result.duration_seconds, "langs": escape(langs), "gc": grade_color,
        "score": result.score, "grade": result.grade, "sev_boxes": sev_boxes, "bar": bar,
        "total": total,
        "fp_note": " (%d confirmed by independent evidence)%s" % (
            confirmed, " &middot; not counted: " + escape(", ".join(other)) if other else ""),
        "owasp_rows": owasp_rows or "<tr><td>None</td></tr>",
        "file_rows": file_rows or "<tr><td>None</td></tr>",
        "buttons": "".join(buttons), "findings": findings_html, "engine_rows": engine_rows,
        "version": __version__, "app": _app_html(result.app) if result.app else "",
        "mobile": _mobile_html(result) if result.app.get("kind") else "",
    }
    # The page itself has no bidirectional controls: any in it came from a scanned file or
    # app (a title, a path, a quoted line) and could make that text read differently.
    return strip_bidi(html)
