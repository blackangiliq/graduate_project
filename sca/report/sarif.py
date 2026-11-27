"""SARIF 2.1.0 export. SARIF is the standard exchange format for static analysis results;
GitHub code scanning, VS Code and most security dashboards can read it.

File locations are relative URIs under %SRCROOT% (the scanned folder). For an app package
they name the virtual files decoded from it (AndroidManifest.xml, lib/arm64-v8a/libapp.so,
_sca/build.txt ...), and %SRCROOT% is described as the package."""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from .. import __version__
from ..cwe import info, mobile_name
from ..models import Finding, ScanResult
from ..walker import strip_bidi

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
         "info": "note"}
APP_KINDS = ("apk", "aab", "apks")
# the app facts copied into the run's properties
APP_PROPERTIES = ("kind", "name", "package", "version_name", "version_code", "sha256",
                  "flutter", "build_mode", "min_sdk", "target_sdk")


def file_uri(path: str) -> str:
    """A relative path as a URI reference: separators kept, everything else that is not an
    unreserved character percent-encoded (spaces, '#', '%', ':' and non-ASCII letters)."""
    return quote(path.replace("\\", "/"), safe="/-._~!$&'()*+,;=@")


def mobile_tags(finding: Finding) -> List[str]:
    """OWASP Mobile Top 10 (2024) and MASVS tags, e.g. "M5:2024 Insecure Communication" and
    "MASVS-NETWORK"; empty for findings without a mobile class."""
    tags = []
    if finding.owasp_mobile:
        tags.append("%s:2024 %s" % (finding.owasp_mobile, mobile_name(finding.owasp_mobile)))
    if finding.masvs:
        tags.append(finding.masvs)
    return tags


def to_sarif(result: ScanResult) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for finding in result.findings:
        if finding.rule_id not in rules:
            kb = info(finding.cwe)
            rule: Dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", "_"),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "help": {"text": finding.fix or "Review this code."},
                "properties": {"tags": [t for t in ("security", finding.cwe, finding.owasp)
                                        if t] + mobile_tags(finding),
                               "security-severity": "%.1f" % finding.risk_score},
            }
            if kb["url"]:
                rule["helpUri"] = kb["url"]
            rules[finding.rule_id] = rule
        message = finding.title
        if finding.ai_explanation:
            message += " | AI review: " + finding.ai_explanation
        entry: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": LEVEL[finding.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri(finding.file),
                                         "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, finding.line),
                               "endLine": max(finding.line, finding.end_line, 1),
                               "snippet": {"text": finding.snippet}},
                }
            }],
            "partialFingerprints": {"scaFingerprint/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity, "confidence": finding.confidence,
                "cwe": finding.cwe, "owasp": finding.owasp, "engines": finding.engines,
                "riskScore": finding.risk_score, "status": finding.status,
                "aiVerdict": finding.ai_verdict, "mlScore": finding.ml_score,
                "tier": finding.tier, "evidence": finding.evidence,
                "reviewerVerdict": finding.user_verdict,
            },
        }
        if getattr(finding, "column", 0) > 0:
            region = entry["locations"][0]["physicalLocation"]["region"]
            region["startColumn"] = finding.column
            if finding.end_line == finding.line and finding.end_column > finding.column:
                region["endColumn"] = finding.end_column
        if result.app:
            entry["properties"].update(owaspMobile=finding.owasp_mobile, masvs=finding.masvs)
            if finding.owasp_mobile or finding.masvs:
                entry["properties"]["tags"] = mobile_tags(finding)
        if finding.status != "open":
            entry["suppressions"] = [{"kind": "external",
                                      "justification": finding.status.replace("_", " ")}]
        results.append(entry)
    run: Dict[str, Any] = {
        "tool": {"driver": {
            "name": "Secure Code Analyzer",
            "version": __version__,
            "informationUri": "https://github.com/blackangiliq/graduate_project",
            "rules": list(rules.values()),
        }},
        "results": results,
        "properties": {"score": result.score, "grade": result.grade,
                       "filesScanned": result.files_scanned,
                       "linesScanned": result.lines_scanned},
    }
    if result.app:
        run["properties"]["app"] = {key: result.app[key] for key in APP_PROPERTIES
                                    if key in result.app}
        apis = result.app.get("apis")
        if isinstance(apis, dict):      # the API and key inventory: counts and alerts
            run["properties"]["apiInventory"] = {
                "summary": apis.get("summary") or {},
                "alerts": [{"level": a.get("level"), "text": a.get("text")}
                           for a in apis.get("alerts") or [] if isinstance(a, dict)],
                "truncated": apis.get("truncated") or {}}
        if result.app.get("kind") in APP_KINDS:
            run["originalUriBaseIds"] = {"%SRCROOT%": {"description": {
                "text": "The files decoded from the app package %s; they are not on disk."
                        % result.app.get("name", "")}}}
    return _without_bidi({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    })


def _without_bidi(value: Any) -> Any:
    """value with the Unicode bidirectional controls removed from every text: they can only
    come from a scanned file or app (a title, a quoted line), where they could make the text
    read differently in a viewer. URIs are percent-encoded, so they keep the exact name."""
    if isinstance(value, str):
        return strip_bidi(value)
    if isinstance(value, dict):
        return {key: _without_bidi(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_without_bidi(item) for item in value]
    return value
