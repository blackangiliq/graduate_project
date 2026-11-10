"""SARIF 2.1.0 export. SARIF is the standard exchange format for static analysis results;
GitHub code scanning, VS Code and most security dashboards can read it."""
from __future__ import annotations

from typing import Any, Dict

from .. import __version__
from ..cwe import info
from ..models import ScanResult

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note",
         "info": "note"}


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
                                        if t],
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
                    "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
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
            },
        }
        if finding.status != "open":
            entry["suppressions"] = [{"kind": "external",
                                      "justification": "Judged a likely false positive by "
                                                       "the AI review"}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
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
        }],
    }
