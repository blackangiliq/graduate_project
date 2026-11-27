"""Original evidence for the dashboard and its exports, separate from analysis data.

The pipeline's findings keep their existing identity and model inputs. A fresh scan's
source snapshots provide the literal evidence for display. Legacy archived scans
without those snapshots need rescanning to recover their original values.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import fields

from .models import Finding, ScanResult
from .sourceview import marked_window


def finding_focus(result: ScanResult, finding: Finding) -> str:
    # Exact detector coordinates take precedence over other keys on the same line.
    if getattr(finding, "column", 0) > 0:
        return ""
    for key in (getattr(result, "visible_apis", None) or {}).get("keys", ()):
        if any(location.get("file") == finding.file and location.get("line") == finding.line
               for location in key.get("locations", ())):
            if key.get("rule_id") in finding.rule_ids or key.get("rule_id") == finding.rule_id:
                return str(key.get("value") or "")
    return ""


def finding_text(result: ScanResult, finding: Finding, *, context: bool = True) -> str:
    """Read the exact scanned line or its surrounding lines, with stored-text fallback."""
    file = result.decoded_files.get(finding.file)
    if file is None or not 1 <= finding.line <= len(file.lines):
        return (finding.context or finding.snippet) if context else finding.snippet
    def displayed(number):
        return marked_window(file.lines[number - 1],
                             column=getattr(finding, "column", 0) if number == finding.line else 0,
                             end_column=getattr(finding, "end_column", 0) if number == finding.line else 0,
                             focus=finding_focus(result, finding) if number == finding.line else "")
    if not context:
        return displayed(finding.line)
    first, last = max(1, finding.line - 3), min(len(file.lines), finding.line + 3)
    return "\n".join("%4d | %s" % (number, displayed(number))
                     for number in range(first, last + 1))


class _PresentationFinding(Finding):
    """A report copy whose identity still names the original analyzed finding."""

    def __init__(self, original: Finding, snippet: str, context: str) -> None:
        super().__init__(**{field.name: deepcopy(getattr(original, field.name, field.default))
                            for field in fields(Finding) if field.init})
        # Not a dataclass field: asdict/to_dict must not serialize this implementation detail.
        self._source_fingerprint = original.fingerprint
        self.snippet, self.context = snippet, context

    @property
    def fingerprint(self) -> str:
        return self._source_fingerprint


def view_result(result: ScanResult) -> ScanResult:
    """Create an independent export view with available original evidence and API values.

    Never pass this presentation copy to model review or history storage. The original
    result remains unchanged, including its fingerprints and previously masked reports.
    Source snapshots themselves are not included in the exported result.
    """
    session_fields = {"decoded_files", "credential_evidence", "visible_apis", "findings", "steps"}
    view = ScanResult(**{field.name: deepcopy(getattr(result, field.name))
                         for field in fields(ScanResult) if field.name not in session_fields})
    # Progress Message is an immutable str subclass with a multi-argument constructor;
    # deepcopy cannot recreate it. Reports need its rendered text, not translation metadata.
    view.steps = [str(step) for step in result.steps]
    view.findings = [_PresentationFinding(finding,
                                          finding_text(result, finding, context=False),
                                          finding_text(result, finding))
                     for finding in result.findings]
    visible_apis = getattr(result, "visible_apis", None)
    if visible_apis:
        view.app["apis"] = deepcopy(visible_apis)
    view._original_text_visible = bool(result.decoded_files)
    return view
