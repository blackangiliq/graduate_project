"""Data models shared by every part of the analyzer."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(value: str) -> str:
    value = (value or "").strip().lower()
    aliases = {"error": "high", "warning": "medium", "warn": "medium", "note": "low",
               "informational": "info", "moderate": "medium"}
    value = aliases.get(value, value)
    return value if value in SEVERITY_RANK else "medium"


@dataclass
class Finding:
    """One potential vulnerability at one location."""

    rule_id: str
    title: str
    file: str                      # path relative to the scanned folder, with "/" separators
    line: int
    severity: str = "medium"
    cwe: str = ""                  # e.g. "CWE-89"
    description: str = ""
    fix: str = ""
    confidence: float = 0.6        # 0..1, how sure the analyzer is that this is real
    engines: List[str] = field(default_factory=list)
    end_line: int = 0
    snippet: str = ""              # the flagged line
    context: str = ""              # a few lines around it
    language: str = ""
    owasp: str = ""
    tainted: bool = False          # user-controlled data was traced to the sink
    rule_ids: List[str] = field(default_factory=list)   # every rule that reported this issue
    evidence: List[str] = field(default_factory=list)   # reasons the finding counts as confirmed
    tier: str = ""                 # confirmed | probable
    user_verdict: str = ""         # true_positive | false_positive (set by the reviewer)
    # --- filled by the AI layer ---
    ml_score: Optional[float] = None
    ai_verdict: str = ""           # true_positive | false_positive | uncertain | ""
    ai_confidence: Optional[float] = None
    ai_explanation: str = ""
    ai_fix: str = ""
    ai_model: str = ""
    # --- filled by scoring ---
    risk_score: float = 0.0        # 0..10
    # open                  counted in the score
    # needs_review          strict mode: not confirmed by independent evidence
    # likely_false_positive judged false by the AI review
    # dismissed             marked false positive by the reviewer
    status: str = "open"

    def __post_init__(self) -> None:
        if not self.rule_ids:
            self.rule_ids = [self.rule_id]
        self.severity = normalize_severity(self.severity)
        self.file = self.file.replace("\\", "/")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.end_line:
            self.end_line = self.line

    @property
    def fingerprint(self) -> str:
        """Stable id: same file + CWE/rule + code text gives the same fingerprint
        even if the line number shifts between scans."""
        key = "|".join([self.file, self.cwe or self.rule_id, " ".join(self.snippet.split())])
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        names = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in names})


@dataclass
class ScanResult:
    target: str
    started_at: str = ""
    duration_seconds: float = 0.0
    files_scanned: int = 0
    lines_scanned: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    engines_used: List[str] = field(default_factory=list)
    engine_notes: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    ai: Dict[str, Any] = field(default_factory=dict)
    scan_id: Optional[int] = None

    @property
    def open_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == "open"]

    def status_count(self, status: str) -> int:
        return sum(1 for f in self.findings if f.status == status)

    def counts(self, only_open: bool = True) -> Dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in (self.open_findings if only_open else self.findings):
            out[f.severity] += 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "Secure Code Analyzer",
            "target": self.target,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "languages": self.languages,
            "engines_used": self.engines_used,
            "engine_notes": self.engine_notes,
            "score": self.score,
            "grade": self.grade,
            "summary": self.counts(),
            "needs_review": self.status_count("needs_review"),
            "likely_false_positives": self.status_count("likely_false_positive"),
            "dismissed": self.status_count("dismissed"),
            "ai": self.ai,
            "findings": [f.to_dict() for f in self.findings],
        }
