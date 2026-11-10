"""Security assessment: a risk score per finding and a 0-100 score for the whole project.

Per finding (0-10, same range as CVSS but NOT an official CVSS score):
    risk = base(severity) * (0.6 + 0.4 * confidence)

Per project:
    penalty = sum(weight(severity) * confidence) over open findings
    density = penalty / KLOC              (KLOC = thousands of lines, at least 0.5)
    score   = 100 * exp(-density / 25)    -> 100 = nothing found, 0 = very poor

Dividing by code size makes projects of different sizes comparable; the exponential keeps
the score inside 0-100 and makes the first serious findings cost the most.
"""
from __future__ import annotations

import math
from typing import Iterable, List, Tuple

from .models import Finding

BASE_RISK = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}
PENALTY = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}
GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
FP_THRESHOLD = 0.6  # LLM confidence needed to mark a finding as a likely false positive
AI_CONFIRM = 0.7           # LLM confidence needed to confirm a finding
CONFIRM_CONFIDENCE = 0.85  # a single engine this sure of itself counts as confirmed


def apply_ai_verdict(finding: Finding) -> None:
    """Fold the AI opinions into confidence and status. The static result is never deleted:
    a finding judged false by the LLM is kept and labelled so a human can review it."""
    if finding.ml_score is not None and finding.user_verdict != "true_positive":
        # the ML score is a second opinion worth 25% of the final confidence
        finding.confidence = 0.75 * finding.confidence + 0.25 * finding.ml_score
    verdict = finding.ai_verdict
    ai_conf = finding.ai_confidence if finding.ai_confidence is not None else 0.7
    if verdict == "true_positive":
        finding.confidence = max(finding.confidence, min(0.97, 0.5 + 0.5 * ai_conf))
    elif verdict == "false_positive":
        finding.confidence *= (1.0 - 0.7 * ai_conf)
        if ai_conf >= FP_THRESHOLD and finding.status == "open" \
                and finding.user_verdict != "true_positive":
            finding.status = "likely_false_positive"
    finding.confidence = round(max(0.0, min(1.0, finding.confidence)), 3)


def risk_score(finding: Finding) -> float:
    return round(BASE_RISK[finding.severity] * (0.6 + 0.4 * finding.confidence), 1)


def grade_for(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "F"


def project_score(findings: Iterable[Finding], lines_of_code: int) -> Tuple[int, str]:
    penalty = sum(PENALTY[f.severity] * f.confidence for f in findings if f.status == "open")
    kloc = max(lines_of_code / 1000.0, 0.5)
    score = int(round(100.0 * math.exp(-(penalty / kloc) / 25.0)))
    score = max(0, min(100, score))
    return score, grade_for(score)


def assign_tier(finding: Finding) -> None:
    """Decide whether a finding is CONFIRMED (independent evidence supports it) or only
    PROBABLE (one rule matched and nothing else backs it up).

    Evidence that confirms a finding:
      * the reviewer confirmed it,
      * the AI review judged it real with confidence >= 0.7,
      * two or more independent static engines reported it,
      * user input was traced to the line (taint analysis),
      * a single engine with confidence >= 0.85 (for example a known key format).
    A finding the AI review judged false is never confirmed unless the reviewer says so.
    A finding that only the LLM reported is confirmed only by its second (verification) pass.
    """
    # built-in and learned pattern rules are one family: two regex rules are not independent
    static = sorted({"rules" if e == "learned" else e for e in finding.engines if e != "llm"})
    evidence: List[str] = []
    if finding.user_verdict == "true_positive":
        evidence.append("confirmed by the reviewer")
    if finding.ai_verdict == "true_positive" and (finding.ai_confidence or 0) >= AI_CONFIRM:
        evidence.append("confirmed by the AI review")
    if len(static) >= 2:
        evidence.append("%d independent engines agree" % len(static))
    if finding.tainted:
        evidence.append("user input was traced to this line")
    if static and finding.confidence >= CONFIRM_CONFIDENCE:
        evidence.append("high-confidence rule")
    contradicted = finding.ai_verdict == "false_positive" and \
        finding.user_verdict != "true_positive"
    finding.evidence = evidence
    finding.tier = "confirmed" if evidence and not contradicted else "probable"


def score_all(findings: List[Finding], lines_of_code: int, strict: bool = False
              ) -> Tuple[int, str]:
    """Final confidence, tier, risk and status of every finding, then the project score.

    In strict mode only confirmed findings stay "open" (and count in the score); the others
    are moved to "needs_review". Nothing is deleted."""
    for finding in findings:
        apply_ai_verdict(finding)
        assign_tier(finding)
        finding.risk_score = risk_score(finding)
        if strict and finding.status == "open" and finding.tier != "confirmed":
            finding.status = "needs_review"
    return project_score(findings, lines_of_code)
