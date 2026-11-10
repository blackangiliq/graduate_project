"""Learning from the reviewer: every "real" / "false positive" verdict changes future scans.

1. The finding itself: a dismissed finding (same file, weakness and code) stays dismissed in
   later scans; a confirmed one is shown as confirmed.

2. The rule that produced it: each rule keeps a count of confirmed (tp) and dismissed (fp)
   findings. Its confidence becomes the mean of a Beta posterior whose prior is the
   confidence the rule was written with:

       confidence' = (tp + K * confidence) / (tp + fp + K)          K = 4

   With no reviews nothing changes. Each false positive pulls the confidence down, each
   confirmation pushes it up, and the written confidence counts like K earlier reviews.

3. Quarantine: a rule with at least 3 false positives whose adjusted confidence falls below
   0.35 is switched off. It is listed in the Learning tab and by `python -m sca rules stats`,
   and can be restored by clearing its feedback.

4. The ML classifier is retrained with the reviewed code lines (see ai/classifier.py).
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple

from ..models import Finding

PRIOR_STRENGTH = 4.0
QUARANTINE_MIN_FP = 3
QUARANTINE_BELOW = 0.35


def adjusted_confidence(confidence: float, tp: int, fp: int) -> float:
    return (tp + PRIOR_STRENGTH * confidence) / (tp + fp + PRIOR_STRENGTH)


def is_quarantined(confidence: float, tp: int, fp: int) -> bool:
    return fp >= QUARANTINE_MIN_FP and adjusted_confidence(confidence, tp, fp) < QUARANTINE_BELOW


def quarantined_rules(stats: Dict[str, Dict[str, int]],
                      confidences: Dict[str, float]) -> Set[str]:
    """Rule ids that are switched off. ``confidences`` maps rule id -> written confidence."""
    return {rule_id for rule_id, s in stats.items()
            if is_quarantined(confidences.get(rule_id, 0.6), s["tp"], s["fp"])}


def apply_rule_stats(findings: Iterable[Finding], stats: Dict[str, Dict[str, int]]
                     ) -> Tuple[List[Finding], List[str]]:
    """Adjust the confidence of raw findings by their rule's track record and drop the
    findings of quarantined rules. Returns (kept findings, quarantined rule ids seen)."""
    kept: List[Finding] = []
    dropped: Set[str] = set()
    for finding in findings:
        entry = stats.get(finding.rule_id)
        if entry:
            if is_quarantined(finding.confidence, entry["tp"], entry["fp"]):
                dropped.add(finding.rule_id)
                continue
            finding.confidence = adjusted_confidence(finding.confidence, entry["tp"],
                                                     entry["fp"])
        kept.append(finding)
    return kept, sorted(dropped)


def apply_verdicts(findings: Iterable[Finding], verdicts: Dict[str, str]) -> Tuple[int, int]:
    """Apply earlier reviewer verdicts to merged findings. Returns (dismissed, confirmed)."""
    dismissed = confirmed = 0
    for finding in findings:
        verdict = verdicts.get(finding.fingerprint)
        if verdict == "fp":
            finding.status = "dismissed"
            finding.user_verdict = "false_positive"
            dismissed += 1
        elif verdict == "tp":
            finding.user_verdict = "true_positive"
            finding.confidence = max(finding.confidence, 0.97)
            confirmed += 1
    return dismissed, confirmed
