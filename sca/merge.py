"""Merges the findings of all engines.

Two findings are the same issue when they are in the same file, describe the same weakness
(CWE) and are at most one line apart. Merging:
  * keeps the highest severity,
  * records every engine that reported it,
  * combines confidences with a "noisy-OR": 1 - (1-c1)(1-c2)...  - independent engines that
    agree make the finding more credible.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from .cwe import canonical, info
from .models import Finding, SEVERITY_RANK

LINE_TOLERANCE = 1
MAX_CONFIDENCE = 0.97
SUPPRESS_MARKERS = ("nosec", "sca:ignore", "nosemgrep")


def is_suppressed(finding: Finding) -> bool:
    lowered = finding.snippet.lower()
    return any(marker in lowered for marker in SUPPRESS_MARKERS)


def _key(finding: Finding) -> Tuple[str, str]:
    return finding.file, canonical(finding.cwe) or finding.rule_id


def merge_findings(findings: Iterable[Finding], lang: str = "en") -> List[Finding]:
    groups: Dict[Tuple[str, str], List[Finding]] = {}
    for finding in findings:
        if is_suppressed(finding):
            continue
        finding.cwe = canonical(finding.cwe)
        groups.setdefault(_key(finding), []).append(finding)

    merged: List[Finding] = []
    for group in groups.values():
        group.sort(key=lambda f: (f.line, -f.confidence))
        clusters: List[List[Finding]] = []
        for finding in group:
            last = clusters[-1] if clusters else None
            if last and finding.line - max(f.end_line for f in last) <= LINE_TOLERANCE \
                    and finding.line - last[0].line <= 12 \
                    and not _same_engine_other_line(last, finding):
                last.append(finding)
            else:
                clusters.append([finding])
        merged.extend(_combine(cluster) for cluster in clusters)

    for finding in merged:
        kb = info(finding.cwe, lang)
        finding.owasp = kb["owasp"]
        if not finding.description:
            finding.description = kb["description"]
        if not finding.fix:
            finding.fix = kb["fix"]
    merged.sort(key=lambda f: (-SEVERITY_RANK[f.severity], -f.confidence, f.file, f.line))
    return merged


def _same_engine_other_line(cluster: List[Finding], finding: Finding) -> bool:
    """One engine reporting two different lines means two separate issues (for example two
    hard-coded secrets on consecutive lines), so they must not be merged."""
    return any(f.line != finding.line and set(f.engines) & set(finding.engines)
               for f in cluster)


def _combine(cluster: List[Finding]) -> Finding:
    # prefer our own engines for wording (they have the knowledge-base text), then confidence
    order = {"ast": 0, "rules": 1, "secrets": 1, "learned": 1}
    best = min(cluster, key=lambda f: (order.get(f.engines[0], 2), -f.confidence))
    if len(cluster) == 1:
        return best
    rule_ids: List[str] = []
    for finding in cluster:
        for rule_id in finding.rule_ids:
            if rule_id not in rule_ids:
                rule_ids.append(rule_id)
    best.rule_ids = rule_ids
    engines: List[str] = []
    per_engine: Dict[str, float] = {}
    for finding in cluster:
        for engine in finding.engines:
            if engine not in engines:
                engines.append(engine)
            per_engine[engine] = max(per_engine.get(engine, 0.0), finding.confidence)
    miss = 1.0
    for value in per_engine.values():
        miss *= (1.0 - value)
    best.engines = engines
    best.confidence = min(MAX_CONFIDENCE, 1.0 - miss)
    best.severity = max((f.severity for f in cluster), key=lambda s: SEVERITY_RANK[s])
    best.tainted = any(f.tainted for f in cluster)
    best.end_line = max(f.end_line for f in cluster)
    if not best.snippet:
        best.snippet = next((f.snippet for f in cluster if f.snippet), "")
    return best
