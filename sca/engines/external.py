"""Adapters for well-known open-source scanners. Each adapter is optional: if the tool is
not installed the analyzer simply skips it and says so in the scan notes.

  * Bandit   - Python security linter (installed with requirements.txt)
  * Semgrep / Opengrep - multi-language pattern engine (optional, must be on PATH)
  * Gitleaks - secret scanner (optional, must be on PATH)

Every tool has a ``parse_*`` function (pure, easy to test) and a ``run_*`` function that
executes the tool and feeds its JSON output to the parser.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..cwe import canonical
from ..models import Finding
from ..walker import SKIP_DIRS
from ..walker import mask_secret as mask

TIMEOUT_SECONDS = 600

# Bandit reports a different CWE than our catalogue for a few checks; align them so that
# the same issue found by two engines is merged into one finding.
BANDIT_CWE_OVERRIDE = {
    "B201": "CWE-489", "B104": "CWE-605", "B311": "CWE-338", "B501": "CWE-295",
    "B506": "CWE-502", "B307": "CWE-95", "B102": "CWE-95", "B108": "CWE-377",
    "B306": "CWE-377", "B105": "CWE-798", "B106": "CWE-798", "B107": "CWE-798",
    "B602": "CWE-78", "B605": "CWE-78", "B701": "CWE-79", "B703": "CWE-79",
    "B324": "CWE-327", "B303": "CWE-327", "B304": "CWE-327", "B305": "CWE-327",
    "B103": "CWE-732", "B202": "CWE-22",
}
BANDIT_SKIP = "B101,B404,B403,B603,B607,B110,B112"  # informational checks that add noise
_LEVEL = {"LOW": 0.4, "MEDIUM": 0.6, "HIGH": 0.8}


def _rel(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix().lstrip("./")


def _read_line(root: Path, rel: str, line: int) -> str:
    try:
        with open(root / rel, "r", encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, start=1):
                if number == line:
                    return text.strip()
    except OSError:
        pass
    return ""


# ----------------------------------------------------------------------------- Bandit
def bandit_available() -> bool:
    return importlib.util.find_spec("bandit") is not None


def parse_bandit(data: Dict[str, Any], root: Path) -> List[Finding]:
    findings = []
    for item in data.get("results", []):
        test_id = item.get("test_id", "")
        cwe = BANDIT_CWE_OVERRIDE.get(test_id) or \
            canonical("CWE-%s" % (item.get("issue_cwe") or {}).get("id", ""))
        rel = _rel(item.get("filename", ""), root)
        line = int(item.get("line_number") or 1)
        code = _read_line(root, rel, line)
        severity = (item.get("issue_severity") or "MEDIUM").lower()
        if cwe in ("CWE-89", "CWE-78", "CWE-95", "CWE-502") and severity == "medium":
            severity = "high"
        findings.append(Finding(
            rule_id="BANDIT-%s" % test_id,
            title=(item.get("issue_text") or item.get("test_name") or "Bandit finding")[:140],
            file=rel, line=line, severity=severity, cwe=cwe,
            confidence=_LEVEL.get((item.get("issue_confidence") or "MEDIUM").upper(), 0.6),
            engines=["bandit"], snippet=code, language="python",
            end_line=max(item.get("line_range") or [line]),
        ))
    return findings


def run_bandit(root: Path) -> Tuple[List[Finding], str]:
    if not bandit_available():
        return [], "not installed (pip install bandit)"
    target = root if root.is_dir() else root.parent
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", "-s", BANDIT_SKIP,
           "-x", ",".join(sorted(str(target / d) for d in SKIP_DIRS))]
    cmd += ["-r", str(root)] if root.is_dir() else [str(root)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                              encoding="utf-8", errors="replace")
        data = json.loads(proc.stdout[proc.stdout.index("{"):])
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        return [], "failed: %s" % str(exc)[:200]
    findings = parse_bandit(data, target)
    return findings, "ok (%d results)" % len(findings)


# ------------------------------------------------------------------ Semgrep / Opengrep
def semgrep_binary() -> Optional[str]:
    return shutil.which("opengrep") or shutil.which("semgrep")


def parse_semgrep(data: Dict[str, Any], root: Path) -> List[Finding]:
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe_raw = meta.get("cwe") or ""
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        rel = _rel(item.get("path", ""), root)
        line = int((item.get("start") or {}).get("line") or 1)
        conf = {"LOW": 0.4, "MEDIUM": 0.6, "HIGH": 0.8}.get(
            str(meta.get("confidence", "MEDIUM")).upper(), 0.6)
        check_id = str(item.get("check_id", "semgrep"))
        message = " ".join(str(extra.get("message", "")).split())
        findings.append(Finding(
            rule_id="SEMGREP-%s" % check_id.split(".")[-1][:60],
            title=(message[:110] or check_id), description=message,
            file=rel, line=line, end_line=int((item.get("end") or {}).get("line") or line),
            severity=str(extra.get("severity", "WARNING")), cwe=canonical(str(cwe_raw)),
            confidence=conf, engines=["semgrep"], snippet=_read_line(root, rel, line),
        ))
    return findings


def run_semgrep(root: Path, config: str = "auto") -> Tuple[List[Finding], str]:
    binary = semgrep_binary()
    if not binary:
        return [], "not installed (optional: install Opengrep or Semgrep)"
    cmd = [binary, "scan", "--config", config, "--json", "--quiet", "--timeout", "30",
           str(root)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                              encoding="utf-8", errors="replace")
        data = json.loads(proc.stdout[proc.stdout.index("{"):])
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        return [], "failed: %s" % str(exc)[:200]
    target = root if root.is_dir() else root.parent
    findings = parse_semgrep(data, target)
    return findings, "ok (%d results, %s)" % (len(findings), Path(binary).name)


# --------------------------------------------------------------------------- Gitleaks
def gitleaks_binary() -> Optional[str]:
    return shutil.which("gitleaks")


def parse_gitleaks(data: List[Dict[str, Any]], root: Path) -> List[Finding]:
    findings = []
    for item in data or []:
        secret = item.get("Secret") or ""
        match = item.get("Match") or ""
        if secret:
            match = match.replace(secret, mask(secret))
        findings.append(Finding(
            rule_id="GITLEAKS-%s" % item.get("RuleID", "secret"),
            title=item.get("Description") or "Secret detected",
            file=_rel(item.get("File", ""), root), line=int(item.get("StartLine") or 1),
            severity="high", cwe="CWE-798", confidence=0.8, engines=["gitleaks"],
            snippet=match[:300],
        ))
    return findings


def run_gitleaks(root: Path) -> Tuple[List[Finding], str]:
    binary = gitleaks_binary()
    if not binary:
        return [], "not installed (optional)"
    target = root if root.is_dir() else root.parent
    fd, report = tempfile.mkstemp(suffix=".json", prefix="sca-gitleaks-")
    os.close(fd)
    try:
        cmd = [binary, "detect", "--source", str(target), "--no-git", "--report-format",
               "json", "--report-path", report, "--exit-code", "0", "--no-banner"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
                       encoding="utf-8", errors="replace")
        with open(report, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read().strip()
        data = json.loads(text) if text else []
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        return [], "failed: %s" % str(exc)[:200]
    finally:
        try:
            os.remove(report)
        except OSError:
            pass
    findings = parse_gitleaks(data, target)
    return findings, "ok (%d results)" % len(findings)


def availability() -> Dict[str, bool]:
    return {"bandit": bandit_available(), "semgrep": semgrep_binary() is not None,
            "gitleaks": gitleaks_binary() is not None}
