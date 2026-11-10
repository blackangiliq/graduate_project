"""Taint-lite: a lightweight data-flow check for languages that have no AST engine.

The pattern rules look at one line. This module adds context: for a finding of an
injection-type rule it looks at the lines above it and asks whether a variable used on the
flagged line was assigned from user input.

    $name = $_POST['name'];                              <- source: $name becomes tainted
    $sql  = "SELECT * FROM users WHERE name = '$name'";  <- flagged line uses $name => traced

When the flow is traced the finding is marked ``tainted`` and its confidence rises. Nothing
is ever removed here: an untraced finding simply stays at its rule confidence.

It is a heuristic, not a real data-flow analysis: it works inside one file, looks at most
60 lines back, follows simple assignments, and knows a fixed list of sources and sanitizers.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Set

from ..cwe import FLOW_CWES, canonical
from ..models import Finding
from ..walker import SourceFile

WINDOW = 60
BOOST = 0.15

# weaknesses where "does user input reach this line?" is the right question
TAINT_CWES = FLOW_CWES

SOURCES: Dict[str, "re.Pattern[str]"] = {
    "javascript": re.compile(
        r"\breq(uest)?\.(query|params|body|headers|cookies)\b|\blocation\.(search|hash|href)\b"
        r"|\bdocument\.(URL|cookie|referrer)\b|\bURLSearchParams\b|\bprocess\.argv\b"),
    "php": re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|php://input"),
    "java": re.compile(
        r"\.getParameter(Values|Map)?\s*\(|\.getHeader\s*\(|\.getCookies\s*\(|\.getQueryString\s*\("
        r"|@RequestParam|@PathVariable|@RequestBody|\.getInputStream\s*\("),
    "go": re.compile(r"\.(FormValue|PostFormValue)\s*\(|\.URL\.Query\(\)|mux\.Vars\(|\bos\.Args\b"),
    "csharp": re.compile(r"\bRequest\.(QueryString|Form|Params|Cookies|Headers|Query)\b|\bRequest\["),
    "ruby": re.compile(r"\bparams\[|\brequest\.(params|body|headers)\b|\bcookies\["),
    "c": re.compile(r"\bargv\b|\bgetenv\s*\("),
}
SANITIZERS = re.compile(
    r"htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd|intval|\(int\)|parseInt"
    r"|parseFloat|Number\(|encodeURIComponent|escapeHtml|sanitize|basename|Integer\.parseInt"
    r"|Long\.parseLong|strconv\.Atoi|filepath\.Base|\.to_i\b|Convert\.ToInt|int\.Parse"
    r"|DOMPurify|Encode\.for|HtmlEncode|GetFileName|prepare\(", re.IGNORECASE)
SOURCE_BASE = re.compile(
    r"^\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)$"
    r"|(^|\.)(query|params|body|headers|cookies|args|form|argv|QueryString|Form|Params|Cookies)$"
    r"|^Request$")
IDENT = re.compile(r"\$?[A-Za-z_]\w*")
ASSIGN = re.compile(
    r"((?:\$?[A-Za-z_]\w*\s*,\s*)*\$?[A-Za-z_]\w*)\s*(?::=|\+=|\.=|=)(?![=>~])\s*(.+)")
DESTRUCTURE = re.compile(r"\{\s*([\w\s,:$]+)\}\s*=(?!=)\s*(.+)")
KEYWORDS = {"if", "else", "for", "while", "return", "const", "let", "var", "new", "function",
            "echo", "print", "true", "false", "null", "nil", "this", "self", "String", "int",
            "char", "void", "public", "private", "static", "final", "await", "async"}


def strip_lookups(text: str) -> str:
    """Blank the content of ``table[...]`` when ``table`` is not itself a request object.

    ``$pages[$_GET['page']]`` reads a value from a fixed table: the result is chosen by the
    user but not written by the user, so it is not treated as user input."""
    out: List[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "[":
            base = re.search(r"(\$?[\w.]+)$", "".join(out))
            depth, j = 1, i + 1
            while j < len(text) and depth:
                depth += {"[": 1, "]": -1}.get(text[j], 0)
                j += 1
            if base and not SOURCE_BASE.search(base.group(1)) and depth == 0:
                out.append("[]")
                i = j
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _idents(text: str) -> Set[str]:
    return {m.group(0) for m in IDENT.finditer(text)} - KEYWORDS


def tainted_names(sf: SourceFile, line: int, source: "re.Pattern[str]") -> Set[str]:
    """Names assigned (directly or through other names) from a source in the lines above."""
    tainted: Set[str] = set()
    for number in range(max(1, line - WINDOW), line):
        if sf.is_comment(number):
            continue
        text = sf.lines[number - 1]
        match = DESTRUCTURE.search(text)
        if match:
            names = [n.split(":")[-1].strip() for n in match.group(1).split(",")]
        else:
            match = ASSIGN.search(text)
            if not match:
                continue
            names = [n.strip() for n in match.group(1).split(",")]
        rhs = strip_lookups(match.group(2))
        if SANITIZERS.search(rhs):
            tainted.difference_update(names)      # re-assigned from a sanitized value
            continue
        if source.search(rhs) or (_idents(rhs) & tainted):
            tainted.update(n for n in names if n and n not in KEYWORDS)
    return tainted


def is_traced(sf: SourceFile, line: int) -> bool:
    source = SOURCES.get(sf.rule_language)
    if source is None or not 1 <= line <= len(sf.lines):
        return False
    text = sf.lines[line - 1]
    if SANITIZERS.search(text):
        return False
    stripped = strip_lookups(text)
    if source.search(stripped):
        return True
    return bool(_idents(stripped) & tainted_names(sf, line, source))


def apply(findings: Iterable[Finding], by_rel: Dict[str, SourceFile]) -> int:
    """Mark pattern findings whose input can be traced. Returns how many were traced."""
    traced = 0
    for finding in findings:
        if finding.tainted or not set(finding.engines) & {"rules", "learned"}:
            continue
        if canonical(finding.cwe) not in TAINT_CWES:
            continue
        sf = by_rel.get(finding.file)
        if sf is None or not is_traced(sf, finding.line):
            continue
        finding.tainted = True
        finding.confidence = min(0.95, finding.confidence + BOOST)
        traced += 1
    return traced
