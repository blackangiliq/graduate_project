"""Bounded literal extraction for typed/multiline assignments and config files.

No expression evaluation or decoding is performed. Every returned value is an exact
substring of the source, with the coordinates of the value (not the field name).
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re


MAX_LITERAL = 16384
_NAME = r"[A-Za-z_][A-Za-z0-9_.-]{0,127}"
_SPACE = r"[ \t]{0,128}(?:\r?\n[ \t]{0,128}){0,3}"
_SENSITIVE = re.compile(
    r"passw(?:or)?d|passwd|pwd|secret|api[_.-]?key|token|auth[_.-]?key|"
    r"access[_.-]?key|private[_.-]?key|credential", re.I)
_QUOTED = re.compile(
    r"(?<![\w.-])(?P<name>" + _NAME + r")[\"']?"
    r"(?:[ \t]{0,32}:[ \t]{0,32}(?:String|string)\??)?"
    r"[ \t]{0,32}(?:=>|:=|=|:)" + _SPACE +
    r"(?P<quote>[\"'`])(?P<value>[^\"'`\r\n\\]{4," + str(MAX_LITERAL) + r"})(?P=quote)")
_UNQUOTED = re.compile(
    r"^[ \t]*(?P<name>" + _NAME + r")[ \t]*(?:=|:)[ \t]*"
    r"(?P<value>[^\r\n]{4," + str(MAX_LITERAL) + r"})\r?$", re.M)
_CONFIG_SUFFIXES = {".yaml", ".yml", ".toml", ".properties", ".ini", ".cfg", ".conf"}
_STRINGS = re.compile(r'''"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\.|[^`\\])*`''')


@dataclass(frozen=True)
class Literal:
    name: str
    value: str
    line: int
    column: int


def quoted_spans(text):
    spans = [item.span() for item in _STRINGS.finditer(text)]
    return spans, [first for first, _ in spans]


def field_head(start, end, quoted):
    """A key may itself be quoted, but prose inside a string is not a field head."""
    spans, starts = quoted
    enclosing = bisect_right(starts, start) - 1
    if enclosing < 0:
        return True
    first, last = spans[enclosing]
    return not first <= start < last or (start in {first, first + 1} and end in {last, last - 1})


def _unquoted_value(raw: str, suffix: str) -> str | None:
    """Keep the complete source scalar, without inventing shared comment syntax.

    Properties comments only start whole lines; '#' and ';' in a value are data,
    including after spaces. YAML starts an inline comment with whitespace plus '#'.
    INI-like formats have differing inline-comment policies, so only a single token
    is accepted here rather than guessing whether a trailing comment is part of it.
    TOML strings must be quoted and are handled by the quoted detector instead.
    Escapes/continuations and YAML aliases, tags and flow containers are unsupported.
    """
    if not raw or raw[0] in "\"'`" or "\\" in raw or suffix == ".toml":
        return None
    if suffix == ".properties":
        return raw
    if suffix in {".yaml", ".yml"}:
        if raw[0] in "[{&*!|>%@#" or re.search(r":[ \t]", raw):
            return None
        comment = re.search(r"[ \t]+#", raw)
        value = raw[:comment.start()] if comment else raw
        return value.rstrip(" \t")
    value = raw.rstrip(" \t")
    return value if not re.search(r"\s", value) else None


def candidates(text: str, rel: str):
    """Yield complete literal candidates; the caller applies credential heuristics.

    Deliberately excludes escaped strings, interpolated strings and concatenations:
    presenting one fragment as the complete credential would give a false value.
    """
    if not _SENSITIVE.search(text):
        return
    starts = [0] + [match.end() for match in re.finditer("\n", text)]
    patterns = [_QUOTED]
    suffix = Path(rel).suffix.lower()
    if suffix in _CONFIG_SUFFIXES:
        patterns.append(_UNQUOTED)
    seen = set()
    quoted = None
    for pattern in patterns:
        for match in pattern.finditer(text):
            name, value = match.group("name"), match.group("value")
            if pattern is _UNQUOTED:
                value = _unquoted_value(value, suffix)
                if value is None or len(value) < 4:
                    continue
            if not _SENSITIVE.search(name) or "$" in value or "#{" in value:
                continue
            if pattern is _QUOTED:
                if quoted is None:
                    quoted = quoted_spans(text)
                if not field_head(match.start(), match.end("name"), quoted):
                    continue
                before = text[match.start() - 1:match.start()] if match.start() else ""
                if before in {"'", '"', "`"} and text[match.end("name"):match.end("name") + 1] != before:
                    continue  # console.log('TOKEN:', value) is a label, not an assignment
                tail = text[match.end():match.end() + 256].lstrip()
                if tail.startswith(("+", ".", "'", '"', "`")):
                    continue
            at = match.start("value")
            if at in seen:
                continue
            seen.add(at)
            number = bisect_right(starts, at)
            yield Literal(name, value, number, at - starts[number - 1] + 1)
