"""Original source snapshots and local comparisons for scanned files."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from stat import S_ISREG
from typing import Sequence

from .engines.secrets import KNOWN_FORMATS
from .walker import MAX_FILE_BYTES, SourceFile

# Match the APK loader's 64 MiB text budget, with room for its small summaries.
# Real multi-DEX apps routinely exceed 240k short strings; the previous line cap
# hid otherwise detected locations even when only a few MiB had been retained.
MAX_PREVIEW_CHARS = 72 << 20
MAX_PREVIEW_LINES = 2_000_000
GOOGLE_KEY_RULE = "SECRET-GOOGLE-001"
_GOOGLE_KEY = re.compile(next(pattern for rule, _, pattern, *_ in KNOWN_FORMATS
                              if rule == GOOGLE_KEY_RULE))
_PACKAGED_MANIFEST = re.compile(r"(?:splits/[^/]+\.apk/)?AndroidManifest\.xml")


@dataclass(frozen=True)
class OriginalSource:
    """A reference to the original text selected on disk, kept only for this scan."""

    path: Path
    digest: bytes = field(repr=False)

    def read_lines(self) -> list[str] | None:
        try:
            if self.path.resolve(strict=True) != self.path:
                return None
            if not S_ISREG(self.path.stat().st_mode):
                return None
            with self.path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        except (OSError, RuntimeError):
            return None
        if len(data) > MAX_FILE_BYTES:
            return None
        text = data.decode("utf-8", errors="replace")
        if hashlib.sha256(text.encode("utf-8")).digest() != self.digest:
            return None
        return text.splitlines()


def _original_source(source: SourceFile, root: Path | None) -> OriginalSource | None:
    if root is None or source.origin or str(root).startswith("\\\\"):
        return None
    relative = PureWindowsPath(source.rel)
    if relative.anchor or ".." in relative.parts or ":" in source.rel:
        return None
    path = root / source.rel
    if path != source.path or not path.is_absolute():
        return None
    return OriginalSource(path, hashlib.sha256(source.text.encode("utf-8")).digest())


@dataclass(frozen=True)
class DecodedFile:
    language: str
    origin: str
    source_line_count: int
    lines: tuple[str, ...] = field(repr=False)
    original: OriginalSource | None = field(default=None, repr=False)
    derivation: dict = field(default_factory=dict)


def validate_derivation(value) -> dict:
    """Accept only the bounded provenance contract, including safe relative paths."""
    if not isinstance(value, dict):
        raise ValueError("Invalid decoded-literal provenance")
    if not value:
        return {}
    expected = {"encoding", "depth", "source_file", "source_line", "source_column",
                "source_end_column", "encoded_sha256", "decoded_sha256"}
    if set(value) != expected or value["encoding"] != "base64" or type(value["depth"]) is not int or value["depth"] not in (1, 2):
        raise ValueError("Invalid decoded-literal provenance")
    path = value["source_file"]
    if (not isinstance(path, str) or not 1 <= len(path) <= 1024
            or PureWindowsPath(path).anchor or ":" in path
            or any(part in ("", ".", "..") for part in path.replace("\\", "/").split("/"))
            or re.search(r"[\x00-\x1f\x7f]", path)):
        raise ValueError("Invalid encoded-source location")
    for name in ("source_line", "source_column", "source_end_column"):
        if type(value[name]) is not int or not 1 <= value[name] <= (1 << 31) - 1:
            raise ValueError("Invalid encoded-source coordinates")
    if value["source_end_column"] <= value["source_column"]:
        raise ValueError("Invalid encoded-source span")
    for name in ("encoded_sha256", "decoded_sha256"):
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{64}", value[name]):
            raise ValueError("Invalid decoded-literal digest")
    return dict(value)


class CredentialEvidence:
    """Compare an owner-supplied value at an existing hit without retaining the literal."""

    def __init__(self, files: Sequence[SourceFile]):
        self._key = secrets.token_bytes(32)
        self._matches: dict[tuple[str, int, str], set[bytes]] = {}
        self._manifest_values: set[tuple[str, int, str]] = set()
        for source in files:
            manifest = source.origin == "decoded" and _PACKAGED_MANIFEST.fullmatch(source.rel)
            for line, rule, value, _, _ in source.secret_hits:
                # PEM rules can match just the public BEGIN marker, not the private key.
                if value and not value.startswith("-----BEGIN "):
                    site = (source.rel, line, rule)
                    self._matches.setdefault(site, set()).add(self._digest(value))
                    if manifest and rule == GOOGLE_KEY_RULE and 1 <= line <= len(source.lines):
                        # render_xml puts each complete attribute on its own line.
                        attr = f'android:value="{value}"'
                        if source.lines[line - 1].strip() in (attr, attr + ">", attr + " />"):
                            self._manifest_values.add(site)

    def _digest(self, value: str) -> bytes:
        return hmac.digest(self._key, value.encode("utf-8", errors="surrogatepass"), "sha256")

    def at(self, path: str, line: int, rule: str) -> bool:
        return (path, line, rule) in self._matches

    def matches(self, path: str, line: int, rule: str, value: str) -> bool:
        digest = self._digest(value)
        return any(hmac.compare_digest(digest, other)
                   for other in self._matches.get((path, line, rule), ()))

    def match_source_file(self, path: str, line: int, rule: str, data: bytes) -> str | None:
        """Return the independently supplied source literal matching the unique hit here."""
        if rule != GOOGLE_KEY_RULE or len(self._matches.get((path, line, rule), ())) != 1:
            return None
        if not data or len(data) > MAX_FILE_BYTES or b"\0" in data:
            return None
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        for candidate in _GOOGLE_KEY.finditer(source):
            value = candidate.group()
            if self.matches(path, line, rule, value):
                return value
        return None

    def matches_manifest_value(self, path: str, line: int, rule: str, value: str) -> bool:
        """Was the supplied literal the entire decoded android:value on this line?"""
        site = (path, line, rule)
        return (site in getattr(self, "_manifest_values", ())
                and len(self._matches.get(site, ())) == 1 and self.matches(path, line, rule, value))



def build_previews(files: Sequence[SourceFile], *, source_root: Path | None = None) -> dict[str, DecodedFile]:
    """Keep bounded scanned lines without masking; analysis JSON excludes these snapshots."""
    previews = {}
    chars_left = MAX_PREVIEW_CHARS
    lines_left = MAX_PREVIEW_LINES
    priority = {"decoded": 0, "decoded_literal": 0, "recovered": 1, "decompiled": 2, "summary": 3, "strings": 4}
    for source in sorted(files, key=lambda item: (priority.get(item.origin, 5), item.rel)):
        raw_lines = []
        for line in source.lines:
            cost = len(line) + 1
            if cost > chars_left or not lines_left:
                break
            raw_lines.append(line)
            chars_left -= cost
            lines_left -= 1
        previews[source.rel] = DecodedFile(
            source.language, source.origin, len(source.lines),
            tuple(raw_lines),
            _original_source(source, source_root),
            validate_derivation(source.derivation),
        )
    return previews
