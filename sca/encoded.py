"""Bounded recovery of relevant Base64 literals with verifiable source provenance.

This is decoding of retained bytes, not execution or a claim of runtime generation.
Derived text never participates in code/taint checks or the lines-of-code denominator.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from pathlib import Path
import re

from .walker import SourceFile

MAX_TOKEN = 16384
MAX_CANDIDATES = 1000000
MAX_FILES = 2000
MAX_DECODED_BYTES = 4 << 20
MAX_DEPTH = 2
ORIGIN = "decoded_literal"
_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=\-])([A-Za-z0-9+/_\-]{16," +
                    str(MAX_TOKEN) + r"}={0,2})(?![A-Za-z0-9+/_=\-])")
_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s<>\"']{3,}")


def decode_text(value):
    """Decode canonical Base64/base64url into strict printable UTF-8, or return None."""
    if len(value) < 16 or len(value) > MAX_TOKEN + 2 or len(value) % 4 == 1:
        return None
    try:
        encoded = value.encode("ascii")
        raw = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        canonical = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        if canonical != value.translate(str.maketrans("+/", "-_")).rstrip("="):
            return None
        decoded = raw.decode("utf-8")
    except (UnicodeError, ValueError, binascii.Error):
        return None
    if not decoded or any(not char.isprintable() and char not in "\r\n\t" for char in decoded):
        return None
    return decoded


def recover(files):
    """Return derived SourceFiles and explicit budget/coverage counters.

    Only decoded text containing a supported credential candidate or URL is retained.
    Source coordinates always refer to the full *encoded* literal. Each derived preview
    contains the actual decoded text and carries a distinct origin/provenance object.
    """
    from .engines import secrets, rules_engine
    rules = rules_engine.secret_rules()
    derived = []
    occupied = {sf.rel for sf in files}
    seen = set()
    coverage = {"candidates_checked": 0, "decoded_files": 0, "decoded_bytes": 0,
                "limits_reached": [], "max_candidates": MAX_CANDIDATES,
                "max_files": MAX_FILES, "max_decoded_bytes": MAX_DECODED_BYTES,
                "max_token_characters": MAX_TOKEN, "max_depth": MAX_DEPTH}
    for sf in files:
        if sf.origin in {ORIGIN, "summary", "placeholder"}:
            continue
        for number, line in enumerate(sf.lines, 1):
            for match in _TOKEN.finditer(line):
                site = (sf.rel, number, match.start(), match.end())
                if site in seen:
                    continue
                seen.add(site)
                if coverage["candidates_checked"] >= MAX_CANDIDATES:
                    coverage["limits_reached"].append("candidate_limit")
                    return derived, coverage
                coverage["candidates_checked"] += 1
                encoded = match.group()
                value = encoded
                for depth in range(1, MAX_DEPTH + 1):
                    decoded = decode_text(value)
                    if decoded is None:
                        break
                    probe = SourceFile(Path("decoded.txt"), "decoded.txt", "config", decoded,
                                       origin="strings")
                    relevant = bool(_URL.search(decoded) or secrets.scan_file(probe, rules))
                    if relevant:
                        size = len(decoded.encode("utf-8"))
                        if len(derived) >= MAX_FILES or coverage["decoded_bytes"] + size > MAX_DECODED_BYTES:
                            coverage["limits_reached"].append("derived_evidence_limit")
                            return derived, coverage
                        identity = "\0".join(map(str, (*site, depth)))
                        stem = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                        rel = f"_decoded_literals/base64/{stem}.txt"
                        index = 1
                        while rel in occupied:
                            rel = f"_decoded_literals/base64/{stem}-{index}.txt"
                            index += 1
                        occupied.add(rel)
                        provenance = {"encoding": "base64", "depth": depth,
                                      "source_file": sf.rel, "source_line": number,
                                      "source_column": match.start() + 1,
                                      "source_end_column": match.end() + 1,
                                      "encoded_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
                                      "decoded_sha256": hashlib.sha256(decoded.encode("utf-8")).hexdigest()}
                        derived.append(SourceFile(Path(rel), rel, "config", decoded,
                                                  origin=ORIGIN, derivation=provenance))
                        coverage["decoded_files"] += 1
                        coverage["decoded_bytes"] += size
                        break
                    # Only whole-string nested encoding: never guess concatenations or
                    # search recursively through arbitrary decoded payloads.
                    if not _TOKEN.fullmatch(decoded):
                        break
                    value = decoded
    return derived, coverage
