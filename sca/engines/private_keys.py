"""Offline recognition of embedded private-key material, not PEM delimiter strings."""
from __future__ import annotations

import base64
import binascii
from bisect import bisect_right
from dataclasses import dataclass
import re


MAX_PEM_TEXT = 128 << 10
_BEGIN = re.compile(r"-----BEGIN ((?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?)-----")
_CONCATENATION = re.compile(r"([\"'])\s*\+\s*\1")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")


@dataclass(frozen=True)
class PrivateKeyMaterial:
    value: str                  # complete PEM with normalized body wrapping
    raw: str                    # exact source substring, for report masking
    line: int
    column: int
    end_line: int
    end_column: int             # exclusive, on end_line
    payload_lines: tuple[str, ...]


def _tlv(data: bytes, at: int = 0):
    if at + 2 > len(data):
        return None
    tag, size, start = data[at], data[at + 1], at + 2
    if size & 128:
        count = size & 127
        if not 1 <= count <= 4 or start + count > len(data):
            return None
        size = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + size
    if end > len(data):
        return None
    return tag, data[start:end], end


def _der_key(label: str, data: bytes) -> bool:
    outer = _tlv(data)
    if outer is None or outer[0] != 0x30 or outer[2] != len(data):
        return False
    fields, at = [], 0
    while at < len(outer[1]) and len(fields) < 16:
        field = _tlv(outer[1], at)
        if field is None:
            return False
        fields.append(field[:2])
        at = field[2]
    if at != len(outer[1]):
        return False
    tags = [field[0] for field in fields]
    if label == "RSA PRIVATE KEY":
        return len(fields) >= 9 and tags[:9] == [2] * 9 and fields[0][1] in (b"\0", b"\1")
    if label == "DSA PRIVATE KEY":
        return tags == [2] * 6 and fields[0][1] == b"\0"
    if label == "EC PRIVATE KEY":
        return len(fields) >= 2 and tags[:2] == [2, 4] and fields[0][1] == b"\1" and len(fields[1][1]) >= 16
    if label == "PRIVATE KEY":
        return (len(fields) >= 3 and tags[:3] == [2, 0x30, 4]
                and fields[0][1] in (b"\0", b"\1") and fields[1][1].startswith(b"\x06")
                and len(fields[2][1]) >= 16)
    if label == "ENCRYPTED PRIVATE KEY":
        return tags == [0x30, 4] and fields[0][1].startswith(b"\x06") and len(fields[1][1]) >= 16
    return False


def _openssh_key(data: bytes) -> bool:
    prefix = b"openssh-key-v1\0"
    if not data.startswith(prefix):
        return False
    at = len(prefix)

    def string():
        nonlocal at
        if at + 4 > len(data):
            return None
        size = int.from_bytes(data[at:at + 4], "big")
        at += 4
        if at + size > len(data):
            return None
        value = data[at:at + size]
        at += size
        return value

    if any(value is None for value in (string(), string(), string())) or at + 4 > len(data):
        return False
    count = int.from_bytes(data[at:at + 4], "big")
    at += 4
    if not 1 <= count <= 16:
        return False
    for _ in range(count):
        if not string():
            return False
    private = string()
    return bool(private and len(private) >= 32 and at == len(data))


def _parse_block(label: str, raw: str):
    text = _CONCATENATION.sub("", raw).replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    text = text.replace("\\/", "/")
    begin, end = f"-----BEGIN {label}-----", f"-----END {label}-----"
    body = text[len(begin):-len(end)]
    headers, payloads, checksum = [], [], ""
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line and not payloads and line.split(":", 1)[0] in {"Proc-Type", "DEK-Info", "Version", "Comment"}:
            headers.append(line)
        elif label == "PGP PRIVATE KEY BLOCK" and re.fullmatch(r"=[A-Za-z0-9+/]{4}", line):
            checksum = line
        elif _BASE64.fullmatch(line):
            payloads.append(line)
        else:
            return None
    joined = "".join(payloads)
    if len(joined) < 40:
        return None
    try:
        decoded = base64.b64decode(joined, validate=True)
    except (ValueError, binascii.Error):
        return None
    encrypted = (label in {"RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"}
                 and any(line == "Proc-Type: 4,ENCRYPTED" for line in headers)
                 and any(re.fullmatch(r"DEK-Info: (?:AES-\d+-CBC|DES-EDE3-CBC|DES-CBC),[0-9A-Fa-f]+", line)
                         for line in headers) and len(decoded) >= 32 and len(decoded) % 8 == 0)
    pgp = (label == "PGP PRIVATE KEY BLOCK" and len(decoded) >= 32 and decoded[0] & 128
           and ((decoded[0] & 63) if decoded[0] & 64 else ((decoded[0] >> 2) & 15)) in {5, 7})
    if not (encrypted or pgp or (label == "OPENSSH PRIVATE KEY" and _openssh_key(decoded)) or _der_key(label, decoded)):
        return None
    canonical = [begin, *headers]
    if headers:
        canonical.append("")
    canonical += [joined[pos:pos + 64] for pos in range(0, len(joined), 64)]
    if checksum:
        canonical.append(checksum)
    canonical.append(end)
    return "\n".join(canonical), tuple(payloads)


def find_private_keys(text: str):
    """Yield complete, structurally parseable embedded keys with exact source coordinates."""
    starts, position = [], 0
    for line in text.splitlines(keepends=True):
        starts.append(position)
        position += len(line)
    for match in _BEGIN.finditer(text):
        closing = f"-----END {match[1]}-----"
        end = text.find(closing, match.end(), match.start() + MAX_PEM_TEXT)
        if end < 0:
            continue
        end += len(closing)
        raw = text[match.start():end]
        parsed = _parse_block(match[1], raw)
        if parsed is None:
            continue
        first_line = bisect_right(starts, match.start())
        last_line = bisect_right(starts, end - 1)
        yield PrivateKeyMaterial(parsed[0], raw, first_line,
                                 match.start() - starts[first_line - 1] + 1,
                                 last_line, end - starts[last_line - 1] + 1, parsed[1])
