"""Signatures of an Android app package: which signing schemes it uses and who signed it.

v1 (JAR signing) keeps PKCS#7 SignedData blocks in META-INF/*.RSA, *.DSA or *.EC. v2, v3 and
v3.1 keep their signers in the APK Signing Block, which sits right before the ZIP central
directory (source.android.com/docs/security/features/apksigning). This module reads the
signer certificates of every scheme and describes them: subject, issuer, validity, key,
signature algorithm, SHA-256 fingerprint, and whether it is the Android debug certificate.

No signature is verified: nothing here proves that the holder of a key signed the app or
that its contents are unchanged (the optional apksigner tool does that). A scheme is listed
when its signature is present; certificates that cannot be read give warnings.

An app package is untrusted: every length is bounds-checked, counts and nesting are capped,
only the byte ranges needed are read, and problems become warnings. read_signatures() never
raises on bad data; parse_certificate() raises CertificateError on bytes it cannot read.
"""
from __future__ import annotations

import datetime
import hashlib
import io
import os
import re
import struct
from dataclasses import dataclass, field
from typing import (Any, BinaryIO, Dict, Iterator, List, Mapping, NamedTuple, Optional, Sequence,
                    Tuple, Union)

BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61
VERITY_PADDING_ID = 0x42726577
SOURCE_STAMP_V1_ID = 0x2B09189E
SOURCE_STAMP_V2_ID = 0x6DFF800D
DEPENDENCY_INFO_ID = 0x504B4453          # AGP dependency metadata, encrypted for Google Play
BLOCK_ID_NAMES = {V2_BLOCK_ID: "v2", V3_BLOCK_ID: "v3", V31_BLOCK_ID: "v3.1",
                  VERITY_PADDING_ID: "verity padding", SOURCE_STAMP_V1_ID: "source stamp v1",
                  SOURCE_STAMP_V2_ID: "source stamp v2", DEPENDENCY_INFO_ID: "dependency info"}
SCHEMES = ("v1", "v2", "v3", "v3.1", "source-stamp")
_SCHEME_OF_BLOCK = {V2_BLOCK_ID: "v2", V3_BLOCK_ID: "v3", V31_BLOCK_ID: "v3.1",
                    SOURCE_STAMP_V1_ID: "source-stamp", SOURCE_STAMP_V2_ID: "source-stamp"}
V1_EXTENSIONS = (".rsa", ".dsa", ".ec")

EOCD_SIGNATURE = b"PK\x05\x06"
EOCD_SIZE = 22
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"

# caps against hostile input
MAX_COMMENT = 0xFFFF
MAX_PAIRS = 1024
MAX_SCHEME_VALUE = 16 << 20     # bytes read for the signers of one scheme
MAX_SIGNERS = 16
MAX_CERTS = 64                  # certificates in one PKCS#7 block
MAX_RDNS = 32
MAX_VALUE_CHARS = 256           # characters kept from one name attribute
MAX_DEPTH = 32                  # nesting of BER indefinite-length elements
MAX_ELEMENTS = 10_000           # elements of one DER sequence or set
MAX_WARNINGS = 50

# DER tags
INTEGER, BIT_STRING, OCTET_STRING, NULL, OID = 0x02, 0x03, 0x04, 0x05, 0x06
UTF8_STRING, PRINTABLE_STRING = 0x0C, 0x13
UTC_TIME, GENERALIZED_TIME = 0x17, 0x18
SEQUENCE, SET = 0x30, 0x31
CONTEXT_0 = 0xA0

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
NAME_KEYS = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "SERIALNUMBER", "2.5.4.6": "C", "2.5.4.7": "L",
    "2.5.4.8": "ST", "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "T",
    "2.5.4.17": "POSTALCODE", "2.5.4.42": "GIVENNAME", "2.5.4.43": "INITIALS",
    "2.5.4.46": "DNQUALIFIER", "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "EMAILADDRESS",
}
SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.1": "dsa-with-sha224",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
OID_RSA, OID_EC, OID_DSA = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1", "1.2.840.10040.4.1"
KEY_ALGORITHMS = {OID_RSA: "RSA", "1.2.840.113549.1.1.10": "RSA", OID_EC: "EC", OID_DSA: "DSA",
                  "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448"}
EC_CURVES = {"1.2.840.10045.3.1.7": 256, "1.3.132.0.34": 384, "1.3.132.0.35": 521,
             "1.3.132.0.10": 256, "1.3.132.0.33": 224, "1.2.840.10045.3.1.1": 192}
DEBUG_SUBJECT = {"CN": "Android Debug", "O": "Android", "C": "US"}
_ESCAPED = set('"+,;<>\\')
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}]")

Source = Union[str, "os.PathLike[str]", bytes, bytearray, memoryview, BinaryIO]


class CertificateError(ValueError):
    """The bytes are not an X.509 certificate this module can read."""


class _Malformed(Exception):
    """A structure does not fit its bounds; the message says what."""


class _Tlv(NamedTuple):
    """One DER/BER element: buf[start:stop] is the whole element, buf[body:end] its content."""

    tag: int
    start: int
    body: int
    end: int
    stop: int


@dataclass
class Certificate:
    """What an X.509 certificate says. Names are written in RFC 4514 order, the last RDN of
    the certificate first, as apksigner and keytool print them."""

    subject: str = ""                   # "C=US, O=Android, CN=Android Debug"
    issuer: str = ""
    subject_parts: Dict[str, str] = field(default_factory=dict)   # {"CN": "Android Debug", ...}
    issuer_parts: Dict[str, str] = field(default_factory=dict)
    serial: str = ""                    # hex without leading zeros: "1"
    valid_from: str = ""                # "2026-03-10"
    valid_to: str = ""
    sha256: str = ""                    # of the DER encoding, as apksigner prints it
    sha1: str = ""
    key_algorithm: str = ""             # "RSA", "EC", "DSA", "Ed25519" or the key's OID
    key_bits: int = 0                   # RSA modulus or DSA prime size, EC curve size
    signature_algorithm: str = ""       # "sha256WithRSAEncryption", "ecdsa-with-SHA256" ...
    is_debug: bool = False              # the Android debug certificate
    schemes: List[str] = field(default_factory=list)     # schemes it signs (read_signatures)
    warnings: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        """"RSA 2048", "EC 256" ..."""
        return f"{self.key_algorithm} {self.key_bits}" if self.key_bits else self.key_algorithm

    def as_dict(self) -> Dict[str, Any]:
        """The certificate as the signing facts of a scan list it."""
        return {"subject": self.subject, "issuer": self.issuer, "sha256": self.sha256,
                "valid_from": self.valid_from, "valid_to": self.valid_to, "key": self.key,
                "signature_algorithm": self.signature_algorithm, "debug": self.is_debug}


@dataclass
class SigningInfo:
    """The signatures found in an app package (none of them verified)."""

    schemes: List[str] = field(default_factory=list)       # present schemes, in SCHEMES order
    signers: List[Certificate] = field(default_factory=list)
    has_block: bool = False                                 # an APK Signing Block is present
    block_ids: List[int] = field(default_factory=list)      # ids of its pairs, in order
    warnings: List[str] = field(default_factory=list)

    @property
    def is_debug(self) -> bool:
        return any(cert.is_debug for cert in self.signers)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append("signing: " + message)
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append("signing: further warnings suppressed")


# ------------------------------------------------------------------ reading an app package

def read_signatures(source: Source, v1_files: Optional[Mapping[str, bytes]] = None) -> SigningInfo:
    """Find the signatures of an APK. source is a path, the bytes of the APK or a seekable
    binary file (left open, its position restored); only the end of central directory
    record and the APK Signing Block are read. v1_files maps the names of the META-INF/*.RSA,
    *.DSA and *.EC entries to their decompressed contents; other names are ignored. Signer
    certificates of several schemes that are the same certificate are listed once. Never
    raises on bad data."""
    info = SigningInfo()
    found: Dict[str, List[bytes]] = {}
    try:
        with _Reader(source) as reader:
            _read_block(reader, info, found)
    except OSError as exc:
        info.warn(f"cannot read the app package: {exc}")
    for name in sorted(v1_files or {}):
        if name.lower().endswith(V1_EXTENSIONS):
            _read_v1(name, bytes(v1_files[name]), info, found.setdefault("v1", []))
    by_digest: Dict[str, Certificate] = {}
    for scheme in SCHEMES:
        if scheme not in found:
            continue
        info.schemes.append(scheme)
        for der in found[scheme]:
            digest = hashlib.sha256(der).hexdigest()
            cert = by_digest.get(digest)
            if cert is None:
                try:
                    cert = by_digest[digest] = parse_certificate(der)
                except CertificateError as exc:
                    info.warn(f"a {scheme} signer certificate cannot be read: {exc}")
                    continue
                info.signers.append(cert)
                for message in cert.warnings:
                    info.warn(f"{scheme} certificate {cert.subject[:80]}: {message}")
            if scheme not in cert.schemes:
                cert.schemes.append(scheme)
    return info


class _Reader:
    """Random access to an APK given as a path, bytes or a seekable binary file."""

    def __init__(self, source: Source) -> None:
        self._buf: Optional[bytes] = None
        self._file: Optional[BinaryIO] = None
        self._owned = False
        self._restore = 0
        if isinstance(source, (bytes, bytearray, memoryview)):
            self._buf = bytes(source)
            self.size = len(self._buf)
            return
        if isinstance(source, (str, os.PathLike)):
            self._file = open(source, "rb")
            self._owned = True
        else:
            self._file = source
            self._restore = source.tell()
        self._file.seek(0, io.SEEK_END)
        self.size = self._file.tell()

    def read(self, offset: int, length: int) -> bytes:
        """length bytes at offset; fewer at the end of the file, none outside it."""
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        if self._buf is not None:
            return self._buf[offset:offset + length]
        self._file.seek(offset)
        return self._file.read(min(length, self.size - offset))

    def __enter__(self) -> "_Reader":
        return self

    def __exit__(self, *exc: object) -> None:
        if self._file is not None:
            if self._owned:
                self._file.close()
            else:
                self._file.seek(self._restore)


def _find_eocd(reader: _Reader, info: SigningInfo) -> Optional[Tuple[int, int, int]]:
    """(offset, central directory offset, central directory size) from the end of central
    directory record: the last one whose comment ends the file, else the last one."""
    start = max(0, reader.size - EOCD_SIZE - MAX_COMMENT)
    tail = reader.read(start, reader.size - start)
    pos, fallback = tail.rfind(EOCD_SIGNATURE), -1
    while pos >= 0:
        if pos + EOCD_SIZE <= len(tail):
            if pos + EOCD_SIZE + struct.unpack_from("<H", tail, pos + 20)[0] == len(tail):
                break
            fallback = max(fallback, pos)
        pos = tail.rfind(EOCD_SIGNATURE, 0, pos)
    if pos < 0:
        if fallback < 0:
            info.warn("no ZIP end of central directory record: not an APK")
            return None
        pos = fallback
        info.warn("the ZIP end of central directory record does not end the file "
                  "(its comment length does not match)")
    cd_size, cd_offset = struct.unpack_from("<II", tail, pos + 12)
    if 0xFFFFFFFF in (cd_size, cd_offset):
        info.warn("ZIP64 archive: Android does not install ZIP64 APKs; signatures not read")
        return None
    if pos >= 20 and tail[pos - 20:pos - 16] == ZIP64_LOCATOR_SIGNATURE:
        info.warn("the archive has a ZIP64 record, which Android does not accept in an APK")
    return start + pos, cd_offset, cd_size


def _read_block(reader: _Reader, info: SigningInfo, found: Dict[str, List[bytes]]) -> None:
    """Find the APK Signing Block before the central directory and read its pairs as
    apksig does (ApkSigningBlockUtils.findApkSigningBlock)."""
    located = _find_eocd(reader, info)
    if located is None:
        return
    eocd, cd_offset, cd_size = located
    if cd_offset + cd_size != eocd:
        info.warn(f"the central directory (offset {cd_offset}, size {cd_size}) does not end where "
                  f"the end of central directory record starts ({eocd})")
        if cd_offset > eocd:
            return
    footer = reader.read(cd_offset - 24, 24) if cd_offset >= 24 else b""
    if len(footer) < 24 or footer[8:] != BLOCK_MAGIC:
        return
    info.has_block = True
    size = struct.unpack_from("<Q", footer)[0]
    if size < 24 or size > cd_offset - 8:
        info.warn(f"the APK Signing Block size ({size}) is out of range; block not read")
        return
    start = cd_offset - size - 8
    head = struct.unpack("<Q", reader.read(start, 8))[0]
    if head != size:
        info.warn(f"the APK Signing Block size fields disagree (header {head}, footer {size}); "
                  "Android ignores such a block")
        return
    pos, end = start + 8, cd_offset - 24
    while pos < end:
        if len(info.block_ids) == MAX_PAIRS:
            info.warn(f"the APK Signing Block has more than {MAX_PAIRS} pairs; "
                      "the rest are skipped")
            return
        pair = reader.read(pos, 12)
        length = struct.unpack_from("<Q", pair)[0] if end - pos >= 12 else 0
        if length < 4 or length > end - pos - 8:
            info.warn(f"pair #{len(info.block_ids) + 1} of the APK Signing Block has a bad size "
                      f"({length}); the rest of the block is skipped")
            return
        pair_id = struct.unpack_from("<I", pair, 8)[0]
        scheme = _SCHEME_OF_BLOCK.get(pair_id)
        if pair_id in info.block_ids:
            info.warn(f"the APK Signing Block holds pair {pair_id:#010x} twice; "
                      "Android uses the first")
        elif scheme == "source-stamp":
            found.setdefault(scheme, [])
        elif scheme and length - 4 > MAX_SCHEME_VALUE:
            info.warn(f"the {scheme} signature is {length - 4} bytes long; "
                      "its signers are not read")
            found.setdefault(scheme, [])
        elif scheme:
            found[scheme] = _scheme_certificates(reader.read(pos + 12, length - 4), scheme, info)
        info.block_ids.append(pair_id)
        pos += 8 + length


def _lp(buf: bytes, pos: int, end: int) -> Tuple[int, int]:
    """(start, end) of the item at pos that a 32-bit little-endian length prefixes."""
    if end - pos < 4:
        raise _Malformed("a length prefix is truncated")
    length = struct.unpack_from("<I", buf, pos)[0]
    if length > end - pos - 4:
        raise _Malformed(f"an item of {length} bytes runs past its parent")
    return pos + 4, pos + 4 + length


def _lp_items(buf: bytes, start: int, end: int) -> Iterator[Tuple[int, int]]:
    """(start, end) of each item of a sequence of length-prefixed items."""
    while start < end:
        item = _lp(buf, start, end)
        yield item
        start = item[1]


def _scheme_certificates(value: bytes, scheme: str, info: SigningInfo) -> List[bytes]:
    """The first certificate of every signer of a v2, v3 or v3.1 signature. A signer starts
    with its signed data, which starts with the digests and then the certificates."""
    certs: List[bytes] = []
    signers = 0
    try:
        for signer_start, signer_end in _lp_items(value, *_lp(value, 0, len(value))):
            if signers == MAX_SIGNERS:
                info.warn(f"the {scheme} signature has more than {MAX_SIGNERS} signers; "
                          "the rest are skipped")
                break
            signers += 1
            signed_start, signed_end = _lp(value, signer_start, signer_end)
            digests_end = _lp(value, signed_start, signed_end)[1]
            first = next(_lp_items(value, *_lp(value, digests_end, signed_end)), None)
            if first is None:
                info.warn(f"a {scheme} signer lists no certificate")
            else:
                certs.append(value[first[0]:first[1]])
    except _Malformed as exc:
        info.warn(f"the {scheme} signature is malformed: {exc}")
        return certs
    if not signers:
        info.warn(f"the {scheme} signature has no signer")
    return certs


def _read_v1(name: str, data: bytes, info: SigningInfo, certs: List[bytes]) -> None:
    """Add the signer certificates of one JAR signature block (PKCS#7 SignedData)."""
    try:
        found, signer_ids = _pkcs7(data)
    except _Malformed as exc:
        info.warn(f"{name} is not a readable PKCS#7 signature block: {exc}")
        return
    if not found:
        info.warn(f"{name} holds no certificate")
    chosen = [der for der in found if _issuer_and_serial(der) in signer_ids] or found[:1]
    certs.extend(der for der in chosen if der not in certs)


def _pkcs7(data: bytes) -> Tuple[List[bytes], List[Tuple[bytes, bytes]]]:
    """(certificates, [(issuer DER, serial bytes)] of the signers) of a PKCS#7 ContentInfo
    holding SignedData. BER indefinite lengths are accepted, as Android accepts them."""
    top = _tlv(data, 0, len(data), ber=True)
    content = _children(data, top, ber=True)
    if top.tag != SEQUENCE or len(content) < 2 or content[0].tag != OID:
        raise _Malformed("not a ContentInfo")
    if _oid(data[content[0].body:content[0].end]) != OID_SIGNED_DATA:
        raise _Malformed("the content is not SignedData")
    signed = _children(data, content[1], ber=True) if content[1].tag == CONTEXT_0 else []
    if not signed or signed[0].tag != SEQUENCE:
        raise _Malformed("SignedData is missing")
    certs: List[bytes] = []
    signer_ids: List[Tuple[bytes, bytes]] = []
    # version, digestAlgorithms and contentInfo come first; then [0] certificates,
    # [1] CRLs and the signerInfos SET
    for part in _children(data, signed[0], ber=True)[3:]:
        if part.tag == CONTEXT_0:
            certs += [data[c.start:c.stop] for c in _children(data, part, ber=True)
                      if c.tag == SEQUENCE][:MAX_CERTS]
        elif part.tag == SET:
            for signer in _children(data, part, ber=True)[:MAX_SIGNERS]:
                fields = _children(data, signer, ber=True) if signer.tag == SEQUENCE else []
                if len(fields) < 2 or fields[1].tag != SEQUENCE:
                    continue                    # identified by key id, not issuer and serial
                sid = _children(data, fields[1], ber=True)
                if len(sid) == 2 and sid[1].tag == INTEGER:
                    issuer, serial = sid
                    signer_ids.append((data[issuer.start:issuer.stop],
                                       data[serial.body:serial.end]))
    return certs, signer_ids


def _issuer_and_serial(der: bytes) -> Tuple[bytes, bytes]:
    """(issuer Name DER, serial number bytes) of a certificate; two empty strings when it
    cannot be read."""
    try:
        serial, _, issuer = _tbs_fields(der)[:3]
    except _Malformed:
        return b"", b""
    return der[issuer.start:issuer.stop], der[serial.body:serial.end]


# ------------------------------------------------------------------ DER

def _tlv(buf: bytes, pos: int, end: int, *, ber: bool = False, depth: int = 0) -> _Tlv:
    """The element at pos. Only definite lengths are accepted unless ber is set; then an
    indefinite length ends at its end-of-contents marker, found through at most MAX_DEPTH
    nested elements."""
    start = pos
    if end - pos < 2:
        raise _Malformed("an element is truncated")
    tag = buf[pos]
    pos += 1
    if tag & 0x1F == 0x1F:                      # high tag number form
        for _ in range(4):
            if pos >= end:
                raise _Malformed("a tag is truncated")
            tag = tag << 8 | buf[pos]
            pos += 1
            if not tag & 0x80:
                break
        else:
            raise _Malformed("a tag is too long")
    if pos >= end:
        raise _Malformed("a length is truncated")
    first = buf[pos]
    pos += 1
    if first == 0x80:
        if not ber:
            raise _Malformed("an indefinite length (BER) where DER is required")
        if depth >= MAX_DEPTH:
            raise _Malformed(f"elements are nested more than {MAX_DEPTH} levels deep")
        child = pos
        for _ in range(MAX_ELEMENTS):
            if end - child < 2:
                raise _Malformed("an indefinite length has no end-of-contents marker")
            if buf[child] == 0 and buf[child + 1] == 0:
                return _Tlv(tag, start, pos, child, child + 2)
            child = _tlv(buf, child, end, ber=True, depth=depth + 1).stop
        raise _Malformed(f"more than {MAX_ELEMENTS} elements")
    length = first
    if first & 0x80:
        count = first & 0x7F
        if count > 4 or end - pos < count:
            raise _Malformed("a length is too long or truncated")
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    if length > end - pos:
        raise _Malformed("an element runs past its parent")
    return _Tlv(tag, start, pos, pos + length, pos + length)


def _children(buf: bytes, parent: _Tlv, *, ber: bool = False) -> List[_Tlv]:
    """The elements inside parent's content."""
    items, pos = [], parent.body
    while pos < parent.end:
        if len(items) == MAX_ELEMENTS:
            raise _Malformed(f"more than {MAX_ELEMENTS} elements")
        items.append(_tlv(buf, pos, parent.end, ber=ber))
        pos = items[-1].stop
    return items


def _oid(raw: bytes) -> str:
    """Dotted form of an OBJECT IDENTIFIER's content."""
    if not raw or len(raw) > 64 or raw[-1] & 0x80:
        raise _Malformed("a malformed object identifier")
    arcs, value = [], 0
    for byte in raw:
        value = value << 7 | byte & 0x7F
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in [first, arcs[0] - 40 * first] + arcs[1:])


def _tbs_fields(der: bytes) -> List[_Tlv]:
    """serial, signature, issuer, validity, subject and public key info of a certificate's
    tbsCertificate, without the optional version, then any further fields."""
    cert = _tlv(der, 0, len(der))
    tbs = _tlv(der, cert.body, cert.end) if cert.tag == SEQUENCE else None
    if tbs is None or tbs.tag != SEQUENCE:
        raise _Malformed("not a certificate SEQUENCE holding a tbsCertificate SEQUENCE")
    fields = _children(der, tbs)
    if fields and fields[0].tag == CONTEXT_0:
        fields = fields[1:]
    expected = (INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE)
    if len(fields) < len(expected) or any(f.tag != t for f, t in zip(fields, expected)):
        raise _Malformed("tbsCertificate does not have the fields of an X.509 certificate")
    return fields


def parse_certificate(der: bytes) -> Certificate:
    """Describe a DER X.509 certificate (definite lengths only). Raises CertificateError
    when its structure cannot be read; smaller problems are in .warnings."""
    der = bytes(der)
    try:
        return _certificate(der)
    except _Malformed as exc:
        raise CertificateError(str(exc)) from None


def _certificate(der: bytes) -> Certificate:
    cert = Certificate()
    serial, signature, issuer, validity, subject, key = _tbs_fields(der)[:6]
    outer = _tlv(der, 0, len(der))
    parts = _children(der, outer)
    if len(parts) < 3 or parts[1].tag != SEQUENCE:
        raise _Malformed("the certificate has no signature algorithm")
    if outer.stop < len(der):
        cert.warnings.append(f"{len(der) - outer.stop} bytes follow the certificate")
    raw = der[:outer.stop]
    cert.sha256, cert.sha1 = hashlib.sha256(raw).hexdigest(), hashlib.sha1(raw).hexdigest()
    number = int.from_bytes(raw[serial.body:serial.end], "big", signed=True)
    cert.serial = format(number, "x") if number >= 0 else "-" + format(-number, "x")
    cert.signature_algorithm = _algorithm(raw, parts[1], SIGNATURE_ALGORITHMS)[0]
    if _algorithm(raw, signature, SIGNATURE_ALGORITHMS)[0] != cert.signature_algorithm:
        cert.warnings.append("the signature algorithm inside the certificate differs from "
                             "the outer one")
    cert.issuer, cert.issuer_parts = _name(raw, issuer)
    cert.subject, cert.subject_parts = _name(raw, subject)
    times = _children(raw, validity)
    if len(times) == 2:
        cert.valid_from, cert.valid_to = (_time(t.tag, raw[t.body:t.end]) for t in times)
    if not (cert.valid_from and cert.valid_to):
        cert.warnings.append("the validity dates cannot be read")
    _public_key(raw, key, cert)
    cert.is_debug = cert.issuer == cert.subject and \
        all(cert.subject_parts.get(k) == v for k, v in DEBUG_SUBJECT.items())
    return cert


def _algorithm(der: bytes, item: _Tlv, names: Dict[str, str]) -> Tuple[str, List[_Tlv]]:
    """(name or dotted OID, parameter elements) of an AlgorithmIdentifier."""
    fields = _children(der, item)
    if not fields or fields[0].tag != OID:
        raise _Malformed("an algorithm identifier has no OID")
    oid = _oid(der[fields[0].body:fields[0].end])
    return names.get(oid, oid), fields[1:]


def _name(der: bytes, item: _Tlv) -> Tuple[str, Dict[str, str]]:
    """("C=..., O=..., CN=...", {"CN": ...}) of a Name: RDNs in RFC 4514 order (the reverse
    of the certificate's order), the attributes of a multi-valued RDN joined by "+", values
    escaped as RFC 4514 does. For a repeated attribute the parts keep the value that comes
    first in the certificate."""
    texts, parts = [], {}
    for rdn in _children(der, item)[:MAX_RDNS]:
        if rdn.tag != SET:
            raise _Malformed("a name holds something other than a SET")
        pieces = []
        for ava in _children(der, rdn):
            kids = _children(der, ava) if ava.tag == SEQUENCE else []
            if len(kids) != 2 or kids[0].tag != OID:
                raise _Malformed("a name attribute is not an OID and a value")
            oid = _oid(der[kids[0].body:kids[0].end])
            key = NAME_KEYS.get(oid, oid)
            value, is_hex = _string(kids[1], der)
            parts.setdefault(key, value)
            pieces.append(f"{key}={value if is_hex else _escape(value)}")
        texts.append("+".join(pieces))
    return ", ".join(reversed(texts)), parts


def _string(item: _Tlv, der: bytes) -> Tuple[str, bool]:
    """(text, whether it is RFC 4514's "#" + hex form) of an attribute value."""
    raw = der[item.body:item.end]
    if item.tag == 0x1E:                                    # BMPString
        text = raw.decode("utf-16-be", "replace")
    elif item.tag == 0x1C and len(raw) % 4 == 0:            # UniversalString
        text = raw.decode("utf-32-be", "replace")
    elif item.tag == 0x14:                                  # TeletexString
        text = raw.decode("latin-1")
    elif item.tag in (UTF8_STRING, PRINTABLE_STRING, 0x12, 0x16, 0x1A):  # Numeric, IA5, Visible
        text = raw.decode("utf-8", "replace")
    else:                                                   # other types: the DER as hex
        return "#" + der[item.start:item.stop][:MAX_VALUE_CHARS // 2].hex(), True
    return text[:MAX_VALUE_CHARS], False


def _escape(value: str) -> str:
    """An attribute value as RFC 4514 writes it in a name, kept on one line."""
    out = []
    for index, ch in enumerate(value):
        if ch in _ESCAPED or ch == "#" and index == 0 or ch == " " and index in (0, len(value) - 1):
            out.append("\\" + ch)
        elif _CONTROL.match(ch):
            out.append("".join(f"\\{b:02x}" for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def _time(tag: int, raw: bytes) -> str:
    """"YYYY-MM-DD" of a UTCTime or GeneralizedTime, or "" when it cannot be read."""
    text = raw.decode("ascii", "replace")
    if tag == UTC_TIME and re.match(r"\d{6}", text):
        year = int(text[:2])
        year, rest = (1900 + year if year >= 50 else 2000 + year), text[2:6]
    elif tag == GENERALIZED_TIME and re.match(r"\d{8}", text):
        year, rest = int(text[:4]), text[4:8]
    else:
        return ""
    try:
        return datetime.date(year, int(rest[:2]), int(rest[2:])).isoformat()
    except ValueError:
        return ""


def _public_key(der: bytes, item: _Tlv, cert: Certificate) -> None:
    """Fill key_algorithm and key_bits from SubjectPublicKeyInfo."""
    fields = _children(der, item)
    if len(fields) != 2 or fields[0].tag != SEQUENCE or fields[1].tag != BIT_STRING:
        raise _Malformed("the public key info is not an algorithm and a BIT STRING")
    cert.key_algorithm, params = _algorithm(der, fields[0], KEY_ALGORITHMS)
    key = der[fields[1].body + 1:fields[1].end]            # after the unused-bits byte
    try:
        if cert.key_algorithm == "RSA":                     # RSAPublicKey: modulus, exponent
            numbers = _children(key, _tlv(key, 0, len(key)))
            cert.key_bits = _bits(key, numbers[0]) if numbers and numbers[0].tag == INTEGER else 0
        elif cert.key_algorithm == "EC":                    # named curve, else the point size
            named = params and params[0].tag == OID
            curve = _oid(der[params[0].body:params[0].end]) if named else ""
            cert.key_bits = EC_CURVES.get(curve) or (len(key) - 1) // 2 * 8
        elif cert.key_algorithm == "DSA" and params and params[0].tag == SEQUENCE:
            numbers = _children(der, params[0])             # p, q, g
            cert.key_bits = _bits(der, numbers[0]) if numbers and numbers[0].tag == INTEGER else 0
        elif cert.key_algorithm in ("Ed25519", "Ed448"):
            cert.key_bits = 256 if cert.key_algorithm == "Ed25519" else 456
    except _Malformed:
        cert.warnings.append(f"the {cert.key_algorithm} public key cannot be read")
    if not cert.key_bits:
        cert.warnings.append("the key size is unknown")


def _bits(buf: bytes, item: _Tlv) -> int:
    return int.from_bytes(buf[item.body:item.end], "big").bit_length()


# ------------------------------------------------------------------ builders for tests

def _der(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def _der_int(value: int) -> bytes:
    return _der(INTEGER, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


def _der_oid(dotted: str) -> bytes:
    arcs = [int(arc) for arc in dotted.split(".")]
    body = bytearray()
    for value in [40 * arcs[0] + arcs[1]] + arcs[2:]:
        chunk = [value & 0x7F]
        while value > 0x7F:
            value >>= 7
            chunk.append(0x80 | value & 0x7F)
        body += bytes(reversed(chunk))
    return _der(OID, bytes(body))


def _der_name(parts: Mapping[str, str]) -> bytes:
    oids = {key: oid for oid, key in NAME_KEYS.items()}
    rdns = b""
    for key, value in parts.items():
        kind = PRINTABLE_STRING if key == "C" else UTF8_STRING
        attribute = _der_oid(oids.get(key, key)) + _der(kind, value.encode("utf-8"))
        rdns += _der(SET, _der(SEQUENCE, attribute))
    return _der(SEQUENCE, rdns)


def _der_time(day: str) -> bytes:
    date = datetime.date.fromisoformat(day)
    stamp = f"{date.month:02d}{date.day:02d}000000Z"
    if 1950 <= date.year < 2050:
        return _der(UTC_TIME, f"{date.year % 100:02d}{stamp}".encode())
    return _der(GENERALIZED_TIME, f"{date.year:04d}{stamp}".encode())


def _der_public_key(algorithm: str, bits: int) -> bytes:
    if algorithm == "RSA":
        key = _der(SEQUENCE, _der_int(1 << (bits - 1) | 0x10001) + _der_int(65537))
        name = _der_oid(OID_RSA) + _der(NULL, b"")
    elif algorithm == "EC":
        curves = {size: oid for oid, size in EC_CURVES.items() if oid != "1.3.132.0.10"}
        key = b"\x04" + b"\x01" * (2 * ((bits + 7) // 8))
        name = _der_oid(OID_EC) + _der_oid(curves[bits])
    elif algorithm == "DSA":
        params = _der_int(1 << (bits - 1) | 1) + _der_int(1 << 255 | 1) + _der_int(2)
        key = _der_int(12345)
        name = _der_oid(OID_DSA) + _der(SEQUENCE, params)
    else:
        raise ValueError(f"build_certificate does not support {algorithm} keys")
    return _der(SEQUENCE, _der(SEQUENCE, name) + _der(BIT_STRING, b"\0" + key))


def build_certificate(subject: Mapping[str, str], issuer: Optional[Mapping[str, str]] = None, *,
                      key_bits: int = 2048, key_algorithm: str = "RSA",
                      sig_alg: str = "sha256WithRSAEncryption", not_before: str = "2026-03-10",
                      not_after: str = "2056-03-02", serial: int = 1, version: int = 3) -> bytes:
    """A structurally valid DER certificate for tests, with a fake key and signature.
    subject and issuer map attribute names (CN, O, OU, C ...) to values in the order of the
    RDNs in the certificate, which Certificate.subject prints in reverse; the issuer defaults
    to the subject (self-signed). Dates are "YYYY-MM-DD"; version 1 leaves
    out the version field, as the Android debug certificate does."""
    oids = {name: oid for oid, name in SIGNATURE_ALGORITHMS.items()}
    algorithm = _der_oid(oids[sig_alg]) + (_der(NULL, b"") if "RSA" in sig_alg else b"")
    algorithm = _der(SEQUENCE, algorithm)
    tbs = _der(CONTEXT_0, _der_int(version - 1)) if version > 1 else b""
    tbs += _der_int(serial) + algorithm + _der_name(subject if issuer is None else issuer)
    tbs += _der(SEQUENCE, _der_time(not_before) + _der_time(not_after)) + _der_name(subject)
    tbs += _der_public_key(key_algorithm, key_bits)
    signature = _der(BIT_STRING, b"\0" + b"\x5a" * max(64, key_bits // 8))
    return _der(SEQUENCE, _der(SEQUENCE, tbs) + algorithm + signature)


def _lp_join(*items: bytes) -> bytes:
    return b"".join(struct.pack("<I", len(item)) + item for item in items)


def _build_signers(certs: Sequence[Union[bytes, Sequence[bytes]]],
                   sdks: Optional[Tuple[int, int]]) -> bytes:
    signers = []
    sdk = struct.pack("<II", *sdks) if sdks else b""
    for chain in certs:
        chain = [chain] if isinstance(chain, (bytes, bytearray)) else list(chain)
        digests = _lp_join(struct.pack("<I", 0x0103) + _lp_join(bytes(32)))
        signed = _lp_join(digests) + _lp_join(_lp_join(*chain)) + sdk + _lp_join(b"")
        signatures = _lp_join(struct.pack("<I", 0x0103) + _lp_join(b"\x5a" * 256))
        signers.append(_lp_join(signed) + sdk + _lp_join(signatures) + _lp_join(b"public key"))
    return _lp_join(_lp_join(*signers))


def build_v2_block(certs: Sequence[Union[bytes, Sequence[bytes]]]) -> bytes:
    """The value of a v2 signature pair for tests: one signer per item of certs, an item
    being a certificate or a chain (the signer's certificate first). Digests, signatures
    and keys are fake."""
    return _build_signers(certs, None)


def build_v3_block(certs: Sequence[Union[bytes, Sequence[bytes]]], min_sdk: int = 24,
                   max_sdk: int = 0x7FFFFFFF) -> bytes:
    """The value of a v3 (or v3.1) signature pair for tests, like build_v2_block."""
    return _build_signers(certs, (min_sdk, max_sdk))


def build_signing_block(pairs: Sequence[Tuple[int, bytes]]) -> bytes:
    """An APK Signing Block holding (id, value) pairs."""
    body = b"".join(struct.pack("<QI", len(value) + 4, pair_id) + value for pair_id, value in pairs)
    size = struct.pack("<Q", len(body) + 24)
    return size + body + size + BLOCK_MAGIC


def _ber(tag: int, content: bytes) -> bytes:
    return bytes([tag, 0x80]) + content + b"\0\0"


def build_pkcs7(certs: Sequence[bytes], *, indefinite: bool = False) -> bytes:
    """A PKCS#7 SignedData block as a META-INF/*.RSA file holds it, for tests: the
    certificates and one signer naming the first of them (fake signature). indefinite
    writes the outer layers with BER indefinite lengths."""
    wrap = _ber if indefinite else _der
    issuer, serial = _issuer_and_serial(bytes(certs[0]))
    digest = _der(SEQUENCE, _der_oid(OID_SHA256) + _der(NULL, b""))
    signer = _der(SEQUENCE, _der_int(1) + _der(SEQUENCE, issuer + _der(INTEGER, serial)) + digest
                  + _der(SEQUENCE, _der_oid(OID_RSA) + _der(NULL, b""))
                  + _der(OCTET_STRING, b"\x5a" * 256))
    signed = _der_int(1) + _der(SET, digest) + _der(SEQUENCE, _der_oid(OID_DATA))
    signed += wrap(CONTEXT_0, b"".join(certs)) + _der(SET, signer)
    return wrap(SEQUENCE, _der_oid(OID_SIGNED_DATA) + wrap(CONTEXT_0, wrap(SEQUENCE, signed)))


def sign_zip(zip_bytes: bytes, block: bytes) -> bytes:
    """Insert an APK Signing Block before the central directory of a ZIP archive and move
    the central directory offset in the end record, as apksigner does."""
    eocd = zip_bytes.rfind(EOCD_SIGNATURE)
    if eocd < 0:
        raise ValueError("not a ZIP archive")
    cd_offset = struct.unpack_from("<I", zip_bytes, eocd + 16)[0]
    out = bytearray(zip_bytes[:cd_offset] + block + zip_bytes[cd_offset:])
    struct.pack_into("<I", out, eocd + len(block) + 16, cd_offset + len(block))
    return bytes(out)
