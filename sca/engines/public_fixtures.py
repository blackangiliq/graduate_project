"""Exact public SDK fixture fingerprints, with immutable upstream source revisions.

No credential literals are stored here. A match identifies published test material;
it does not determine how the app uses that material at runtime.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Optional


MAX_FIXTURE_VALUE = 128 << 10
PEM_KIND = "pem_der_sha256"
JWT_KIND = "jwt_sha256"
FIXTURE_ADVICE = (
    "Review whether this public SDK fixture is used only for tests or capability probes. "
    "Runtime trust or signing with it would require remediation; its presence alone is not a secret leak."
)
_NETTY_COMMIT = "7c16c1a783b7e7f45f16c4dd9e16685a5d28712d"
_GOOGLE_COMMIT = "cfdb6e8db0fc35148112972d0e9383f30c09b97c"
_NETTY_SOURCE = ("https://raw.githubusercontent.com/netty/netty/" + _NETTY_COMMIT +
                 "/handler/src/main/java/io/netty/handler/ssl/SslUtils.java")
_GOOGLE_SOURCE = ("https://raw.githubusercontent.com/googleapis/google-http-java-client/" +
                  _GOOGLE_COMMIT + "/google-http-client/src/main/java/com/google/api/client/"
                  "testing/json/webtoken/TestCertificates.java")

# PEM digests cover decoded DER; JWT digests cover the complete exact ASCII token.
PUBLIC_FIXTURES = {
    (PEM_KIND, "9186408b8399cd7bd95651a76d3f603b0b91631f5e6a226ef057cc48b4224398"):
        {"library": "Netty", "symbol": "SslUtils.PROBING_KEY", "source": _NETTY_SOURCE,
         "commit": _NETTY_COMMIT},
    (PEM_KIND, "04fb5ba76efffe3861a2139869bdb2673adb37d1344585fb4dd866d9e78b953d"):
        {"library": "Google HTTP Client", "symbol": "TestCertificates.CA_KEY",
         "source": _GOOGLE_SOURCE, "commit": _GOOGLE_COMMIT},
    (PEM_KIND, "a0757796dab4f4851a25c8c51fdbacc7431d86bc777aa38bd50cc230417935b3"):
        {"library": "Google HTTP Client", "symbol": "TestCertificates.FOO_BAR_COM_KEY",
         "source": _GOOGLE_SOURCE, "commit": _GOOGLE_COMMIT},
    (JWT_KIND, "bbca296facaefce5867917a4a4a4fa0885a54b01b989de99e541781217b4e107"):
        {"library": "Google HTTP Client", "symbol": "TestCertificates.JWS_SIGNATURE",
         "source": _GOOGLE_SOURCE, "commit": _GOOGLE_COMMIT},
}


def fixture_for_digest(kind: str, digest: str) -> Optional[dict]:
    item = PUBLIC_FIXTURES.get((kind, digest))
    if item is None:
        return None
    return {**item, "digest_kind": kind, "sha256": digest,
            "title": "Known public SDK test private key" if kind == PEM_KIND
            else "Known public SDK test JWT"}


def identify_public_fixture(value: str) -> Optional[dict]:
    """Return provenance only on an exact fingerprint match, never on a filename/label."""
    if len(value) > MAX_FIXTURE_VALUE:
        return None
    if value.startswith("-----BEGIN "):
        match = re.fullmatch(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----\s*(.*?)\s*-----END \1-----",
                             value, re.S)
        if match is None:
            return None
        try:
            data = base64.b64decode(re.sub(r"\s", "", match[2]), validate=True)
        except (ValueError, binascii.Error):
            return None
        return fixture_for_digest(PEM_KIND, hashlib.sha256(data).hexdigest())
    if value.startswith("eyJ") and value.count(".") == 2:
        try:
            data = value.encode("ascii")
        except UnicodeEncodeError:
            return None
        return fixture_for_digest(JWT_KIND, hashlib.sha256(data).hexdigest())
    return None


def fixture_description(item: dict) -> str:
    return ("This value exactly matches published SDK test material: %s %s. "
            "Match: %s %s. Source: %s. Its presence alone does not demonstrate a leaked "
            "production secret. %s" % (item["library"], item["symbol"], item["digest_kind"],
                                       item["sha256"], item["source"], FIXTURE_ADVICE))
