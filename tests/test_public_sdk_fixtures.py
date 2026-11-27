"""Exact fingerprint classification; public fixtures remain visible, unknown keys do not downgrade."""
import base64
import hashlib
from pathlib import Path

import pytest

from sca.engines import public_fixtures, secrets
from sca.flutter import inventory
from sca.merge import merge_findings
from sca.walker import SourceFile


@pytest.mark.parametrize("kind,digest,symbol", [
    (public_fixtures.PEM_KIND, "9186408b8399cd7bd95651a76d3f603b0b91631f5e6a226ef057cc48b4224398", "SslUtils.PROBING_KEY"),
    (public_fixtures.PEM_KIND, "04fb5ba76efffe3861a2139869bdb2673adb37d1344585fb4dd866d9e78b953d", "TestCertificates.CA_KEY"),
    (public_fixtures.PEM_KIND, "a0757796dab4f4851a25c8c51fdbacc7431d86bc777aa38bd50cc230417935b3", "TestCertificates.FOO_BAR_COM_KEY"),
    (public_fixtures.JWT_KIND, "bbca296facaefce5867917a4a4a4fa0885a54b01b989de99e541781217b4e107", "TestCertificates.JWS_SIGNATURE"),
])
def test_registered_fingerprints_have_pinned_upstream_provenance(kind, digest, symbol):
    found = public_fixtures.fixture_for_digest(kind, digest)
    assert found["symbol"] == symbol and found["sha256"] == digest
    assert len(found["commit"]) == 40 and "/" + found["commit"] + "/" in found["source"]
    assert found["source"].startswith("https://raw.githubusercontent.com/")
    assert public_fixtures.fixture_for_digest(kind, digest[:-1] + ("0" if digest[-1] != "0" else "1")) is None
    other_kind = public_fixtures.JWT_KIND if kind == public_fixtures.PEM_KIND else public_fixtures.PEM_KIND
    assert public_fixtures.fixture_for_digest(other_kind, digest) is None


def synthetic_key(seed):
    data = bytes.fromhex("302e020100300506032b657004220420") + bytes((seed + i) % 256 for i in range(32))
    pem = "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(data).decode() + "\n-----END PRIVATE KEY-----"
    return pem, hashlib.sha256(data).hexdigest()


def allow_fixture(monkeypatch, kind, digest):
    metadata = {"library": "Fixture SDK", "symbol": "Test.PUBLIC_VALUE", "commit": "1" * 40,
                "source": "https://example.invalid/source/" + "1" * 40 + "/Fixture.java"}
    monkeypatch.setitem(public_fixtures.PUBLIC_FIXTURES, (kind, digest), metadata)
    return metadata


@pytest.mark.parametrize("escaped", [False, True])
def test_public_pem_is_info_with_full_value_and_nearby_unknown_remains_critical(monkeypatch, escaped):
    known, digest = synthetic_key(71)
    unknown, _ = synthetic_key(72)
    metadata = allow_fixture(monkeypatch, public_fixtures.PEM_KIND, digest)
    body = known + "\n" + unknown
    if escaped:
        body = 'String first="' + known.replace("\n", r"\n") + '";\nString second="' + unknown.replace("\n", r"\n") + '";'
    sf = SourceFile(Path("classes.dex"), "classes.dex", "config", body, origin="strings")
    findings = merge_findings(secrets.scan_file(sf, rules=[]))
    public, = [f for f in findings if f.severity == "info"]
    critical, = [f for f in findings if f.severity == "critical"]
    assert public.title == "Known public SDK test private key"
    assert metadata["source"] in public.description and "not a secret leak" in public.fix
    assert critical.rule_id == public.rule_id == "SECRET-KEY-001"
    assert sf.text == body and sf.lines[public.line - 1][public.column - 1:].startswith("-----BEGIN")
    shown = inventory.build(None, [sf], findings, reveal_values=True)
    keys = {key["value"]: key for key in shown["keys"]}
    assert set(keys) == {known, unknown}
    assert keys[known]["severity"] == "info" and keys[known]["public"]
    assert keys[known]["advice"] == "public_fixture"
    assert keys[known]["provenance"]["sha256"] == digest
    assert metadata["source"] in keys[known]["used_by"]
    assert keys[known]["locations"] == [{"file": sf.rel, "line": public.line}]
    assert keys[unknown]["severity"] == "critical" and not keys[unknown]["public"]
    assert shown["summary"]["keys"] == 2 and shown["summary"]["secret_keys"] == 1


def test_public_jwt_requires_exact_token_digest_and_retains_unknown_jwt(monkeypatch):
    encode = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
    token = ".".join((encode(b'{"alg":"RS256"}'), encode(b'{"foo":"bar"}'), encode(b"synthetic-signature-for-tests")))
    unknown = token[:-1] + ("Z" if token[-1] != "Z" else "Y")
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    metadata = allow_fixture(monkeypatch, public_fixtures.JWT_KIND, digest)
    sf = SourceFile(Path("classes.dex"), "classes.dex", "config", token + "\n" + unknown, origin="strings")
    findings = secrets.scan_file(sf, rules=[])
    assert [(f.rule_id, f.severity, f.line) for f in findings] == [
        ("SECRET-JWT-001", "info", 1), ("SECRET-JWT-001", "medium", 2)]
    assert metadata["source"] in findings[0].description
    shown = inventory.build(None, [sf], findings, reveal_values=True)
    keys = {key["value"]: key for key in shown["keys"]}
    assert keys[token]["type"] == "Known public SDK test JWT"
    assert keys[token]["public"] and keys[token]["severity"] == "info"
    assert not keys[unknown]["public"] and keys[unknown]["severity"] == "medium"
    assert keys[token]["provenance"]["digest_kind"] == public_fixtures.JWT_KIND


def test_malformed_or_unregistered_values_do_not_match_public_fixture_registry():
    for value in ("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n?\n-----END PRIVATE KEY-----",
                  "TestCertificates.CA_KEY", "SslUtils.PROBING_KEY", "eyJ" + "a" * 200_000):
        assert public_fixtures.identify_public_fixture(value) is None
