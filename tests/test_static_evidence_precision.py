"""Regressions from manual inspection of the real Android app audit."""
from pathlib import Path
import json

import pytest

from sca.engines import secrets
from sca.flutter import checks, inventory, tools
from sca.flutter.context import MobileContext
from sca.flutter.xmltree import parse_xml_text
from sca.walker import SourceFile


def source(text, rel="lib/arm64-v8a/libapp.so", origin="strings"):
    return SourceFile(Path(rel), rel, "config", text, origin=origin)


def compiled_findings(text):
    sf = source(text)
    ctx = MobileContext(kind="apk", root=Path("review.apk"), files=[sf],
                        strings_files=[sf.rel], facts={"flutter": True})
    findings, _ = checks.analyze(ctx, {sf.rel: sf})
    return findings


def test_sdk_policy_link_is_not_a_cleartext_api_finding():
    addresses = ["http://developers.facebook.com/policy/",
                 "http://developers.facebook.com/api/fixture",
                 "http://service.example/policy/"]
    findings = compiled_findings("\n".join(addresses))
    assert [f.line for f in findings if f.rule_id == "FLUTTER-APP-007"] == [2, 3]
    listed = inventory.build(None, [source("\n".join(addresses))], [], reveal_values=True)
    assert {item["url"] for item in listed["endpoints"]} == set(addresses[1:])


def test_compiled_sql_fragment_requires_execution_and_input_review():
    findings = compiled_findings("SELECT * FROM users WHERE name = '")
    finding, = [f for f in findings if f.rule_id == "FLUTTER-APP-008"]
    assert finding.severity == "low" and finding.confidence <= .45
    assert "fragment" in finding.title and "review" in finding.title
    assert "do not establish execution" in finding.description
    assert "allows SQL injection" not in finding.description
    assert "input flow" in finding.fix


@pytest.mark.parametrize("address", [
    "http://localhost:8080/api/status", "http://localhost:%d/api", "ws://localhost:9090/debug",
    "http://127.0.0.1:8080/api", "http://127.0.1.2/api", "http://10.0.2.2:8081/status",
    "http://10.0.3.2:8081/status", "http://[::1]", "http://[::1]:8080/api",
])
def test_local_addresses_are_navigable_inventory_evidence_without_security_alerts(address):
    sf = source("before\n" + address + "\nafter")
    out = inventory.build(None, [sf], [], reveal_values=True)
    item, = out["endpoints"]
    assert item["url"] == address
    assert item["category"] == inventory.LOCAL and item["alerts"] == []
    assert item["locations"] == [{"file": sf.rel, "line": 2}]
    assert not any(a["code"] in {"cleartext", "private_ip", "ip_host", "dev_host"}
                   for a in out["alerts"])
    assert not [f for f in compiled_findings(address) if f.rule_id == "FLUTTER-APP-007"]


def test_private_lan_addresses_and_runtime_metadata_keep_existing_inventory_classification():
    addresses = ["http://192.168.5.10/api", "http://metadata.google.internal/computeMetadata/v1/"]
    out = inventory.build(None, [source("\n".join(addresses))], [], reveal_values=True)
    by_url = {item["url"]: item for item in out["endpoints"]}
    assert set(by_url) == set(addresses)
    assert all(item["category"] != inventory.LOCAL for item in by_url.values())
    assert "private_ip" in by_url[addresses[0]]["alerts"]


def test_manifest_reference_to_maps_key_gets_maps_advice_without_downgrading_unknown_keys():
    maps = "AIza" + "M" * 35
    unknown = "AIza" + "U" * 35
    xml = '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n' \
          '<application><meta-data android:name="com.google.android.geo.API_KEY" ' \
          'android:value="@string/google_maps_api_key"/></application></manifest>'
    manifest = source(xml, "AndroidManifest.xml", "decoded")
    resources = source('<resources>\n<string name="google_maps_api_key">' + maps +
                       '</string>\n<string name="apiKeyProd">' + unknown + '</string>\n</resources>',
                       "res/values/strings.xml", "decoded")
    root, error = parse_xml_text(xml)
    assert not error
    ctx = MobileContext(kind="apk", root=Path("review.apk"), files=[manifest, resources],
                        manifests=[(manifest.rel, root)])
    findings = secrets.scan_file(resources, rules=[])
    checks.refine(findings, {resources.rel: resources}, ctx)
    out = inventory.build(ctx, ctx.files, findings, reveal_values=True)
    keys = {item["value"]: item for item in out["keys"]}
    assert keys[maps]["advice"] == "google" and "Google Maps" in keys[maps]["used_by"]
    assert "security rules" not in keys[maps]["advice_text"].lower()
    assert keys[unknown]["severity"] == "high" and not keys[unknown]["public"]


def test_kotlin_to_string_runtime_token_field_is_not_a_literal_secret():
    sf = source('return un30.l("PushTokenUpdateReqModel(firebaseRegistrationToken=", '
                'this.firebaseRegistrationToken, ", firebaseAppInstanceId=", '
                'this.firebaseAppInstanceId, ")");', "jadx/example/Model.java", "decompiled")
    assert secrets.scan_file(sf, rules=[]) == []
    real = source('firebaseRegistrationToken="Fixture2Secret4Value6";',
                  "jadx/example/Client.java", "decompiled")
    assert any(f.rule_id == "SECRET-HARDCODED-001" for f in secrets.scan_file(real, rules=[]))


def test_jadx_cache_preserves_errors_and_exact_omission_count(tmp_path, monkeypatch):
    apk = tmp_path / "classes.dex"
    apk.write_bytes(b"fixture dex")
    out = tmp_path / "output"
    monkeypatch.setattr(tools, "availability", lambda: {"jadx": "jadx"})
    monkeypatch.setattr(tools, "MAX_JAVA_FILES", 2)
    calls = []
    def run(command, timeout):
        calls.append(command)
        work = Path(command[command.index("--output-dir-src") + 1])
        for name in ("fixture/A", "fixture/B", "fixture/C", "unrelated/Other"):
            path = work / (name + ".java")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class Fixture {}", encoding="utf-8")
        return 1, "ERROR - fixture decompilation warning"
    monkeypatch.setattr(tools, "_run", run)
    files, first = tools.jadx_decompile(apk, out, ["fixture.*"])
    assert len(files) == 2 and "1 matching Java files omitted" in first
    assert "jadx reported errors" in first
    cached, again = tools.jadx_decompile(apk, out, ["fixture.*"])
    assert cached == files and len(calls) == 1
    assert first in again and "earlier scan" in again
    marker = json.loads((out / tools.MARKER).read_text(encoding="utf-8"))
    assert marker["omitted_files"] == 1
    del marker["note"]
    (out / tools.MARKER).write_text(json.dumps(marker), encoding="utf-8")
    _, legacy = tools.jadx_decompile(apk, out, ["fixture.*"])
    assert "status unavailable" in legacy and len(calls) == 1
