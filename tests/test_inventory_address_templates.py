"""Observed corpus URL shapes must retain literal values and honest provenance."""
from pathlib import Path

import pytest

from sca.flutter import inventory
from sca.flutter.context import MobileContext
from sca.flutter.xmltree import parse_xml_text
from sca.walker import SourceFile
from tools.independent_apk_audit import url_value


def source(text, rel="classes.dex", origin="strings"):
    return SourceFile(Path(rel), rel, "config", text, origin=origin)


@pytest.mark.parametrize("address", [
    "https://cdn.audit.example/assets/EmptyState{scale}.png",
    "https://s3.audit.example/subscription/{filePath}",
    "https://{subdomain}.{region}.sessions.audit.example/v4/verify",
    "https://iamcredentials.%s/v1/projects/-/serviceAccounts/%s:generateAccessToken",
    "https://sts.{universe_domain}/v1/token",
    "https://sts.{region}.amazonaws.com",
    "https://%s.%s/room-size",
    "https://api.audit.example/v1/${user.id}?token=${accessToken}",
    "https://$subdomain.audit.example/v1/$itemId",
    "http://localhost:%d/api",
    "http://127.0.0.1:${port}/api",
])
def test_runtime_templates_are_complete_navigable_unresolved_literals(address):
    sf = source("before\n" + address + "\nafter")
    item, = inventory.build(None, [sf], [], reveal_values=True)["endpoints"]
    assert item["url"] == address
    assert item["evidence_kind"] == "url_template"
    assert item["requires_runtime_resolution"] is True
    assert item["locations"] == [{"file": sf.rel, "line": 2}]
    assert item["url"] in sf.lines[item["locations"][0]["line"] - 1]
    assert "secret_in_url" not in item["alerts"]


@pytest.mark.parametrize("address", [
    "http://[fd00:ec2::254]", "https://[2001:db8::1]",
    "https://[2001:db8::1]:443/api", "https://api.audit.example/v1/(public)",
])
def test_balanced_url_brackets_survive(address):
    item, = inventory.build(None, [source(address)], [], reveal_values=True)["endpoints"]
    assert item["url"] == address
    assert not item.get("requires_runtime_resolution")


@pytest.mark.parametrize("address", [
    "https://api.audit.example:{bad port}/v1", "https://api.audit.example:invalid/v1",
    "https://api.audit.example:999999/v1", "https://{unclosed.audit.example/path",
    "https://api.audit.example/{not+a+placeholder}",
])
def test_malformed_templates_or_ports_are_not_asserted_as_valid_urls(address):
    assert inventory.build(None, [source(address)], [], reveal_values=True)["endpoints"] == []


def test_punctuation_after_a_complete_url_does_not_cut_balanced_placeholder():
    address = "https://cdn.audit.example/{resource}"
    sf = source("See (" + address + ").")
    item, = inventory.build(None, [sf], [], reveal_values=True)["endpoints"]
    assert item["url"] == address
    assert url_value(address) == address
    assert url_value(address + ").") == address


def test_referenced_manifest_config_points_to_the_actual_resource_value():
    value = "FixtureResourceValue0123456789"
    text = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n'
            '<application><meta-data android:name="com.google.android.geo.API_KEY"\n'
            'android:value="@string/maps_key"/></application></manifest>')
    manifest = source(text, "AndroidManifest.xml", "decoded")
    resource = source('<resources>\n<string name="maps_key">' + value +
                      '</string>\n</resources>', "res/values/strings.xml", "decoded")
    tree, error = parse_xml_text(text)
    assert not error
    ctx = MobileContext(kind="apk", root=Path("fixture.apk"), files=[manifest, resource],
                        manifests=[(manifest.rel, tree)])
    entries = inventory.build(ctx, ctx.files, [], reveal_values=True)["config"]
    item, = [entry for entry in entries if entry["value"] == value]
    assert item["locations"] == [{"file": resource.rel, "line": 2}]
    assert value not in manifest.text


def test_google_maps_navigation_is_retained_but_namespace_and_documentation_are_not():
    address = "https://www.google.com/maps/search/?api=1&query=${e.latitude},${e.longitude}"
    sf = source(address + "\nhttps://www.google.com/kml/ext/2.2\nhttps://www.google.com")
    item, = inventory.build(None, [sf], [], reveal_values=True)["endpoints"]
    assert item["url"] == address and item["requires_runtime_resolution"]
    assert item["locations"] == [{"file": sf.rel, "line": 1}]


def test_terminal_asterisk_is_retained_as_literal_url_evidence():
    address = "https://payment.audit.example/p/s/i.*scheme=.*"
    item, = inventory.build(None, [source(address)], [], reveal_values=True)["endpoints"]
    assert item["url"] == address
