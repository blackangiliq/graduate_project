"""Regression cases for observed APK extraction and inventory coverage gaps."""
from pathlib import Path
import base64
import re

import pytest
import flutter_kit as kit

from sca.engines import secrets, rules_engine
from sca.flutter import apk, inventory
from sca.walker import SourceFile


GOOGLE = "AIza" + "CoverageFixtureKeyOnly0123456789abcde"[:35]


def source(text, rel="assets/config.json", language="config", origin="decoded"):
    return SourceFile(Path(rel), rel, language, text, origin=origin)


@pytest.mark.parametrize("prefix", [570, 990, 2030, 5000])
def test_key_survives_old_wrap_and_detector_boundaries(prefix):
    literal = "x" * prefix + " " + GOOGLE
    sf = source("\n".join(apk._string_lines("service_config", literal)),
                "res/values/strings.xml")
    findings = secrets.scan_file(sf, rules=[])
    assert len(sf.lines) == 1
    assert sf.lines[0].endswith(GOOGLE + "</string>")
    hits = [hit for hit in sf.secret_hits if hit[1] == "SECRET-GOOGLE-001"]
    assert [(hit[0], hit[2]) for hit in hits] == [(1, GOOGLE)]
    assert [f.line for f in findings] == [1]


def test_binary_dump_preserves_long_token_and_line_coordinates():
    token = "ghp_" + "A0b1C2d3E4f5G6h7I8j9" * 80
    lines = apk.dump_lines(["before", token, "after"], 10)
    assert lines == ["before", token, "after"]
    sf = source("\n".join(lines), "lib/arm64-v8a/libapp.so", origin="strings")
    secrets.scan_file(sf, rules=[])
    assert [(hit[0], hit[2]) for hit in sf.secret_hits] == [(2, token)]


def test_real_apk_xml_preserves_long_attribute_and_resource_value(tmp_path):
    value = "prefix-" + "R" * 1200 + " " + GOOGLE
    manifest = kit.MANIFEST.replace('android:label="@string/app_name"',
                                    'android:label="%s"' % value)
    path = tmp_path / "complete-values.apk"
    path.write_bytes(kit.build_apk(manifest=manifest, strings={"app_name": "Fixture", "config": value}))
    ctx = apk.load_app(path)
    files = {sf.rel: sf for sf in ctx.files}
    app = ctx.manifests[0][1].find("application")
    number = app.line_of("android:label")
    sf = files["AndroidManifest.xml"]
    assert value in sf.lines[number - 1]
    secrets.scan_file(sf, rules=[])
    assert (number, "SECRET-GOOGLE-001", GOOGLE) in [hit[:3] for hit in sf.secret_hits]
    assert any(value in line for line in files["res/values/strings.xml"].lines)


def test_imported_pattern_crosses_window_boundary_once_without_partial_value():
    token = "fixture_token_" + "A2b4C6d8E0" * 5
    rule = rules_engine.Rule("TEST-WINDOW", "Fixture pattern", ["any"], "CWE-798", "high",
                             .8, re.compile(r"fixture_token_[A-Za-z0-9]{50}"),
                             kind="secret", keywords=["fixture_token_"])
    sf = source("x" * 2035 + " " + token + " " + "x" * 5000)
    secrets.scan_file(sf, rules=[rule])
    assert [(hit[0], hit[2]) for hit in sf.secret_hits] == [(1, token)]


def test_generic_assignment_on_long_line_uses_original_line_once():
    value = "D4t8F2k6L0m3P7q1R5s9"
    sf = source('padding="' + "X" * 5000 + '", api_key="' + value + '"')
    secrets.scan_file(sf, rules=[])
    assert [(hit[0], hit[2]) for hit in sf.secret_hits] == [(1, value)]


def test_long_line_urls_remain_complete_and_keep_the_scanned_line():
    address = "https://api.coverage.example/v1/events?cursor=" + "a" * 5000
    sf = source('const value = "' + "x" * 6000 + '"; const url = "' + address + '";',
                "src/client.js", "javascript", "")
    result = inventory.build(None, [sf], [], reveal_values=True)
    assert result["endpoints"][0]["url"] == address
    assert result["endpoints"][0]["locations"] == [{"file": sf.rel, "line": 1}]
    assert result["coverage"]["context_lines_skipped"] == 1
    assert result["coverage"]["literal_urls_scanned"] is True


@pytest.mark.parametrize("value", ["", "%s", "%1$s", "%2$d", "%(token)s", "$token", "***"])
def test_runtime_query_templates_are_addresses_not_embedded_secret_alerts(value):
    address = "https://api.coverage.example/events?api_key=" + value
    sf = source(address, "classes.dex", origin="strings")
    result = inventory.build(None, [sf], [], reveal_values=True)
    assert result["summary"]["endpoints"] == 1
    assert "secret_in_url" not in result["endpoints"][0]["alerts"]


def test_literal_query_values_still_alert_and_remain_visible():
    address = "https://api.coverage.example/events?api_key=Fixture2Auth4Value6"
    result = inventory.build(None, [source(address)], [], reveal_values=True)
    assert result["endpoints"][0]["url"] == address
    assert "secret_in_url" in result["endpoints"][0]["alerts"]


def test_dashboard_inventory_does_not_apply_legacy_report_row_and_location_caps():
    addresses = [f"https://api.coverage.example/v1/item/{number}" for number in range(450)]
    sf = source("\n".join(addresses + [addresses[0]] * 45))
    shown = inventory.build(None, [sf], [], reveal_values=True)
    assert len(shown["endpoints"]) == 450 == shown["summary"]["endpoints"]
    first = next(item for item in shown["endpoints"] if item["url"] == addresses[0])
    assert len(first["locations"]) == 46 == first["count"]
    assert "endpoints" not in shown.get("truncated", {})
    legacy = inventory.build(None, [sf], [])
    assert len(legacy["endpoints"]) == inventory.MAX_ITEMS


def test_visible_inventory_explicit_collection_limit_is_counted(monkeypatch):
    monkeypatch.setattr(inventory, "MAX_VISIBLE_ITEMS", 3)
    sf = source("\n".join(f"https://api.coverage.example/item/{n}" for n in range(8)))
    result = inventory.build(None, [sf], [], reveal_values=True)
    assert len(result["endpoints"]) == 3
    assert result["summary"]["endpoints"] == 8
    assert result["truncated"]["endpoints"] == 5


def test_native_library_budget_covers_more_than_ten_libraries(tmp_path):
    libraries = {f"libfeature{n:02}.so": f"https://feature{n}.coverage.example/v1/api".encode()
                 for n in range(12)}
    path = tmp_path / "many-libraries.apk"
    path.write_bytes(kit.build_apk(native_libs=libraries))
    ctx = apk.load_app(path)
    files = {sf.rel for sf in ctx.files}
    assert all("lib/arm64-v8a/" + name in files for name in libraries)
    assert not any("only the first 10" in warning for warning in ctx.warnings)


def test_plain_react_native_bundle_above_one_mib_is_read_as_javascript(tmp_path):
    text = 'var padding="' + "p" * ((1 << 20) + 200) + '"; var key="' + GOOGLE + '";'
    path = tmp_path / "react-native.apk"
    path.write_bytes(kit.build_apk(mode="none", assets={"index.android.bundle": text}))
    ctx = apk.load_app(path)
    sf = next(sf for sf in ctx.files if sf.rel == "assets/index.android.bundle")
    assert sf.language == "javascript" and sf.origin == "decoded"
    assert len(sf.lines) == 1 and sf.lines[0] == text
    findings = secrets.scan_file(sf, rules=[])
    finding = next(f for f in findings if f.rule_id == "SECRET-GOOGLE-001")
    assert finding.line == 1 and finding.column == text.index(GOOGLE) + 1
    assert finding.end_column == finding.column + len(GOOGLE)
    assert len(finding.context) < 600 and "columns" in finding.context
    assert GOOGLE in sf.lines[0]


def test_binary_javascript_bundle_is_marked_strings_only(tmp_path):
    content = b"\xc6\x1f\xbc\x03\x00\x00" + b"https://binary.coverage.example/v1/items\0" + GOOGLE.encode() + b"\0"
    path = tmp_path / "binary-bundle.apk"
    path.write_bytes(kit.build_apk(mode="none", assets={"index.android.bundle": content}))
    ctx = apk.load_app(path)
    sf = next(sf for sf in ctx.files if sf.rel == "assets/index.android.bundle")
    assert sf.origin == "strings" and sf.language == "config"
    assert GOOGLE in sf.lines
    assert any("Binary JavaScript bundle: only embedded strings" in w for w in ctx.warnings)


@pytest.mark.parametrize("prefix,inner,pattern", [
    ("wrka-", "eyJ" + "a" * 32 + ".eyJ" + "b" * 40 + "." + "c" * 30,
     r"wrka-eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    # Assemble the synthetic fixture instead of publishing a token-shaped literal.
    ("xoxe.", "xoxb-" + "123456789012-" + "ABCdef123456789012",
     r"xoxe\.xoxb-[A-Za-z0-9-]+"),
])
def test_provider_wrapper_takes_precedence_over_inner_generic_token(prefix, inner, pattern):
    value = prefix + inner
    rule = rules_engine.Rule("TEST-WRAPPED", "Complete provider credential", ["any"],
                             "CWE-798", "high", .9, re.compile(pattern), kind="secret")
    sf = source('token="' + value + '"')
    findings = secrets.scan_file(sf, rules=[rule])
    assert len(findings) == 1 and findings[0].rule_id == "TEST-WRAPPED"
    assert [hit[2] for hit in sf.secret_hits] == [value]


def test_long_jwt_is_detected_without_splitting_or_partial_value():
    token = "eyJ" + "a" * 1500 + ".eyJ" + "b" * 1500 + "." + "c" * 35
    sf = source('token="' + token + '"')
    findings = secrets.scan_file(sf, rules=[])
    assert [hit[2] for hit in sf.secret_hits] == [token]
    assert findings[0].column == 8


def private_pem(seed=0):
    # RFC 8410 Ed25519 PrivateKeyInfo with a local deterministic fixture seed.
    der = bytes.fromhex("302e020100300506032b657004220420") + bytes((seed + i) % 256 for i in range(32))
    body = base64.b64encode(der).decode()
    return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"


@pytest.mark.parametrize("escape", [False, True])
def test_complete_pem_values_are_distinct_and_keep_actual_source_coordinates(escape):
    first, second = private_pem(0), private_pem(23)
    body = first + "\n" + second
    if escape:
        body = 'const key1="' + first.replace("\n", r"\n") + '";\nconst key2="' + second.replace("\n", r"\n") + '";'
    sf = source(body, "assets/keys.js", "javascript")
    findings = secrets.scan_file(sf, rules=[])
    assert len(findings) == 2
    assert {hit[2] for hit in sf.secret_hits} == {first, second}
    for finding in findings:
        assert sf.lines[finding.line - 1][finding.column - 1:].startswith("-----BEGIN PRIVATE KEY-----")
        assert sf.lines[finding.end_line - 1][:finding.end_column - 1].endswith("-----END PRIVATE KEY-----")
    shown = inventory.build(None, [sf], findings, reveal_values=True)
    assert len(shown["keys"]) == 2 and {key["value"] for key in shown["keys"]} == {first, second}
    assert all(first.splitlines()[1] not in f.context and second.splitlines()[1] not in f.context for f in findings)


def test_private_key_formatter_and_marker_constants_are_not_private_material():
    text = ('var PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----";\n'
            'function getPrivateKey(){var t="-----BEGIN RSA PRIVATE KEY-----\\n";'
            'return t+=wrap(getPrivateBaseKeyB64())+"\\n",t+="-----END RSA PRIVATE KEY-----";}\n'
            'const EC_END="-----END EC PRIVATE KEY-----";')
    sf = source(text, "assets/index.android.bundle", "javascript")
    marker_rule = rules_engine.Rule("TEST-PEM", "Marker only", ["any"], "CWE-798", "high", .9,
                                   re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), kind="secret")
    assert secrets.scan_file(sf, rules=[marker_rule]) == []


@pytest.mark.parametrize("body", ["not-a-key", "A" * 64, base64.b64encode(b"randomly-labelled-body" * 4).decode()])
def test_pem_delimiters_with_invalid_or_non_key_body_are_not_secret_keys(body):
    sf = source("-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----")
    assert secrets.scan_file(sf, rules=[]) == []


def test_static_literal_pem_concatenation_is_recognized_without_executing_code():
    value = private_pem()
    text = 'const key="' + '" +\n"'.join(value.replace("\n", "\\n\n").splitlines()) + '";'
    sf = source(text, "assets/config.js", "javascript")
    findings = secrets.scan_file(sf, rules=[])
    assert len(findings) == 1 and sf.secret_hits[0][2] == value


def test_braze_sdk_key_names_remain_public_identifiers():
    value = "11223344-5566-7788-99aa-bbccddeeff00"
    sf = source(f'<string name="com_braze_api_key">{value}</string>', "res/values/strings.xml")
    shown = inventory.build(None, [sf], [], reveal_values=True)
    assert shown["config"][0]["value"] == value
    assert shown["config"][0]["label"] == "Braze SDK app identifier"
    assert shown["config"][0]["secret"] is False


@pytest.mark.parametrize("text", [
    "const types={'new-password':'password-new'};",
    "const types={'new-password':'newPassword'};",
    "PushTokenKey:'@userStore:pushToken'",
    'E.APPLICATION_PASSWORD="ApplicationPassword";',
    "console.log('TOKEN:',e);var t=(0,l.default)(e,'token');",
    "n.password='%filtered%';",
    "e.AI_USAGE_PROMPT_TOKENS_ATTRIBUTE='ai.usage.promptTokens';",
    'o.JoinSessionInvalidPassword="ZoomVideoSDKError_JoinSession_InvalidPassword";',
    'n.onSessionNeedPassword="onSessionNeedPassword";',
])
def test_sdk_ui_enum_and_logging_strings_are_not_secret_assignments(text):
    sf = source(" " * 5000 + text, "assets/index.android.bundle", "javascript")
    assert secrets.scan_file(sf, rules=[]) == []


@pytest.mark.parametrize("text", [
    'apiKey="aN4fQ7jL2xR9tB6kP3vY8mD5";',
    'password="Pr0d-DB-pass!2026";',
])
def test_secret_literals_still_detected_next_to_sdk_identifiers(text):
    sf = source(" " * 5000 + text, "assets/index.android.bundle", "javascript")
    assert secrets.scan_file(sf, rules=[])


def test_base_apk_qualified_resources_keep_keys_endpoints_and_exact_locations(tmp_path):
    localized_key = "AIza" + "LocalizedOnlyFixtureKey0123456789abcd"[:35]
    default_url = "https://service.locale.example/en/terms"
    french_url = "https://service.locale.example/fr/terms"
    arabic_url = "https://service.locale.example/ar/terms"
    entries = [("string", "service_url", default_url),
               ("string", "service_url", french_url, "fr"),
               ("string", "service_url", arabic_url, "ar"),
               ("string", "localized_key", localized_key, "fr")]
    manifest = '<manifest package="com.example.locales"><application/></manifest>'
    path = tmp_path / "base.apk"
    path.write_bytes(kit.zipread.build_zip([
        ("AndroidManifest.xml", kit.axml.encode_axml(kit.compile_xml(manifest)), 8),
        ("resources.arsc", kit.arsc.build_arsc("com.example.locales", entries), 8)]))
    ctx = apk.load_app(path)
    files = {sf.rel: sf for sf in ctx.files}
    assert len(files) == len(ctx.files)
    assert {"res/values/strings.xml", "res/values-fr/strings.xml", "res/values-ar/strings.xml"} <= set(files)
    assert localized_key not in files["res/values/strings.xml"].text
    findings = [finding for sf in ctx.files for finding in secrets.scan_file(sf, rules=[])]
    found, = [f for f in findings if f.rule_id == "SECRET-GOOGLE-001"]
    assert found.file == "res/values-fr/strings.xml"
    assert localized_key in files[found.file].lines[found.line - 1]
    shown = inventory.build(ctx, ctx.files, findings, reveal_values=True)
    by_url = {item["url"]: item for item in shown["endpoints"]}
    for url, rel in [(default_url, "res/values/strings.xml"),
                     (french_url, "res/values-fr/strings.xml"),
                     (arabic_url, "res/values-ar/strings.xml")]:
        location, = by_url[url]["locations"]
        assert location["file"] == rel
        assert url in files[rel].lines[location["line"] - 1]
    key, = shown["keys"]
    assert key["value"] == localized_key
    assert key["locations"] == [{"file": found.file, "line": found.line}]


def test_qualified_resources_have_independent_item_and_global_text_budgets(tmp_path, monkeypatch):
    manifest = '<manifest package="com.example.locales"><application/></manifest>'
    table = kit.arsc.build_arsc("com.example.locales", [
        ("string", "label", "Default"), ("string", "label", "French value", "fr"),
        ("string", "label", "Arabic value", "ar"), ("string", "label", "Urdu value", "ur")])
    path = tmp_path / "locales.apk"
    path.write_bytes(kit.zipread.build_zip([
        ("AndroidManifest.xml", kit.axml.encode_axml(kit.compile_xml(manifest)), 8),
        ("resources.arsc", table, 8)]))
    monkeypatch.setattr(apk, "MAX_STRING_RESOURCES", 1)
    ctx = apk.load_app(path)
    assert len([sf for sf in ctx.files if sf.rel.startswith("res/values-")]) == 3
    monkeypatch.setattr(apk, "MAX_LOCALIZED_STRING_RESOURCES", 2)
    ctx = apk.load_app(path)
    assert len([sf for sf in ctx.files if sf.rel.startswith("res/values-")]) == 2
    assert "Localized string resource limit reached" in ctx.warnings
    monkeypatch.setattr(apk, "MAX_TEXT", 1)
    ctx = apk.load_app(path)
    assert "Localized resource text limit reached" in ctx.warnings


def test_text_raw_resources_keep_urls_keys_and_locations_but_skip_binary(tmp_path):
    address = "https://raw.resource.example/api/content"
    files = [("res/raw/order_items.json", '{"url":"' + address + '","api_key":"' + GOOGLE + '"}'),
             ("res/raw/player.html", '<script src="https://www.youtube.com/iframe_api"></script>'),
             ("res/raw-fr/sample.kml", '<kml><href>https://map.resource.example/tile</href></kml>')]
    entries = [(name, text.encode()) for name, text in files]
    entries += [("res/raw/binary.json", b"\x00\x01" + GOOGLE.encode())]
    path = tmp_path / "raw-resources.apk"
    path.write_bytes(kit.build_apk(mode="none", extra_entries=entries))
    ctx = apk.load_app(path)
    by_rel = {sf.rel: sf for sf in ctx.files}
    assert {name for name, _ in files} <= set(by_rel)
    assert "res/raw/binary.json" not in by_rel
    findings = secrets.scan_file(by_rel[files[0][0]], rules=[])
    shown = inventory.build(ctx, ctx.files, findings, reveal_values=True)
    endpoint = next(item for item in shown["endpoints"] if item["url"] == address)
    assert endpoint["locations"] == [{"file": files[0][0], "line": 1}]
    assert any(key["value"] == GOOGLE for key in shown["keys"])


def test_native_ascii_strings_past_old_raw_run_limit_are_kept():
    address = "https://native.resource.example/late-endpoint"
    data = b"\x00".join([b"Repeated runtime label"] * 100_010 + [address.encode()])
    lines, reason = apk._native_string_lines(data, apk.MAX_LIB_LINES, apk.MAX_TEXT)
    assert not reason and lines == ["Repeated runtime label", address]


def test_native_ascii_limits_are_explicit_and_never_return_partial_values():
    data = b"first value\x00second value\x00third value"
    lines, reason = apk._native_string_lines(data, 2, 200)
    assert lines == ["first value", "second value"] and reason == "Native strings line limit reached"
    lines, reason = apk._native_string_lines(data, 20, len("first value") + 1)
    assert lines == ["first value"] and reason == "Native strings decoded text limit reached"
    lines, reason = apk._native_string_lines(b"repeat value\x00repeat value", 1, len("repeat value") + 1)
    assert lines == ["repeat value"] and reason == ""


def test_native_string_limit_marks_install_member_partial(tmp_path, monkeypatch):
    native = kit.snapshot.build_elf({"EmbeddedValue": b"\x00first value\x00second value\x00third value\x00"})
    data = kit.build_apk(native_libs={"libreview.so": native})
    path = tmp_path / "review.apks"
    path.write_bytes(kit.build_apk_set({"base": data}))
    monkeypatch.setattr(apk, "MAX_LIB_LINES", 1)
    ctx = apk.load_app(path)
    assert any("libreview.so: Native strings line limit reached" in warning for warning in ctx.warnings)
    assert any(row["status"] == "partial" and row["reason"] == "Native strings line limit reached"
               for row in ctx.facts["apk_members"])
