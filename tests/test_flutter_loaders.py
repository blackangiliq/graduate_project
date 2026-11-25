"""Tests for the loaders of the Flutter / Android module: app packages (sca/flutter/apk.py),
source projects (sca/flutter/project.py), the optional tools (sca/flutter/tools.py) and the
public API (sca/flutter/__init__.py).

App packages are built with tests/flutter_kit.py; hostile ones are kit packages with parts
replaced or damaged. Tools are faked, except a real subprocess for the runner. The checks on
real packages run only when SCA_FLUTTER_APK_DIR (debug.apk, release.apk, release_obf.apk and
release.aab of the vuln_probe lab app) or SCA_FLUTTER_PROBE_DIR (the same four packages built
from samples/flutter_apk_probe) is set; the jadx checks also need SCA_JADX.
"""
import hashlib
import os
import re
import shutil
import sys
import time
from pathlib import Path

import pytest

import flutter_kit as kit
from sca import flutter
from sca.flutter import apk, dex, project, tools, zipread
from sca.flutter.context import (BUILD_FILE, PACKAGES_FILE, SIGNING_FILE, MobileContext,
                                 find_line)
from sca.walker import SKIP_DIRS, walk_project

ROOT = Path(__file__).resolve().parent.parent
APK_DIR = Path(os.environ.get("SCA_FLUTTER_APK_DIR", "") or "missing")
PROBE_DIR = Path(os.environ.get("SCA_FLUTTER_PROBE_DIR", "") or "missing")
PACKAGES = ("debug.apk", "release.apk", "release_obf.apk", "release.aab")
real_apks = pytest.mark.skipif(not all((APK_DIR / n).is_file() for n in PACKAGES),
                               reason="SCA_FLUTTER_APK_DIR does not hold the vuln_probe packages")
real_probe = pytest.mark.skipif(not all((PROBE_DIR / n).is_file() for n in PACKAGES),
                                reason="SCA_FLUTTER_PROBE_DIR does not hold the probe packages")
with_jadx = pytest.mark.skipif(not os.environ.get("SCA_JADX"), reason="SCA_JADX is not set")
CONTROL = re.compile("[\x00-\x08\x0a-\x1f\x85\u2028\u2029]")
DEBUG_SHA256 = hashlib.sha256(kit.DEBUG_CERT).hexdigest()


def load(tmp_path, data, name="app.apk", **options):
    path = tmp_path / name
    path.write_bytes(data)
    return flutter.load_app(path, **options)


def files_of(ctx):
    return {source.rel: source for source in ctx.files}


def rebuild(data, replace=None, add=(), drop=()):
    """The entries of a ZIP with some replaced, added or dropped, zipped again (unsigned)."""
    archive = zipread.ZipArchive(data)
    entries = []
    for entry in archive.entries:
        if entry.name in drop:
            continue
        body = (replace or {}).get(entry.name, archive.read(entry))
        entries.append((entry.name, body, 8 if entry.name.endswith((".xml", ".dex")) else 0))
    return zipread.build_zip(entries + [(name, body, 8) for name, body in add])


def check_virtual_files(ctx):
    """The rules for virtual files: unique rels that are their paths, no "#", lines shorter
    than 600 characters without control characters, a known origin."""
    rels = [source.rel for source in ctx.files]
    assert len(rels) == len(set(rels))
    for source in ctx.files:
        assert source.path == Path(source.rel) and "#" not in source.rel and "\\" not in source.rel
        assert source.lines == source.text.splitlines()
        assert all(len(line) < 600 and not CONTROL.search(line) for line in source.lines)
        assert source.origin in ("decoded", "recovered", "decompiled", "strings", "summary")


# ------------------------------------------------------------------ helpers of apk.py
def test_text_lines_clean_and_split():
    text = "a\x00b\tc\x0bd\x0ce\x1cf\x85g\u2028h\u2029i\r\nj\x7f\ud800" + "x" * 1300
    lines = apk.text_lines(text)
    assert lines[:8] == ["ab\tc", "d", "e", "f", "g", "h", "i", "j\x7f\ufffd" + "x" * 596]
    assert [len(line) for line in lines[8:]] == [599, 105]
    assert apk.text_lines("") == [] and apk.text_lines("one\n\ntwo") == ["one", "", "two"]
    assert apk.clean_line("ok\x1b[0m") == "ok[0m"


def test_dump_lines():
    strings = ["plain", "two\nlines", "  ", "", "tab\tkept", "y" * 1200, "\x01\x02"]
    assert apk.dump_lines(strings, 100) == ["plain", "two", "lines", "tab\tkept",
                                            "y" * 599, "y" * 599, "y" * 2]
    assert apk.dump_lines(strings, 3) == ["plain", "two", "lines"]
    assert apk.dump_lines(["z" * 2000], 2) == ["z" * 599, "z" * 599]


def test_string_resource_lines():
    assert apk._string_lines("app_name", "A & B <x>\n\"q\"\ttab\u2028") == [
        '    <string name="app_name">A &amp; B &lt;x&gt;\\n"q"\\ttab</string>']
    assert apk._string_lines('we"ird', "v") == ['    <string name="we&quot;ird">v</string>']
    lines = apk._string_lines("long", "&" * 700)
    assert all(len(line) < 600 for line in lines) and len(lines) == 6
    assert "".join(lines) == '    <string name="long">' + "&amp;" * 700 + "</string>"
    assert all(re.fullmatch(r"(.*>)?(&amp;)*(</string>)?", line) for line in lines)


def test_notice_names():
    text = kit.notices(["skia", "abseil-cpp", "http", "dio", "http", "Bad Name", "flutter"])
    names = apk.notice_names(apk._inflate(text, 1 << 20))
    assert names == ["http", "dio"]
    two_blocks = ("collection\nmeta\n\nlicence text\nnot_a_head\n" + "-" * 80
                  + "\n\r\nvector_math\r\n\r\nx")
    assert apk.notice_names(two_blocks) == ["collection", "meta", "vector_math"]
    assert apk.notice_names("") == []


def test_bundle_strings():
    data = kit.resources_pb("com.example.kitapp", {"app_name": "Kit", "google_api_key": "AIza1"},
                            other_configs={"greeting": "Bonjour"})
    assert apk.bundle_strings(data) == ({"app_name": "Kit", "google_api_key": "AIza1"}, "")
    strings, error = apk.bundle_strings(data[:-3])
    assert error and isinstance(strings, dict)
    assert apk.bundle_strings(b"") == ({}, "")


def test_dex_strings_filter():
    types = {"Lcom/example/Main;"}
    keep = ["https://example.com/api", "SELECT * FROM t", "Hello world", "onCreate"]
    drop = ["Lcom/example/Main;", "Ljava/lang/String;", "[Ljava/lang/Object;", "VLLLLL",
            "ZLLIJJ", "Ljava/util/Map<TK;TV;>;", "Lkotlin/jvm/functions/Function1<",
            "(Ljava/lang/String;)V", "short", "\x00\x02\n\x08binary", "SMAP\nA.kt\nKotlin"]
    assert [text for text in keep + drop if apk._keep_dex_string(text, types)] == keep


def test_is_app_package(tmp_path):
    good = tmp_path / "app.APK"
    good.write_bytes(kit.build_apk(mode="none"))
    (tmp_path / "text.apk").write_text("not a zip")
    (tmp_path / "app.zip").write_bytes(good.read_bytes())
    (tmp_path / "dir.apk").mkdir()
    assert flutter.is_app_package(good)
    for name in ("text.apk", "app.zip", "dir.apk", "missing.apk"):
        assert not flutter.is_app_package(tmp_path / name)
    assert flutter.APP_SUFFIXES == (".apk", ".aab", ".apks", ".xapk", ".apkm")


# ------------------------------------------------------------------ app packages
def test_release_apk(tmp_path):
    data = kit.build_apk()
    ctx = load(tmp_path, data, "release.apk")
    assert isinstance(ctx, MobileContext) and ctx.kind == "apk" and ctx.is_app and ctx.is_flutter
    assert ctx.root == tmp_path / "release.apk"
    assert [(s.rel, s.origin, s.language) for s in ctx.files] == [
        ("AndroidManifest.xml", "decoded", "config"),
        ("res/xml/network_security_config.xml", "decoded", "config"),
        ("res/xml/file_paths.xml", "decoded", "config"),
        ("res/values/strings.xml", "decoded", "config"),
        ("assets/flutter_assets/assets/.env", "decoded", "config"),
        ("lib/arm64-v8a/libapp.so", "strings", "config"),
        ("classes.dex", "strings", "config"),
        (SIGNING_FILE, "summary", "config"), (BUILD_FILE, "summary", "config"),
        (PACKAGES_FILE, "summary", "config")]
    check_virtual_files(ctx)
    by = files_of(ctx)
    # the resource files are stored under shortened names and named back through the table
    names = zipread.ZipArchive(data).names()
    assert "res/00.xml" in names and "res/01.xml" in names and "res/xml/file_paths.xml" not in names
    manifest = by["AndroidManifest.xml"]
    root = ctx.manifests[0][1]
    assert ctx.manifests == [("AndroidManifest.xml", root)]
    application = root.find("application")
    assert application.get("android:networkSecurityConfig") == "@xml/network_security_config"
    assert application.get("android:label") == "@string/app_name"
    line = application.line_of("android:allowBackup")
    assert manifest.lines[line - 1].strip() == 'android:allowBackup="true"'
    nsc_rel = "res/xml/network_security_config.xml"
    assert ctx.resource_files["@xml/network_security_config"] == nsc_rel
    assert ctx.resource_files["@xml/file_paths"] == "res/xml/file_paths.xml"
    assert ctx.resource_files["@0x7f010000"] == nsc_rel
    nsc = ctx.xml_resources["res/xml/network_security_config.xml"]
    assert nsc.find("base-config").get("cleartextTrafficPermitted") == "true"
    assert find_line(by["res/xml/file_paths.xml"], "<root-path") == 3
    assert by["res/values/strings.xml"].lines == [
        '<?xml version="1.0" encoding="utf-8"?>', "<resources>",
        '    <string name="app_name">Kit App</string>', "</resources>"]
    assert by["assets/flutter_assets/assets/.env"].lines == kit.ENV_TEXT.splitlines()
    libapp = by["lib/arm64-v8a/libapp.so"]
    for text in (kit.AWS_KEY, kit.CLEARTEXT_URL, kit.SQL_TEXT, kit.LOG_TOKEN, "KitVaultService"):
        assert text in libapp.lines
    assert "https://kit-probe.example/terms" in by["classes.dex"].lines
    assert ctx.strings_files == ["lib/arm64-v8a/libapp.so", "classes.dex"]
    assert by[SIGNING_FILE].lines == [
        "Signature schemes: v2", "v1 (JAR signing): no", "v2 (APK Signature Scheme v2): yes",
        "v3 (APK Signature Scheme v3): no", "v3.1 (APK Signature Scheme v3.1): no",
        "Signer 1 subject: C=US, O=Android, CN=Android Debug",
        "Signer 1 issuer: C=US, O=Android, CN=Android Debug",
        "Signer 1 certificate SHA-256: " + DEBUG_SHA256,
        "Signer 1 valid: 2026-03-10 to 2056-03-02", "Signer 1 key: RSA 2048 bits",
        "Signer 1 signature algorithm: sha256WithRSAEncryption",
        "Signature verified by apksigner: not checked"]
    assert by[BUILD_FILE].lines == [
        "Flutter app: yes", "Build mode: release",
        'Build mode evidence: snapshot features start with "product"', "ABIs: arm64-v8a",
        "Dart version: 3.12.2 (stable)", "Flutter engine revision: " + kit.ENGINE_REVISION,
        "Snapshot hash: " + kit.SNAPSHOT_HASH,
        "Snapshot features: " + " ".join(kit.RELEASE_FEATURES),
        "Dart obfuscation: no (4 package: URIs, 1 short private names)",
        "Debug symbols in libapp.so: no", "Dart kernel (kernel_blob.bin): not present",
        "Dart sources recovered: 0"]
    assert by[PACKAGES_FILE].lines == ["collection unknown (snapshot)", "http unknown (snapshot)"]
    facts = ctx.facts
    assert {key: facts[key] for key in (
        "kind", "name", "size_bytes", "sha256", "package", "version_name", "version_code",
        "min_sdk", "target_sdk", "compile_sdk", "flutter", "build_mode", "abis", "dart_version",
        "engine_revision", "snapshot_hash", "obfuscated", "debug_symbols", "plugins",
        "dart_sources")} == {
        "kind": "apk", "name": "release.apk", "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "package": "com.example.kitapp",
        "version_name": "1.2.3", "version_code": "7", "min_sdk": 21, "target_sdk": 34,
        "compile_sdk": 36, "flutter": True, "build_mode": "release", "abis": ["arm64-v8a"],
        "dart_version": "3.12.2", "engine_revision": kit.ENGINE_REVISION,
        "snapshot_hash": kit.SNAPSHOT_HASH, "obfuscated": False, "debug_symbols": False,
        "plugins": [], "dart_sources": {"recovered": 0, "files": []}}
    assert facts["snapshot_features"] == " ".join(kit.RELEASE_FEATURES)
    assert facts["obfuscation_note"].startswith("1 of 81 private names are short")
    assert facts["signing"] == {"schemes": ["v2"], "certificates": [{
        "subject": "C=US, O=Android, CN=Android Debug",
        "issuer": "C=US, O=Android, CN=Android Debug", "sha256": DEBUG_SHA256,
        "valid_from": "2026-03-10", "valid_to": "2056-03-02", "key": "RSA 2048",
        "signature_algorithm": "sha256WithRSAEncryption", "debug": True}], "verified": None}
    assert facts["packages"] == ctx.packages == [
        {"name": "collection", "version": "", "source": "hosted", "found_in": "snapshot"},
        {"name": "http", "version": "", "source": "hosted", "found_in": "snapshot"}]
    assert facts["flutter_markers"]["flutter_jni"] and facts["flutter_markers"]["flutter"]
    assert facts["dex"] == {"files": 1, "classes": 4, "strings": len(ctx.dex[0].strings())}
    assert "warnings" not in facts and ctx.warnings == []
    assert ctx.snapshot.build_mode == "release"
    assert ctx.engine.engine_revision == kit.ENGINE_REVISION
    assert ctx.signing.schemes == ["v2"] and ctx.kernel is None and len(ctx.dex) == 1
    assert ctx.gradle_files == ctx.keystores == ctx.plists == ctx.pubspecs == []


def test_debug_apk(tmp_path):
    ctx = load(tmp_path, kit.build_apk(mode="debug"))
    check_virtual_files(ctx)
    by = files_of(ctx)
    main = by["dart/lib/main.dart"]
    assert (main.origin, main.language) == ("recovered", "dart")
    assert main.text == kit.MAIN_DART
    assert "lib/arm64-v8a/libapp.so" not in by and ctx.snapshot is None
    assert ctx.manifests[0][1].find("application").get("android:debuggable") == "true"
    # a debug build keeps the resource file names
    assert "res/xml/network_security_config.xml" in zipread.ZipArchive(
        kit.build_apk(mode="debug")).names()
    facts = ctx.facts
    assert facts["build_mode"] == "debug" and facts["obfuscated"] is False
    assert facts["obfuscation_note"] == "debug build: the Dart source is in kernel_blob.bin"
    assert facts["dart_sources"] == {"recovered": 1, "files": ["dart/lib/main.dart"]}
    assert facts["snapshot_hash"] == kit.SNAPSHOT_HASH and facts["snapshot_features"] == "release"
    assert facts["packages"] == [
        {"name": "collection", "version": "1.19.1", "source": "hosted", "found_in": "kernel"},
        {"name": "http", "version": "0.13.0", "source": "hosted", "found_in": "kernel"}]
    assert ctx.kernel.main_package == kit.APP
    assert by[BUILD_FILE].lines[1:3] == [
        "Build mode: debug",
        "Build mode evidence: kernel_blob.bin holds the Dart program (JIT debug build)"]
    assert by[BUILD_FILE].lines[6:] == [
        "Snapshot hash: " + kit.SNAPSHOT_HASH,
        "Snapshot features: release (JIT snapshot kFullCore in isolate_snapshot_data)",
        "Dart obfuscation: no (debug build: the Dart source is in kernel_blob.bin)",
        "Debug symbols in libapp.so: no libapp.so", "Dart kernel (kernel_blob.bin): 4 sources",
        "Dart sources recovered: 1", "Build path: " + kit.BUILD_FOLDER,
        "Build path: file:///C:/flutter",
        "Build path: file:///C:/Users/dev/AppData/Local/Pub/Cache"]
    assert by[PACKAGES_FILE].lines == ["collection 1.19.1 (kernel)", "http 0.13.0 (kernel)"]


def test_debug_apk_without_app_sources_and_with_git_packages(tmp_path):
    ctx = load(tmp_path, kit.build_apk(mode="debug", dart_sources={}, packages={}))
    assert ctx.facts["dart_sources"] == {"recovered": 0, "files": []}
    assert ctx.facts["build_mode"] == "debug" and ctx.facts["packages"] == []


def test_profile_and_obfuscated_builds(tmp_path):
    profile = load(tmp_path, kit.build_apk(mode="profile"), "profile.apk")
    assert profile.facts["build_mode"] == "profile"
    assert profile.manifests[0][1].find("application").get("android:debuggable") == "true"
    assert files_of(profile)[BUILD_FILE].lines[2] == \
        'Build mode evidence: snapshot features start with "release"'
    obf = load(tmp_path, kit.build_apk(obfuscated=True, symbols=True), "obf.apk")
    facts = obf.facts
    assert facts["obfuscated"] is True and facts["debug_symbols"] is True
    lines = files_of(obf)[BUILD_FILE].lines
    assert "Dart obfuscation: yes (0 package: URIs, 81 short private names)" in lines
    assert "Debug symbols in libapp.so: yes" in lines
    # an obfuscated snapshot names no packages: NOTICES does, without the engine's code
    assert [(p["name"], p["found_in"]) for p in facts["packages"]] == [
        ("collection", "notices"), ("http", "notices")]
    assert kit.AWS_KEY in files_of(obf)["lib/arm64-v8a/libapp.so"].lines


def test_plain_android_app(tmp_path):
    ctx = load(tmp_path, kit.build_apk(mode="none"))
    check_virtual_files(ctx)
    facts = ctx.facts
    assert facts["flutter"] is False and facts["build_mode"] == "unknown" and not ctx.is_flutter
    for key in ("dart_version", "obfuscated", "debug_symbols", "dart_sources", "snapshot_hash"):
        assert key not in facts
    assert facts["abis"] == [] and facts["packages"] == []
    assert not facts["flutter_markers"]["flutter"]
    by = files_of(ctx)
    assert by[BUILD_FILE].lines == ["Flutter app: no", "ABIs: none"]
    assert by[PACKAGES_FILE].lines == [] and by[PACKAGES_FILE].text == ""


def test_signing_variants(tmp_path):
    unsigned = load(tmp_path, kit.build_apk(certificate=None), "unsigned.apk")
    assert files_of(unsigned)[SIGNING_FILE].lines == [
        "Signature schemes: none", "v1 (JAR signing): no", "v2 (APK Signature Scheme v2): no",
        "v3 (APK Signature Scheme v3): no", "v3.1 (APK Signature Scheme v3.1): no",
        "Signature verified by apksigner: not checked"]
    assert unsigned.facts["signing"] == {"schemes": [], "certificates": [], "verified": None}
    signed = load(tmp_path, kit.build_apk(certificate="release", schemes=("v1", "v2", "v3")),
                  "signed.apk")
    lines = files_of(signed)[SIGNING_FILE].lines
    assert lines[:5] == ["Signature schemes: v1, v2, v3", "v1 (JAR signing): yes",
                         "v2 (APK Signature Scheme v2): yes", "v3 (APK Signature Scheme v3): yes",
                         "v3.1 (APK Signature Scheme v3.1): no"]
    assert lines[5] == "Signer 1 subject: CN=Kit Release, O=Example Org, C=SA"
    assert signed.facts["signing"]["certificates"][0]["debug"] is False
    weak = kit.signing.build_certificate({"CN": "Old"}, key_algorithm="DSA", key_bits=1024,
                                         sig_alg="dsa-with-sha1")
    v1_only = load(tmp_path, kit.build_apk(certificate=weak, schemes=("v1",)), "v1.apk")
    lines = files_of(v1_only)[SIGNING_FILE].lines
    assert lines[0] == "Signature schemes: v1" and "Signer 1 key: DSA 1024 bits" in lines
    assert "Signer 1 signature algorithm: dsa-with-sha1" in lines


def test_app_bundle(tmp_path):
    ctx = load(tmp_path, kit.build_aab(), "app.aab")
    check_virtual_files(ctx)
    assert ctx.kind == ctx.facts["kind"] == "aab"
    by = files_of(ctx)
    assert sorted(by) == sorted([
        "AndroidManifest.xml", "res/xml/file_paths.xml", "res/xml/network_security_config.xml",
        "res/values/strings.xml", "assets/flutter_assets/assets/.env", "lib/arm64-v8a/libapp.so",
        "classes.dex", SIGNING_FILE, BUILD_FILE, PACKAGES_FILE])
    application = ctx.manifests[0][1].find("application")
    assert application.get("android:networkSecurityConfig") == "@xml/network_security_config"
    assert ctx.resource_files == {"@xml/file_paths": "res/xml/file_paths.xml",
                                  "@xml/network_security_config":
                                      "res/xml/network_security_config.xml"}
    assert '    <string name="app_name">Kit App</string>' in by["res/values/strings.xml"].lines
    assert ctx.facts["signing"]["schemes"] == ["v1"] and ctx.facts["build_mode"] == "release"
    assert ctx.facts["package"] == "com.example.kitapp"
    modules = rebuild(kit.build_aab(), add=[("feature/manifest/AndroidManifest.xml", b"x"),
                                            ("feature/dex/classes.dex", b"x")])
    ctx = load(tmp_path, modules, "modules.aab")
    assert "modules.aab: app bundle module 'feature' is not analysed (only the base module " \
           "is)" in ctx.warnings and "classes.dex" in files_of(ctx)


@pytest.mark.parametrize("layout, suffix", [("apks", ".apks"), ("xapk", ".xapk"),
                                            ("apkm", ".apkm")])
def test_split_apk_sets(tmp_path, layout, suffix):
    parts = kit.split_apk(kit.build_apk(abis=("arm64-v8a", "x86_64")))
    assert sorted(parts) == ["base", "split_config.arm64_v8a", "split_config.x86_64"]
    assert not any(n.startswith("lib/") for n in zipread.ZipArchive(parts["base"]).names())
    ctx = load(tmp_path, kit.build_apk_set(parts, layout=layout), "set" + suffix)
    check_virtual_files(ctx)
    assert ctx.kind == ctx.facts["kind"] == "apks"
    assert ctx.facts["abis"] == ["arm64-v8a", "x86_64"] and ctx.facts["build_mode"] == "release"
    by = files_of(ctx)
    assert kit.AWS_KEY in by["lib/arm64-v8a/libapp.so"].lines and "AndroidManifest.xml" in by
    assert ctx.facts["signing"]["schemes"] == ["v2"]
    assert ctx.facts["signing"]["certificates"][0]["debug"] is True
    assert ctx.warnings == []


def test_split_set_with_a_feature_split_and_no_base(tmp_path):
    parts = kit.split_apk(kit.build_apk())
    parts["split_extras"] = kit.build_apk(mode="none")
    ctx = load(tmp_path, kit.build_apk_set(parts), "set.apks")
    assert any("split_extras is a feature split" in w for w in ctx.warnings)
    del parts["base"]
    with pytest.raises(flutter.AppError, match="no AndroidManifest.xml"):
        load(tmp_path, kit.build_apk_set({"split_config.arm64_v8a":
                                          parts["split_config.arm64_v8a"]}), "nobase.apks")


def test_plugins_and_more_dex_files(tmp_path):
    plugins = {"path_provider_android": "io.flutter.plugins.pathprovider.PathProviderPlugin",
               "shared_preferences_android":
                   "io.flutter.plugins.sharedpreferences.SharedPreferencesPlugin"}
    extra = kit.dex.build_dex(["https://second.example/dex"], [("Lcom/example/kitapp/B;", None)])
    ctx = load(tmp_path, kit.build_apk(plugins=plugins, extra_dex=[extra, extra]))
    assert ctx.facts["plugins"] == sorted(plugins.values())
    found = {p["name"]: p["found_in"] for p in ctx.facts["packages"]}
    assert found == {"collection": "snapshot", "http": "snapshot",
                     "path_provider_android": "plugin", "shared_preferences_android": "plugin"}
    assert [d.name for d in ctx.dex] == ["classes.dex", "classes2.dex", "classes3.dex"]
    assert ctx.strings_files[-2:] == ["classes2.dex", "classes3.dex"]
    assert ctx.facts["dex"]["files"] == 3


def test_resources_without_a_table(tmp_path):
    debug_names = kit.build_apk(mode="debug", strings={})
    ctx = load(tmp_path, rebuild(debug_names, drop={"resources.arsc"}), "notable.apk")
    assert sorted(ctx.xml_resources) == ["res/xml/file_paths.xml",
                                         "res/xml/network_security_config.xml"]
    assert ctx.resource_files["@xml/file_paths"] == "res/xml/file_paths.xml"
    root = ctx.manifests[0][1].find("application")
    assert root.get("android:networkSecurityConfig").startswith("@0x7f")   # not resolved
    ctx = load(tmp_path, rebuild(debug_names, replace={"resources.arsc": b"garbage!"}), "bad.apk")
    assert "res/xml/file_paths.xml" in ctx.xml_resources
    assert any(w.startswith("resources.arsc: ") for w in ctx.warnings)
    shortened = rebuild(kit.build_apk(), drop={"res/00.xml"})
    ctx = load(tmp_path, shortened, "missing.apk")
    assert "res/xml/network_security_config.xml: resources.arsc names res/00.xml, which the " \
           "package does not hold" in ctx.warnings
    assert list(ctx.xml_resources) == ["res/xml/file_paths.xml"]


def test_resource_configurations_and_long_strings(tmp_path):
    long_value = "x" * 1000 + "AIzaSyLongKey"
    ctx = load(tmp_path, kit.build_apk(strings={"app_name": "Kit", "terms": long_value}))
    lines = files_of(ctx)["res/values/strings.xml"].lines
    assert lines[3].startswith('    <string name="terms">x') and lines[-1] == "</resources>"
    assert "".join(lines[3:-1]) == '    <string name="terms">%s</string>' % long_value
    table = kit.arsc.build_arsc("com.example.kitapp", [
        ("xml", "shortcuts", "res/Ab.xml", "v25"), ("xml", "shortcuts", "res/Ac.xml")])
    data = rebuild(kit.build_apk(mode="none", xml_resources={}, strings={}),
                   replace={"resources.arsc": table},
                   add=[("res/Ab.xml", kit.axml.encode_axml(kit.compile_xml("<shortcuts a='1'/>"))),
                        ("res/Ac.xml", kit.axml.encode_axml(kit.compile_xml("<shortcuts/>")))])
    ctx = load(tmp_path, data, "configs.apk")
    assert sorted(ctx.xml_resources) == ["res/xml-v25/shortcuts.xml", "res/xml/shortcuts.xml"]
    assert ctx.resource_files["@xml/shortcuts"] == "res/xml/shortcuts.xml"


def test_native_libraries_and_abi_choice(tmp_path):
    native = kit.snapshot.build_elf({"kSecret": b"\x00jdbc:mysql://db.internal/app\x00k\x00"})
    libs = {"libnative.so": native, "libVkLayer_khronos_validation.so": native}
    libs.update({"libextra%d.so" % n: native for n in range(11)})
    # both ABIs have libapp.so and arm64-v8a is read; the other libraries are in armeabi-v7a
    # (the first ABI given), so none of them is dumped
    data = kit.build_apk(abis=("armeabi-v7a", "arm64-v8a"), native_libs=libs)
    ctx = load(tmp_path, data)
    assert ctx.facts["abis"] == ["arm64-v8a", "armeabi-v7a"]
    by = files_of(ctx)
    assert "lib/arm64-v8a/libapp.so" in by
    assert not any(rel.startswith("lib/armeabi-v7a/") for rel in by)
    data = kit.build_apk(native_libs=libs)
    ctx = load(tmp_path, data, "libs.apk")
    dumped = [rel for rel in files_of(ctx) if rel.startswith("lib/arm64-v8a/lib") and
              rel != "lib/arm64-v8a/libapp.so"]
    assert len(dumped) == 10 and "lib/arm64-v8a/libVkLayer_khronos_validation.so" not in dumped
    assert "jdbc:mysql://db.internal/app" in files_of(ctx)["lib/arm64-v8a/libextra0.so"].lines
    assert "12 other native libraries; only the first 10 are read" in ctx.warnings
    assert all(rel in ctx.strings_files for rel in dumped)


def test_text_assets(tmp_path, monkeypatch):
    monkeypatch.setattr(apk, "MAX_ASSET_BYTES", 100)
    assets = {"config.json": '{"apiKey": "k"}', "data.bin": b"\x00\x01", "nul.json": b"{\x00}",
              "utf16.txt": "\ufeffhello utf16".encode("utf-16-le"), "big.txt": "b" * 101,
              "dir/.env.production": "SECRET=1", "page.html": "<script>x</script>",
              "a#b.yml": "k: v", "flutter_assets/FontManifest.json": "[]",
              "flutter_assets/AssetManifest.json": "{}", "min.min.js": "var a=1"}
    ctx = load(tmp_path, kit.build_apk(mode="none", assets=assets))
    found = {s.rel: s.language for s in ctx.files if s.rel.startswith("assets/")}
    assert found == {"assets/a_b.yml": "config", "assets/config.json": "config",
                     "assets/dir/.env.production": "config", "assets/min.min.js": "config",
                     "assets/page.html": "html", "assets/utf16.txt": "config"}
    assert files_of(ctx)["assets/utf16.txt"].lines == ["hello utf16"]


def test_app_errors(tmp_path):
    (tmp_path / "text.apk").write_text("hello")
    (tmp_path / "folder.apk").mkdir()
    (tmp_path / "nomanifest.apk").write_bytes(zipread.build_zip([("classes.dex", b"x", 8)]))
    with pytest.raises(flutter.AppError,
                       match=r"text.apk is not a readable app package: not a ZIP"):
        flutter.load_app(tmp_path / "text.apk")
    with pytest.raises(flutter.AppError, match="missing.apk: no such file"):
        flutter.load_app(tmp_path / "missing.apk")
    with pytest.raises(flutter.AppError, match="folder.apk: not a file"):
        flutter.load_app(tmp_path / "folder.apk")
    with pytest.raises(flutter.AppError, match="nomanifest.apk is not an Android app package: it "
                                               "has no AndroidManifest.xml"):
        flutter.load_app(tmp_path / "nomanifest.apk")
    assert issubclass(flutter.AppError, ValueError)


def test_hostile_parts_become_warnings(tmp_path):
    debug = kit.build_apk(mode="debug")
    data = rebuild(debug, replace={"AndroidManifest.xml": b"<manifest/>",
                                   "assets/flutter_assets/kernel_blob.bin": b"\x90\xab\xcd\xef" * 9,
                                   "assets/flutter_assets/NOTICES.Z": b"not gzip",
                                   "classes.dex": b"dex\n035\x00" + b"\xff" * 200},
                   add=[("assets/x.env", b"A=1"), ("assets/x.env", b"B=2")])
    ctx = load(tmp_path, data)
    warnings = ctx.warnings
    assert "AndroidManifest.xml: not decoded (this is text XML, not binary XML)" in warnings
    assert any(w.startswith("kernel: ") for w in warnings)
    assert any(w.startswith("assets/flutter_assets/NOTICES.Z: not decoded") for w in warnings)
    assert any("duplicate entry name 'assets/x.env'" in w for w in warnings)
    assert any(w.startswith("classes.dex: ") for w in warnings)
    assert files_of(ctx)["assets/x.env"].lines == ["A=1"]
    assert ctx.manifests == [] and ctx.facts["build_mode"] == "debug"
    assert "res/xml/network_security_config.xml" in files_of(ctx)
    assert ctx.facts["warnings"] == warnings
    release = kit.build_apk()
    archive = zipread.ZipArchive(release)
    entry = archive.get("classes.dex")
    broken = bytearray(release)
    broken[entry.data_offset:entry.data_offset + 8] = b"\xff" * 8
    ctx = load(tmp_path, bytes(broken), "broken.apk")
    assert "classes.dex" not in files_of(ctx) and "lib/arm64-v8a/libapp.so" in files_of(ctx)
    assert any("classes.dex: corrupt deflate data" in w for w in ctx.warnings)
    garbage = rebuild(release, replace={"lib/arm64-v8a/libapp.so": b"\x7fELF" + b"junk" * 40})
    ctx = load(tmp_path, garbage, "garbage.apk")
    assert ctx.facts["build_mode"] == "unknown" and ctx.facts["obfuscated"] is None
    assert any(w.startswith("libapp.so: ") for w in ctx.warnings)
    assert "Dart obfuscation: unknown (too few Dart names in the snapshot to judge obfuscation)" \
        in files_of(ctx)[BUILD_FILE].lines


def test_long_lines_in_decoded_xml(tmp_path):
    manifest = kit.MANIFEST.replace('android:label="@string/app_name"',
                                    'android:label="%s"' % ("L" * 900))
    ctx = load(tmp_path, kit.build_apk(manifest=manifest))
    check_virtual_files(ctx)
    application = ctx.manifests[0][1].find("application")
    assert application.get("android:label") == "L" * 900          # the tree keeps the value
    line = files_of(ctx)["AndroidManifest.xml"].lines[application.line_of("android:label") - 1]
    assert len(line) == 599 and line.endswith("LLL...")


def test_a_failing_decoder_does_not_stop_the_rest(tmp_path, monkeypatch):
    def broken(data, name="classes.dex"):
        raise RuntimeError("decoder bug")

    monkeypatch.setattr(dex, "parse_dex", broken)
    ctx = load(tmp_path, kit.build_apk())
    assert "DEX: not decoded (RuntimeError: decoder bug)" in ctx.warnings
    assert "classes.dex" not in files_of(ctx) and "lib/arm64-v8a/libapp.so" in files_of(ctx)
    assert ctx.facts["signing"]["schemes"] == ["v2"]


def test_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(apk, "MAX_TEXT", 2000)
    ctx = load(tmp_path, kit.build_apk())
    assert any(w.startswith("the decoded text reached 0 MiB; ") for w in ctx.warnings)
    assert [s.rel for s in ctx.files][-3:] == [SIGNING_FILE, BUILD_FILE, PACKAGES_FILE]
    assert "lib/arm64-v8a/libapp.so" not in files_of(ctx)
    monkeypatch.setattr(apk, "MAX_TEXT", 64 << 20)
    monkeypatch.setattr(apk, "MAX_XML_RESOURCES", 1)
    monkeypatch.setattr(apk, "MAX_STRING_RESOURCES", 1)
    monkeypatch.setattr(apk, "MAX_DEX_FILES", 1)
    monkeypatch.setattr(apk, "MAX_LIBAPP_LINES", 3)
    ctx = load(tmp_path, kit.build_apk(strings={"a": "1", "b": "2"}, extra_dex=[b"dex"]), "2.apk")
    assert list(ctx.xml_resources) == ["res/xml/network_security_config.xml"]
    assert "2 XML resources; only the first 1 are decoded" in ctx.warnings
    assert "3 string resources; only the first 1 are listed" in ctx.warnings     # + app_name
    assert "2 DEX files; only the first 1 are read" in ctx.warnings
    assert len(files_of(ctx)["lib/arm64-v8a/libapp.so"].lines) == 3


def test_parts_for_python_decoders_are_read_within_smaller_limits(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(apk, "MAX_DEX_BYTES", 100)
        ctx = load(tmp_path, kit.build_apk())
    assert any(w.startswith("app.apk: classes.dex: inflates to more than the read limit of 100 "
                            "bytes") for w in ctx.warnings)
    # only the head of isolate_snapshot_data is read (its header), stored or deflated, and
    # reading less than the whole file is not an anomaly
    debug = kit.build_apk(mode="debug")
    name = "assets/flutter_assets/isolate_snapshot_data"
    padded = zipread.ZipArchive(debug).read(name) + bytes(apk.MAX_SNAPSHOT_BYTES * 2)
    for data in (rebuild(debug, replace={name: padded}),
                 rebuild(debug, drop={name}, add=[(name, padded)])):
        ctx = load(tmp_path, data, "debug.apk")
        assert ctx.facts["snapshot_hash"] == kit.SNAPSHOT_HASH and ctx.warnings == []


def test_notice_names_are_kept_once_and_capped():
    blocks = ["\n".join("pkg_%d" % (50 * block + n) for n in range(50)) + "\n\nlicence\n"
              for block in range(1000)]
    text = ("-" * 80 + "\n").join(blocks + ["pkg_0\npkg_1\n\nrepeated\n"])
    started = time.perf_counter()
    names = apk.notice_names(text)             # 50,000 names: one list scan each was quadratic
    assert time.perf_counter() - started < 1
    assert names == ["pkg_%d" % n for n in range(apk.MAX_PACKAGES)]
    assert apk.notice_names(text[-60:] + "\n" + text[-60:]) == ["pkg_0", "pkg_1"]


def test_an_xml_resource_of_many_configurations_is_decoded_once(tmp_path, monkeypatch):
    configs = [("xml", "shortcuts", "res/Ab.xml", "v%d" % level) for level in range(21, 31)]
    table = kit.arsc.build_arsc("com.example.kitapp", configs + [("xml", "shortcuts",
                                                                  "res/Ab.xml")])
    shortcut = kit.axml.encode_axml(kit.compile_xml("<shortcuts a='1'/>"))
    data = rebuild(kit.build_apk(mode="none", xml_resources={}, strings={}),
                   replace={"resources.arsc": table}, add=[("res/Ab.xml", shortcut)])
    decoded = []
    real = kit.axml.decode_axml
    monkeypatch.setattr(apk.axml, "decode_axml",
                        lambda data, resolve=None: decoded.append(len(data)) or real(data, resolve))
    ctx = load(tmp_path, data)
    assert decoded.count(len(shortcut)) == 1 and len(ctx.xml_resources) == 11
    assert sorted(ctx.xml_resources)[:2] == ["res/xml-v21/shortcuts.xml",
                                             "res/xml-v22/shortcuts.xml"]
    assert len({id(root) for root in ctx.xml_resources.values()}) == 1
    assert all(files_of(ctx)[rel].lines == files_of(ctx)["res/xml/shortcuts.xml"].lines
               for rel in ctx.xml_resources)
    assert ctx.resource_files["@xml/shortcuts"] == "res/xml/shortcuts.xml"


def test_dex_files_are_kept_without_their_bytes(tmp_path, monkeypatch):
    data = kit.build_apk()
    parsed = dex.parse_dex(zipread.ZipArchive(data).read("classes.dex"))
    monkeypatch.delattr(dex.DexFile, "release", raising=False)
    ctx = load(tmp_path, data)
    kept, = ctx.dex
    assert not getattr(kept, "_data", None) and kept.class_defs() == parsed.class_defs()
    real = dex.parse_dex

    def keeping(data, name="classes.dex"):     # a DexFile that holds its input
        found = real(data, name)
        found._data = data
        return found

    monkeypatch.setattr(dex, "parse_dex", keeping)
    ctx = load(tmp_path, data, "kept.apk")
    kept, = ctx.dex
    assert isinstance(kept, apk.DexSummary) and not getattr(kept, "_data", None)
    assert (kept.name, kept.version, kept.size) == ("classes.dex", parsed.version, parsed.size)
    assert (kept.strings(), kept.type_names(), kept.class_defs()) == (
        parsed.strings(), parsed.type_names(), parsed.class_defs())
    released = []

    def release(self):
        released.append(self.name)
        self._data = b""

    monkeypatch.setattr(dex.DexFile, "release", release, raising=False)
    ctx = load(tmp_path, data, "released.apk")
    kept, = ctx.dex
    assert isinstance(kept, dex.DexFile) and released == ["classes.dex"] and not kept._data
    assert kept.class_defs() == parsed.class_defs() and ctx.facts["dex"]["classes"] == 4


def test_split_sets_read_stored_apks_in_place(tmp_path):
    parts = kit.split_apk(kit.build_apk())
    path = tmp_path / "set.apks"
    path.write_bytes(kit.build_apk_set(parts))         # bundletool stores the APKs
    with zipread.open_container(path) as container:
        outer = container.archive.get("splits/base-master.apk")
        base = dict(container.apks)["base"]
        assert outer.method == 0 and base.path == "" and base._data == b""      # not copied
        assert base.size == len(parts["base"]) and base.read_raw(0, 4) == b"PK\x03\x04"
        assert base.sha256() == hashlib.sha256(parts["base"]).hexdigest()
        with base.open_raw() as raw:
            assert raw.read() == parts["base"] and raw.seek(-4, os.SEEK_END) == base.size - 4
            assert raw.read(10) == parts["base"][-4:] and raw.tell() == base.size
        assert container.warnings == [] and container.archive.warnings == []
    # the APKs inside share the set's total read limit (each had 4 GiB of its own)
    used = sum(len(data) for data in parts.values())       # their CRC checks read them once
    with zipread.open_container(path, total_limit=used + 1000) as container:
        base = dict(container.apks)["base"]
        with pytest.raises(zipread.ZipError, match="total read limit"):
            for entry in base.entries:
                base.read(entry)
    # a damaged APK in a set: its CRC is still checked
    data = bytearray(kit.build_apk_set(parts))
    offset = zipread.ZipArchive(bytes(data)).get("splits/base-master.apk").data_offset
    data[offset + 40] ^= 0xFF
    (tmp_path / "bad.apks").write_bytes(bytes(data))
    with zipread.open_container(tmp_path / "bad.apks") as container:
        assert "bad.apks: splits/base-master.apk: CRC mismatch" in container.archive.warnings


def test_compressed_apks_of_a_set_are_inflated_within_limits(tmp_path, monkeypatch):
    parts = kit.split_apk(kit.build_apk())
    path = tmp_path / "deflated.apks"
    path.write_bytes(zipread.build_zip([
        ("splits/base-master.apk", parts["base"], 8),
        ("splits/base-arm64_v8a.apk", parts["split_config.arm64_v8a"], 8)]))
    ctx = flutter.load_app(path)
    assert ctx.facts["build_mode"] == "release" and ctx.warnings == []
    assert "lib/arm64-v8a/libapp.so" in files_of(ctx)
    with zipread.open_container(path) as container:
        base = dict(container.apks)["base"]
        assert base.read_raw(0, base.size) == parts["base"]
    monkeypatch.setattr(zipread, "MAX_INFLATED_APKS", len(parts["base"]) + 100)
    with zipread.open_container(path) as container:
        assert [label for label, _ in container.apks] == ["base"]
        warning, = container.warnings
        assert warning.startswith("deflated.apks: splits/base-arm64_v8a.apk is compressed and ")
    monkeypatch.setattr(zipread, "MAX_INFLATED_APK", 100)
    with pytest.raises(flutter.AppError, match="no AndroidManifest.xml"):
        flutter.load_app(path)


@pytest.mark.parametrize("piece", [999_999, 4096, 1 << 20])
def test_inflating_in_pieces_keeps_every_byte(monkeypatch, piece):
    # one inflate call into a buffer gives at most zipread._PIECE bytes; zlib can hold output
    # back after the last input is consumed, and it must still be read
    monkeypatch.setattr(zipread, "_PIECE", piece)
    data = bytes(5_000_000) + b"end"
    with zipread.ZipArchive(zipread.build_zip([("zeros.bin", data, 8)])) as archive:
        assert archive.read("zeros.bin") == data and archive.warnings == []
        buffer = archive._read_into_buffer(archive.get("zeros.bin"), len(data))
        assert isinstance(buffer, bytearray) and buffer == data and archive.warnings == []


def test_unicode_digits_are_not_numbers_in_app_packages():
    assert apk._int(" 21 ") == 21 and apk._int("-1") == -1
    assert apk._int("²") is None and apk._int("٣٣") is None
    assert apk._dex_order("classes2.dex") == 2 and apk._dex_order("classes٢.dex") == 0


def test_no_exception_but_app_error_leaves_load_app(tmp_path, monkeypatch):
    path = tmp_path / "app.apk"
    path.write_bytes(kit.build_apk())

    def bug(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(apk._AppLoader, "_build_lines", bug)
    ctx = flutter.load_app(path)
    assert "_sca/build.txt: not decoded (RuntimeError: bug)" in ctx.warnings
    assert SIGNING_FILE in files_of(ctx) and BUILD_FILE not in files_of(ctx)
    assert PACKAGES_FILE in files_of(ctx)
    monkeypatch.setattr(apk._AppLoader, "_index", bug)
    with pytest.raises(flutter.AppError, match="^app.apk could not be analysed: RuntimeError: bug"):
        flutter.load_app(path)
    monkeypatch.setattr(zipread, "open_container", bug)
    with pytest.raises(flutter.AppError,
                       match="^app.apk is not a readable app package: RuntimeError: bug"):
        flutter.load_app(path)


# ------------------------------------------------------------------ optional tools
def launcher(folder, name):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (name + (".bat" if os.name == "nt" else ""))
    path.write_text("echo fake\n")
    return str(path)


@pytest.fixture
def no_tools(monkeypatch, tmp_path):
    """An environment where no tool is installed."""
    for variable in ("SCA_JADX", "JADX_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "FLUTTER_ROOT"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    monkeypatch.setattr(tools.Path, "home", classmethod(lambda cls: tmp_path / "home"))


def test_availability(tmp_path, monkeypatch, no_tools):
    assert tools.availability() == dict.fromkeys(tools.TOOLS)
    jadx = launcher(tmp_path / "jadx-1.5" / "bin", "jadx")
    monkeypatch.setenv("SCA_JADX", str(tmp_path / "jadx-1.5"))
    sdk = tmp_path / "sdk"
    for version in ("35.0.0", "36.0.0-rc1", "9.0.0"):
        launcher(sdk / "build-tools" / version, "apksigner")
    newest = launcher(sdk / "build-tools" / "36.1.0", "apksigner")
    launcher(sdk / "build-tools" / "36.1.0", "aapt2")
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    flutter_root = tmp_path / "flutter"
    flutter_launcher = launcher(flutter_root / "bin", "flutter")
    dart = launcher(flutter_root / "bin" / "cache" / "dart-sdk" / "bin", "dart")
    monkeypatch.setenv("FLUTTER_ROOT", str(flutter_root))
    found = tools.availability()
    assert found == {"jadx": jadx, "apksigner": newest, "aapt2": str(Path(newest).with_name(
        Path(newest).name.replace("apksigner", "aapt2"))), "flutter": flutter_launcher,
        "dart": dart}
    monkeypatch.setenv("SCA_JADX", jadx)                       # the launcher itself
    assert tools.availability()["jadx"] == jadx
    monkeypatch.delenv("SCA_JADX")
    monkeypatch.setenv("JADX_HOME", str(tmp_path / "jadx-1.5" / "bin"))
    assert tools.availability()["jadx"] == jadx
    monkeypatch.delenv("ANDROID_SDK_ROOT")
    local_sdk = tmp_path / "localappdata" / "Android" / "Sdk"
    local = launcher(local_sdk / "build-tools" / "34.0.0", "apksigner")
    assert tools.availability()["apksigner"] == local
    assert set(tools.hints()) == set(tools.TOOLS)
    assert all(text.startswith("optional:") for text in tools.hints().values())


def test_batch_safe_paths_and_versions():
    assert tools.batch_safe(Path("C:/Users/dev/data/apps/0a1b/jadx-input"))
    assert tools.batch_safe(Path("/home/dev/sca data/apps (1)/x~y"))
    for bad in ("C:/a&b", "C:/100%", "C:/a!b", 'C:/a"b', "C:/a^b", "C:/a|b", "C:/a<b"):
        assert not tools.batch_safe(Path(bad))
    assert tools._version_key("36.1.0") > tools._version_key("36.0.0") > \
        tools._version_key("36.0.0-rc1") > tools._version_key("9.0.0")


def test_run_exit_codes_and_timeouts():
    code, output = tools._run([sys.executable, "-c", "print('out'); import sys; "
                               "sys.stderr.write('err'); sys.exit(3)"], 60)
    assert code == 3 and output.replace("\r", "") == "out\nerr"
    started = time.time()
    code, output = tools._run([sys.executable, "-c", "import time; time.sleep(30)"], 1)
    assert (code, output) == (None, "timed out after 1 s") and time.time() - started < 20
    code, output = tools._run([str(Path("no-such-tool-here"))], 5)
    assert code is None and output


def test_apksigner_outcomes(tmp_path, monkeypatch, no_tools):
    assert tools.apksigner_verify(tmp_path / "app.apk") == (None, tools.NOT_INSTALLED["apksigner"])
    monkeypatch.setattr(tools, "availability", lambda: {"apksigner": "apksigner"})
    outputs = {
        0: "Verifies\nVerified using v1 scheme (JAR signing): false\n"
           "Verified using v2 scheme (APK Signature Scheme v2): true\n",
        1: "DOES NOT VERIFY\nERROR: APK Signature Scheme v2 signer #1: digest mismatch\n",
        2: "Error: A JNI error has occurred\n"}
    for code, expected in ((0, (True, "ok (verified: v2)")),
                           (1, (False, "ok (does not verify: ERROR: APK Signature Scheme v2 "
                                       "signer #1: digest mismatch)")),
                           (2, (None, "failed: Error: A JNI error has occurred"))):
        monkeypatch.setattr(tools, "_run", lambda command, timeout, code=code:
                            (code, outputs[code]))
        assert tools.apksigner_verify(tmp_path / "app.apk") == expected
    monkeypatch.setattr(tools, "_run", lambda command, timeout: (None, "timed out after 120 s"))
    assert tools.apksigner_verify(tmp_path / "app.apk") == (None, "failed: timed out after 120 s")
    monkeypatch.setattr(tools, "availability", lambda: {"apksigner": "apksigner.bat"})
    verified, note = tools.apksigner_verify(tmp_path / "a&b.apk")
    assert verified is None and note.startswith("failed: ")


def fake_jadx(calls, classes, code=0):
    """A stand-in for _run that writes Java files for classes where jadx would."""
    def run(command, timeout):
        calls.append(command)
        out = Path(command[command.index("--output-dir-src") + 1])
        for name in classes:
            path = out.joinpath(*name.split(".")).with_suffix(".java")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class %s {}\n" % name.rsplit(".", 1)[-1])
        return code, "INFO - done" if not code else "ERROR - finished with errors, count: 2"
    return run


def test_jadx_decompile(tmp_path, monkeypatch, no_tools):
    inputs = tmp_path / "work" / "jadx-input"
    inputs.mkdir(parents=True)
    (inputs / "classes.dex").write_bytes(b"dex\n035\x00")
    out_dir = tmp_path / "work" / "jadx"
    assert tools.jadx_decompile(inputs, out_dir, ["a.*"]) == ([], tools.NOT_INSTALLED["jadx"])
    monkeypatch.setattr(tools, "availability", lambda: {"jadx": "jadx"})
    calls = []
    monkeypatch.setattr(tools, "_run", fake_jadx(calls, [
        "com.example.app.MainActivity", "com.example.app.ui.Screen", "com.example.other.X",
        "androidx.core.content.FileProvider", "a.b"], code=1))
    wanted = ["com.example.app.*", "androidx.core.content.FileProvider"]
    files, note = tools.jadx_decompile(inputs, out_dir, wanted)
    assert note == "ok (3 files; jadx reported errors)"
    assert [p.relative_to(out_dir).as_posix() for p in files] == [
        "androidx/core/content/FileProvider.java", "com/example/app/MainActivity.java",
        "com/example/app/ui/Screen.java"]
    assert all(path.is_file() for path in files) and len(calls) == 1
    assert calls[0][:6] == ["jadx", "--no-res", "--quiet", "--comments-level", "warn",
                            "--output-dir-src"] and calls[0][-1] == str(inputs / "classes.dex")
    assert sorted(p.name for p in out_dir.parent.iterdir()) == ["jadx", "jadx-input"]
    again, note = tools.jadx_decompile(inputs, out_dir, list(reversed(wanted)))
    assert again == files and note == "ok (3 files, from an earlier scan of this app)"
    assert len(calls) == 1
    (inputs / "classes.dex").write_bytes(b"dex\n035\x00changed")
    monkeypatch.setattr(tools, "MAX_JAVA_FILES", 1)
    files, note = tools.jadx_decompile(inputs, out_dir, wanted)
    assert len(calls) == 2 and note == "ok (1 files; jadx reported errors)" and len(files) == 1
    monkeypatch.setattr(tools, "_run", fake_jadx(calls, ["other.Y"], code=1))
    files, note = tools.jadx_decompile(inputs / "classes.dex", tmp_path / "w2" / "jadx", wanted)
    assert files == [] and note == "failed: ERROR - finished with errors, count: 2"
    monkeypatch.setattr(tools, "_run", lambda command, timeout: (None, "timed out after 300 s"))
    assert tools.jadx_decompile(inputs, tmp_path / "w3" / "jadx", wanted) == (
        [], "failed: timed out after 300 s")
    assert tools.jadx_decompile(tmp_path / "empty", out_dir, wanted) == (
        [], "failed: nothing to decompile")
    monkeypatch.setattr(tools, "availability", lambda: {"jadx": "jadx.cmd"})
    unsafe = tmp_path / "a&b"
    unsafe.mkdir()
    (unsafe / "classes.dex").write_bytes(b"dex")
    files, note = tools.jadx_decompile(unsafe, tmp_path / "w4" / "jadx", wanted)
    assert files == [] and note.startswith("failed: the work folder path holds characters")


def test_load_app_with_tools(tmp_path, monkeypatch):
    seen = {}

    def verify(path):
        seen["verify"] = (path, path.is_file(), path.read_bytes()[:2])
        return True, "ok (verified: v2)"

    def decompile(inputs, out_dir, classes):
        seen["decompile"] = (sorted(p.name for p in inputs.iterdir()), out_dir, classes)
        target = out_dir / "com" / "example" / "kitapp" / "MainActivity.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class MainActivity {\n  String url = \"http://x.example\";\n}\n")
        return [target], "ok (1 files)"

    monkeypatch.setattr(tools, "availability", lambda: {"jadx": "jadx", "apksigner": "a"})
    monkeypatch.setattr(tools, "apksigner_verify", verify)
    monkeypatch.setattr(tools, "jadx_decompile", decompile)
    other = kit.dex.build_dex(["unrelated"], [("Lother/Thing;", None)])
    ctx = load(tmp_path, kit.build_apk(extra_dex=[other]), use_tools=True)
    check_virtual_files(ctx)
    work = Path(os.environ["SCA_DATA_DIR"]) / "apps" / ctx.facts["sha256"][:12]
    assert seen["verify"][0] == work / "verify" / "base.apk" and seen["verify"][1:] == (True, b"PK")
    assert seen["decompile"] == (["classes.dex"], work / "jadx", [
        "androidx.core.content.FileProvider", "com.example.kitapp.*",
        "com.example.kitapp.KitReceiver", "com.example.kitapp.MainActivity"])
    assert ctx.facts["tools"] == {"apksigner": "ok (verified: v2)", "jadx": "ok (1 files)"}
    assert ctx.facts["signing"]["verified"] is True
    by = files_of(ctx)
    assert by[SIGNING_FILE].lines[-1] == "Signature verified by apksigner: yes"
    java = by["jadx/com/example/kitapp/MainActivity.java"]
    assert (java.origin, java.language, java.lines[1]) == (
        "decompiled", "java", '  String url = "http://x.example";')
    assert sorted(p.name for p in work.iterdir()) == ["jadx"]       # copies removed
    monkeypatch.setattr(tools, "apksigner_verify", lambda path: (False, "ok (does not verify: "
                                                                        "ERROR: bad digest)"))
    ctx = load(tmp_path, kit.build_apk(), "bad.apk", use_tools=True)
    assert files_of(ctx)[SIGNING_FILE].lines[-1] == \
        "Signature verified by apksigner: no: ERROR: bad digest"
    monkeypatch.setattr(tools, "apksigner_verify", lambda path: (None, "failed: no java"))
    ctx = load(tmp_path, kit.build_apk(), "nojava.apk", use_tools=True)
    assert files_of(ctx)[SIGNING_FILE].lines[-1] == \
        "Signature verified by apksigner: not checked (failed: no java)"
    assert ctx.facts["signing"]["verified"] is None
    ctx = load(tmp_path, kit.build_aab(), "app.aab", use_tools=True)
    assert ctx.facts["tools"]["apksigner"] == "not run: apksigner reads APK files only"
    copies = []
    monkeypatch.setattr(tools, "apksigner_verify",
                        lambda path: copies.append(path.read_bytes()) or verify(path))
    parts = kit.split_apk(kit.build_apk())
    ctx = load(tmp_path, kit.build_apk_set(parts), "set.apks", use_tools=True)
    assert ctx.facts["signing"]["verified"] is True
    assert copies == [parts["base"]]       # the base APK, copied in blocks from the set


def test_load_app_without_tools(tmp_path, no_tools):
    ctx = load(tmp_path, kit.build_apk(), use_tools=True)
    assert ctx.facts["tools"] == {"apksigner": tools.NOT_INSTALLED["apksigner"],
                                  "jadx": tools.NOT_INSTALLED["jadx"]}
    assert files_of(ctx)[SIGNING_FILE].lines[-1] == \
        "Signature verified by apksigner: not checked (apksigner is not installed)"
    assert not any(s.origin == "decompiled" for s in ctx.files)


# ------------------------------------------------------------------ source projects
FLUTTER_PUBSPEC = """name: demo_app
publish_to: 'none'
version: 1.2.3+4
environment:
  sdk: ^3.5.0
dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.0
flutter:
  assets:
    - .env
"""
LOCK = """packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "0.13.0"
sdks:
  dart: ">=3.5.0 <4.0.0"
"""
APP_GRADLE = """plugins {
    id("com.android.application")
}
android {
    namespace = "com.example.demo"
    // minSdk = 16
    /* targetSdk = 15 */
    defaultConfig {
        applicationId = "com.example.demo"
        minSdk = flutter.minSdkVersion
        targetSdk = 34
        versionCode = flutter.versionCode
    }
}
"""
MANIFEST_XML = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="demo" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>
"""


def write(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")


def flutter_project(root):
    write(root, {
        "pubspec.yaml": FLUTTER_PUBSPEC, "pubspec.lock": LOCK, "lib/main.dart": "void main() {}\n",
        ".env": "KEY=1\n",
        "android/build.gradle.kts": "allprojects {}\n",
        "android/app/build.gradle.kts": APP_GRADLE,
        "android/app/src/main/AndroidManifest.xml": MANIFEST_XML,
        "android/app/src/debug/AndroidManifest.xml": MANIFEST_XML,
        "android/app/src/profile/AndroidManifest.xml": MANIFEST_XML,
        "android/app/src/main/res/xml/network_security_config.xml":
            "<network-security-config><base-config cleartextTrafficPermitted=\"true\"/>"
            "</network-security-config>\n",
        "android/app/src/main/res/xml-v25/shortcuts.xml": "<shortcuts/>\n",
        "android/key.properties": "storePassword=secret\nkeyPassword=secret\n",
        "android/app/upload-keystore.jks": b"\xfe\xed\xfe\xed" + bytes(60),
        "build/app/outputs/release.keystore": b"\x00" * 10,
        "secrets/old.p12": b"\x30\x82" + bytes(20),
        "ios/Runner/Info.plist": "<plist><dict/></plist>\n",
        "ios/Flutter/AppFrameworkInfo.plist": "<plist><dict/></plist>\n",
        "macos/Runner/Info.plist": "<plist><dict/></plist>\n",
        "web/index.html": "<html></html>\n",
        "example/pubspec.yaml": FLUTTER_PUBSPEC.replace("demo_app", "demo_example"),
        "packages/helper/pubspec.yaml": "name: helper\nresolution: workspace\n",
    })


def test_flutter_project(tmp_path):
    root = tmp_path / "demo"
    flutter_project(root)
    files = list(walk_project(str(root)))
    ctx = flutter.load_project(root, files, exclude_dirs=["secrets"])
    assert ctx.kind == "flutter-project" and ctx.root == root and not ctx.is_app and ctx.is_flutter
    facts = ctx.facts
    assert facts == {
        "debug_manifests": ["android/app/src/debug/AndroidManifest.xml",
                            "android/app/src/profile/AndroidManifest.xml"],
        "kind": "flutter-project", "flutter": True, "name": "demo_app",
        "package": "com.example.demo", "version_name": "1.2.3", "version_code": "4",
        "min_sdk": None, "min_sdk_note": "flutter.minSdkVersion (the Flutter SDK default)",
        "target_sdk": 34, "compile_sdk": None, "platforms": ["android", "ios", "web", "macos"],
        "packages": [{"name": "http", "version": "0.13.0", "source": "hosted",
                      "dependency": "direct main"}],
        "dart_sdk": "^3.5.0"}
    assert [rel for rel, _ in ctx.manifests] == ["android/app/src/main/AndroidManifest.xml"]
    assert ctx.manifests[0][1].find("application").get("android:allowBackup") == "true"
    assert sorted(ctx.xml_resources) == ["android/app/src/main/res/xml-v25/shortcuts.xml",
                                         "android/app/src/main/res/xml/network_security_config.xml"]
    assert ctx.resource_files == {
        "@xml/network_security_config": "android/app/src/main/res/xml/network_security_config.xml"}
    assert ctx.gradle_files == ["android/app/build.gradle.kts"]
    assert ctx.key_properties == ["android/key.properties"]
    assert ctx.plists == ["ios/Runner/Info.plist", "macos/Runner/Info.plist"]
    assert ctx.pubspecs == [("example/pubspec.yaml", None),
                            ("packages/helper/pubspec.yaml", "pubspec.lock"),
                            ("pubspec.yaml", "pubspec.lock")]
    assert ctx.keystores == ["android/app/upload-keystore.jks"]
    placeholder, = ctx.files
    assert (placeholder.rel, placeholder.path, placeholder.origin, placeholder.language) == (
        "android/app/upload-keystore.jks", Path("android/app/upload-keystore.jks"),
        "placeholder", "config")
    assert placeholder.lines == ["Binary keystore file (64 bytes): it holds an app signing key."]
    assert ctx.packages == [] and ctx.warnings == []
    ctx = flutter.load_project(root, files)
    assert ctx.keystores == ["android/app/upload-keystore.jks", "secrets/old.p12"]


def test_android_project(tmp_path):
    write(tmp_path, {
        "settings.gradle": "include ':app', ':library'\n",
        "app/build.gradle": "apply plugin: 'com.android.application'\nandroid {\n"
                            "    compileSdkVersion 33\n    defaultConfig {\n"
                            "        applicationId \"org.example.legacy\"\n"
                            "        minSdkVersion 19\n        targetSdkVersion(30)\n"
                            "        versionCode 12\n        versionName '4.5'\n    }\n}\n",
        "app/src/main/AndroidManifest.xml": MANIFEST_XML.replace(
            "<manifest ", '<manifest package="org.example.manifest" '),
        "library/build.gradle": "apply plugin: 'com.android.library'\n",
        "library/src/main/AndroidManifest.xml": MANIFEST_XML,
        "library/src/main/res/xml/paths.xml": "<paths/>",
    })
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    assert ctx.kind == "android-project" and not ctx.is_flutter
    assert ctx.facts == {"kind": "android-project", "flutter": False, "name": tmp_path.name,
                         "package": "org.example.legacy", "version_name": "4.5",
                         "version_code": "12", "min_sdk": 19, "target_sdk": 30,
                         "compile_sdk": 33, "platforms": ["android"]}
    assert [rel for rel, _ in ctx.manifests] == ["app/src/main/AndroidManifest.xml",
                                                 "library/src/main/AndroidManifest.xml"]
    assert ctx.library_manifests == ["library/src/main/AndroidManifest.xml"]
    assert ctx.gradle_files == ["app/build.gradle"]
    assert ctx.resource_files == {"@xml/paths": "library/src/main/res/xml/paths.xml"}
    assert ctx.pubspecs == [] and ctx.files == []


def test_not_a_mobile_project(tmp_path):
    write(tmp_path / "dart", {"pubspec.yaml": "name: tool\nenvironment:\n  sdk: ^3.0.0\n",
                              "bin/main.dart": "void main() {}\n"})
    write(tmp_path / "loose", {"src/main/AndroidManifest.xml": MANIFEST_XML, "app.py": "x = 1\n"})
    write(tmp_path / "debugonly", {"app/build.gradle": "apply plugin: 'com.android.application'\n",
                                   "app/src/debug/AndroidManifest.xml": MANIFEST_XML})
    for folder in ("dart", "loose", "debugonly"):
        root = tmp_path / folder
        assert flutter.load_project(root, list(walk_project(str(root)))) is None
    assert flutter.load_project(tmp_path / "loose" / "app.py", []) is None


def test_project_warnings_and_fallbacks(tmp_path):
    write(tmp_path, {
        "pubspec.yaml": "name: broken\ndependencies:\n  flutter:\n    sdk: flutter\n",
        "pubspec.lock": "packages: [unclosed\n",
        "android/app/src/main/AndroidManifest.xml": "<manifest><application>",
        "android/app/src/main/res/xml/bad.xml": "<x",
        "android/app/build.gradle": "android { defaultConfig { minSdkVersion localMin } }\n",
    })
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    assert ctx.kind == "flutter-project" and ctx.manifests == [] and ctx.xml_resources == {}
    assert any(w.startswith("android/app/src/main/AndroidManifest.xml: not parsed (") for w in
               ctx.warnings)
    assert any(w.startswith("android/app/src/main/res/xml/bad.xml: not parsed (") for w in
               ctx.warnings)
    assert any(w.startswith("pubspec.lock: not parsed (") for w in ctx.warnings)
    assert ctx.facts["min_sdk"] is None and ctx.facts["min_sdk_note"] == "localMin"
    assert ctx.facts["package"] == "broken" and ctx.facts["version_name"] == ""
    assert ctx.gradle_files == ["android/app/build.gradle"]       # no application plugin
    assert ctx.facts["warnings"] == ctx.warnings


ANDROID_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def test_library_modules_are_not_the_app(tmp_path):
    lib_manifest = ('<manifest %s package="com.example.alib"><application>\n'
                    '  <service android:name=".LibService" android:exported="false"/>\n'
                    '</application></manifest>\n' % ANDROID_NS)
    write(tmp_path, {
        "alib/build.gradle.kts": 'plugins {\n    id("com.android.library")\n}\n'
                                 'android {\n    namespace = "com.example.alib"\n'
                                 '    defaultConfig { minSdk = 21 }\n}\n',
        "alib/src/main/AndroidManifest.xml": lib_manifest,
        "alib/src/prod/AndroidManifest.xml": "<manifest/>",
        "app/build.gradle": "plugins { id 'com.android.application' }\nandroid {\n"
                            "    defaultConfig { applicationId 'com.example.p6'; minSdk 26; "
                            "targetSdk 34 }\n}\n",
        "app/src/main/AndroidManifest.xml":
            '<manifest %s><application android:allowBackup="false"/></manifest>\n' % ANDROID_NS,
        "catalog/build.gradle.kts": "plugins {\n    alias(libs.plugins.android.library)\n}\n",
        "catalog/src/main/AndroidManifest.xml": "<manifest><application/></manifest>\n",
        "feature/build.gradle": "// apply plugin: 'com.android.library'\n"
                                "apply plugin: 'com.android.dynamic-feature'\n",
        "feature/src/main/AndroidManifest.xml": "<manifest/>\n",
    })
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    assert [rel for rel, _ in ctx.manifests] == [
        "app/src/main/AndroidManifest.xml", "feature/src/main/AndroidManifest.xml",
        "alib/src/main/AndroidManifest.xml", "alib/src/prod/AndroidManifest.xml",
        "catalog/src/main/AndroidManifest.xml"]
    assert ctx.library_manifests == ["alib/src/main/AndroidManifest.xml",
                                     "alib/src/prod/AndroidManifest.xml",
                                     "catalog/src/main/AndroidManifest.xml"]
    assert ctx.gradle_files == ["app/build.gradle"]
    facts = ctx.facts
    assert (facts["package"], facts["min_sdk"], facts["target_sdk"]) == ("com.example.p6", 26, 34)
    # a project of libraries only: no app-level Gradle file and no SDK levels of a library
    for rel in ("app/build.gradle", "app/src/main/AndroidManifest.xml", "feature/build.gradle",
                "feature/src/main/AndroidManifest.xml"):
        (tmp_path / rel).unlink()
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    assert ctx.kind == "android-project" and ctx.gradle_files == []
    assert ctx.library_manifests == [rel for rel, _ in ctx.manifests]
    assert ctx.facts["package"] == "com.example.alib"
    assert ctx.facts["min_sdk"] is None and ctx.facts["target_sdk"] is None


def test_product_flavor_source_sets_are_release_manifests(tmp_path):
    flavor = ('<manifest %s><application android:debuggable="true">\n'
              '  <receiver android:name=".ProdReceiver" android:exported="true"/>\n'
              '</application></manifest>\n' % ANDROID_NS)
    write(tmp_path, {
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "android/app/build.gradle.kts": APP_GRADLE,
        "android/app/src/main/AndroidManifest.xml": MANIFEST_XML,
        "android/app/src/main/res/xml/nsc.xml": "<network-security-config/>\n",
        "android/app/src/dev/AndroidManifest.xml": flavor,
        "android/app/src/dev/res/xml/nsc.xml":
            '<network-security-config><base-config cleartextTrafficPermitted="true"/>'
            '</network-security-config>\n',
        "android/app/src/prod/AndroidManifest.xml": flavor,
        "android/app/src/prodRelease/AndroidManifest.xml": flavor,
        "android/app/src/release/AndroidManifest.xml": flavor,
        "android/app/src/debug/AndroidManifest.xml": flavor,
        "android/app/src/prodDebug/AndroidManifest.xml": flavor,
        "android/app/src/devProfile/AndroidManifest.xml": flavor,
        "android/app/src/devProfile/res/xml/profile.xml": "<x/>\n",
        "android/app/src/androidTest/AndroidManifest.xml": flavor,
        "android/app/src/testFixtures/AndroidManifest.xml": flavor,
        "android/app/src/androidTestProd/res/xml/test.xml": "<x/>\n",
    })
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    prefix = "android/app/src/"
    assert [rel[len(prefix):] for rel, _ in ctx.manifests] == [
        "main/AndroidManifest.xml", "dev/AndroidManifest.xml", "prod/AndroidManifest.xml",
        "prodRelease/AndroidManifest.xml", "release/AndroidManifest.xml"]
    assert [rel[len(prefix):] for rel in ctx.facts["debug_manifests"]] == [
        "debug/AndroidManifest.xml", "devProfile/AndroidManifest.xml",
        "prodDebug/AndroidManifest.xml"]
    assert sorted(ctx.xml_resources) == [prefix + "dev/res/xml/nsc.xml",
                                         prefix + "main/res/xml/nsc.xml"]
    assert ctx.resource_files == {"@xml/nsc": prefix + "main/res/xml/nsc.xml"}
    assert ctx.library_manifests == [] and ctx.warnings == []
    assert ctx.facts["package"] == "com.example.demo"


@pytest.mark.parametrize("gradle, uses_sdk, expected", [
    ("minSdkVersion 16", "", (16, 16, project.TARGET_SDK_DEFAULT_NOTE)),
    ("minSdk = flutter.minSdkVersion", "", (None, None, None)),
    ("minSdkVersion 16\n        targetSdkVersion flutter.targetSdkVersion", "",
     (16, None, "flutter.targetSdkVersion (the Flutter SDK default)")),
    ("", '<uses-sdk android:minSdkVersion="21"/>', (21, 21, project.TARGET_SDK_DEFAULT_NOTE)),
    ("minSdkVersion 16", '<uses-sdk android:targetSdkVersion="30"/>', (16, 30, None)),
])
def test_target_sdk_defaults_to_min_sdk(tmp_path, gradle, uses_sdk, expected):
    write(tmp_path, {
        "app/build.gradle": "apply plugin: 'com.android.application'\nandroid {\n"
                            "    defaultConfig {\n        %s\n    }\n}\n" % gradle,
        "app/src/main/AndroidManifest.xml":
            "<manifest %s>%s<application/></manifest>\n" % (ANDROID_NS, uses_sdk)})
    facts = flutter.load_project(tmp_path, list(walk_project(str(tmp_path)))).facts
    assert (facts["min_sdk"], facts["target_sdk"], facts.get("target_sdk_note")) == expected


def test_unicode_digits_are_not_sdk_levels(tmp_path):
    # "²".isdigit() is true but int() refuses it: the project was not read at all
    write(tmp_path, {
        "app/build.gradle": "apply plugin: 'com.android.application'\n",
        "app/src/main/AndroidManifest.xml":
            '<manifest %s android:versionCode="²"><uses-sdk android:minSdkVersion="²" '
            'android:targetSdkVersion="٣٣"/><application/></manifest>\n' % ANDROID_NS})
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    facts = ctx.facts
    assert (facts["min_sdk"], facts["min_sdk_note"]) == (None, "²")
    assert (facts["target_sdk"], facts["target_sdk_note"]) == (None, "٣٣")
    assert ctx.warnings == [] and len(ctx.manifests) == 1


def test_unclosed_gradle_comments_take_linear_time(tmp_path):
    started = time.perf_counter()
    assert project._code("/*a" * 40_000) == " "          # was quadratic: 17 s
    assert time.perf_counter() - started < 1
    assert project._code('minSdk = 21 /* note\ntargetSdk = 15').split() == ["minSdk", "=", "21"]
    assert project._code('x = "/*" // c\ny = 1') == 'x = "/*"  \ny = 1'
    write(tmp_path, {"app/build.gradle": "apply plugin: 'com.android.application'\n"
                                         + "/*a" * 40_000,
                     "app/src/main/AndroidManifest.xml": MANIFEST_XML})
    started = time.perf_counter()
    ctx = flutter.load_project(tmp_path, list(walk_project(str(tmp_path))))
    assert time.perf_counter() - started < 2 and ctx.gradle_files == ["app/build.gradle"]


def test_no_exception_but_app_error_leaves_load_project(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    flutter_project(root)
    files = list(walk_project(str(root)))

    def bug(*args, **kwargs):
        raise RuntimeError("bug")

    with monkeypatch.context() as patch:
        patch.setattr(project, "_facts", bug)
        ctx = flutter.load_project(root, files)
        assert ctx.warnings == ["facts: not read (RuntimeError: bug)"]
        assert ctx.facts["kind"] == "flutter-project" and ctx.manifests and ctx.keystores
    with monkeypatch.context() as patch:
        patch.setattr(project, "_android", bug)
        ctx = flutter.load_project(root, files)
        assert ctx.warnings == ["Android modules: not read (RuntimeError: bug)"]
        assert ctx.facts["package"] == "demo_app" and ctx.pubspecs
    with monkeypatch.context() as patch:
        patch.setattr(project.pubspec, "parse_pubspec", bug)
        ctx = flutter.load_project(root, files)
        assert ctx.kind == "android-project"
        assert "pubspec.yaml: not read (RuntimeError: bug)" in ctx.warnings
    monkeypatch.setattr(project, "_manifest_files", bug)
    with pytest.raises(flutter.AppError,
                       match=r"^demo: the project could not be read \(RuntimeError: bug\)"):
        flutter.load_project(root, files)


def test_keystore_walk_limits(tmp_path, monkeypatch):
    write(tmp_path, {"pubspec.yaml": FLUTTER_PUBSPEC, "a.keystore": b"k", "b.P12": b"k",
                     "c.pfx": b"k", "node_modules/d.jks": b"k", "Pods/e.jks": b"k"})
    files = list(walk_project(str(tmp_path)))
    assert flutter.load_project(tmp_path, files).keystores == ["a.keystore", "b.P12", "c.pfx"]
    assert "node_modules" in SKIP_DIRS
    monkeypatch.setattr(project, "MAX_KEYSTORES", 2)
    assert flutter.load_project(tmp_path, files).keystores == ["a.keystore", "b.P12"]
    monkeypatch.setattr(project, "MAX_WALK_FILES", 1)
    assert flutter.load_project(tmp_path, files).keystores == ["a.keystore"]


def test_repository_samples():
    samples = ROOT / "samples"
    vulnerable = flutter.load_project(samples / "flutter_vulnerable_app", list(walk_project(
        str(samples / "flutter_vulnerable_app"))))
    assert vulnerable.kind == "flutter-project"
    assert vulnerable.facts["package"] == "com.pocketshop.app"
    assert vulnerable.key_properties == ["android/key.properties"]
    assert vulnerable.plists == ["ios/Runner/Info.plist"]
    assert vulnerable.pubspecs == [("pubspec.yaml", "pubspec.lock")]
    assert sorted(vulnerable.resource_files) == ["@xml/file_paths", "@xml/network_security_config"]
    assert len(vulnerable.facts["packages"]) > 50
    safe = flutter.load_project(samples / "flutter_safe_app",
                                list(walk_project(str(samples / "flutter_safe_app"))))
    assert safe.kind == "flutter-project" and safe.key_properties == []
    probe = flutter.load_project(samples / "flutter_apk_probe",
                                 list(walk_project(str(samples / "flutter_apk_probe"))))
    assert probe.pubspecs == [("pubspec.yaml", None)] and probe.facts["platforms"] == ["android"]
    assert flutter.load_project(samples / "vulnerable_app",
                                list(walk_project(str(samples / "vulnerable_app")))) is None


@pytest.mark.parametrize("lab, package, manifests", [
    ("DVMA", "dvma", 3), ("DVFA", "com.schmiemandev.dvfa", 1),
    ("Ostorlab-Insecure-Flutter", "com.example.ostorlab_insecure_flutter_app", 1)])
def test_lab_projects(lab, package, manifests):
    root = ROOT / "infected_project" / lab
    if not root.is_dir():
        pytest.skip("the %s lab is not fetched" % lab)
    ctx = flutter.load_project(root, list(walk_project(str(root))))
    assert ctx.kind == "flutter-project" and ctx.facts["package"] == package
    assert len(ctx.manifests) == manifests and len(ctx.facts["debug_manifests"]) == 2
    assert ctx.facts["min_sdk_note"] == "flutter.minSdkVersion (the Flutter SDK default)"
    assert ctx.warnings == []


# ------------------------------------------------------------------ public API
def test_analyze_and_refine_come_from_checks(monkeypatch):
    calls = []
    fake = type(sys)("sca.flutter.checks")
    fake.analyze = lambda ctx, by_rel: calls.append(("analyze", ctx, by_rel)) or ([], "ok")
    fake.refine = lambda findings, by_rel, ctx: calls.append(("refine", findings)) or 2
    monkeypatch.setitem(sys.modules, "sca.flutter.checks", fake)
    ctx = MobileContext(kind="apk", root=Path("app.apk"))
    assert flutter.analyze(ctx, {}) == ([], "ok")
    assert flutter.refine([], {}, ctx) == 2
    assert calls == [("analyze", ctx, {}), ("refine", [])]


# ------------------------------------------------------------------ real app packages
@real_apks
@pytest.mark.parametrize("name, mode, obfuscated", [
    ("debug.apk", "debug", False), ("release.apk", "release", False),
    ("release_obf.apk", "release", True), ("release.aab", "release", False)])
def test_real_vuln_probe_packages(name, mode, obfuscated):
    started = time.time()
    ctx = flutter.load_app(APK_DIR / name)
    assert time.time() - started < (40 if mode == "debug" else 20)
    check_virtual_files(ctx)
    facts = ctx.facts
    assert (facts["package"], facts["build_mode"], facts["obfuscated"]) == (
        "com.example.vuln_probe", mode, obfuscated)
    assert (facts["min_sdk"], facts["target_sdk"], facts["compile_sdk"]) == (24, 36, 36)
    assert facts["dart_version"] == "3.12.2"
    assert facts["engine_revision"] == "0cd610717bde95fd88343c64f81c11ba4e5c0010"
    assert facts["snapshot_hash"] == "ace654289f5abc240509fc941453ebc5"
    assert facts["signing"]["certificates"][0]["subject"] == "C=US, O=Android, CN=Android Debug"
    assert facts["signing"]["schemes"] == (["v1"] if name.endswith(".aab") else ["v2"])
    assert ctx.warnings == []
    by = files_of(ctx)
    if mode == "debug":
        assert by["dart/lib/main.dart"].origin == "recovered"
        assert facts["packages"][0] == {"name": "characters", "version": "1.4.1",
                                        "source": "hosted", "found_in": "kernel"}
    else:
        assert len(by["lib/arm64-v8a/libapp.so"].lines) > 5000


@real_probe
@pytest.mark.parametrize("name", PACKAGES)
def test_real_probe_packages(name):
    started = time.time()
    ctx = flutter.load_app(PROBE_DIR / name)
    assert time.time() - started < (40 if name == "debug.apk" else 20)
    check_virtual_files(ctx)
    by = files_of(ctx)
    manifest = by["AndroidManifest.xml"]
    for text in ('android:allowBackup="true"', 'android:usesCleartextTraffic="true"',
                 'android:scheme="probe"', 'android:scheme="https"', ".ProbeReceiver"):
        assert find_line(manifest, text), text
    application = ctx.manifests[0][1].find("application")
    assert application.get("android:networkSecurityConfig") == "@xml/network_security_config"
    nsc = by["res/xml/network_security_config.xml"]
    assert find_line(nsc, 'cleartextTrafficPermitted="true"') and find_line(nsc, 'src="user"')
    assert find_line(by["res/xml/file_paths.xml"], "<root-path")
    assert ctx.resource_files["@xml/network_security_config"] == \
        "res/xml/network_security_config.xml"
    env = by["assets/flutter_assets/assets/.env"]
    assert "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in env.lines
    code = by["dart/lib/main.dart"] if name == "debug.apk" else by["lib/arm64-v8a/libapp.so"]
    for text in ("AKIAIOSFODNN7EXAMPLE", "http://api.flutter-probe.example/v1/login",
                 "SELECT * FROM users WHERE name = '"):
        assert find_line(code, text), text
    assert ctx.facts["build_mode"] == ("debug" if name == "debug.apk" else "release")
    assert ctx.facts["obfuscated"] is (name == "release_obf.apk")
    if name != "debug.apk":
        archive = zipread.open_container(PROBE_DIR / name)
        with archive:
            names = archive.archive.names()
        if name.endswith(".apk"):
            assert "res/8G.xml" in names and "res/8K.xml" in names
    assert by[BUILD_FILE].lines[0] == "Flutter app: yes" and ctx.warnings == []


@real_probe
def test_real_probe_apk_set(tmp_path):
    parts = kit.split_apk((PROBE_DIR / "release.apk").read_bytes())
    assert sorted(parts) == ["base", "split_config.arm64_v8a"]
    ctx = load(tmp_path, kit.build_apk_set(parts), "probe.apks")
    assert ctx.kind == "apks" and ctx.facts["build_mode"] == "release"
    by = files_of(ctx)
    assert find_line(by["lib/arm64-v8a/libapp.so"], "AKIAIOSFODNN7EXAMPLE")
    assert "res/xml/network_security_config.xml" in by and "classes.dex" in by
    assert ctx.facts["engine_revision"] == "0cd610717bde95fd88343c64f81c11ba4e5c0010"


@real_probe
@with_jadx
@pytest.mark.parametrize("name", ["release.apk", "debug.apk"])
def test_real_tools(name):
    ctx = flutter.load_app(PROBE_DIR / name, use_tools=True)
    decompiled = sorted(s.rel for s in ctx.files if s.origin == "decompiled")
    assert "jadx/com/example/flutter_apk_probe/ProbeReceiver.java" in decompiled
    assert "jadx/com/example/flutter_apk_probe/MainActivity.java" in decompiled
    assert ctx.facts["tools"]["jadx"].startswith("ok (")
    if tools.availability()["apksigner"]:
        assert ctx.facts["signing"]["verified"] is True
        assert files_of(ctx)[SIGNING_FILE].lines[-1] == "Signature verified by apksigner: yes"
    work = Path(os.environ["SCA_DATA_DIR"]) / "apps" / ctx.facts["sha256"][:12]
    assert sorted(p.name for p in work.iterdir()) == ["jadx"]
    shutil.rmtree(tools._long(work), ignore_errors=True)
