"""Tests for the structural checks of the Flutter / Android module (sca/flutter/checks.py and
sca/flutter/android.py): the check catalog, manifests written in a project and decoded from
binary or protobuf XML, network security configs, FileProvider paths, Gradle builds,
key.properties and keystores, Info.plist, pubspec assets and dependencies, the summaries and
strings dumps of an app package, the app facts and refine().

The real inputs: samples/flutter_vulnerable_app against samples/flutter_ground_truth.json,
samples/flutter_safe_app, the Flutter labs in infected_project/ (skipped when they are not
fetched) and the built APKs (skipped unless SCA_FLUTTER_PROBE_DIR points to the packages built
from samples/flutter_apk_probe, or SCA_FLUTTER_APK_DIR to the vuln_probe packages)."""
import json
import os
import random
import re
import zipfile
from datetime import date
from pathlib import Path

import pytest

from sca import cwe
from sca.flutter import aabproto, arsc, axml, checks, pubspec
from sca.flutter.android import (FileProviderPaths, ManifestInfo, NetworkSecurityConfig,
                                 backup_policy, cleartext_policy, full_class_name,
                                 protection_base)
from sca.flutter.checks import BY_ID, CHECKS, analyze, read_gradle, refine
from sca.flutter.context import MobileContext
from sca.flutter.xmltree import XmlNode, parse_xml_text, render_xml
from sca.models import SEVERITY_RANK, Finding
from sca.walker import SKIP_DIRS, SourceFile, walk_project

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
VULN = SAMPLES / "flutter_vulnerable_app"
SAFE = SAMPLES / "flutter_safe_app"
LABS = ROOT / "infected_project"
PROBE_DIR = os.environ.get("SCA_FLUTTER_PROBE_DIR", "")
APK_DIR = os.environ.get("SCA_FLUTTER_APK_DIR", "")
TAG = re.compile(r"\[([A-Z]\d{2})\]")
KEYSTORE_SUFFIXES = (".jks", ".keystore", ".p12", ".pfx")
ANDROID_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'
TOOLS_NS = 'xmlns:tools="http://schemas.android.com/tools"'


# ------------------------------------------------------------------ helpers
def project_context(folder):
    """A MobileContext for a source folder, built the way design section 8 describes the
    project loader: the walked files, the release manifests (src/main and src/release) of
    every Android module with a Gradle file, their res/xml files, key.properties, Info.plist
    under ios/ and macos/, pubspec.yaml / pubspec.lock pairs and keystore placeholders."""
    folder = Path(folder)
    by_rel = {sf.rel: sf for sf in walk_project(str(folder))}
    ctx = MobileContext(kind="flutter-project", root=folder)
    for rel in sorted(by_rel):
        match = re.fullmatch(r"(?:(.+)/)?src/main/AndroidManifest\.xml", rel)
        if not match:
            continue
        module = match.group(1) + "/" if match.group(1) else ""
        gradle = [module + name for name in ("build.gradle.kts", "build.gradle")
                  if module + name in by_rel]
        if not gradle:
            continue
        ctx.gradle_files.append(gradle[0])
        for source_set in ("main", "release"):
            manifest = "%ssrc/%s/AndroidManifest.xml" % (module, source_set)
            if manifest in by_rel:
                root, error = parse_xml_text(by_rel[manifest].text)
                assert root is not None, (manifest, error)
                ctx.manifests.append((manifest, root))
        xml_dir = module + "src/main/res/xml/"
        for name in sorted(by_rel):
            rest = name[len(xml_dir):]
            if name.startswith(xml_dir) and rest.endswith(".xml") and "/" not in rest:
                root, _error = parse_xml_text(by_rel[name].text)
                if root is not None:
                    ctx.xml_resources[name] = root
                    ctx.resource_files.setdefault("@xml/" + rest[:-4], name)
    for rel in sorted(by_rel):
        name = rel.rsplit("/", 1)[-1]
        if name == "key.properties":
            ctx.key_properties.append(rel)
        elif name == "Info.plist" and re.match(r"(ios|macos)/", rel):
            ctx.plists.append(rel)
        elif name == "pubspec.yaml":
            lock = rel[:-len("pubspec.yaml")] + "pubspec.lock"
            ctx.pubspecs.append((rel, lock if lock in by_rel else None))
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = sorted(d for d in dirnames if d.lower() not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.lower().endswith(KEYSTORE_SUFFIXES):
                path = Path(dirpath) / name
                rel = path.relative_to(folder).as_posix()
                ctx.files.append(SourceFile(
                    Path(rel), rel, "config", "Binary keystore file (%d bytes): it holds an app "
                    "signing key." % path.stat().st_size, origin="placeholder"))
                ctx.keystores.append(rel)
    ctx.facts.update({"kind": ctx.kind, "name": folder.name, "flutter": True})
    return ctx, by_rel


def make_project(folder, files):
    """Write a project (rel -> text or bytes) and build its context."""
    for rel, content in files.items():
        path = folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    return project_context(folder)


def decoded(text, resolve=None):
    """Source XML turned into binary XML and decoded again, as an app package gives it."""
    root, error = parse_xml_text(text)
    assert root is not None, error
    return axml.decode_axml(axml.encode_axml(root), resolve)


def virtual(rel, text, origin="decoded"):
    return SourceFile(Path(rel), rel, "config", text, origin=origin)


def app_context(manifest, resources=(), files=(), kind="apk", resolve=None, **facts):
    """An app-package context: the decoded manifest, res/xml resources (name -> source XML)
    and other virtual files (rel -> (text, origin))."""
    ctx = MobileContext(kind=kind, root=Path("app." + kind))
    doc = decoded(manifest, resolve)
    ctx.files.append(virtual("AndroidManifest.xml", doc.text))
    ctx.manifests.append(("AndroidManifest.xml", doc.root))
    for name, text in dict(resources).items():
        res = decoded(text)
        rel = "res/xml/%s.xml" % name
        ctx.files.append(virtual(rel, res.text))
        ctx.xml_resources[rel] = res.root
        ctx.resource_files["@xml/" + name] = rel
    for rel, (text, origin) in dict(files).items():
        ctx.files.append(virtual(rel, text, origin))
    ctx.facts.update(facts)
    return ctx


def run(ctx, by_rel=None):
    """analyze() with the invariants every finding keeps."""
    findings, note = analyze(ctx, by_rel or {})
    assert note.startswith("ok (") and "not checked" not in note, note
    files = {sf.rel: sf for sf in ctx.files}
    files.update(by_rel or {})
    for finding in findings:
        check = BY_ID[finding.rule_id]
        assert finding.cwe == check.cwe and finding.engines == ["flutter"], finding
        assert finding.file in files and 1 <= finding.line <= max(1, len(files[finding.file].lines))
        assert finding.description and finding.fix and finding.title, finding.rule_id
        if finding.rule_id.startswith(("ANDROID-", "IOS-", "FLUTTER-APP-")):
            assert finding.snippet == files[finding.file].line_text(finding.line)
    return findings


def summary(findings):
    return sorted((f.rule_id, f.file, f.line) for f in findings)


def line_of(text, needle, start=1):
    """1-based line of the first line at or after `start` that contains `needle`."""
    for number, line in enumerate(text.splitlines(), 1):
        if number >= start and needle in line:
            return number
    raise AssertionError("not found: %r" % needle)


def start_tag(text, needle, tag):
    """Line of the <tag start tag of the element whose attributes contain `needle` (attribute
    order differs between binary and protobuf XML)."""
    lines = text.splitlines()
    inside = line_of(text, needle)
    return next(n for n in range(inside, 0, -1) if lines[n - 1].lstrip().startswith("<" + tag))


def only(findings, rule_id):
    found = [f for f in findings if f.rule_id == rule_id]
    assert len(found) == 1, (rule_id, summary(findings))
    return found[0]


LAUNCHER = """\
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>"""

# the main manifest of `flutter create` (Flutter 3.44), with the package added
TEMPLATE_MANIFEST = """\
<manifest %s
    package="com.example.template">
    <application
        android:label="template"
        android:name="${applicationName}"
        android:icon="@mipmap/ic_launcher">
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTop"
            android:taskAffinity=""
            android:theme="@style/LaunchTheme"
            android:hardwareAccelerated="true"
            android:windowSoftInputMode="adjustResize">
            <meta-data
              android:name="io.flutter.embedding.android.NormalTheme"
              android:resource="@style/NormalTheme" />
%s
        </activity>
        <meta-data
            android:name="flutterEmbedding"
            android:value="2" />
    </application>
    <queries>
        <intent>
            <action android:name="android.intent.action.PROCESS_TEXT"/>
            <data android:mimeType="text/plain"/>
        </intent>
    </queries>
</manifest>
""" % (ANDROID_NS, LAUNCHER)

# the app-level build.gradle.kts of `flutter create`, with a release key instead of the
# template's debug signing (ANDROID-GRADLE-001 has its own tests)
TEMPLATE_GRADLE = """\
plugins {
    id("com.android.application")
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.example.template"
    compileSdk = flutter.compileSdkVersion

    defaultConfig {
        applicationId = "com.example.template"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
"""


def android_project(tmp_path, manifest, resources=(), extra=(), gradle=TEMPLATE_GRADLE):
    files = {"android/app/build.gradle.kts": gradle,
             "android/app/src/main/AndroidManifest.xml": manifest}
    for name, text in dict(resources).items():
        files["android/app/src/main/res/xml/%s.xml" % name] = text
    files.update(dict(extra))
    return make_project(tmp_path, files)


MAIN_MANIFEST = "android/app/src/main/AndroidManifest.xml"


# ------------------------------------------------------------------ catalog
def test_catalog_lists_every_check_once_with_both_titles():
    ids = [check.id for check in CHECKS]
    assert len(ids) == len(set(ids)) == len(BY_ID) == 52
    expected = (["ANDROID-MANIFEST-%03d" % n for n in range(1, 16)]
                + ["ANDROID-SDK-001", "ANDROID-SDK-002", "ANDROID-FILEPROVIDER-001"]
                + ["ANDROID-NSC-%03d" % n for n in range(1, 5)]
                + ["ANDROID-GRADLE-%03d" % n for n in range(1, 5)]
                + ["ANDROID-SIGN-%03d" % n for n in (1, 2, 3, 4, 10, 11)]
                + ["IOS-PLIST-%03d" % n for n in range(1, 6)]
                + ["FLUTTER-APP-%03d" % n for n in range(1, 10)]
                + ["FLUTTER-PUB-%03d" % n for n in range(1, 7)])
    assert sorted(ids) == sorted(expected)
    for check in CHECKS:
        assert check.title and re.search("[\u0600-\u06ff]", check.title_ar), check.id
        assert check.severity in SEVERITY_RANK and 0 < check.confidence <= 1, check.id
        assert check.area in checks.AREAS and check.target in checks.TARGETS, check.id
        assert re.fullmatch(r"CWE-\d+", check.cwe), check.id
        assert cwe.info(check.cwe)["description"], check.id     # a KB entry (or a fold)
    assert BY_ID["IOS-PLIST-003"].cwe == "CWE-326" and cwe.canonical("CWE-326") == "CWE-327"
    assert BY_ID["FLUTTER-APP-008"].confidence == 0.45 and BY_ID["FLUTTER-APP-008"].cwe == "CWE-89"
    for area in checks.AREAS.values():
        assert re.search("[\u0600-\u06ff]", area[1])


# ------------------------------------------------------------------ manifest: application
MEMORY_OPTIONS = {
    "ANDROID-MANIFEST-013": "allowNativeHeapPointerTagging",
    "ANDROID-MANIFEST-014": "gwpAsanMode",
    "ANDROID-MANIFEST-015": "memtagMode",
}


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "compiled-xml"])
def test_explicit_native_memory_opt_outs_point_to_each_attribute(tmp_path, packaged):
    manifest = manifest_with(
        '\n        android:allowNativeHeapPointerTagging="false"'
        '\n        android:gwpAsanMode="%s"\n        android:memtagMode="%s"'
        % (("0", "0x00000000") if packaged else ("never", "off")))
    if packaged:
        ctx = app_context(manifest)
        findings = run(ctx)
        rel, text = "AndroidManifest.xml", ctx.files[0].text
    else:
        findings = run(*android_project(tmp_path, manifest))
        rel, text = MAIN_MANIFEST, manifest
    actual = {f.rule_id: (f.file, f.line) for f in findings if f.rule_id in MEMORY_OPTIONS}
    assert actual == {rule: (rel, line_of(text, name)) for rule, name in MEMORY_OPTIONS.items()}


@pytest.mark.parametrize("attrs", [
    "",
    ' android:allowNativeHeapPointerTagging="true" android:memtagMode="async" android:gwpAsanMode="always"',
    ' android:memtagMode="2" android:gwpAsanMode="-1"',
    ' android:memtagMode="@integer/mode" android:gwpAsanMode="${gwpMode}"',
])
def test_memory_hardening_ignores_safe_absent_and_unresolved_settings(attrs):
    findings = run(app_context(manifest_with(attrs)))
    assert not any(f.rule_id in MEMORY_OPTIONS for f in findings)


@pytest.mark.parametrize("overlay", [
    'a:gwpAsanMode="always"',
    't:remove="a:memtagMode, a:gwpAsanMode"',
    't:node="replace"',
])
def test_release_overlay_supersedes_native_memory_setting(tmp_path, overlay):
    release = ('<manifest xmlns:a="http://schemas.android.com/apk/res/android" '
               'xmlns:t="http://schemas.android.com/tools"><application %s/></manifest>' % overlay)
    main = manifest_with(' android:gwpAsanMode="never"')
    findings = run(*android_project(tmp_path, main, extra={
        "android/app/src/release/AndroidManifest.xml": release,
    }))
    assert not any(f.rule_id in MEMORY_OPTIONS for f in findings)


def test_flutter_template_only_gets_the_backup_default(tmp_path):
    ctx, by_rel = android_project(tmp_path, TEMPLATE_MANIFEST)
    findings = run(ctx, by_rel)
    backup = only(findings, "ANDROID-MANIFEST-003")
    assert len(findings) == 1 and backup.file == MAIN_MANIFEST
    assert backup.line == line_of(TEMPLATE_MANIFEST, "<application")
    assert (backup.severity, backup.confidence) == ("low", 0.6)
    assert "Flutter app template" in backup.description
    assert ctx.facts["flags"] == {"debuggable": "no", "allow_backup": "yes (default)",
                                  "cleartext": "not allowed (default)",
                                  "network_security_config": "none"}
    main = ctx.facts["components"][0]
    assert main == {"type": "activity", "name": "com.example.template.MainActivity",
                    "exported": True, "permission": "", "launcher": True, "deep_links": []}


APP_FLAGS_MANIFEST = """\
<manifest %s package="com.example.flags">
    <application
        android:debuggable="true"
        android:testOnly="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:requestLegacyExternalStorage="true" />
</manifest>
""" % ANDROID_NS


def test_application_attributes_point_to_their_lines(tmp_path):
    ctx, by_rel = android_project(tmp_path, APP_FLAGS_MANIFEST)
    findings = run(ctx, by_rel)
    expected = {"ANDROID-MANIFEST-001": ('android:debuggable="true"', "high", 0.9),
                "ANDROID-MANIFEST-002": ('android:testOnly="true"', "medium", 0.9),
                "ANDROID-MANIFEST-003": ('android:allowBackup="true"', "medium", 0.8),
                "ANDROID-MANIFEST-004": ('android:usesCleartextTraffic="true"', "medium", 0.85),
                "ANDROID-MANIFEST-010": ('android:requestLegacyExternalStorage', "low", 0.7)}
    assert sorted(f.rule_id for f in findings) == sorted(expected)
    for rule_id, (needle, severity, confidence) in expected.items():
        finding = only(findings, rule_id)
        assert finding.line == line_of(APP_FLAGS_MANIFEST, needle), rule_id
        assert (finding.severity, finding.confidence) == (severity, confidence), rule_id
    assert "Dart code" in only(findings, "ANDROID-MANIFEST-004").description
    assert ctx.facts["flags"]["debuggable"] == "yes"
    assert ctx.facts["flags"]["cleartext"] == "allowed (android:usesCleartextTraffic)"


@pytest.mark.parametrize("attributes", [
    'android:allowBackup="false"',
    'android:fullBackupContent="@xml/backup_rules"',
    'android:allowBackup="true" android:dataExtractionRules="@xml/extraction_rules"',
    'android:allowBackup="true" android:fullBackupContent="false"',
    'android:backupAgent=".Backup"',
    'android:allowBackup="${allowBackup}"',
])
def test_backup_rules_or_false_silence_the_backup_check(tmp_path, attributes):
    manifest = '<manifest %s package="com.example.b"><application %s /></manifest>' % (
        ANDROID_NS, attributes)
    ctx, by_rel = android_project(tmp_path, manifest)
    assert run(ctx, by_rel) == []


# ------------------------------------------------------------------ manifest: components
COMPONENTS_MANIFEST = """\
<manifest %s
    package="com.example.shop">
    <permission android:name="com.example.shop.SIGNED" android:protectionLevel="signature" />
    <permission android:name="com.example.shop.OPEN" />
    <permission android:name="com.example.shop.RISKY" android:protectionLevel="dangerous" />
    <application android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true" android:taskAffinity="">
%s
        </activity>
        <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver"
            android:permission="android.permission.DUMP"
            android:exported="true" />
        <service android:name=".SyncJob"
            android:permission="android.permission.BIND_JOB_SERVICE"
            android:exported="true" />
        <receiver android:name="com.google.firebase.iid.FirebaseInstanceIdReceiver"
            android:exported="true"
            android:permission="com.google.android.c2dm.permission.SEND" />
        <receiver android:name=".Signed"
            android:exported="true"
            android:permission="com.example.shop.SIGNED" />
        <receiver android:name=".Open"
            android:exported="true" />
        <service android:name="Implicit">
            <intent-filter><action android:name="com.example.shop.SYNC" /></intent-filter>
        </service>
        <service android:name=".Private" android:exported="false">
            <intent-filter><action android:name="com.example.shop.PRIVATE" /></intent-filter>
        </service>
        <activity android:name=".Normal"
            android:exported="true"
            android:permission="com.example.shop.OPEN" />
        <activity android:name=".Typo"
            android:exported="true"
            android:permission="com.example.shop.SIGNEDD" />
        <activity android:name=".Platform"
            android:exported="true"
            android:permission="android.permission.INTERNET" />
        <provider android:name=".Data"
            android:authorities="com.example.shop.data"
            android:exported="true" />
        <provider android:name=".Guarded"
            android:authorities="com.example.shop.guarded"
            android:exported="true"
            android:readPermission="com.example.shop.SIGNED"
            android:writePermission="com.example.shop.SIGNED" />
        <provider android:name=".HalfOpen"
            android:authorities="com.example.shop.half"
            android:exported="true"
            android:readPermission="com.example.shop.SIGNED" />
        <provider android:name=".Risky"
            android:authorities="com.example.shop.risky"
            android:exported="true"
            android:permission="com.example.shop.RISKY" />
        <provider android:name="androidx.core.content.FileProvider"
            android:authorities="com.example.shop.files"
            android:exported="true"
            android:grantUriPermissions="true" />
        <provider android:name=".Legacy" android:authorities="com.example.shop.legacy" />
        <receiver android:name=".Removed" android:exported="true" tools:node="remove" />
    </application>
</manifest>
""" % (ANDROID_NS + " " + TOOLS_NS, LAUNCHER)


def test_exported_components_are_calibrated(tmp_path):
    ctx, by_rel = android_project(tmp_path, COMPONENTS_MANIFEST)
    findings = run(ctx, by_rel)
    text = COMPONENTS_MANIFEST

    def exported_line(name):
        return line_of(text, 'android:exported="true"', line_of(text, 'android:name="%s"' % name))

    def guard_line(permission):
        return line_of(text, 'android:permission="%s"' % permission)
    assert summary(findings) == sorted([
        ("ANDROID-MANIFEST-005", MAIN_MANIFEST, exported_line(".Open")),
        ("ANDROID-MANIFEST-005", MAIN_MANIFEST, line_of(text, '<service android:name="Implicit">')),
        ("ANDROID-MANIFEST-006", MAIN_MANIFEST, guard_line("com.example.shop.OPEN")),
        ("ANDROID-MANIFEST-006", MAIN_MANIFEST, guard_line("com.example.shop.SIGNEDD")),
        ("ANDROID-MANIFEST-006", MAIN_MANIFEST, guard_line("android.permission.INTERNET")),
        ("ANDROID-MANIFEST-005", MAIN_MANIFEST, exported_line(".Data")),
        ("ANDROID-MANIFEST-005", MAIN_MANIFEST, exported_line(".HalfOpen")),
        ("ANDROID-MANIFEST-006", MAIN_MANIFEST, guard_line("com.example.shop.RISKY")),
    ])
    by_line = {f.line: f for f in findings}
    implicit = by_line[line_of(text, '<service android:name="Implicit">')]
    assert "com.example.shop.Implicit" in implicit.title and "by default" in implicit.description
    assert "protection level is normal" in by_line[guard_line("com.example.shop.OPEN")].description
    assert "neither this app nor Android" in by_line[line_of(text, "SIGNEDD")].description
    assert "change its data" in by_line[exported_line(".HalfOpen")].description
    assert "read and change" in by_line[exported_line(".Data")].description
    components = {c["name"]: c for c in ctx.facts["components"]}
    assert "com.example.shop.Removed" not in components
    assert components["com.example.shop.Legacy"]["exported"] is False
    assert components["com.example.shop.Guarded"]["permission"] == "com.example.shop.SIGNED"
    assert components["androidx.profileinstaller.ProfileInstallReceiver"]["permission"] \
        == "android.permission.DUMP"


@pytest.mark.parametrize("level, expected", [("signature", 0), ("normal", 1), ("", 1)])
def test_application_permission_guards_components(tmp_path, level, expected):
    level_attr = ' android:protectionLevel="%s"' % level if level else ""
    manifest = """\
<manifest %s package="com.example.app">
    <permission android:name="com.example.app.GUARD"%s />
    <application
        android:allowBackup="false"
        android:permission="com.example.app.GUARD">
        <receiver android:name=".Inbox" android:exported="true" />
    </application>
</manifest>
""" % (ANDROID_NS, level_attr)
    ctx, by_rel = android_project(tmp_path, manifest)
    findings = run(ctx, by_rel)
    assert len(findings) == expected
    if expected:
        assert findings[0].rule_id == "ANDROID-MANIFEST-006"
        assert findings[0].line == line_of(manifest, 'android:permission="com.example.app.GUARD"')


LINKS_MANIFEST = """\
<manifest %s package="com.example.links">
    <application android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true" android:taskAffinity="">
%s
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data
                    android:scheme="shop"
                    android:host="open" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="shop" android:host="pay" />
            </intent-filter>
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="shop.example" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" />
                <data android:host="promo.example" android:pathPrefix="/deal" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="content" android:mimeType="application/pdf" />
            </intent-filter>
        </activity>
        <activity android:name=".Hidden" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="hidden" />
            </intent-filter>
        </activity>
        <activity android:name=".AuthRedirect" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="com.example.links.auth" />
            </intent-filter>
        </activity>
        <activity android:name=".Mixed"
            android:exported="true">
            <intent-filter>
                <action android:name="com.example.links.OPEN" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <data android:scheme="mixed" />
            </intent-filter>
        </activity>
    </application>
</manifest>
""" % (ANDROID_NS, LAUNCHER)


def test_deep_links(tmp_path):
    ctx, by_rel = android_project(tmp_path, LINKS_MANIFEST)
    findings = run(ctx, by_rel)
    text = LINKS_MANIFEST
    # the redirect activity only opens links: exported by design, reported as a link only
    assert summary(findings) == sorted([
        ("ANDROID-MANIFEST-007", MAIN_MANIFEST, line_of(text, 'android:scheme="shop"')),
        ("ANDROID-MANIFEST-008", MAIN_MANIFEST,
         line_of(text, "<intent-filter>", line_of(text, 'android:autoVerify="true"') + 1)),
        ("ANDROID-MANIFEST-007", MAIN_MANIFEST,
         line_of(text, 'android:scheme="com.example.links.auth"')),
        ("ANDROID-MANIFEST-005", MAIN_MANIFEST,
         line_of(text, 'android:exported="true"', line_of(text, ".Mixed"))),
        ("ANDROID-MANIFEST-007", MAIN_MANIFEST, line_of(text, 'android:scheme="mixed"'))])
    titles = sorted(f.title for f in findings if f.rule_id == "ANDROID-MANIFEST-007")
    assert titles == ["Deep link with a custom scheme: com.example.links.auth://",
                      "Deep link with a custom scheme: mixed://",
                      "Deep link with a custom scheme: shop://"]
    assert "promo.example" in only(findings, "ANDROID-MANIFEST-008").description
    main = next(c for c in ctx.facts["components"] if c["name"].endswith("MainActivity"))
    assert main["deep_links"] == ["shop://open", "shop://pay", "https://shop.example",
                                  "https://promo.example/deal*", "content:"]


PERMISSIONS_MANIFEST = """\
<manifest %s %s package="com.example.perms">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission-sdk-23 android:name="android.permission.READ_CONTACTS" />
    <uses-permission
        android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.health.READ_HEART_RATE" />
    <uses-permission android:name="android.permission.CAMERA" tools:node="remove" />
    <uses-permission android:name="com.example.perms.CUSTOM" />
    <application android:allowBackup="false" />
</manifest>
""" % (ANDROID_NS, TOOLS_NS)


def test_dangerous_and_special_permissions(tmp_path):
    ctx, by_rel = android_project(tmp_path, PERMISSIONS_MANIFEST)
    findings = run(ctx, by_rel)
    text = PERMISSIONS_MANIFEST
    assert [(f.line, f.title) for f in findings] == [
        (line_of(text, "READ_CONTACTS"), "Dangerous permission requested: READ_CONTACTS"),
        (line_of(text, "SYSTEM_ALERT_WINDOW"),
         "Special access permission requested: SYSTEM_ALERT_WINDOW"),
        (line_of(text, "READ_HEART_RATE"),
         "Dangerous permission requested: health.READ_HEART_RATE")]
    assert all((f.rule_id, f.severity, f.confidence) == ("ANDROID-MANIFEST-009", "info", 0.9)
               for f in findings)
    assert ctx.facts["permissions"] == [
        {"name": "android.permission.INTERNET", "dangerous": False},
        {"name": "android.permission.READ_CONTACTS", "dangerous": True},
        {"name": "android.permission.SYSTEM_ALERT_WINDOW", "dangerous": True},
        {"name": "android.permission.health.READ_HEART_RATE", "dangerous": True},
        {"name": "com.example.perms.CUSTOM", "dangerous": False}]


TASK_MANIFEST = """\
<manifest %s%s>
    <application android:allowBackup="false">
        <activity android:name=".A" android:taskAffinity="" />
        <activity android:name=".B" android:taskAffinity="com.example.task.sub" />
        <activity android:name=".C"
            android:taskAffinity="com.bank.app" />
        <activity android:name=".D"
            android:allowTaskReparenting="true" />
        <activity android:name=".E" android:taskAffinity="${applicationId}.e" />
    </application>
</manifest>
"""


@pytest.mark.parametrize("package", [' package="com.example.task"', ""])
def test_task_hijacking_exposure(tmp_path, package):
    manifest = TASK_MANIFEST % (ANDROID_NS, package)
    gradle = TEMPLATE_GRADLE.replace("com.example.template", "com.example.other") if package \
        else TEMPLATE_GRADLE.replace('applicationId = "com.example.template"', "") \
        .replace('namespace = "com.example.template"', "")
    ctx, by_rel = android_project(tmp_path, manifest, gradle=gradle)
    findings = run(ctx, by_rel)
    lines = [line_of(manifest, 'android:allowTaskReparenting="true"')]
    if package:      # the foreign affinity can only be told apart when the package is known
        lines.insert(0, line_of(manifest, 'android:taskAffinity="com.bank.app"'))
    assert [(f.rule_id, f.line) for f in findings] == [("ANDROID-MANIFEST-011", n) for n in lines]


def test_gradle_ids_name_the_package_of_a_manifest_without_one(tmp_path):
    manifest = TASK_MANIFEST % (ANDROID_NS, "")
    ctx, by_rel = android_project(tmp_path, manifest,
                                  gradle=TEMPLATE_GRADLE.replace("com.example.template",
                                                                 "com.example.task"))
    findings = run(ctx, by_rel)
    assert [f.line for f in findings] == [line_of(manifest, "com.bank.app"),
                                         line_of(manifest, "allowTaskReparenting")]
    assert ctx.facts["components"][0]["name"] == "com.example.task.A"


def test_release_overlay_counts_and_debug_source_sets_do_not(tmp_path):
    debug = """\
<manifest %s>
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <application android:debuggable="true" />
</manifest>
""" % ANDROID_NS
    release = """\
<manifest %s %s>
    <application
        android:debuggable="true"
        android:allowBackup="false"
        tools:replace="android:debuggable" />
</manifest>
""" % (ANDROID_NS, TOOLS_NS)
    ctx, by_rel = android_project(tmp_path, TEMPLATE_MANIFEST, extra={
        "android/app/src/debug/AndroidManifest.xml": debug,
        "android/app/src/profile/AndroidManifest.xml": debug,
        "android/app/src/release/AndroidManifest.xml": release})
    ctx.manifests.append(("android/app/src/debug/AndroidManifest.xml",
                          parse_xml_text(debug)[0]))     # a loader may list it: it is skipped
    expected = [("ANDROID-MANIFEST-001", "android/app/src/release/AndroidManifest.xml",
                 line_of(release, "android:debuggable"))]
    assert summary(run(ctx, by_rel)) == expected
    assert ctx.facts["flags"]["allow_backup"] == "no"
    # the overlay is read even when the loader hands over only src/main
    ctx.manifests = [m for m in ctx.manifests if m[0] == MAIN_MANIFEST]
    assert summary(run(ctx, by_rel)) == expected


def test_sdk_levels_from_gradle_and_the_implicit_cleartext_default(tmp_path):
    gradle = """\
android {
    defaultConfig {
        applicationId "com.example.old"
        minSdkVersion 21
        targetSdkVersion 27
    }
}
"""
    manifest = '<manifest %s>\n    <application android:allowBackup="false" />\n</manifest>\n' \
        % ANDROID_NS
    ctx, by_rel = make_project(tmp_path, {"android/app/build.gradle": gradle,
                                          MAIN_MANIFEST: manifest})
    findings = run(ctx, by_rel)
    assert summary(findings) == sorted([
        ("ANDROID-SDK-001", "android/app/build.gradle", 4),
        ("ANDROID-SDK-002", "android/app/build.gradle", 5),
        ("ANDROID-MANIFEST-004", MAIN_MANIFEST, 2)])
    implicit = only(findings, "ANDROID-MANIFEST-004")
    assert (implicit.severity, implicit.confidence) == ("low", 0.6)
    assert "targets API 27" in implicit.description
    assert ctx.facts["flags"]["cleartext"] == "allowed (default for targetSdk 27)"


def test_flutter_sdk_defaults_are_not_flagged(tmp_path):
    ctx, by_rel = android_project(tmp_path, TEMPLATE_MANIFEST.replace(
        "<application", '<application android:allowBackup="false"', 1))
    assert run(ctx, by_rel) == []


# ------------------------------------------------------------------ network security config
NSC = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" overridePins="true" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">legacy.example.com</domain>
        <pin-set expiration="2018-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
        <domain-config>
            <domain>nested.example.com</domain>
        </domain-config>
    </domain-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain>10.0.2.2</domain>
        <domain>localhost</domain>
    </domain-config>
    <domain-config>
        <domain>pinned.example.com</domain>
        <pin-set expiration="2099-01-01">
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""
NSC_MANIFEST = """\
<manifest %s package="com.example.net">
    <application
        android:allowBackup="false"
        android:networkSecurityConfig="@xml/network_security_config" />
</manifest>
""" % ANDROID_NS


def test_network_security_config_checks(tmp_path):
    unused = NSC.replace("legacy.example.com", "unused.example.com")
    ctx, by_rel = android_project(tmp_path, NSC_MANIFEST, resources={
        "network_security_config": NSC, "unused_config": unused})
    findings = run(ctx, by_rel)
    rel = "android/app/src/main/res/xml/network_security_config.xml"
    assert summary(findings) == sorted([
        ("ANDROID-NSC-001", rel, line_of(NSC, "<base-config")),
        ("ANDROID-NSC-003", rel, line_of(NSC, 'src="user"')),
        ("ANDROID-NSC-004", rel, line_of(NSC, 'overridePins="true"')),
        ("ANDROID-NSC-002", rel, line_of(NSC, "<domain-config cleartextTrafficPermitted")),
        ("ANDROID-NSC-004", rel, line_of(NSC, 'expiration="2018-01-01"'))])
    for finding in findings:      # Dart networking does not read the config: every text says so
        assert "Dart code" in finding.description, finding.rule_id
    assert "legacy.example.com" in only(findings, "ANDROID-NSC-002").description
    assert ctx.facts["flags"]["cleartext"] == "allowed (network security config)"
    assert ctx.facts["flags"]["network_security_config"] == "@xml/network_security_config"


def test_network_security_config_model():
    root = parse_xml_text(NSC)[0]
    config = NetworkSecurityConfig.from_node(root)
    assert config.base_cleartext is True and len(config.base_trust_anchors) == 2
    assert [d.names for d in config.domains] == [["legacy.example.com"],
                                                ["nested.example.com"],
                                                ["10.0.2.2", "localhost"],
                                                ["pinned.example.com"]]
    assert config.domains[1].cleartext is True            # inherited from its parent
    assert config.domains[2].loopback_only and not config.domains[0].loopback_only
    assert [a.src for a in config.debug_trust_anchors] == ["user"]
    assert config.domains[0].pin_set.expired(date(2020, 1, 1))
    assert not config.domains[3].pin_set.expired(date(2020, 1, 1))
    assert config.domains[0].pin_set.pins == 1


def test_safe_network_config_and_cleartext_flag(tmp_path):
    safe = NSC_MANIFEST
    config = """\
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain>10.0.2.2</domain>
    </domain-config>
</network-security-config>
"""
    ctx, by_rel = android_project(tmp_path, safe, resources={"network_security_config": config})
    assert run(ctx, by_rel) == []
    assert ctx.facts["flags"]["cleartext"] == "not allowed (network security config)"


# ------------------------------------------------------------------ FileProvider
PATHS = """\
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <root-path name="root" path="" />
    <files-path name="all" path="." />
    <external-path name="ext" path="/" />
    <cache-path name="cache" path="." />
    <files-path name="receipts" path="receipts/" />
    <external-files-path name="own" path="." />
</paths>
"""
PROVIDER_MANIFEST = """\
<manifest %s package="com.example.files">
    <application android:allowBackup="false">
        <provider
            android:name="io.flutter.plugins.imagepicker.ImagePickerFileProvider"
            android:authorities="com.example.files.picker"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/shared_paths" />
        </provider>
    </application>
</manifest>
""" % ANDROID_NS


def test_file_provider_paths(tmp_path):
    ctx, by_rel = android_project(tmp_path, PROVIDER_MANIFEST, resources={"shared_paths": PATHS})
    findings = run(ctx, by_rel)
    rel = "android/app/src/main/res/xml/shared_paths.xml"
    assert [(f.file, f.line, f.severity, f.confidence) for f in findings] == [
        (rel, line_of(PATHS, "<root-path"), "high", 0.8),
        (rel, line_of(PATHS, '<files-path name="all"'), "medium", 0.6),
        (rel, line_of(PATHS, "<external-path"), "medium", 0.6)]
    assert all(f.rule_id == "ANDROID-FILEPROVIDER-001" for f in findings)
    assert "internal files folder" in findings[1].title
    assert [p.kind for p in FileProviderPaths.from_node(parse_xml_text(PATHS)[0]).too_wide()] \
        == ["root-path", "files-path", "external-path"]


# ------------------------------------------------------------------ app packages: binary XML
APK_MANIFEST = """\
<manifest %s package="com.example.apk">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34" />
    <application
        android:debuggable="true"
        android:networkSecurityConfig="@0x7f0f0000">
        <activity android:name="com.example.apk.MainActivity" android:exported="true">
%s
        </activity>
        <receiver android:name="com.example.apk.Inbox" android:exported="true" />
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="com.example.apk.files"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@0x7f0f0001" />
        </provider>
    </application>
</manifest>
""" % (ANDROID_NS, LAUNCHER)
REFS = {0x7f0f0000: "@xml/network_security_config", 0x7f0f0001: "@xml/file_paths"}


def test_decoded_app_manifest_lines_follow_the_rendered_text():
    ctx = app_context(APK_MANIFEST, resources={
        "network_security_config": NSC, "file_paths": PATHS}, resolve=REFS.get)
    findings = run(ctx)
    manifest = ctx.files[0].text
    nsc = ctx.files[1].text
    paths = ctx.files[2].text
    assert summary(findings) == sorted([
        ("ANDROID-MANIFEST-001", "AndroidManifest.xml", line_of(manifest, "android:debuggable")),
        ("ANDROID-MANIFEST-003", "AndroidManifest.xml", line_of(manifest, "<application")),
        ("ANDROID-MANIFEST-005", "AndroidManifest.xml",
         line_of(manifest, 'android:exported="true"', line_of(manifest, "Inbox"))),
        ("ANDROID-SDK-001", "AndroidManifest.xml", line_of(manifest, "android:minSdkVersion")),
        ("ANDROID-NSC-001", "res/xml/network_security_config.xml",
         line_of(nsc, "cleartextTrafficPermitted")),
        ("ANDROID-NSC-002", "res/xml/network_security_config.xml",
         line_of(nsc, "cleartextTrafficPermitted", line_of(nsc, "<domain-config"))),
        ("ANDROID-NSC-003", "res/xml/network_security_config.xml", line_of(nsc, 'src="user"')),
        # the app is debuggable, so its <debug-overrides> apply
        ("ANDROID-NSC-003", "res/xml/network_security_config.xml",
         line_of(nsc, 'src="user"', line_of(nsc, "<debug-overrides"))),
        ("ANDROID-NSC-004", "res/xml/network_security_config.xml", line_of(nsc, "overridePins")),
        ("ANDROID-NSC-004", "res/xml/network_security_config.xml", line_of(nsc, "expiration")),
        ("ANDROID-FILEPROVIDER-001", "res/xml/file_paths.xml", line_of(paths, "<root-path")),
        ("ANDROID-FILEPROVIDER-001", "res/xml/file_paths.xml", line_of(paths, 'name="all"') - 1),
        ("ANDROID-FILEPROVIDER-001", "res/xml/file_paths.xml", line_of(paths, "<external-path"))])
    assert only(findings, "ANDROID-MANIFEST-001").confidence == 0.95
    assert ctx.facts["flags"]["network_security_config"] == "@xml/network_security_config"


def test_unresolved_reference_uses_the_only_network_config():
    ctx = app_context(APK_MANIFEST, resources={"network_security_config": NSC})
    findings = run(ctx)
    assert sum(f.rule_id.startswith("ANDROID-NSC-") for f in findings) == 6  # debuggable
    assert not any(f.rule_id == "ANDROID-FILEPROVIDER-001" for f in findings)


def test_app_bundle_manifest_from_protobuf_xml():
    root = parse_xml_text(APK_MANIFEST.replace("@0x7f0f0000", "@xml/network_security_config"))[0]
    doc = aabproto.decode_proto_xml(aabproto.encode_proto_xml(root))
    ctx = MobileContext(kind="aab", root=Path("app.aab"))
    ctx.files.append(virtual("AndroidManifest.xml", doc.text))
    ctx.manifests.append(("AndroidManifest.xml", doc.root))
    findings = run(ctx)
    assert only(findings, "ANDROID-MANIFEST-001").line == line_of(doc.text, "android:debuggable")
    assert only(findings, "ANDROID-MANIFEST-005").snippet == 'android:exported="true" />'


# ------------------------------------------------------------------ Gradle
KTS = """\
android {
    namespace = "com.example.kts"
    defaultConfig {
        applicationId = "com.example.kts.app"
        minSdk = 21
        targetSdk = flutter.targetSdkVersion
    }
    signingConfigs {
        getByName("debug") {
            storePassword = "android"
        }
        create("upload") {
            storeFile = file("upload.jks")
            storePassword = "S3cret-Store"
            keyPassword = System.getenv("KEY_PASSWORD")
            keyAlias = "upload"
        }
    }
    buildTypes {
        // release { isDebuggable = true }
        release {
            val note = "a { brace } and a // in a string"
            /* signingConfig = signingConfigs.getByName("debug") */
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
            isDebuggable = true
            isJniDebuggable = true
        }
        debug {
            isMinifyEnabled = false
        }
    }
}
"""
GROOVY = """\
android {
    defaultConfig {
        applicationId "com.example.groovy"
        minSdkVersion 19
        targetSdkVersion 26
    }
    signingConfigs {
        release {
            storePassword 'groovy-pass'
            keyPassword "${System.env.KEY_PASSWORD}"
        }
    }
    buildTypes {
        release {
            signingConfig signingConfigs.debug
            minifyEnabled false
            debuggable true
        }
    }
}
"""
FALLBACK = """\
android {
    buildTypes {
        release {
            signingConfig = if (hasReleaseKey) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }
}
"""


def test_read_gradle_kotlin_dsl():
    build = read_gradle(KTS)
    assert (build.application_id, build.namespace) == ("com.example.kts.app", "com.example.kts")
    assert build.min_sdk == (21, 5) and build.target_sdk is None
    after_comment = line_of(KTS, "/* signingConfig") + 1          # the comment does not count
    assert build.debug_signing == [(line_of(KTS, "signingConfig = signingConfigs", after_comment),
                                    False)]
    assert build.no_minify == [line_of(KTS, "isMinifyEnabled = false")]
    assert build.debuggable == [line_of(KTS, "isDebuggable = true", 21)]
    assert build.passwords == [(line_of(KTS, '"S3cret-Store"'), "storePassword")]


def test_read_gradle_groovy_and_fallback_signing():
    build = read_gradle(GROOVY)
    assert build.application_id == "com.example.groovy"
    assert (build.min_sdk, build.target_sdk) == ((19, 4), (26, 5))
    assert build.debug_signing == [(15, False)] and build.no_minify == [16]
    assert build.debuggable == [17] and build.passwords == [(9, "storePassword")]
    assert read_gradle(FALLBACK).debug_signing == [(7, True)]
    called = 'android {\n    buildTypes.getByName("release") {\n        isMinifyEnabled = false\n' \
             '    }\n    productFlavors {\n        release {\n            minifyEnabled false\n' \
             '        }\n    }\n}\n'
    assert read_gradle(called).no_minify == [3]      # a flavor named release does not count


@pytest.mark.parametrize("text", [
    "android { buildTypes { release { /* never closed",
    'android { buildTypes { release { val s = "never closed',
    "{" * 5000 + "release {" + "}" * 10,
    "}}}} release { minifyEnabled false",
    "",
])
def test_read_gradle_survives_broken_files(text):
    read_gradle(text)


def test_gradle_findings_in_a_project(tmp_path):
    ctx, by_rel = android_project(tmp_path, TEMPLATE_MANIFEST.replace(
        "<application", '<application android:allowBackup="false"', 1), gradle=KTS)
    findings = run(ctx, by_rel)
    gradle = "android/app/build.gradle.kts"
    assert summary(findings) == sorted([
        ("ANDROID-GRADLE-001", gradle, 24), ("ANDROID-GRADLE-002", gradle, 25),
        ("ANDROID-GRADLE-003", gradle, 26), ("ANDROID-GRADLE-004", gradle, 14),
        ("ANDROID-SDK-001", gradle, 5)])
    assert "Flutter app template" in only(findings, "ANDROID-GRADLE-001").description
    assert ctx.facts["flags"]["debuggable"] == "yes"
    ctx, by_rel = make_project(tmp_path / "fallback", {"android/app/build.gradle.kts": FALLBACK})
    ctx.gradle_files = ["android/app/build.gradle.kts"]
    fallback = only(run(ctx, by_rel), "ANDROID-GRADLE-001")
    assert fallback.confidence == 0.6 and "falls back" in fallback.description


# ------------------------------------------------------------------ signing files
def test_key_properties_and_keystores(tmp_path):
    ctx, by_rel = make_project(tmp_path, {
        "android/key.properties": "storePassword=MyStorePass1\nkeyPassword = <your key password>"
                                  "\n# keyPassword=commented\nkeyAlias=upload\n"
                                  "storeFile=upload.jks\n",
        "android/ci/key.properties": "keyPassword=${KEY_PASSWORD}\nstorePassword=\n",
        "android/app/upload.jks": b"\xfe\xed\xfe\xed\x00\x00\x00\x02",
        "android/app/debug.keystore": b"\xfe\xed\xfe\xed\x00\x00\x00\x02"})
    findings = run(ctx, by_rel)
    assert summary(findings) == [("ANDROID-SIGN-010", "android/key.properties", 1),
                                 ("ANDROID-SIGN-011", "android/app/upload.jks", 1)]
    assert only(findings, "ANDROID-SIGN-011").snippet.startswith("Binary keystore file (8 bytes)")


# ------------------------------------------------------------------ Info.plist
PLIST = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array><string>shop</string></array>
		</dict>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array><string>https</string></array>
		</dict>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array><string>com.googleusercontent.apps.123</string></array>
		</dict>
	</array>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSAllowsArbitraryLoadsInWebContent</key>
		<true/>
		<key>NSAllowsArbitraryLoadsForMedia</key>
		<false/>
		<key>NSExceptionDomains</key>
		<dict>
			<key>localhost</key>
			<dict>
				<key>NSExceptionAllowsInsecureHTTPLoads</key>
				<true/>
			</dict>
			<key>legacy.example.com</key>
			<dict>
				<key>NSExceptionAllowsInsecureHTTPLoads</key>
				<true/>
				<key>NSExceptionMinimumTLSVersion</key>
				<string>TLSv1.2</string>
			</dict>
			<key>old.example.com</key>
			<dict>
				<key>NSExceptionMinimumTLSVersion</key>
				<string>TLSv1.1</string>
			</dict>
		</dict>
	</dict>
	<key>LSSupportsOpeningDocumentsInPlace</key>
	<true/>
	<key>UIFileSharingEnabled</key>
	<true/>
</dict>
</plist>
"""


def nth_line(text, needle, n):
    return [i for i, line in enumerate(text.splitlines(), 1) if needle in line][n - 1]


def test_info_plist_checks(tmp_path):
    macos = PLIST.split("<key>CFBundleURLTypes</key>")[0] + \
        "\t<key>LSSupportsOpeningDocumentsInPlace</key>\n\t<true/>\n</dict>\n</plist>\n"
    ctx, by_rel = make_project(tmp_path, {"ios/Runner/Info.plist": PLIST,
                                          "macos/Runner/Info.plist": macos})
    findings = run(ctx, by_rel)
    rel = "ios/Runner/Info.plist"
    assert summary(findings) == sorted([
        ("IOS-PLIST-004", rel, nth_line(PLIST, "CFBundleURLSchemes", 1)),
        ("IOS-PLIST-004", rel, nth_line(PLIST, "CFBundleURLSchemes", 3)),
        # NSAllowsArbitraryLoadsInWebContent makes iOS 10 and later ignore
        # NSAllowsArbitraryLoads: no IOS-PLIST-001, a note in IOS-PLIST-002
        ("IOS-PLIST-002", rel, nth_line(PLIST, "NSAllowsArbitraryLoadsInWebContent", 1)),
        ("IOS-PLIST-002", rel, nth_line(PLIST, "NSExceptionAllowsInsecureHTTPLoads", 2)),
        ("IOS-PLIST-003", rel, nth_line(PLIST, "NSExceptionMinimumTLSVersion", 2)),
        ("IOS-PLIST-005", rel, nth_line(PLIST, "UIFileSharingEnabled", 1))])
    assert "Files app" in only(findings, "IOS-PLIST-005").description
    assert "TLSv1.1" in only(findings, "IOS-PLIST-003").description
    web = next(f for f in findings if f.line == nth_line(PLIST, "InWebContent", 1))
    assert "iOS 10 and later ignore it" in web.description
    schemes = [f.title for f in findings if f.rule_id == "IOS-PLIST-004"]
    assert sorted(schemes) == ["Custom URL scheme registered: com.googleusercontent.apps.123://",
                               "Custom URL scheme registered: shop://"]


# ------------------------------------------------------------------ pubspec
ASSETS_PUBSPEC = """\
name: assets_app
publish_to: none
environment:
  sdk: ^3.5.0
dependencies:
  flutter:
    sdk: flutter
flutter:
  assets:
    - .env
    - ./config/.env.production
    - config/.env.example
    - secrets/
    - images/
    - path: keys/
      flavors: [prod]
"""


def test_bundled_secret_assets(tmp_path):
    ctx, by_rel = make_project(tmp_path, {
        "pubspec.yaml": ASSETS_PUBSPEC, "pubspec.lock": "packages: {}\n",
        ".env": "API_KEY=x\n", "config/.env.production": "A=1\n", "config/.env.example": "A=\n",
        "secrets/.env": "B=2\n", "secrets/readme.txt": "notes\n", "images/logo.txt": "logo\n",
        "keys/prod.env": "C=3\n", "lib/main.dart": "void main() {}\n"})
    findings = run(ctx, by_rel)
    assert [(f.rule_id, f.line) for f in findings] == [
        ("FLUTTER-APP-006", line_of(ASSETS_PUBSPEC, "- .env")),
        ("FLUTTER-APP-006", line_of(ASSETS_PUBSPEC, ".env.production")),
        ("FLUTTER-APP-006", line_of(ASSETS_PUBSPEC, "- secrets/")),
        ("FLUTTER-APP-006", line_of(ASSETS_PUBSPEC, "- path: keys/"))]
    assert "secrets/.env" in findings[2].description and "keys/prod.env" in findings[3].title


WORKSPACE_ROOT = """\
name: root_app
publish_to: none
environment:
  sdk: ^3.6.0
workspace:
  - packages/member
dependencies:
  flutter:
    sdk: flutter
  http: 0.13.1
"""
MEMBER = """\
name: member
resolution: workspace
environment:
  sdk: ^3.6.0
dependencies:
  dio: ^4.0.0
"""


def locked(name, version):
    return ("  %s:\n    dependency: \"direct main\"\n    description:\n      name: %s\n"
            "      url: \"https://pub.dev\"\n    source: hosted\n    version: \"%s\"\n"
            % (name, name, version))


def test_dependencies_go_through_the_pub_audit(tmp_path):
    lock = "packages:\n" + locked("http", "0.13.1") + locked("dio", "4.0.6")
    ctx, by_rel = make_project(tmp_path, {
        "pubspec.yaml": WORKSPACE_ROOT, "pubspec.lock": lock, "lib/main.dart": "void main(){}\n",
        "packages/member/pubspec.yaml": MEMBER})
    # a loader may pair the member with the workspace root's lock: it is audited without it
    ctx.pubspecs = [("pubspec.yaml", "pubspec.lock"),
                    ("packages/member/pubspec.yaml", "pubspec.lock")]
    findings = run(ctx, by_rel)
    expected = pubspec.audit_project(by_rel["pubspec.yaml"], by_rel["pubspec.lock"], app=True) \
        + pubspec.audit_project(by_rel["packages/member/pubspec.yaml"])
    assert summary(findings) == summary(expected)
    assert ("FLUTTER-PUB-001", "packages/member/pubspec.yaml",
            line_of(MEMBER, "dio:")) in summary(findings)
    assert ctx.facts["dependency_issues"] == len(findings) == 3


def test_app_flag_comes_from_the_project_layout(tmp_path):
    spec = ("name: tool\nenvironment:\n  sdk: ^3.5.0\ndependencies:\n  flutter:\n"
            "    sdk: flutter\n  path: any\n")
    lock = "packages:\n" + locked("path", "1.9.0")
    plain = make_project(tmp_path / "package", {"pubspec.yaml": spec, "pubspec.lock": lock})
    assert run(*plain) == []                                   # a package, not an app
    app = make_project(tmp_path / "app", {"pubspec.yaml": spec, "pubspec.lock": lock,
                                          "android/app/build.gradle": "android {}\n"})
    assert [f.rule_id for f in run(*app)] == ["FLUTTER-PUB-004"]


# ------------------------------------------------------------------ app summaries
def build_txt(mode="release", obfuscation="no (380 package: URIs, 72 short private names)",
              symbols="no", kernel="not present", paths=(), flutter="yes"):
    """_sca/build.txt in the format of design section 7 (labels on lines 1 to 12)."""
    lines = ["Flutter app: %s" % flutter, "Build mode: %s" % mode,
             "Build mode evidence: snapshot features start with \"product\"", "ABIs: arm64-v8a",
             "Dart version: 3.12.2 (stable)",
             "Flutter engine revision: 0cd610717bde95fd88343c64f81c11ba4e5c0010",
             "Snapshot hash: ace654289f5abc240509fc941453ebc5",
             "Snapshot features: product no-code_comments no-dwarf_stack_traces_mode",
             "Dart obfuscation: %s" % obfuscation, "Debug symbols in libapp.so: %s" % symbols,
             "Dart kernel (kernel_blob.bin): %s" % kernel, "Dart sources recovered: 0"]
    lines += ["Build path: %s" % path for path in paths]
    return "\n".join(lines) + "\n"


def summary_context(**files):
    return app_context("<manifest %s package=\"com.example.app\"><application "
                       "android:allowBackup=\"false\" /></manifest>" % ANDROID_NS,
                       files={rel: (text, "summary") for rel, text in files.items()})


def build_findings(text):
    findings = run(summary_context(**{"_sca/build.txt": text}))
    return [(f.rule_id, f.line) for f in findings]


def test_build_summary_checks():
    paths = ["file:///C:/Users/dev/app/lib/main.dart", "file:///opt/build/lib/a.dart",
             "file:///home/ci/app/lib/b.dart"]
    assert build_findings(build_txt()) == [("FLUTTER-APP-003", 9)]
    assert build_findings(build_txt(obfuscation="yes (4 package: URIs)")) == []
    assert build_findings(build_txt(obfuscation="unknown (strings dump)")) == []
    assert build_findings(build_txt(mode="debug", kernel="775 sources", paths=paths)) == [
        ("FLUTTER-APP-001", 11), ("FLUTTER-APP-005", 13)]
    assert build_findings(build_txt(mode="profile", symbols="yes")) == [
        ("FLUTTER-APP-002", 2), ("FLUTTER-APP-004", 10)]
    assert build_findings(build_txt(paths=["file:///opt/build/lib/a.dart"],
                                    obfuscation="yes")) == []
    assert build_findings(build_txt(flutter="no", mode="debug", kernel="1 sources")) == []
    debug = run(summary_context(**{"_sca/build.txt": build_txt(mode="debug", paths=paths)}))
    assert [f.rule_id for f in debug] == ["FLUTTER-APP-001", "FLUTTER-APP-005"]
    assert debug[0].line == 2 and "2 absolute path(s)" in debug[1].description


def signing_txt(schemes="v2", subject="CN=Android Debug, O=Android, C=US", key="RSA 2048 bits",
                algorithm="sha256WithRSAEncryption"):
    flags = {name: "yes" if name in schemes else "no" for name in ("v1", "v2", "v3", "v3.1")}
    return ("Signature schemes: %s\nv1 (JAR signing): %s\nv2 (APK Signature Scheme v2): %s\n"
            "v3 (APK Signature Scheme v3): %s\nv3.1 (APK Signature Scheme v3.1): %s\n"
            "Signer 1 subject: %s\nSigner 1 issuer: %s\nSigner 1 certificate SHA-256: 0bf4\n"
            "Signer 1 valid: 2026-03-10 to 2056-03-02\nSigner 1 key: %s\n"
            "Signer 1 signature algorithm: %s\nSignature verified by apksigner: not checked\n"
            % (schemes, flags["v1"], flags["v2"], flags["v3"], flags["v3.1"], subject, subject,
               key, algorithm))


def signing_findings(text, kind="apk", **facts):
    ctx = summary_context(**{"_sca/signing.txt": text})
    ctx.kind = kind
    ctx.facts.update(facts)
    return [(f.rule_id, f.line) for f in run(ctx)]


def test_signing_summary_checks():
    release = "CN=Shop Release, O=Shop, C=DE"
    assert signing_findings(signing_txt()) == [("ANDROID-SIGN-001", 6)]
    assert signing_findings(signing_txt(subject=release)) == []
    assert signing_findings(signing_txt("v1", release)) == [("ANDROID-SIGN-002", 1)]
    assert signing_findings(signing_txt("v1", release), kind="aab") == []
    assert signing_findings(signing_txt("none", release)) == [("ANDROID-SIGN-003", 1)]
    assert signing_findings(signing_txt("v1, v2, v3", release, "RSA 1024 bits",
                                        "sha1WithRSAEncryption")) == [("ANDROID-SIGN-004", 10)]
    # Android does not verify the certificate's own signature: only a weak key counts
    assert signing_findings(signing_txt("v2", release, algorithm="md5WithRSAEncryption")) == []
    assert signing_findings(signing_txt("v2", release, "DSA 2048 bits")) \
        == [("ANDROID-SIGN-004", 10)]
    assert signing_findings(signing_txt("v2", release, "EC 256 bits", "sha1WithECDSA")) == []
    # the loader's certificate facts decide when they are there
    facts = {"certificates": [{"debug": True}]}
    assert signing_findings(signing_txt(subject=release), signing=facts) \
        == [("ANDROID-SIGN-001", 6)]
    assert signing_findings(signing_txt(), signing="unexpected") == [("ANDROID-SIGN-001", 6)]


def test_packages_of_an_app_package():
    text = "dio unknown (snapshot)\nhttp 0.13.1 (kernel)\nuni_links unknown (notices)\n" \
           "cronet_http 1.0.0 (plugin)\n"
    ctx = summary_context(**{"_sca/packages.txt": text})
    ctx.packages = [{"name": "dio", "version": None, "source": "snapshot"},
                    {"name": "http", "version": "0.13.1", "source": "kernel"},
                    {"name": "uni_links", "version": "unknown", "source": "notices"},
                    {"name": "cronet_http", "version": "1.0.0", "source": "plugin"}]
    findings = run(ctx)
    assert [(f.rule_id, f.line, f.severity, f.confidence) for f in findings] == [
        ("FLUTTER-PUB-001", 1, "info", 0.3), ("FLUTTER-PUB-001", 2, "medium", 0.9),
        ("FLUTTER-PUB-002", 3, "low", 0.8)]
    assert ctx.facts["dependency_issues"] == 3


# ------------------------------------------------------------------ strings dumps
DUMP = """\
http://api.shop.example/v1/login
Some text
http://api.shop.example/v1/login
https://secure.shop.example/v1
http://schemas.android.com/apk/res/android
http://localhost:8080/debug
http://10.0.2.2:3000
http://www.apache.org/licenses/LICENSE-2.0
ws://chat.shop.example/socket
See http://docs.example.org/licence.html for details
SELECT * FROM users WHERE name = '
SELECT * FROM orders WHERE id = ?
UPDATE users SET token = '
http://$host/api
See https://github.com/flutter/flutter/issues/30701 for this error.
"""


def test_strings_dump_checks_and_endpoints():
    ctx = summary_context()
    ctx.files.append(virtual("lib/arm64-v8a/libapp.so", DUMP, "strings"))
    ctx.files.append(virtual("classes.dex", DUMP, "strings"))
    ctx.files.append(SourceFile(Path("dart/lib/main.dart"), "dart/lib/main.dart", "dart",
                                "// docs: http://docs.internal.example/x\n"
                                "const api = 'http://recovered.example/api';\n",
                                origin="recovered"))
    ctx.strings_files = ["lib/arm64-v8a/libapp.so", "classes.dex"]
    findings = run(ctx)
    assert [(f.rule_id, f.file, f.line) for f in findings] == [
        ("FLUTTER-APP-007", "lib/arm64-v8a/libapp.so", 1),
        ("FLUTTER-APP-007", "lib/arm64-v8a/libapp.so", 9),
        ("FLUTTER-APP-008", "lib/arm64-v8a/libapp.so", 11),
        ("FLUTTER-APP-008", "lib/arm64-v8a/libapp.so", 13)]
    assert "Dart networking" in findings[0].description
    assert ctx.facts["endpoints"] == [
        {"url": "http://api.shop.example/v1/login", "cleartext": True,
         "file": "lib/arm64-v8a/libapp.so"},
        {"url": "https://secure.shop.example/v1", "cleartext": False,
         "file": "lib/arm64-v8a/libapp.so"},
        {"url": "ws://chat.shop.example/socket", "cleartext": True,
         "file": "lib/arm64-v8a/libapp.so"},
        {"url": "http://recovered.example/api", "cleartext": True, "file": "dart/lib/main.dart"}]


def test_bundled_asset_in_an_app_package():
    ctx = summary_context()
    ctx.files.append(virtual("assets/flutter_assets/assets/.env", "API_URL=https://x\n"))
    ctx.files.append(virtual("assets/flutter_assets/config.json", "{}\n"))
    findings = run(ctx)
    assert summary(findings) == [("FLUTTER-APP-006", "assets/flutter_assets/assets/.env", 1)]


def test_tampering_warnings_become_one_finding():
    ctx = summary_context(**{"_sca/build.txt": build_txt(obfuscation="yes")})
    ctx.warnings = ["app.apk: duplicate entry name 'classes.dex' (2 entries)",
                    "AndroidManifest.xml: <application> attribute 'name' has the resource id of "
                    "android:debuggable", "app.apk: lib/x.so: 600 MB, more than the read limit"]
    findings = run(ctx)
    tampering = only(findings, "FLUTTER-APP-009")
    assert tampering.file == "_sca/build.txt" and "duplicate entry name" in tampering.description
    assert "read limit" not in tampering.description
    ctx.warnings = ctx.warnings[2:]
    assert run(ctx) == []


# ------------------------------------------------------------------ limits and broken input
def test_cap_per_file_and_check(tmp_path):
    permissions = "".join(
        '    <uses-permission android:name="android.permission.health.READ_%d" />\n' % n
        for n in range(60))
    manifest = "<manifest %s package=\"com.example.many\">\n%s    <application " \
               "android:allowBackup=\"false\" />\n</manifest>\n" % (ANDROID_NS, permissions)
    ctx, by_rel = android_project(tmp_path, manifest)
    findings, note = analyze(ctx, by_rel)
    assert len(findings) == checks.MAX_PER_FILE == 50
    assert "10 more dropped: ANDROID-MANIFEST-009 in %s" % MAIN_MANIFEST in note
    assert len(ctx.facts["permissions"]) == 60


def test_broken_files_are_named_and_the_rest_still_runs(tmp_path):
    ctx, by_rel = android_project(tmp_path, NSC_MANIFEST.replace(
        'android:allowBackup="false"', 'android:allowBackup="true"'), extra={
        "android/app/src/main/res/xml/network_security_config.xml": "<network-security-config>",
        "ios/Runner/Info.plist": "<plist><dict><key>broken</dict>",
        "pubspec.yaml": "name: [broken\n"})
    findings, note = analyze(ctx, by_rel)
    assert [f.rule_id for f in findings] == ["ANDROID-MANIFEST-003"]
    assert note.startswith("ok (1 findings; not checked: ")
    for rel in ("network_security_config.xml", "ios/Runner/Info.plist", "pubspec.yaml"):
        assert rel in note


# which children an element usually has; any tag can also turn up anywhere
FUZZ_CHILDREN = {
    "manifest": ["uses-sdk", "uses-permission", "permission", "application"],
    "application": ["activity", "activity-alias", "service", "receiver", "provider",
                    "meta-data"],
    "activity": ["intent-filter", "meta-data"], "activity-alias": ["intent-filter"],
    "service": ["intent-filter"], "receiver": ["intent-filter"],
    "provider": ["meta-data", "path-permission"],
    "intent-filter": ["action", "category", "data"],
    "network-security-config": ["base-config", "domain-config", "debug-overrides"],
    "base-config": ["trust-anchors"], "debug-overrides": ["trust-anchors"],
    "domain-config": ["domain", "pin-set", "trust-anchors", "domain-config"],
    "trust-anchors": ["certificates"], "pin-set": ["pin"],
    "paths": ["root-path", "files-path", "external-path", "cache-path"]}
FUZZ_TAGS = sorted({tag for tags in FUZZ_CHILDREN.values() for tag in tags})
BOOLEANS = ["true", "false", "TRUE", "${flag}"]
NAMES = [".X", "com.a.B", "androidx.core.content.FileProvider",
         "android.support.FILE_PROVIDER_PATHS", "android.intent.action.VIEW",
         "android.intent.action.MAIN", "android.intent.category.LAUNCHER",
         "android.intent.category.BROWSABLE", "android.permission.CAMERA", "com.a.PERM"]
# attribute -> typical values; every attribute can also get one of FUZZ_JUNK
FUZZ_ATTRS = {
    "android:name": NAMES, "android:exported": BOOLEANS, "android:permission": NAMES,
    "android:readPermission": NAMES, "android:taskAffinity": ["", "com.other", "com.a"],
    "android:allowTaskReparenting": BOOLEANS, "android:scheme": ["myapp", "https", "content"],
    "android:host": ["a.example", "localhost"], "android:pathPrefix": ["/x"],
    "android:autoVerify": BOOLEANS, "android:debuggable": BOOLEANS,
    "android:allowBackup": BOOLEANS, "android:usesCleartextTraffic": BOOLEANS,
    "android:resource": ["@xml/file_paths", "@xml/network_security_config", "@0x7f0f0000"],
    "android:networkSecurityConfig": ["@xml/network_security_config", "@0x7f0f0001"],
    "android:protectionLevel": ["signature", "normal", "dangerous|appop", "0x12"],
    "android:minSdkVersion": ["16", "24"], "android:targetSdkVersion": ["26", "35"],
    "cleartextTrafficPermitted": BOOLEANS, "src": ["user", "system", "@raw/ca"],
    "overridePins": BOOLEANS, "expiration": ["2001-02-30", "2018-01-01", "2099-01-01"],
    "path": ["", ".", "/", "a/"], "tools:node": ["remove", "merge"], "package": ["com.a"]}
FUZZ_JUNK = ["", "x" * 300, "‮\u0000", "-1", "@", "${applicationId}"]
# the attributes an element usually has, with values that fit it
FUZZ_TAG_ATTRS = {
    "action": {"android:name": ["android.intent.action.VIEW", "android.intent.action.MAIN"]},
    "category": {"android:name": ["android.intent.category.LAUNCHER",
                                  "android.intent.category.BROWSABLE"]},
    "meta-data": {"android:name": ["android.support.FILE_PROVIDER_PATHS"],
                  "android:resource": ["@xml/file_paths", "@0x7f0f0000"]},
    "uses-permission": {"android:name": ["android.permission.CAMERA",
                                         "android.permission.INTERNET"]},
    "data": {"android:scheme": ["myapp", "https"], "android:host": ["a.example"]},
    "intent-filter": {"android:autoVerify": BOOLEANS},
    "certificates": {"src": ["user", "system"], "overridePins": BOOLEANS},
    "pin-set": {"expiration": ["2018-01-01", "2099-01-01"]},
    "root-path": {"path": [""]}, "files-path": {"path": [".", "a/"]},
    "provider": {"android:name": ["androidx.core.content.FileProvider", ".P"]}}


def random_tree(rng, tag, depth=0):
    node = XmlNode(tag)
    for name in rng.sample(sorted(FUZZ_ATTRS), rng.randint(0, 4)):
        node.attrs[name] = rng.choice(FUZZ_JUNK if rng.random() < 0.1 else FUZZ_ATTRS[name])
    if rng.random() < 0.8:
        for name, pool in FUZZ_TAG_ATTRS.get(tag, {}).items():
            node.attrs[name] = rng.choice(pool)
    if depth < 6:
        for _ in range(rng.randint(0, 4)):
            choices = FUZZ_CHILDREN.get(tag) or FUZZ_TAGS
            child = rng.choice(FUZZ_TAGS) if rng.random() < 0.1 else rng.choice(choices)
            node.children.append(random_tree(rng, child, depth + 1))
    return node


def test_random_trees_never_break_a_check():
    rng = random.Random(7)
    seen = set()
    for _ in range(300):
        ctx = MobileContext(kind="apk", root=Path("fuzz.apk"))
        for rel, root in (("AndroidManifest.xml", "manifest"),
                          ("res/xml/network_security_config.xml", "network-security-config"),
                          ("res/xml/file_paths.xml", "paths")):
            tree = random_tree(rng, root)
            if root == "manifest":
                ctx.manifests.append((rel, tree))
            else:
                ctx.xml_resources[rel] = tree
                ctx.resource_files["@xml/" + rel[len("res/xml/"):-len(".xml")]] = rel
            ctx.files.append(virtual(rel, render_xml(tree)))
        findings, note = analyze(ctx, {})
        assert "not checked" not in note, note
        assert all(f.rule_id in BY_ID for f in findings)
        seen.update(f.rule_id for f in findings)
    # the trees reach the checks of every part
    assert {"ANDROID-MANIFEST-005", "ANDROID-MANIFEST-007", "ANDROID-NSC-003",
            "ANDROID-FILEPROVIDER-001"} <= seen


# ------------------------------------------------------------------ android.py helpers
def test_manifest_model_helpers():
    assert full_class_name(".Main", "com.a") == "com.a.Main"
    assert full_class_name("Main", "com.a") == "com.a.Main"
    assert full_class_name("org.b.Main", "com.a") == "org.b.Main"
    assert full_class_name("${applicationName}", "com.a") == "${applicationName}"
    assert full_class_name(".Main", "") == ".Main"
    assert [protection_base(level) for level in ("", "normal", "dangerous", "signature",
                                                  "signature|privileged", "signatureOrSystem",
                                                  "0x12", "knownSigner|signature")] \
        == [0, 0, 1, 2, 2, 3, 2, 2]
    root = parse_xml_text('<manifest xmlns:a="http://schemas.android.com/apk/res/android" '
                          'package="p.q"><uses-sdk a:minSdkVersion="23"/><application>'
                          '<receiver a:name=".R" a:exported="true"/></application></manifest>')[0]
    info = ManifestInfo.from_node(root)
    assert (info.min_sdk, info.target_sdk) == (23, 23)      # targetSdk defaults to minSdk
    assert info.components[0].name == "p.q.R" and info.components[0].exported()


@pytest.mark.parametrize("attrs, expected", [
    ({}, (True, False, False)),
    ({"allowBackup": "true"}, (True, True, False)),
    ({"allowBackup": "FALSE"}, (False, True, False)),
    ({"allowBackup": "${backup}"}, (None, True, False)),
    ({"fullBackupContent": "@xml/rules"}, (True, False, True)),
    ({"allowBackup": "true", "fullBackupContent": "false"}, (True, True, True)),
    ({"dataExtractionRules": "@xml/extraction"}, (True, False, True)),
    ({"backupAgent": ".Agent"}, (True, False, True)),
])
def test_backup_policy(attrs, expected):
    policy = backup_policy(attrs.get)
    assert (policy.allowed, policy.explicit, policy.rules) == expected


def test_cleartext_policy():
    config = NetworkSecurityConfig.from_node(parse_xml_text(NSC)[0])
    blocked = NetworkSecurityConfig.from_node(parse_xml_text(
        "<network-security-config><domain-config cleartextTrafficPermitted=\"true\">"
        "<domain>api.example.com</domain></domain-config></network-security-config>")[0])
    policy = cleartext_policy("false", config, 34)        # the config replaces the attribute
    assert (policy.permitted, policy.source, policy.domains) == (
        True, "network security config", ["legacy.example.com", "nested.example.com"])
    assert (cleartext_policy(None, blocked, 34).permitted,
            cleartext_policy(None, blocked, 27).permitted) == (False, True)
    assert cleartext_policy(None, blocked, 34).domains == ["api.example.com"]
    assert cleartext_policy("true", None, 34).source == "android:usesCleartextTraffic"
    assert [cleartext_policy(None, None, sdk).permitted for sdk in (27, 28, None)] \
        == [True, False, None]


# ------------------------------------------------------------------ refine
def finding_at(rel, line, rule="SECRET-GOOGLE-001", cwe_id="CWE-798"):
    return Finding(rule_id=rule, title="Google API key", file=rel, line=line, severity="high",
                   cwe=cwe_id, confidence=0.9, description="A key.", fix="Remove it.")


def test_refine_downgrades_firebase_keys_only():
    key = "AIza" + "B" * 35
    files = {
        "android/app/google-services.json": '{\n  "current_key": "%s"\n}\n' % key,
        "ios/Runner/GoogleService-Info.plist": "<key>API_KEY</key>\n<string>%s</string>\n" % key,
        "lib/firebase_options.dart": "  apiKey: '%s',\n" % key,
        "res/values/strings.xml": '<string name="google_api_key">%s</string>\n'
                                  '<string name="maps_key">%s</string>\n' % (key, key),
        "lib/maps.dart": "const mapsKey = '%s';\n" % key}
    by_rel = {rel: SourceFile(Path(rel), rel, "config", text) for rel, text in files.items()}
    findings = [finding_at("android/app/google-services.json", 2),
                finding_at("ios/Runner/GoogleService-Info.plist", 2),
                finding_at("lib/firebase_options.dart", 1, "DART-SECRET-001"),
                finding_at("res/values/strings.xml", 1),
                finding_at("res/values/strings.xml", 2),
                finding_at("lib/maps.dart", 1),
                finding_at("lib/firebase_options.dart", 1, "OTHER", "CWE-319")]
    assert refine(findings, by_rel, None) == 4
    assert [(f.severity, f.confidence) for f in findings[:4]] == [("low", 0.4)] * 4
    assert all(f.description.startswith(checks.FIREBASE_NOTE) for f in findings[:4])
    assert [(f.severity, f.confidence) for f in findings[4:]] == [("high", 0.9)] * 3
    assert refine(findings, by_rel, None) == 0                      # already refined


@pytest.mark.parametrize("name", ["com.google.android.geo.API_KEY",
                                  "com.google.android.maps.v2.API_KEY"])
def test_compiled_maps_client_classification_requires_the_exact_metadata_value(name):
    key = "AIza" + "T" * 35
    rel = "AndroidManifest.xml"
    doc = ('<manifest xmlns:a="http://schemas.android.com/apk/res/android">\n'
           '  <application>\n'
           '    <meta-data a:name="%s"\n'
           '        a:value="%s"/>\n'
           '    <meta-data a:name="test.other" a:value="%s"/>\n'
           '    <activity a:name=".Example">\n'
           '      <meta-data a:name="%s" a:value="%s"/>\n'
           '    </activity>\n'
           '  </application>\n'
           '</manifest>') % (name, key, key, name, key)
    root, error = parse_xml_text(doc)
    assert not error
    by_rel = {rel: SourceFile(Path(rel), rel, "xml", doc)}
    ctx = MobileContext(kind="apk", root=Path("demo.apk"), manifests=[(rel, root)])
    findings = [finding_at(rel, n) for n in (3, 4, 5, 7)]
    findings.append(finding_at(rel, 4, rule="UNRELATED-001"))
    assert refine(findings, by_rel, ctx) == 1
    assert findings[1].description == checks.MAPS_CLIENT_NOTE
    assert findings[1].fix == checks.MAPS_CLIENT_FIX
    assert [(f.severity, f.confidence) for f in findings] == [
        ("high", 0.9), ("low", 0.6), ("high", 0.9), ("high", 0.9), ("high", 0.9)]
    assert refine(findings, by_rel, ctx) == 0
    ctx.kind = "project"
    assert refine([finding_at(rel, 4)], by_rel, ctx) == 0  # literal in the source tree


def test_minified_manifest_with_two_google_keys_leaves_each_for_review():
    first, second = ("AIza" + letter * 35 for letter in ("T", "V"))
    rel = "AndroidManifest.xml"
    doc = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
           '<application><meta-data android:name="com.google.android.geo.API_KEY" '
           'android:value="%s"/><meta-data android:name="other" android:value="%s"/>'
           '</application></manifest>') % (first, second)
    root, error = parse_xml_text(doc)
    assert not error
    ctx = MobileContext(kind="apk", root=Path("demo.apk"), manifests=[(rel, root)])
    by_rel = {rel: SourceFile(Path(rel), rel, "xml", doc)}
    findings = [finding_at(rel, 1), finding_at(rel, 1)]
    assert refine(findings, by_rel, ctx) == 0
    assert all(f.severity == "high" for f in findings)


# ------------------------------------------------------------------ review fixes (round 2)
def manifest_with(application_attrs="", body="", package="com.example.fix", head=""):
    return ("<manifest %s package=\"%s\">\n%s    <application android:allowBackup=\"false\"%s>\n"
            "%s    </application>\n</manifest>\n" % (ANDROID_NS, package, head,
                                                     application_attrs, body))


def gradle_with(default_config, plugin="com.android.application"):
    """TEMPLATE_GRADLE with other defaultConfig SDK lines (and plugin)."""
    return TEMPLATE_GRADLE.replace("com.android.application", plugin).replace(
        "minSdk = flutter.minSdkVersion\n        targetSdk = flutter.targetSdkVersion",
        default_config)


@pytest.mark.parametrize("path, resolved", [
    ("../", None), ("..", None), ("../../../", None), ("images/../../", None), ("/.", ""),
    ("./", ""), ("", ""), ("images/../", ""), ("images/./shared/", "images/shared"),
    ("/images", "images")])
def test_file_provider_paths_are_resolved_like_androidx(path, resolved):
    node = parse_xml_text('<paths><files-path name="x" path="%s"/></paths>' % path)[0]
    shared = FileProviderPaths.from_node(node).paths[0]
    assert shared.resolved == resolved
    assert shared.escapes == (resolved is None)


ESCAPING_PATHS = """\
<paths>
    <files-path name="a" path="../" />
    <cache-path name="b" path=".." />
    <external-files-path name="c" path="../../../" />
    <files-path name="d" path="images/../../" />
    <files-path name="e" path="/." />
    <cache-path name="f" path="images/../" />
    <files-path name="g" path="images/" />
    <root-path name="h" path="storage/emulated/0/Download/MyApp/" />
    <root-path name="i" path="data/" />
    <root-path name="j" path="/storage/emulated/0" />
    <root-path name="k" path="data/data/com.example.fix/" />
    <root-path name="l" path=".." />
</paths>
"""


def test_file_provider_paths_that_climb_out_or_share_a_narrow_root(tmp_path):
    ctx, by_rel = android_project(tmp_path, PROVIDER_MANIFEST.replace(
        "com.example.files", "com.example.fix"), resources={"shared_paths": ESCAPING_PATHS})
    findings = run(ctx, by_rel)
    got = {f.line: (f.severity, f.confidence, f.title) for f in findings}

    def at(name):
        return line_of(ESCAPING_PATHS, 'name="%s"' % name)
    assert sorted(got) == sorted(at(n) for n in "abcdehijkl")
    for name in "abd":                                   # internal storage: the app's data
        assert got[at(name)][:2] == ("high", 0.8) and "climbs out" in got[at(name)][2]
    assert got[at("c")][:2] == ("medium", 0.6)           # external storage parent
    assert got[at("e")][2] == "FileProvider shares the whole internal files folder"
    assert got[at("h")][:2] == ("low", 0.5)              # a narrow folder through root-path
    for name in "ijl":
        assert got[at(name)][:2] == ("high", 0.8)
        assert got[at(name)][2] == "FileProvider shares the file system root"
    assert got[at("k")][2] == "FileProvider shares the app's private data folder"


def test_plugin_folders_are_not_apps(tmp_path):
    spec = ("name: my_plugin\nenvironment:\n  sdk: ^3.5.0\ndependencies:\n  flutter:\n"
            "    sdk: flutter\n  path: any\nflutter:\n  plugin:\n    platforms:\n"
            "      android:\n        package: com.example.my_plugin\n"
            "        pluginClass: MyPlugin\n")
    files = {"pubspec.yaml": spec, "android/build.gradle": "android {}\n",
             "ios/Classes/MyPlugin.swift": "class MyPlugin {}\n"}
    assert run(*make_project(tmp_path / "plugin", files)) == []
    app = make_project(tmp_path / "app", {**files, "pubspec.yaml": spec.split("flutter:\n  plugin")[0]
                                          + "publish_to: none\n"})
    assert sorted(f.rule_id for f in run(*app)) == ["FLUTTER-PUB-004", "FLUTTER-PUB-005"]


ATS_ONLY = """\
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
%s	</dict>
</dict>
</plist>
"""


@pytest.mark.parametrize("extra, expected", [
    ("", ["IOS-PLIST-001"]),
    ("\t\t<key>NSAllowsLocalNetworking</key>\n\t\t<true/>\n", []),
    ("\t\t<key>NSAllowsArbitraryLoadsForMedia</key>\n\t\t<true/>\n", ["IOS-PLIST-002"]),
    ("\t\t<key>NSAllowsArbitraryLoadsInWebContent</key>\n\t\t<false/>\n", []),
    ("\t\t<key>NSExceptionDomains</key>\n\t\t<dict>\n\t\t\t<key>cdn.example.org</key>\n"
     "\t\t\t<dict>\n\t\t\t\t<key>NSThirdPartyExceptionAllowsInsecureHTTPLoads</key>\n"
     "\t\t\t\t<true/>\n\t\t\t\t<key>NSThirdPartyExceptionMinimumTLSVersion</key>\n"
     "\t\t\t\t<string>TLSv1.0</string>\n\t\t\t</dict>\n\t\t</dict>\n",
     ["IOS-PLIST-001", "IOS-PLIST-002", "IOS-PLIST-003"]),
])
def test_ats_keys_that_override_arbitrary_loads_and_legacy_keys(tmp_path, extra, expected):
    ctx, by_rel = make_project(tmp_path, {"ios/Runner/Info.plist": ATS_ONLY % extra})
    assert sorted(f.rule_id for f in run(ctx, by_rel)) == expected


@pytest.mark.parametrize("text, signing, debuggable", [
    # defaultConfig signs with the debug key and the release type does not override it
    ("android {\n    defaultConfig {\n        signingConfig signingConfigs.debug\n    }\n"
     "    buildTypes {\n        release {\n            minifyEnabled true\n        }\n    }\n}\n",
     [(3, False)], []),
    ("android {\n    defaultConfig {\n        signingConfig signingConfigs.debug\n    }\n"
     "    buildTypes {\n        release {\n            signingConfig signingConfigs.release\n"
     "        }\n    }\n}\n", [], []),
    ("android {\n    buildTypes.release {\n        signingConfig signingConfigs.debug\n"
     "        debuggable true\n    }\n}\n", [(3, False)], [4]),
    ("android {\n    buildTypes.getByName(\"release\").apply {\n"
     "        signingConfig = signingConfigs.getByName(\"debug\")\n        isDebuggable = true\n"
     "    }\n}\n", [(3, False)], [4]),
    ("android {\n    buildTypes {\n        getByName<ApplicationBuildType>(\"release\") {\n"
     "            signingConfig = signingConfigs.findByName(\"debug\")\n        }\n    }\n}\n",
     [(4, False)], []),
    ("android {\n    buildTypes {\n        release {\n            initWith debug\n        }\n"
     "    }\n}\n", [(4, False)], [4]),
    ("android {\n    buildTypes {\n        release {\n            initWith debug\n"
     "            debuggable false\n            signingConfig signingConfigs.release\n"
     "        }\n    }\n}\n", [], []),
    ("android.buildTypes.release.signingConfig = android.signingConfigs.debug\n",
     [(1, False)], []),
])
def test_read_gradle_release_forms(text, signing, debuggable):
    build = read_gradle(text)
    assert build.debug_signing == signing and build.debuggable == debuggable


def test_read_gradle_stays_linear_on_deeply_nested_blocks():
    import time
    for text in ("a{" * 100000 + "}" * 100000,
                 "buildTypes{release{" * 20000 + "}" * 40000,
                 "defaultConfig{minSdk 21 " * 20000 + "}" * 20000):
        started = time.perf_counter()
        read_gradle(text)
        assert time.perf_counter() - started < 3.0


def test_gradle_target_defaults_to_min_and_library_modules(tmp_path):
    gradle = gradle_with("minSdk = 16")
    ctx, by_rel = android_project(tmp_path, manifest_with(), gradle=gradle)
    found = {f.rule_id: f for f in run(ctx, by_rel)}
    assert set(found) == {"ANDROID-SDK-001", "ANDROID-SDK-002", "ANDROID-MANIFEST-004"}
    assert "sets no targetSdk" in found["ANDROID-SDK-002"].description
    # targetSdk written in a form that is not a literal: no default
    gradle = gradle_with("minSdk = 16\n        targetSdk = rootProject.ext.target")
    ctx, by_rel = android_project(tmp_path / "b", manifest_with(), gradle=gradle)
    assert [f.rule_id for f in run(ctx, by_rel)] == ["ANDROID-SDK-001"]


LIBRARY_MANIFEST = """\
<manifest %s>
    <application android:debuggable="true">
        <service android:name="com.example.lib.LibService" android:exported="true" />
    </application>
</manifest>
""" % ANDROID_NS


@pytest.mark.parametrize("how", ["context", "gradle"])
def test_library_modules_get_only_component_checks(tmp_path, how):
    gradle = gradle_with("minSdk = 16") if how == "context" \
        else gradle_with("minSdk = 16", plugin="com.android.library")
    gradle = gradle.replace('signingConfigs.getByName("release")', 'signingConfigs.getByName('
                            '"debug")\n            isMinifyEnabled = false')
    ctx, by_rel = android_project(tmp_path, LIBRARY_MANIFEST, gradle=gradle)
    if how == "context":
        ctx.library_manifests = [MAIN_MANIFEST]      # the loader's contract
    assert [f.rule_id for f in run(ctx, by_rel)] == ["ANDROID-MANIFEST-005"]


LOOPBACK_PARENT = """\
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain-config>
            <domain>api.prod.example.com</domain>
        </domain-config>
        <domain-config cleartextTrafficPermitted="false">
            <domain>secure.example.com</domain>
        </domain-config>
    </domain-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain>legacy.example.com</domain>
        <domain-config>
            <domain>nested.legacy.example.com</domain>
        </domain-config>
    </domain-config>
</network-security-config>
"""


def test_nested_domain_config_inherits_cleartext_from_a_loopback_parent(tmp_path):
    ctx, by_rel = android_project(tmp_path, NSC_MANIFEST,
                                  resources={"network_security_config": LOOPBACK_PARENT})
    findings = run(ctx, by_rel)
    assert [(f.rule_id, f.line) for f in findings] == [
        ("ANDROID-NSC-002", line_of(LOOPBACK_PARENT, "<domain-config>")),
        ("ANDROID-NSC-002", line_of(LOOPBACK_PARENT, 'cleartextTrafficPermitted="true"', 9))]
    assert "api.prod.example.com" in findings[0].description
    assert "inherits" in findings[0].description


GUARDS = """\
<manifest %s package="com.example.guard">
    <permission android:name="${applicationId}.permission.OWN"
        android:protectionLevel="signature" />
    <permission android:name="com.example.guard.permission.SIG"
        android:protectionLevel="signature" />
    <application android:allowBackup="false">
        <service android:name=".Sync" android:exported="true"
            android:permission="${applicationId}.permission.SIG" />
        <service android:name=".Own" android:exported="true"
            android:permission="com.example.guard.permission.OWN" />
        <service android:name=".Fg" android:exported="true"
            android:permission="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
        <service android:name=".Query" android:exported="true"
            android:permission="android.permission.QUERY_ALL_PACKAGES" />
        <service android:name=".Unknown" android:exported="true"
            android:permission="android.permission.SOME_FUTURE_PERMISSION" />
        <service android:name=".Docs" android:exported="true"
            android:permission="android.permission.MANAGE_DOCUMENTS" />
        <activity android:name=".Target" android:exported="false" />
        <activity-alias android:name=".Alias" android:targetActivity=".Target"
            android:exported="true" />
        <activity android:name=".Share" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="text/plain" />
            </intent-filter>
        </activity>
        <receiver android:name=".Widget" android:exported="true">
            <intent-filter>
                <action android:name="android.appwidget.action.APPWIDGET_UPDATE" />
            </intent-filter>
        </receiver>
        <receiver android:name=".WidgetAndMore" android:exported="true">
            <intent-filter>
                <action android:name="android.appwidget.action.APPWIDGET_UPDATE" />
                <action android:name="com.example.guard.ACTION_TRANSFER" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
""" % ANDROID_NS


def test_guards_placeholders_aliases_and_entry_points_by_design(tmp_path):
    ctx, by_rel = android_project(tmp_path, GUARDS)
    findings = run(ctx, by_rel)
    names = {(f.rule_id, f.title.rsplit(".", 1)[-1]) for f in findings}
    # placeholders resolve to signature permissions (Sync, Own), MANAGE_DOCUMENTS is signature
    # level (Docs), a share target and a widget are entry points by design (Share, Widget)
    assert names == {("ANDROID-MANIFEST-006", "Fg"), ("ANDROID-MANIFEST-006", "Query"),
                     ("ANDROID-MANIFEST-006", "Unknown"), ("ANDROID-MANIFEST-005", "Alias"),
                     ("ANDROID-MANIFEST-005", "WidgetAndMore")}
    unknown = next(f for f in findings if f.title.endswith("Unknown"))
    assert "not known to be signature level" in unknown.description
    info = ManifestInfo.from_node(parse_xml_text(GUARDS)[0])
    assert info.guard_strength("${applicationId}.permission.OWN") == "strong"
    assert info.guard_strength("${packageName}.permission.SIG") == "strong"
    assert info.guard_strength("android.permission.FOREGROUND_SERVICE_DATA_SYNC") == "weak"
    # an activity-alias does not take the application's permission (it needs its own)
    guarded = ManifestInfo.from_node(parse_xml_text(GUARDS.replace(
        '<application android:allowBackup="false">', '<application android:allowBackup="false" '
        'android:permission="com.example.guard.permission.SIG">'))[0])
    kinds = {c.kind: c for c in guarded.components}
    assert kinds["activity-alias"].guard == "" and kinds["activity"].guard.endswith(".SIG")


def test_pin_set_expires_on_its_date_and_debug_overrides_apply_when_debuggable(tmp_path):
    config = """\
<network-security-config>
    <domain-config>
        <domain>pinned.example.com</domain>
        <pin-set expiration="%s">
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
        </pin-set>
    </domain-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" overridePins="true" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
""" % date.today().isoformat()
    ctx, by_rel = android_project(tmp_path, NSC_MANIFEST,
                                  resources={"network_security_config": config})
    assert [f.rule_id for f in run(ctx, by_rel)] == ["ANDROID-NSC-004"]     # expired today
    debuggable = NSC_MANIFEST.replace('android:allowBackup="false"',
                                      'android:allowBackup="false" android:debuggable="true"')
    ctx, by_rel = android_project(tmp_path / "debug", debuggable,
                                  resources={"network_security_config": config})
    assert summary(run(ctx, by_rel)) == sorted([
        ("ANDROID-MANIFEST-001", MAIN_MANIFEST, line_of(debuggable, "android:debuggable")),
        ("ANDROID-NSC-004", "android/app/src/main/res/xml/network_security_config.xml",
         line_of(config, "expiration")),
        ("ANDROID-NSC-003", "android/app/src/main/res/xml/network_security_config.xml",
         line_of(config, 'src="user"')),
        ("ANDROID-NSC-004", "android/app/src/main/res/xml/network_security_config.xml",
         line_of(config, 'src="user"'))])
    # a debuggable release build type in Gradle makes the overrides apply as well
    gradle = TEMPLATE_GRADLE.replace('signingConfig = signingConfigs.getByName("release")',
                                     'signingConfig = signingConfigs.getByName("release")\n'
                                     '            isDebuggable = true')
    ctx, by_rel = android_project(tmp_path / "gradle", NSC_MANIFEST, gradle=gradle,
                                  resources={"network_security_config": config})
    assert "ANDROID-NSC-003" in {f.rule_id for f in run(ctx, by_rel)}


@pytest.mark.parametrize("min_sdk, expected", [("24", ("low", 0.6)), ("21", ("medium", 0.85))])
def test_cleartext_attribute_beside_a_network_config(tmp_path, min_sdk, expected):
    manifest = NSC_MANIFEST.replace('android:allowBackup="false"',
                                    'android:allowBackup="false" '
                                    'android:usesCleartextTraffic="true"')
    config = '<network-security-config>\n    <base-config cleartextTrafficPermitted="false" />\n' \
             '</network-security-config>\n'
    ctx, by_rel = android_project(tmp_path, manifest, gradle=gradle_with(
        "minSdk = %s\n        targetSdk = 34" % min_sdk),
        resources={"network_security_config": config})
    finding = only(run(ctx, by_rel), "ANDROID-MANIFEST-004")
    assert (finding.severity, finding.confidence) == expected
    assert finding.line == line_of(manifest, "usesCleartextTraffic")
    assert ("has no effect" in finding.description) == (min_sdk == "24")


@pytest.mark.parametrize("attrs, target, expected", [
    (' android:fullBackupContent="@xml/backup_rules"', "34", ("low", 0.6)),
    (' android:fullBackupContent="false"', "31", ("low", 0.6)),
    (' android:fullBackupContent="@xml/backup_rules"', "30", None),
    (' android:fullBackupContent="@xml/backup_rules" '
     'android:dataExtractionRules="@xml/extraction_rules"', "34", None),
])
def test_full_backup_content_alone_leaves_device_transfer_open(tmp_path, attrs, target, expected):
    manifest = manifest_with().replace(' android:allowBackup="false"', attrs)
    ctx, by_rel = android_project(tmp_path, manifest, gradle=gradle_with(
        "minSdk = 24\n        targetSdk = %s" % target))
    found = [f for f in run(ctx, by_rel) if f.rule_id == "ANDROID-MANIFEST-003"]
    if expected is None:
        assert found == []
    else:
        assert [(f.severity, f.confidence) for f in found] == [expected]
        assert "device-to-device" in found[0].description
        assert found[0].line == line_of(manifest, "fullBackupContent")


def test_safe_browsing_switched_off(tmp_path):
    meta = ('        <meta-data android:name="android.webkit.WebView.EnableSafeBrowsing"\n'
            '            android:value="%s" />\n')
    ctx, by_rel = android_project(tmp_path, manifest_with(body=meta % "false"))
    finding = only(run(ctx, by_rel), "ANDROID-MANIFEST-012")
    assert finding.line == line_of(manifest_with(body=meta % "false"), 'android:value="false"')
    assert (finding.cwe, finding.severity, finding.confidence) == ("CWE-1188", "low", 0.8)
    ctx, by_rel = android_project(tmp_path / "on", manifest_with(body=meta % "true"))
    assert run(ctx, by_rel) == []
    apk = app_context(manifest_with(body=meta % "false"))
    assert [f.rule_id for f in run(apk)] == ["ANDROID-MANIFEST-012"]


def test_key_properties_and_keystores_kept_out_of_git(tmp_path):
    files = {"android/key.properties": "storePassword=hunter2hunter2\nkeyPassword=hunter2\n",
             "android/app/upload.jks": b"\xfe\xed\xfe\xed",
             "android/.gitignore": "# Remember to never publicly share your keystore.\n"
                                   "key.properties\n**/*.jks\n"}
    ctx, by_rel = make_project(tmp_path, files)
    findings = run(ctx, by_rel)
    assert sorted((f.rule_id, f.severity) for f in findings) == [
        ("ANDROID-SIGN-010", "low"), ("ANDROID-SIGN-010", "low"), ("ANDROID-SIGN-011", "low")]
    assert all("android/.gitignore" in f.description for f in findings)
    files["android/.gitignore"] = "key.properties\n!key.properties\n"
    ctx, by_rel = make_project(tmp_path / "again", files)
    assert sorted((f.rule_id, f.severity) for f in run(ctx, by_rel)) == [
        ("ANDROID-SIGN-010", "high"), ("ANDROID-SIGN-010", "high"), ("ANDROID-SIGN-011", "medium")]


def test_debug_signed_app_bundle_names_the_upload_key():
    apk = only(run(summary_context(**{"_sca/signing.txt": signing_txt()})), "ANDROID-SIGN-001")
    assert "upload key" not in apk.description
    ctx = summary_context(**{"_sca/signing.txt": signing_txt()})
    ctx.kind = "aab"
    bundle = only(run(ctx), "ANDROID-SIGN-001")
    assert "upload key" in bundle.description and "rejects" in bundle.description


def test_spec_and_namespace_urls_are_not_endpoints():
    dump = ("http://www.apple.com/DTDs/PropertyList-1.0.dtd\nhttp://xmlns.jcp.org/xml/ns/javaee\n"
            "http://www.color.org/icc\nhttp://www.aiim.org/pdfa/ns/id/\n"
            "http://schemas.openxmlformats.org/drawingml/2006/main\n"
            "http://www.apache.org/licenses/LICENSE-2.0\nhttp://json-schema.org/draft-07/schema#\n"
            "http://www.topografix.com/GPX/1/1\nhttp://api.shop.example/v1\n")
    ctx = summary_context()
    ctx.files.append(virtual("lib/arm64-v8a/libapp.so", dump, "strings"))
    ctx.strings_files = ["lib/arm64-v8a/libapp.so"]
    assert [(f.rule_id, f.line) for f in run(ctx)] == [("FLUTTER-APP-007", 9)]


def test_sql_open_quote_after_values():
    dump = ("INSERT INTO users (name) VALUES ('\nINSERT INTO t (a, b) VALUES (1, '\n"
            "INSERT INTO t (a) VALUES (?)\n")
    ctx = summary_context()
    ctx.files.append(virtual("lib/arm64-v8a/libapp.so", dump, "strings"))
    ctx.strings_files = ["lib/arm64-v8a/libapp.so"]
    assert [(f.rule_id, f.line) for f in run(ctx)] == [("FLUTTER-APP-008", 1),
                                                       ("FLUTTER-APP-008", 2)]


def test_refine_lowers_firebase_keys_in_libapp_and_web_files():
    key = "AIza" + "C" * 35
    files = {
        "lib/arm64-v8a/libapp.so": ("strings", "%s\nshop-app.firebaseio.com\nshop-app.appspot.com\n"
                                    % key),
        "lib/x86_64/libapp.so": ("strings", "%s\nhttps://example.org\n" % key),
        "web/index.html": ("", "<script>\n  const firebaseConfig = {\n    apiKey: \"%s\",\n"
                               "  };\n</script>\n" % key),
        "web/firebase-messaging-sw.js": ("", "firebase.initializeApp({apiKey: '%s'});\n" % key),
        "web/maps.html": ("", "<script src=\"https://maps.googleapis.com/x?key=%s\"></script>\n"
                              % key)}
    by_rel = {rel: SourceFile(Path(rel), rel, "config", text, origin=origin)
              for rel, (origin, text) in files.items()}
    findings = [finding_at("lib/arm64-v8a/libapp.so", 1), finding_at("lib/x86_64/libapp.so", 1),
                finding_at("web/index.html", 3), finding_at("web/firebase-messaging-sw.js", 1),
                finding_at("web/maps.html", 1)]
    assert refine(findings, by_rel, None) == 3
    assert [f.severity for f in findings] == ["low", "high", "low", "low", "high"]


# ------------------------------------------------------------------ real samples
def ground_truth():
    return json.loads((SAMPLES / "flutter_ground_truth.json").read_text(encoding="utf-8"))["tags"]


def resolve_anchor(folder, anchor):
    """The line an anchor labels, as samples/flutter_ground_truth.json defines it."""
    lines = (folder / anchor["file"]).read_text(encoding="utf-8").splitlines()
    start = 0
    if anchor.get("near"):
        start = next((i for i, line in enumerate(lines) if anchor["near"] in line), len(lines))
    return next((i + 1 for i in range(start, len(lines)) if anchor["text"] in lines[i]), 0)


def labelled_lines(folder):
    found = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            rel = path.relative_to(folder).as_posix()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for tag in TAG.findall(line):
                    found[tag] = (rel, number)
    for tag, spec in ground_truth().items():
        if "anchor" in spec:
            found[tag] = (spec["anchor"]["file"], resolve_anchor(folder, spec["anchor"]))
    return found


STRUCTURAL = ("ANDROID-", "IOS-", "FLUTTER-APP-", "FLUTTER-PUB-")


def test_vulnerable_sample_matches_the_ground_truth():
    ctx, by_rel = project_context(VULN)
    findings = run(ctx, by_rel)
    lines = labelled_lines(VULN)
    expected = set()
    for tag, spec in ground_truth().items():
        if spec["note"].startswith(STRUCTURAL) and not spec.get("hard"):
            rel, line = lines[tag]
            expected.add((rel, line, spec["cwe"][0]))
    assert len(expected) == 28
    found = {(f.file, f.line, cwe.canonical(f.cwe)) for f in findings}
    assert found == expected
    assert ctx.facts["dependency_issues"] == 7
    assert ctx.facts["flags"] == {"debuggable": "no", "allow_backup": "yes",
                                  "cleartext": "allowed (network security config)",
                                  "network_security_config": "@xml/network_security_config"}
    urls = [e["url"] for e in ctx.facts["endpoints"]]
    assert "http://api.pocketshop.example/v1" in urls


def test_safe_sample_has_no_structural_findings():
    ctx, by_rel = project_context(SAFE)
    assert run(ctx, by_rel) == []
    assert ctx.facts["flags"]["allow_backup"] == "no"
    assert all(not p["dangerous"] for p in ctx.facts["permissions"])


# ------------------------------------------------------------------ third-party labs
LAB_FINDINGS = {
    "DVMA": [
        ("ANDROID-GRADLE-001", "android/app/build.gradle.kts", 131),
        ("ANDROID-GRADLE-002", "android/app/build.gradle.kts", 146),
        ("ANDROID-MANIFEST-001", "android/app/src/release/AndroidManifest.xml", 11),
        ("ANDROID-MANIFEST-003", MAIN_MANIFEST, 75),
        ("ANDROID-MANIFEST-004", MAIN_MANIFEST, 76),
        ("ANDROID-MANIFEST-006", MAIN_MANIFEST, 132),
        ("ANDROID-NSC-001", "android/app/src/main/res/xml/network_security_config.xml", 14),
        ("ANDROID-NSC-003", "android/app/src/main/res/xml/network_security_config.xml", 17),
        ("ANDROID-MANIFEST-005", "companion/dvma-attacker/app/src/main/AndroidManifest.xml", 41),
        ("ANDROID-MANIFEST-005", "companion/dvma-attacker/app/src/main/AndroidManifest.xml", 58),
        ("ANDROID-MANIFEST-009", "companion/dvma-attacker/app/src/main/AndroidManifest.xml", 14),
        ("ANDROID-MANIFEST-011", "companion/dvma-attacker/app/src/main/AndroidManifest.xml", 43),
        ("IOS-PLIST-001", "ios/Runner/Info.plist", 20),
        ("IOS-PLIST-004", "ios/Runner/Info.plist", 32),
        ("IOS-PLIST-005", "ios/Runner/Info.plist", 42),
        ("ANDROID-MANIFEST-012", MAIN_MANIFEST, 115)]
    + [("ANDROID-MANIFEST-005", MAIN_MANIFEST, n)
       for n in (122, 140, 148, 156, 164, 177, 191, 197, 205, 212, 224, 237, 261, 295, 310, 324)]
    + [("ANDROID-MANIFEST-009", MAIN_MANIFEST, n)
       for n in (6, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 23, 25)],
    "DVFA": [("ANDROID-GRADLE-001", "android/app/build.gradle.kts", 37),
             ("ANDROID-MANIFEST-003", MAIN_MANIFEST, 3),
             ("ANDROID-MANIFEST-007", MAIN_MANIFEST, 32)],
    "Ostorlab-Insecure-Flutter/ostorlab_insecure_flutter_app": [
        ("ANDROID-GRADLE-001", "android/app/build.gradle", 60),
        ("ANDROID-MANIFEST-003", MAIN_MANIFEST, 3),
        ("FLUTTER-PUB-002", "pubspec.lock", 704),
        ("FLUTTER-PUB-004", "pubspec.lock", 92),
        ("FLUTTER-PUB-004", "pubspec.lock", 124),
        ("FLUTTER-PUB-004", "pubspec.lock", 571)],
}


@pytest.mark.parametrize("lab", sorted(LAB_FINDINGS))
def test_flutter_labs_give_only_reviewed_findings(lab):
    folder = LABS / lab
    if not (folder / "pubspec.yaml").is_file():
        pytest.skip("lab not fetched (infected_project/fetch_labs.py)")
    ctx, by_rel = project_context(folder)
    assert summary(run(ctx, by_rel)) == sorted(LAB_FINDINGS[lab])


# ------------------------------------------------------------------ built app packages
def decoded_apk(path):
    """The manifest and res/xml files of an APK or app bundle, decoded the way the app loader
    decodes them (binary XML with the resources.arsc resolver, protobuf XML for a bundle)."""
    ctx = MobileContext(kind="aab" if path.suffix == ".aab" else "apk", root=path)
    with zipfile.ZipFile(path) as archive:
        if ctx.kind == "aab":
            doc = aabproto.decode_proto_xml(archive.read("base/manifest/AndroidManifest.xml"))
            resources = {name[len("base/"):]: aabproto.decode_proto_xml(archive.read(name))
                         for name in archive.namelist() if name.startswith("base/res/xml/")}
        else:
            table = arsc.parse_arsc(archive.read("resources.arsc"))
            logical = table.file_paths()
            doc = axml.decode_axml(archive.read("AndroidManifest.xml"), table.name_of)
            resources = {"res/%s.xml" % logical.get(name, name[4:-4]):
                         axml.decode_axml(archive.read(name), table.name_of)
                         for name in archive.namelist()
                         if logical.get(name, "").startswith("xml/") or name.startswith("res/xml/")}
    assert not doc.warnings
    ctx.files.append(virtual("AndroidManifest.xml", doc.text))
    ctx.manifests.append(("AndroidManifest.xml", doc.root))
    for rel, res in resources.items():
        ctx.files.append(virtual(rel, res.text))
        ctx.xml_resources[rel] = res.root
        ctx.resource_files["@" + rel[len("res/"):-len(".xml")]] = rel
    return ctx


@pytest.mark.skipif(not PROBE_DIR, reason="set SCA_FLUTTER_PROBE_DIR to the built probe packages")
@pytest.mark.parametrize("name", ["debug.apk", "release.apk", "release_obf.apk", "release.aab"])
def test_probe_packages_manifest_network_and_file_provider(name):
    ctx = decoded_apk(Path(PROBE_DIR) / name)
    findings = run(ctx)
    manifest = ctx.files[0].text
    nsc = next(sf.text for sf in ctx.files if sf.rel == "res/xml/network_security_config.xml")
    paths = next(sf.text for sf in ctx.files if sf.rel == "res/xml/file_paths.xml")
    expected = [
        ("ANDROID-MANIFEST-003", "AndroidManifest.xml",
         line_of(manifest, 'android:allowBackup="true"')),
        ("ANDROID-MANIFEST-004", "AndroidManifest.xml",
         line_of(manifest, 'android:usesCleartextTraffic="true"')),
        ("ANDROID-MANIFEST-007", "AndroidManifest.xml",
         line_of(manifest, 'android:scheme="probe"')),
        ("ANDROID-MANIFEST-008", "AndroidManifest.xml",
         line_of(manifest, "<intent-filter", line_of(manifest, 'android:scheme="probe"'))),
        ("ANDROID-MANIFEST-005", "AndroidManifest.xml", line_of(
            manifest, 'android:exported="true"', start_tag(manifest, "ProbeReceiver", "receiver"))),
        ("ANDROID-NSC-001", "res/xml/network_security_config.xml",
         line_of(nsc, 'cleartextTrafficPermitted="true"')),
        ("ANDROID-NSC-003", "res/xml/network_security_config.xml", line_of(nsc, 'src="user"')),
        ("ANDROID-FILEPROVIDER-001", "res/xml/file_paths.xml", line_of(paths, "<root-path"))]
    if name == "debug.apk":
        expected.append(("ANDROID-MANIFEST-001", "AndroidManifest.xml",
                         line_of(manifest, 'android:debuggable="true"')))
    assert summary(findings) == sorted(expected)
    components = {c["name"]: c for c in ctx.facts["components"]}
    assert components["androidx.profileinstaller.ProfileInstallReceiver"]["exported"]
    assert ctx.facts["flags"]["network_security_config"] == "@xml/network_security_config"


@pytest.mark.skipif(not APK_DIR, reason="set SCA_FLUTTER_APK_DIR to the vuln_probe packages")
@pytest.mark.parametrize("name", ["debug.apk", "release.apk", "release_obf.apk"])
def test_flutter_template_app_packages(name):
    ctx = decoded_apk(Path(APK_DIR) / name)
    manifest = ctx.files[0].text
    expected = [("ANDROID-MANIFEST-003", "AndroidManifest.xml", line_of(manifest, "<application"))]
    if name == "debug.apk":
        expected.append(("ANDROID-MANIFEST-001", "AndroidManifest.xml",
                         line_of(manifest, 'android:debuggable="true"')))
    assert summary(run(ctx)) == sorted(expected)
