"""Compare source ZIP and APK scans across Android app types."""
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

import flutter_kit as kit
from sca.pipeline import ScanOptions, inspect_mobile, run_scan

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
OPTIONS = ScanOptions(save=False, use_ml=False, use_feedback=False, use_bandit=False,
                      use_semgrep=False, use_gitleaks=False)
MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />
    <application android:label="Archive test" android:allowBackup="false"
        android:debuggable="{risky}" android:usesCleartextTraffic="{risky}" />
</manifest>
"""
MANIFEST_RULES = {"ANDROID-MANIFEST-001", "ANDROID-MANIFEST-004"}
KEY_RULE = "SECRET-AWS-001"


def rule_ids(findings):
    return {rule for finding in findings for rule in finding.rule_ids}


def android_manifest(package, risky):
    return MANIFEST.format(package=package, risky=str(risky).lower())


@pytest.mark.parametrize("sample,risky", [("flutter_vulnerable_app", True),
                                         ("flutter_safe_app", False)])
def test_flutter_source_archive_matches_directory(sample, risky, tmp_path):
    folder = SAMPLES / sample
    archive_path = tmp_path / f"{sample}.zip"
    with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
        for file in folder.rglob("*"):
            if file.is_file():
                archive.write(file, f"{sample}/{file.relative_to(folder).as_posix()}")

    directory = run_scan(str(folder), OPTIONS)
    uploaded = run_scan(str(archive_path), OPTIONS)

    assert uploaded.target == str(archive_path)
    assert uploaded.app["kind"] == "flutter-project"
    assert uploaded.app["package"] == "com.pocketshop.app"
    assert uploaded.languages == directory.languages
    assert uploaded.files_scanned == directory.files_scanned
    assert {finding.fingerprint for finding in uploaded.findings} == {
        finding.fingerprint for finding in directory.findings
    }
    assert ("ANDROID-MANIFEST-004" in rule_ids(uploaded.findings)) is risky


@pytest.mark.parametrize("language,extension,wrapped", [("java", "java", False),
                                                        ("kotlin", "kt", True)])
@pytest.mark.parametrize("risky", [False, True], ids=["clean", "risky"])
def test_native_source_archive_runs_rules_and_manifest_checks(language, extension, wrapped,
                                                               risky, tmp_path):
    package = f"com.example.{language}archive"
    mode = "AES/ECB/PKCS5Padding" if risky else "AES/GCM/NoPadding"
    key = kit.AWS_KEY if risky else "your-key-here"
    if language == "java":
        source = (f"package {package};\nimport javax.crypto.Cipher;\n"
                  f"class App {{ static final String API_KEY = \"{key}\";\n"
                  f"Cipher cipher() throws Exception {{ return Cipher.getInstance(\"{mode}\"); }}\n}}\n")
    else:
        source = (f"package {package}\nimport javax.crypto.Cipher\n"
                  f"private const val API_KEY = \"{key}\"\n"
                  f"fun cipher() = Cipher.getInstance(\"{mode}\")\n")
    path = f"app/src/main/{language}/{package.replace('.', '/')}/App.{extension}"
    prefix = "source-export/" if wrapped else ""
    archive_path = tmp_path / f"{language}.zip"
    with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
        archive.writestr(prefix + "settings.gradle.kts", 'include(":app")\n')
        archive.writestr(prefix + "app/build.gradle.kts",
                         f'plugins {{ id("com.android.application") }}\n'
                         f'android {{ namespace = "{package}" }}\n')
        archive.writestr(prefix + "app/src/main/AndroidManifest.xml",
                         android_manifest(package, risky))
        archive.writestr(prefix + path, source)

    result = run_scan(str(archive_path), OPTIONS)
    assert result.app["kind"] == "android-project"
    assert result.app["package"] == package
    assert result.languages[language] > 0
    scoped = [finding for finding in result.findings if finding.file == path]
    expected = {"JAVA-CRYPTO-002", KEY_RULE}
    assert (rule_ids(scoped) & expected) == (expected if risky else set())
    assert (rule_ids(result.findings) & MANIFEST_RULES) == (MANIFEST_RULES if risky else set())
    assert kit.AWS_KEY not in json.dumps(result.to_dict())

    context, _, findings, _ = inspect_mobile(str(archive_path))
    assert context is not None
    assert context.facts["package"] == package
    assert (rule_ids(findings) & MANIFEST_RULES) == (MANIFEST_RULES if risky else set())


@pytest.mark.parametrize("risky", [False, True], ids=["clean", "risky"])
def test_native_apk_reads_binary_manifest_and_dex(risky, tmp_path):
    package = "com.example.nativeapk"
    path = tmp_path / "native.apk"
    path.write_bytes(kit.build_apk(mode="none", manifest=android_manifest(package, risky),
                                  xml_resources={}, strings={}, certificate="release",
                                  dex_strings=[kit.AWS_KEY] if risky else []))

    result = run_scan(str(path), OPTIONS)
    assert result.app["kind"] == "apk"
    assert result.app["flutter"] is False
    assert result.app["package"] == package
    expected = MANIFEST_RULES | {KEY_RULE}
    assert (rule_ids(result.findings) & expected) == (expected if risky else set())
    assert kit.AWS_KEY not in json.dumps(result.to_dict())
