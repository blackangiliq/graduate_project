"""Tests for the Flutter / Android part of the scan pipeline (sca/pipeline.py), the learning
loop (sca/learn/loop.py) and the reports (HTML, PDF, SARIF, JSON) of app packages and
Flutter projects.

App packages are built with tests/flutter_kit.py. The scans of real packages run only when
SCA_FLUTTER_APK_DIR (debug.apk, release.apk, release_obf.apk and release.aab of the
vuln_probe lab app) or SCA_FLUTTER_PROBE_DIR (the same packages built from
samples/flutter_apk_probe) is set; the jadx scan also needs SCA_JADX.
"""
import json
import os
import re
import time
import zlib
from pathlib import Path

import pytest

import flutter_kit as kit
from sca import flutter, pipeline
from sca.ai import llm as llm_module
from sca.engines import rules_engine
from sca.flutter import zipread
from sca.flutter.context import AI_ORIGINS, KLOC_ORIGINS, RULES_ORIGINS, MobileContext
from sca.learn import loop
from sca.models import Finding, ScanResult
from sca.pipeline import ScanOptions, inspect_mobile, mask_facts, run_scan, scan_project
from sca.report import write_reports
from sca.report.html_report import APP_ROWS, app_overview, app_tables, render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import file_uri, to_sarif
from sca.storage import Storage
from sca.walker import SourceFile

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
APK_DIR = Path(os.environ.get("SCA_FLUTTER_APK_DIR", "") or "missing")
PROBE_DIR = Path(os.environ.get("SCA_FLUTTER_PROBE_DIR", "") or "missing")
PACKAGES = ("debug.apk", "release.apk", "release_obf.apk", "release.aab")
real_apks = pytest.mark.skipif(not all((APK_DIR / n).is_file() for n in PACKAGES),
                               reason="SCA_FLUTTER_APK_DIR does not hold the vuln_probe packages")
real_probe = pytest.mark.skipif(not all((PROBE_DIR / n).is_file() for n in PACKAGES),
                                reason="SCA_FLUTTER_PROBE_DIR does not hold the probe packages")
with_jadx = pytest.mark.skipif(not os.environ.get("SCA_JADX"), reason="SCA_JADX is not set")
# no history, no AI and no external tools on folders: fast and independent of this computer
QUIET = dict(save=False, use_ml=False, use_feedback=False, use_semgrep=False,
             use_gitleaks=False)
URL_PASSWORD = "Kp9vXq2Lr7Wz"
GOOGLE_KEY = "AIza" + "SyD3x7Kq9Lm2Np4Rs6Tv8Wx0Yz1Ab3Cd5Ef"


def write_app(tmp_path, data, name="app.apk"):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def texts(result):
    return [str(message) for message in result.steps]


def pdf_text(data):
    """The text of a PDF made by fpdf2 (its page streams are deflated)."""
    parts = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        try:
            parts.append(zlib.decompress(match.group(1)))
        except zlib.error:
            parts.append(match.group(1))
    return b"\n".join(parts).decode("latin-1")


# ------------------------------------------------------------------ app packages
def test_scan_of_a_release_apk(tmp_path):
    path = write_app(tmp_path, kit.build_apk())
    result, files = scan_project(str(path), ScanOptions(**QUIET))
    steps = texts(result)
    assert steps[0] == "Unpacking the app app.apk"
    decoded = next(m for m in result.steps if m.template == "Decoded the app: %d files, %s build")
    assert decoded.args == (len(files), "release")
    assert "Bandit: skipped - not used for app packages" in steps
    assert {"secrets", "rules", "flutter"} <= set(result.engines_used)
    assert result.app["kind"] == "apk" and result.app["package"] == kit.PACKAGE
    assert result.app["permissions"] and result.app["flags"]      # filled by the checks

    # only code and decoded text count as lines of code; strings dumps and summaries do not
    assert result.lines_scanned == sum(len(sf.lines) for sf in files
                                       if sf.origin in KLOC_ORIGINS)
    assert result.lines_scanned < sum(len(sf.lines) for sf in files)
    assert result.files_scanned == len(files)
    origins = {sf.rel: sf.origin for sf in files}
    assert origins["_sca/signing.txt"] == "summary"
    assert origins["lib/arm64-v8a/libapp.so"] == "strings"

    ids = {(rule, f.file) for f in result.findings for rule in f.rule_ids}
    assert ("ANDROID-SIGN-001", "_sca/signing.txt") in ids
    assert any(rule == "FLUTTER-APP-006" for rule, _ in ids)
    for finding in result.findings:
        origin = origins[finding.file]
        assert origin in RULES_ORIGINS or "rules" not in finding.engines
        assert origin != "summary" or finding.engines == ["flutter"]
        assert kit.AWS_KEY not in finding.snippet and kit.AWS_KEY not in finding.context
    # the AWS key is found in the .env asset and in the libapp.so strings dump, and masked
    secret_files = {f.file for f in result.findings if "secrets" in f.engines}
    assert "lib/arm64-v8a/libapp.so" in secret_files
    signing = next(f for f in result.findings if f.rule_id == "ANDROID-SIGN-001")
    assert (signing.owasp_mobile, signing.masvs) == ("M8", "MASVS-PLATFORM")
    assert all(f.owasp_mobile for f in result.findings if f.cwe in ("CWE-319", "CWE-798"))


def test_reports_of_an_app_scan(tmp_path):
    path = write_app(tmp_path, kit.build_apk(
        extra_strings=["http://admin:%s@api.kit-probe.example/v2" % URL_PASSWORD]))
    result = run_scan(str(path), ScanOptions(**QUIET))
    written = write_reports(result, str(tmp_path / "out"), ["html", "json", "sarif", "pdf"])
    html = Path(written["html"]).read_text(encoding="utf-8")
    report = Path(written["json"]).read_text(encoding="utf-8")
    sarif_text = Path(written["sarif"]).read_text(encoding="utf-8")
    pdf = pdf_text(Path(written["pdf"]).read_bytes())
    # the secrets of the strings dumps are masked in every format, the facts and the titles
    # and descriptions that quote the URL included
    for text in (html, report, sarif_text, pdf):
        assert kit.AWS_KEY not in text and URL_PASSWORD not in text
    endpoint = next(e["url"] for e in result.app["endpoints"] if "admin" in e["url"])
    assert URL_PASSWORD[:4] in endpoint and "*" in endpoint
    cleartext = next(f for f in result.findings
                     if f.rule_id == "FLUTTER-APP-007" and "admin" in f.title)
    assert URL_PASSWORD[:4] + "*" in cleartext.title
    assert URL_PASSWORD[:4] + "*" in cleartext.description

    for text in ("App package", "OWASP Mobile Top 10 (2024)", "MASVS groups",
                 "Signing certificates", "M8 Security Misconfiguration", kit.PACKAGE,
                 "Build mode", "Snapshot hash", kit.SNAPSHOT_HASH, "Permissions (2)"):
        assert text in html
    assert "App facts" in pdf and kit.PACKAGE in pdf and "OWASP Mobile Top 10" in pdf
    assert json.loads(report)["app"]["package"] == kit.PACKAGE

    run = json.loads(sarif_text)["runs"][0]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in run["results"]}
    assert {"_sca/signing.txt", "lib/arm64-v8a/libapp.so", "AndroidManifest.xml"} <= uris
    tags = {tag for rule in run["tool"]["driver"]["rules"] for tag in rule["properties"]["tags"]}
    assert "M8:2024 Security Misconfiguration" in tags and "MASVS-PLATFORM" in tags
    signing = next(r for r in run["results"] if r["ruleId"] == "ANDROID-SIGN-001")
    assert signing["properties"]["owaspMobile"] == "M8"
    assert run["properties"]["app"]["package"] == kit.PACKAGE
    assert "app.apk" in run["originalUriBaseIds"]["%SRCROOT%"]["description"]["text"]


def test_debug_apk_recovered_dart_is_scanned_and_scored(tmp_path):
    sources = {"main.dart": kit.MAIN_DART,
               "test/fake_api.dart": "final c = HttpClient()..badCertificateCallback = "
                                     "(cert, host, port) => true;\n"}
    path = write_app(tmp_path, kit.build_apk(mode="debug", dart_sources=sources))
    options = ScanOptions(**dict(QUIET, use_ml=True))
    result, files = scan_project(str(path), options)
    by_rel = {sf.rel: sf for sf in files}
    assert by_rel["dart/lib/main.dart"].origin == "recovered"
    tls = [f for f in result.findings if f.rule_id == "DART-TLS-001"]
    assert {f.file for f in tls} == {"dart/lib/main.dart", "dart/lib/test/fake_api.dart"}
    # lib/test/ of the app is shipped to its users like the rest: not test code
    assert [f.test_code for f in tls if f.file.startswith("dart/lib/test/")] == [False]
    # ML scores code findings, never the structural checks or strings dumps
    for finding in result.findings:
        if "flutter" in finding.engines or by_rel[finding.file].origin not in AI_ORIGINS:
            assert finding.ml_score is None
    assert any(f.ml_score is not None for f in tls)

    skipped = run_scan(str(path), ScanOptions(**dict(QUIET, include_tests=False)))
    assert not [text for text in texts(skipped) if text.startswith("Left out")]
    assert [f for f in skipped.findings if f.file.startswith("dart/lib/test/")]
    assert skipped.app["build_mode"] == "debug"


def test_files_of_an_app_package_are_never_test_code(tmp_path):
    """An asset under test/, mocks/ or fixtures/ of an app is shipped to every user: it is
    scanned with its full confidence, also when test code is skipped."""
    env = "AWS_ACCESS_KEY_ID=%s\n" % kit.AWS_KEY
    assets = {"flutter_assets/assets/%s/prod.env" % folder: env
              for folder in ("config", "test", "mocks", "fixtures")}
    path = write_app(tmp_path, kit.build_apk(assets=assets))
    for include_tests in (True, False):
        result, files = scan_project(str(path), ScanOptions(**dict(QUIET,
                                                                   include_tests=include_tests)))
        keys = {f.file: f for f in result.findings if f.file.endswith("/prod.env")}
        assert len(keys) == 4, sorted(keys)
        assert not [f for f in keys.values() if f.test_code]
        assert len({round(f.confidence, 3) for f in keys.values()}) == 1      # all the same
        assert "test code" not in result.engine_notes


def test_no_flutter_switch_keeps_the_app_decoded(tmp_path):
    path = write_app(tmp_path, kit.build_apk())
    result = run_scan(str(path), ScanOptions(**dict(QUIET, use_flutter=False)))
    assert "Flutter/Android checks: skipped - switched off" in texts(result)
    assert "flutter" not in result.engines_used
    assert result.app["kind"] == "apk" and "permissions" not in result.app
    assert any("secrets" in f.engines for f in result.findings)
    assert all(f.owasp_mobile for f in result.findings if f.cwe == "CWE-798")


def test_app_bundle_and_split_sets(tmp_path):
    bundle = run_scan(str(write_app(tmp_path, kit.build_aab(), "app.aab")), ScanOptions(**QUIET))
    assert bundle.app["kind"] == "aab" and "flutter" in bundle.engines_used
    assert any(f.file == "AndroidManifest.xml" for f in bundle.findings)
    splits = kit.split_apk(kit.build_apk())
    apks = write_app(tmp_path, kit.build_apk_set(splits, layout="xapk"), "app.xapk")
    result = run_scan(str(apks), ScanOptions(**QUIET))
    assert result.app["kind"] == "apks" and texts(result)[0] == "Unpacking the app app.xapk"


def test_unreadable_app_package(tmp_path):
    with pytest.raises(flutter.AppError, match="not a readable app package"):
        run_scan(str(write_app(tmp_path, b"not a zip file", "broken.apk")), ScanOptions(**QUIET))
    no_manifest = write_app(tmp_path, zipread.build_zip([("a.txt", b"x", 0)]), "x.apk")
    with pytest.raises(flutter.AppError, match="no AndroidManifest.xml"):
        run_scan(str(no_manifest), ScanOptions(**QUIET))


def test_firebase_key_in_string_resources_is_lowered(tmp_path):
    path = write_app(tmp_path, kit.build_apk(strings={"app_name": "Kit",
                                                      "google_api_key": GOOGLE_KEY}))
    result = run_scan(str(path), ScanOptions(**QUIET))
    key = next(f for f in result.findings if f.file == "res/values/strings.xml"
               and f.cwe == "CWE-798")
    assert key.severity == "low" and key.confidence <= 0.4
    assert "Firebase" in key.description
    assert "lowered to low severity" in result.engine_notes["flutter"]


@pytest.mark.parametrize("with_other_copy", [False, True])
def test_maps_client_key_keeps_location_and_restriction_review(tmp_path, with_other_copy):
    metadata = ('        <meta-data android:name="com.google.android.geo.API_KEY"\n'
                '            android:value="%s" />\n' % GOOGLE_KEY)
    manifest = kit.MANIFEST.replace("    </application>", metadata + "    </application>")
    assets = {"flutter_assets/assets/other.json": '{"key":"%s"}' % GOOGLE_KEY} \
        if with_other_copy else {}
    path = write_app(tmp_path, kit.build_apk(manifest=manifest, assets=assets))
    result, files = scan_project(str(path), ScanOptions(**QUIET))
    finding = next(f for f in result.findings if f.file == "AndroidManifest.xml"
                   and f.rule_id == "SECRET-GOOGLE-001")
    assert (finding.severity, finding.tier) == ("low", "probable")
    assert "restrictions require verification" in finding.description
    manifest_file = next(sf for sf in files if sf.rel == finding.file)
    assert GOOGLE_KEY in manifest_file.lines[finding.line - 1]
    item = next(k for k in result.app["apis"]["keys"] if k["rule_id"] == finding.rule_id)
    assert {"file": finding.file, "line": finding.line} in item["locations"]
    assert item["advice"] == "google"
    assert item["public"] == (not with_other_copy)
    assert item["severity"] == ("high" if with_other_copy else "low")
    assert GOOGLE_KEY not in json.dumps(result.to_dict())


def test_llm_never_sees_summaries_or_strings_dumps(tmp_path, monkeypatch):
    class Client:
        label, is_local, requests, base_url = "fake/model", True, 0, "http://127.0.0.1"

        def check(self):
            return True, ""

    triaged, audited = [], []

    def triage(client, finding, context, lang):
        triaged.append(finding.file)
        return {"verdict": "true_positive", "confidence": 0.8, "explanation": "", "fix": ""}

    def deep_scan(client, sf, known, lang):
        audited.append(sf.rel)
        return [Finding(rule_id="LLM-1", title="t", file=sf.rel, line=1, cwe="CWE-319",
                        engines=["llm"], snippet=sf.line_text(1))]

    monkeypatch.setattr(pipeline, "client_from_options", lambda options: Client())
    monkeypatch.setattr(llm_module, "triage_finding", triage)
    monkeypatch.setattr(llm_module, "deep_scan_file", deep_scan)
    path = write_app(tmp_path, kit.build_apk(mode="debug"))
    result, files = scan_project(str(path), ScanOptions(**dict(
        QUIET, use_llm=True, llm_deep_scan=True, llm_deep_max_files=50, llm_max_findings=500)))
    origins = {sf.rel: sf.origin for sf in files}
    assert audited == ["dart/lib/main.dart"]
    assert triaged and not [rel for rel in triaged if origins[rel] in ("summary", "placeholder")]
    added = next(f for f in result.findings if f.engines == ["llm"])
    assert (added.owasp_mobile, added.masvs) == ("M5", "MASVS-NETWORK")   # merged as mobile


def test_inspect_mobile_runs_only_the_checks(tmp_path):
    path = write_app(tmp_path, kit.build_apk())
    ctx, files, findings, note = inspect_mobile(str(path))
    assert note.startswith("ok (") and findings
    assert {f.engines[0] for f in findings} == {"flutter"}
    assert ctx.facts["components"] and ctx.facts["flags"]["debuggable"] == "no"
    assert any(sf.secret_values for sf in files)          # secrets found, so quotes are masked
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.py").write_text("print(1)\n", encoding="utf-8")
    assert inspect_mobile(str(plain))[0] is None
    with pytest.raises(FileNotFoundError):
        inspect_mobile(str(tmp_path / "missing.apk"))


BIDI = re.compile("[؜‎‏‪-‮⁦-⁩]")


def bidi_app(tmp_path):
    """An app whose manifest and label hide Unicode bidirectional controls in names."""
    manifest = kit.MANIFEST.replace(".KitReceiver", ".Kit‮Reviecer⁦x⁩") \
        .replace('android:host="kit-probe.example"', 'android:host="kit‏-probe.example"')
    return write_app(tmp_path, kit.build_apk(manifest=manifest,
                                             strings={"app_name": "Kit؜‭App"}))


def test_bidi_controls_of_an_app_are_removed_from_every_output(tmp_path):
    path = bidi_app(tmp_path)
    result, files = scan_project(str(path), ScanOptions(**QUIET))
    assert any(BIDI.search(sf.text) for sf in files)      # the decoded manifest keeps them
    assert any("KitReviecerx" in f.title for f in result.findings)
    assert [f.title for f in result.findings
            if BIDI.search(f.title + f.description + f.snippet + f.context)] == []
    assert not BIDI.search(json.dumps(result.app, ensure_ascii=False))
    assert not BIDI.search(json.dumps(result.to_dict(), ensure_ascii=False))
    assert not BIDI.search(render_html(result))
    assert not BIDI.search(json.dumps(to_sarif(result), ensure_ascii=False))
    assert not BIDI.search(pdf_text(render_pdf(result)))
    ctx, _files, findings, _note = inspect_mobile(str(path))
    assert not BIDI.search(json.dumps(ctx.facts, ensure_ascii=False))
    assert not [f.title for f in findings if BIDI.search(f.title)]
    # the HTML report strips them from any text, also of a scan saved by an older version
    old = ScanResult(target="x‮.apk", findings=[Finding(
        rule_id="R", title="t‮itle", file="a⁧.dart", line=1, severity="low",
        cwe="CWE-1", confidence=0.5, engines=["rules"], snippet="s‏nippet")])
    assert not BIDI.search(render_html(old) + json.dumps(to_sarif(old), ensure_ascii=False))


def test_a_loader_that_fails_is_an_error_message(tmp_path, monkeypatch):
    """An unexpected error of the project loader or of a decoder (a bug, an input nobody
    thought of) is a message for the user: AppError for `flutter info|decode|deps` and the
    scan of an app, an engine note in the scan of a folder."""
    project = SAMPLES / "flutter_vulnerable_app"

    def broken(*args, **kwargs):
        raise ValueError("invalid literal for int() with base 10: '²'")

    monkeypatch.setattr(flutter, "load_project", broken)
    with pytest.raises(flutter.AppError) as error:
        inspect_mobile(str(project))
    assert str(error.value) == ("The Flutter/Android project in flutter_vulnerable_app could "
                                "not be read: ValueError: invalid literal for int() with base "
                                "10: '²'")
    result = run_scan(str(project), ScanOptions(**QUIET))
    assert result.engine_notes["flutter"].startswith("failed: ValueError: invalid literal")
    assert result.app == {} and result.findings                  # the other engines ran

    monkeypatch.setattr(flutter, "load_app", broken)
    path = write_app(tmp_path, kit.build_apk())
    for call in (lambda: inspect_mobile(str(path)), lambda: run_scan(str(path),
                                                                     ScanOptions(**QUIET))):
        with pytest.raises(flutter.AppError) as error:
            call()
        assert str(error.value).startswith("app.apk could not be decoded: ValueError: ")


def test_masking_of_facts_and_of_the_titles_of_the_checks():
    secret = "ZQ81mVb3Kc0LpX5n"
    sf = SourceFile(Path("lib/x86/libapp.so"), "lib/x86/libapp.so", "config",
                    "https://h.example/?k=%s\n" % secret, secret_values=[secret],
                    origin="strings")
    manifest = SourceFile(Path("AndroidManifest.xml"), "AndroidManifest.xml", "config",
                          "<data android:scheme='app%s' />\n" % secret, secret_values=[secret])
    ctx = MobileContext(kind="apk", root=Path("app.apk"), facts={
        "endpoints": [{"url": "https://h.example/?k=%s" % secret, "file": sf.rel},
                      {"url": "https://h.example/?k=%s" % secret[:9], "file": sf.rel}],
        "components": [{"type": "activity", "deep_links": ["app%s://open" % secret]}]})
    ctx.manifests = [("AndroidManifest.xml", None)]
    mask_facts(ctx, {sf.rel: sf, manifest.rel: manifest})
    assert secret not in json.dumps(ctx.facts)
    # only whole secrets are replaced: a text that merely starts like one stays as it is
    assert ctx.facts["endpoints"][1]["url"] == "https://h.example/?k=%s" % secret[:9]
    # a title that shortens the quote with "..." in the middle of the secret
    title = pipeline._mask_text(sf, "URL: https://h.example/?k=%s... in the app" % secret[:7])
    assert secret[:7] not in title and title.endswith("?k=ZQ81***... in the app")
    assert pipeline._mask_text(sf, "URL ending in %s" % secret[:7]) == \
        "URL ending in %s" % secret[:7]                               # no "..." marker
    assert pipeline._mask_text(sf, "") == ""


def test_titles_of_other_engines_are_never_masked(tmp_path):
    """Titles of the pattern rules, the secrets engine and the external tools name a rule or
    a variable. A title that ends with the first letters of a secret of the file ("Stripe
    access toke*" for token_xyz789) or names a variable whose value is the secret stays as it
    is; only the titles of the Flutter/Android checks quote the file."""
    secret, other = "token_xyz789", "newPassword"
    sf = SourceFile(Path("app.py"), "app.py", "python",
                    'TOKEN = "%s"\npassword = "%s"\n' % (secret, other),
                    secret_values=[secret, other])
    titles = ["Stripe access token", "Hard-coded secret in 'newPassword'", "token..."]
    for engines in (["gitleaks"], ["secrets"], ["rules"], ["bandit"]):
        for title in titles:
            finding = Finding(rule_id="R", title=title, file="app.py", line=1, severity="high",
                              cwe="CWE-798", confidence=0.8, engines=engines,
                              description="The value of %s." % other)
            pipeline._clean_quotes(finding, sf, False)
            assert finding.title == title and finding.description == "The value of %s." % other
    check = Finding(rule_id="ANDROID-X", title="Quoted %s and %s..." % (secret, other[:6]),
                    file="app.py", line=1, severity="low", cwe="CWE-200", confidence=0.5,
                    engines=["flutter"])
    pipeline._clean_quotes(check, sf, False)
    assert secret not in check.title and other[:6] + "..." not in check.title

    # a whole scan of a project like pygoat's lab: the titles are those of the rules
    (tmp_path / "app.py").write_text(
        'SENSITIVE_DATA = {\n    "api_key": "sk_live_9876543210abcdef",\n'
        '    "user_token": "token_xyz789",\n}\n', encoding="utf-8")
    result = run_scan(str(tmp_path), ScanOptions(**dict(QUIET, use_bandit=False)))
    assert result.findings and not [f.title for f in result.findings if "*" in f.title]


# ------------------------------------------------------------------ source projects
def test_scan_of_the_flutter_sample_project():
    result, files = scan_project(str(SAMPLES / "flutter_vulnerable_app"), ScanOptions(**QUIET))
    found = next(m for m in result.steps if m.template == "Found a Flutter project: %s")
    assert found.args[0] == result.app["name"]
    assert result.app["kind"] == "flutter-project" and "flutter" in result.engines_used
    manifest = "android/app/src/main/AndroidManifest.xml"
    assert any(f.file == manifest and f.engines == ["flutter"] for f in result.findings)
    assert any(f.rule_id.startswith("DART-") for f in result.findings)
    assert all(f.masvs for f in result.findings if f.file == manifest)
    assert result.lines_scanned == sum(len(sf.lines) for sf in files)     # all on disk


def test_keystore_placeholders_and_test_folders(tmp_path):
    (tmp_path / "pubspec.yaml").write_text(
        "name: kit_app\npublish_to: none\nenvironment:\n  sdk: ^3.5.0\n"
        "dependencies:\n  flutter:\n    sdk: flutter\n", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "main.dart").write_text("void main() {}\n", encoding="utf-8")
    (tmp_path / "android" / "app").mkdir(parents=True)
    (tmp_path / "android" / "app" / "upload.jks").write_bytes(b"\xfe\xed\xfe\xed" + b"\0" * 60)
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "fixture.p12").write_bytes(b"\x30\x82" + b"\0" * 30)
    result, files = scan_project(str(tmp_path), ScanOptions(**QUIET))
    origins = {sf.rel: sf.origin for sf in files}
    assert origins["android/app/upload.jks"] == "placeholder"
    assert origins["test/fixture.p12"] == "placeholder"
    assert result.lines_scanned == sum(len(sf.lines) for sf in files
                                       if sf.origin != "placeholder")
    keystore = next(f for f in result.findings if f.file == "android/app/upload.jks")
    assert keystore.rule_id == "ANDROID-SIGN-011" and keystore.line == 1
    assert next(f for f in result.findings if f.file == "test/fixture.p12").test_code

    without, files = scan_project(str(tmp_path), ScanOptions(**dict(QUIET, include_tests=False)))
    assert "test/fixture.p12" not in {sf.rel for sf in files}
    assert {f.file for f in without.findings} >= {"android/app/upload.jks"}


def test_folder_without_mobile_files(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system('ls ' + input())\n", encoding="utf-8")
    result = run_scan(str(tmp_path), ScanOptions(**dict(QUIET, use_bandit=False)))
    assert "Flutter/Android checks: skipped - no Flutter or Android files" in texts(result)
    assert result.app == {} and result.findings
    assert not [f for f in result.findings if f.owasp_mobile or f.masvs]
    assert "App package" not in render_html(result) and "MASVS" not in render_html(result)
    run = to_sarif(result)["runs"][0]
    assert "app" not in run["properties"] and "originalUriBaseIds" not in run
    off = run_scan(str(SAMPLES / "flutter_safe_app"), ScanOptions(**dict(QUIET,
                                                                         use_flutter=False)))
    assert off.app == {} and "flutter" not in off.engines_used


# ------------------------------------------------------------------ learning
def test_learning_reads_the_decoded_files_of_an_app(tmp_path):
    path = write_app(tmp_path, kit.build_apk(mode="debug"))
    files = loop.load_files(str(path))
    assert {sf.origin for sf in files} <= {"decoded", "recovered", "decompiled"}
    rels = {sf.rel for sf in files}
    assert {"AndroidManifest.xml", "dart/lib/main.dart"} <= rels
    assert not [rel for rel in rels if rel.startswith("_sca/") or rel.endswith((".so", ".dex"))]
    assert any(sf.secret_values for sf in files)


def test_learning_skips_findings_in_strings_dumps(tmp_path):
    storage = Storage(str(tmp_path / "h.db"))
    dump = SourceFile(Path("classes.dex"), "classes.dex", "config", "SELECT 1\n",
                      origin="strings")
    finding = Finding(rule_id="LLM-1", title="t", file="classes.dex", line=1, cwe="CWE-89",
                      engines=["llm"], ai_verdict="true_positive", snippet="SELECT 1")
    result = ScanResult(target="x", findings=[finding])
    assert loop.learn_from_scan(result, [dump], client=None, storage=storage) == []


def test_coverage_counts_only_rules_for_whole_languages(monkeypatch):
    def rule(rule_id, files):
        return rules_engine.parse_rule({"id": rule_id, "title": "t", "languages": ["lua"],
                                        "cwe": "CWE-78", "pattern": "os\\.execute",
                                        "files": files})

    monkeypatch.setattr(loop.rules_engine, "load_rules",
                        lambda: [rule("A", []), rule("B", ["**/ci/*.lua"])])
    assert loop.coverage_matrix()["lua"] == {"CWE-78": 1}


# ------------------------------------------------------------------ reports of facts
def facts():
    return {
        "kind": "apk", "name": "app.apk", "size_bytes": 2_000_000, "sha256": "ab" * 32,
        "flutter": True, "package": "com.example.<script>alert(1)</script>",
        "version_name": "1.0", "version_code": "3", "min_sdk": 21, "target_sdk": None,
        "target_sdk_note": "flutter.targetSdkVersion", "compile_sdk": 36,
        "build_mode": "release", "abis": ["arm64-v8a", "x86_64"], "dart_version": "3.12.2",
        "engine_revision": "e" * 40, "snapshot_hash": "f" * 32, "snapshot_features": "product",
        "obfuscated": None, "obfuscation_note": "not judged", "debug_symbols": False,
        "signing": {"schemes": ["v2"], "verified": False, "certificates": [{
            "subject": "CN=Kit", "issuer": "CN=Kit", "sha256": "c" * 64,
            "valid_from": "2026-01-01", "valid_to": "2056-01-01", "key": "RSA 1024",
            "signature_algorithm": "sha1WithRSAEncryption", "debug": False}]},
        "dart_sources": {"recovered": 2, "files": ["dart/lib/a.dart", "dart/lib/b.dart"]},
        "packages": [{"name": "http", "version": "", "source": "hosted", "found_in": "notices"}],
        "plugins": ["io.flutter.plugins.pathprovider.PathProviderPlugin"],
        "platforms": ["android", "ios"],
        "permissions": [{"name": "android.permission.P%d" % n, "dangerous": n % 2 == 0}
                        for n in range(APP_ROWS + 5)],
        "components": [{"type": "activity", "name": ".Main", "exported": True,
                        "permission": "", "launcher": True, "deep_links": ["kit://open"]}],
        "flags": {"debuggable": "yes", "allow_backup": "yes (default)",
                  "cleartext": "allowed (android:usesCleartextTraffic)",
                  "network_security_config": "none"},
        "endpoints": [{"url": "http://api.example.com/v1", "cleartext": True,
                       "file": "lib/arm64-v8a/libapp.so"}],
        "dependency_issues": 4, "warnings": ["zip: \x1b[2Jtwo entries named a.txt"],
        "tools": {"jadx": "ok (3 files)"}, "dex": {"files": 2, "classes": 10, "strings": 90},
        "future_fact": {"value": 7},
    }


def test_app_card_shows_every_fact():
    data = facts()
    labels = dict(app_overview(data))
    assert labels["SDK levels"] == "min 21, target flutter.targetSdkVersion, compile 36"
    assert labels["Dart obfuscation"] == "unknown (not judged)"
    assert labels["Signature verified by apksigner"] == "no"
    assert labels["Future fact"] == '{"value": 7}'
    assert labels["Size"] == "2.0 MB (2,000,000 bytes)"         # decimal units
    assert dict(app_overview({"size_bytes": 4_878}))["Size"] == "5 KB (4,878 bytes)"
    # an Android app without Flutter has no build mode and no Dart packages
    plain = dict(app_overview(dict(data, flutter=False, build_mode="unknown")))
    assert plain["Flutter"] == "no" and "Build mode" not in plain
    assert "Dependency issues" not in plain
    titles = {title for title, _, _ in app_tables(data)}
    assert titles == {"Signing certificates", "Permissions", "Components", "Endpoints",
                      "Packages", "Plugins", "Recovered Dart sources", "Tools", "Warnings"}
    warnings = next(rows for title, _, rows in app_tables(data) if title == "Warnings")
    assert "\x1b" not in warnings[0][0]

    result = ScanResult(target="app.apk", app=data)
    html = render_html(result)
    assert "<script>alert" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "and 5 more" in html and "Permissions (%d)" % (APP_ROWS + 5) in html
    for text in ("2.0 MB", "ab" * 32, "arm64-v8a, x86_64", "3.12.2", "e" * 40, "f" * 32,
                 "sha1WithRSAEncryption", "dart/lib/b.dart", "PathProviderPlugin",
                 "android, ios", "kit://open", "yes (default)", "http://api.example.com/v1",
                 "ok (3 files)", "2 files, 10 classes, 90 strings", "notices",
                 "Dependency issues", "OWASP Mobile Top 10 (2024)"):
        assert escape_free(text) in html, text
    pdf = pdf_text(render_pdf(result))
    assert "App facts" in pdf and "and 5 more" in pdf and "com.example." in pdf


def escape_free(text):
    return text.replace("<", "&lt;").replace(">", "&gt;")


def test_sarif_uris_are_relative_and_encoded():
    assert file_uri("lib/arm64-v8a/libapp.so") == "lib/arm64-v8a/libapp.so"
    assert file_uri("_sca/build.txt") == "_sca/build.txt"
    assert file_uri("my dir/a#b%c:d.dart") == "my%20dir/a%23b%25c%3Ad.dart"
    assert file_uri("src\\main\\ص.dart") == "src/main/%D8%B5.dart"


# ------------------------------------------------------------------ real packages
def _scan_real(path, **options):
    began = time.time()
    result, files = scan_project(str(path), ScanOptions(**dict(QUIET, **options)))
    return result, files, time.time() - began


def _check_real(result, files, seconds, limit, tmp_path):
    steps = texts(result)
    assert seconds < limit, "%s took %.1f s" % (result.target, seconds)
    assert "Bandit: skipped - not used for app packages" in steps
    assert result.engine_notes["flutter"].startswith("ok (")
    assert result.lines_scanned == sum(len(sf.lines) for sf in files
                                       if sf.origin in KLOC_ORIGINS)
    values = {value for sf in files for value in sf.secret_values}
    written = write_reports(result, str(tmp_path / Path(result.target).stem),
                            ["html", "json", "sarif", "pdf"])
    for fmt, name in written.items():
        data = Path(name).read_bytes()
        text = pdf_text(data) if fmt == "pdf" else data.decode("utf-8")
        assert not [value for value in values if value in text], fmt


@real_apks
def test_real_vuln_probe_packages(tmp_path):
    for name, limit in (("release.apk", 20), ("release_obf.apk", 20), ("release.aab", 20),
                        ("debug.apk", 40)):
        result, files, seconds = _scan_real(APK_DIR / name)
        _check_real(result, files, seconds, limit, tmp_path)
        assert result.app["flutter"] is True


@real_probe
def test_real_probe_packages(tmp_path):
    expected = {"ANDROID-MANIFEST-004", "ANDROID-NSC-001", "ANDROID-FILEPROVIDER-001",
                "ANDROID-SIGN-001", "FLUTTER-APP-006"}
    for name, limit in (("release.apk", 20), ("release.aab", 20), ("debug.apk", 40)):
        result, files, seconds = _scan_real(PROBE_DIR / name)
        _check_real(result, files, seconds, limit, tmp_path)
        rules = {rule for f in result.findings for rule in f.rule_ids}
        missing = expected - rules - ({"ANDROID-SIGN-001"} if name.endswith(".aab") else set())
        assert not missing, (name, missing)


@real_probe
@with_jadx
def test_real_probe_with_jadx(tmp_path):
    result, files, seconds = _scan_real(PROBE_DIR / "release.apk", apk_tools=True)
    decompiled = [sf for sf in files if sf.origin == "decompiled"]
    assert decompiled and all(sf.rel.startswith("jadx/") for sf in decompiled)
    assert result.app["tools"]["jadx"].startswith("ok")
    assert result.lines_scanned >= sum(len(sf.lines) for sf in decompiled)
