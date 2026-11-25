"""Tests for the command line of the Flutter / Android module: `scan` on app packages,
`flutter info|decode|deps|tools`, the mobile part of `doctor`, and the `files` field in
`rules show|edit|test`.

App packages are built with tests/flutter_kit.py. The commands on real packages run only when
SCA_FLUTTER_PROBE_DIR holds the packages built from samples/flutter_apk_probe; the jadx scan
also needs SCA_JADX.
"""
import json
import os
import re
from pathlib import Path

import pytest

import flutter_kit as kit
from sca import pipeline, rulebook
from sca.__main__ import main as cli
from sca.__main__ import output_path
from sca.flutter import MobileContext, tools
from sca.walker import SourceFile

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
PROBE_DIR = Path(os.environ.get("SCA_FLUTTER_PROBE_DIR", "") or "missing")
PACKAGES = ("debug.apk", "release.apk", "release_obf.apk", "release.aab")
real_probe = pytest.mark.skipif(not all((PROBE_DIR / n).is_file() for n in PACKAGES),
                                reason="SCA_FLUTTER_PROBE_DIR does not hold the probe packages")
with_jadx = pytest.mark.skipif(not os.environ.get("SCA_JADX"), reason="SCA_JADX is not set")
FAST = ["--no-save", "--quiet", "--no-ml", "--no-semgrep", "--no-gitleaks", "--no-bandit"]


def write_app(tmp_path, data, name="app.apk"):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def all_files(folder):
    return sorted(p.relative_to(folder).as_posix() for p in Path(folder).rglob("*")
                  if p.is_file())


# ------------------------------------------------------------------ scan
def test_scan_an_app_package(tmp_path, capsys):
    path = write_app(tmp_path, kit.build_apk())
    out = tmp_path / "reports"
    assert cli(["scan", path, "--out", str(out), "--format", "json,sarif"] + FAST) == 0
    printed = capsys.readouterr().out
    assert "App    : com.example.kitapp 1.2.3 (7) - APK, Flutter release build" in printed
    assert "_sca/signing.txt" in printed
    report = json.loads((out / "sca-report.json").read_text(encoding="utf-8"))
    assert report["app"]["kind"] == "apk" and "flutter" in report["engines_used"]
    assert kit.AWS_KEY not in (out / "sca-report.sarif").read_text(encoding="utf-8")

    assert cli(["scan", path, "--out", str(out), "--format", "json", "--no-flutter"]
               + FAST) == 0
    report = json.loads((out / "sca-report.json").read_text(encoding="utf-8"))
    assert "flutter" not in report["engines_used"] and report["app"]["kind"] == "apk"


def test_scan_of_a_broken_package_is_an_error(tmp_path, capsys):
    path = write_app(tmp_path, b"PK\x03\x04 not really", "broken.aab")
    assert cli(["scan", path, "--format", ""] + FAST) == 2
    error = capsys.readouterr().err
    assert error.startswith("Error: broken.aab is not a readable app package")


def test_learn_from_a_broken_package_is_an_error(tmp_path, monkeypatch, capsys):
    import sca.__main__ as main_module

    monkeypatch.setattr(main_module, "_client", lambda args: object())
    path = write_app(tmp_path, b"PK\x03\x04 not really", "broken.apk")
    assert cli(["learn", path, "--quiet"]) == 2
    assert capsys.readouterr().err.startswith("Error: broken.apk is not a readable app package")


def test_help_texts_name_app_packages(capsys):
    with pytest.raises(SystemExit):
        cli(["scan", "--help"])
    text = capsys.readouterr().out
    assert ".apk, .aab" in text and "--no-flutter" in text and "--apk-tools" in text
    assert "Dart" in text                                      # --no-taint-lite
    with pytest.raises(SystemExit):
        cli(["rules", "--help"])
    text = capsys.readouterr().out
    assert "files" in text and "app package" in text
    with pytest.raises(SystemExit):
        cli(["flutter", "--help"])
    assert "decode PATH --out DIR" in capsys.readouterr().out


# ------------------------------------------------------------------ flutter info / deps
def test_flutter_info(tmp_path, capsys):
    path = write_app(tmp_path, kit.build_apk())
    assert cli(["flutter", "info", path]) == 0
    text = capsys.readouterr().out
    for expected in ("Package", kit.PACKAGE, "Build mode", "release", "Signing certificates (1)",
                     "Permissions (2)", "Components (", "checks found"):
        assert expected in text
    assert cli(["flutter", "info", path, "--json"]) == 0
    facts = json.loads(capsys.readouterr().out)
    assert facts["kind"] == "apk" and facts["flags"]["cleartext"].startswith("allowed")

    assert cli(["flutter", "info", str(SAMPLES / "flutter_vulnerable_app")]) == 0
    assert "Flutter project" in capsys.readouterr().out
    plain = tmp_path / "plain"
    plain.mkdir()
    assert cli(["flutter", "info", str(plain)]) == 2
    assert "neither a Flutter app nor an Android project" in capsys.readouterr().err
    assert cli(["flutter", "info"]) == 2
    assert cli(["flutter", "info", str(tmp_path / "missing.apk")]) == 2


def test_flutter_deps(tmp_path, capsys):
    path = write_app(tmp_path, kit.build_apk(mode="debug"))
    assert cli(["flutter", "deps", path]) == 0
    text = capsys.readouterr().out
    assert "http" in text and "0.13.0" in text and "FLUTTER-PUB-001" in text
    assert cli(["flutter", "deps", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {p["name"] for p in data["packages"]} >= {"http", "collection"}
    assert [i["rule_id"] for i in data["issues"]] == ["FLUTTER-PUB-001"]


def test_flutter_options_can_come_before_or_after_the_path(tmp_path, capsys):
    """`flutter info --json app.apk` and the other orders of options, action and path."""
    path = write_app(tmp_path, kit.build_apk())
    for args in (["info", "--json", path], ["--json", "info", path], ["info", path, "--json"],
                 ["info", "--apk-tools", "--json", path], ["info", "--exclude", "x", path,
                                                           "--json"]):
        assert cli(["flutter"] + args) == 0, args
        assert json.loads(capsys.readouterr().out)["kind"] == "apk", args
    assert cli(["flutter", "info", "--apk-tools", path]) == 0
    assert "Package" in capsys.readouterr().out
    assert cli(["flutter", "deps", "--json", path]) == 0
    assert json.loads(capsys.readouterr().out)["packages"]
    for number, args in enumerate((["decode", "--out", "DIR", path],
                                   ["--out", "DIR", "decode", path],
                                   ["decode", path, "--out", "DIR"])):
        out = tmp_path / ("decoded%d" % number)
        assert cli(["flutter"] + [str(out) if a == "DIR" else a for a in args]) == 0, args
        assert (out / "facts.json").is_file()
    capsys.readouterr()
    with pytest.raises(SystemExit):                     # the action is still required
        cli(["flutter", "--json"])
    with pytest.raises(SystemExit):
        cli(["flutter", "show", path])


def test_flutter_commands_report_a_project_that_cannot_be_read(tmp_path, monkeypatch,
                                                                capsys):
    """A failure of the project loader is an error message, never a stack trace."""
    import sca.flutter as flutter_package

    def broken(*args, **kwargs):
        raise ValueError("invalid literal for int() with base 10: 'x'")

    project = str(SAMPLES / "flutter_vulnerable_app")
    with monkeypatch.context() as patch:
        patch.setattr(flutter_package, "load_project", broken)
        for args in (["info", project], ["deps", "--json", project],
                     ["decode", project, "--out", str(tmp_path / "out")]):
            assert cli(["flutter"] + args) == 2, args
            assert capsys.readouterr().err == (
                "Error: The Flutter/Android project in flutter_vulnerable_app could not be "
                "read: ValueError: invalid literal for int() with base 10: 'x'\n")
    assert not (tmp_path / "out").exists()
    # the project of the review: a superscript digit as the SDK level in the manifest
    root = tmp_path / "sdk"
    (root / "app" / "src" / "main").mkdir(parents=True)
    (root / "app" / "src" / "main" / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.evil">\n  <uses-sdk android:minSdkVersion="²"/>\n'
        '  <application android:debuggable="true"/>\n</manifest>\n', encoding="utf-8")
    (root / "app" / "build.gradle").write_text("apply plugin: 'com.android.application'\n",
                                               encoding="utf-8")
    for action in ("info", "deps"):
        code = cli(["flutter", action, str(root)])
        printed = capsys.readouterr()
        assert code == 0 or (code == 2 and printed.err.startswith("Error: ")), printed.err


def test_app_line_names_flutter_once():
    from sca.__main__ import _app_line
    assert _app_line({"kind": "flutter-project", "flutter": True, "name": "tiny"}) == \
        "tiny - Flutter project"
    assert _app_line({"kind": "android-project", "flutter": False, "name": "droid"}) == \
        "droid - Android project"
    assert _app_line({"kind": "apk", "flutter": True, "build_mode": "release",
                      "package": "a.b", "version_name": "1.0", "version_code": "2"}) == \
        "a.b 1.0 (2) - APK, Flutter release build"


def test_command_line_never_prints_bidi_controls(tmp_path, capsys):
    """Unicode bidirectional controls in the names of an app are removed from everything the
    command line prints (scan, progress, flutter info|deps, JSON)."""
    bidi = re.compile("[؜‎‏‪-‮⁦-⁩]")
    manifest = kit.MANIFEST.replace(".KitReceiver", ".Kit‮Reviecer⁦x⁩")
    path = write_app(tmp_path, kit.build_apk(manifest=manifest,
                                             strings={"app_name": "Kit‏App"}),
                     "w‮ird.apk")
    loud = [option for option in FAST if option != "--quiet"]
    assert cli(["scan", path, "--format", "", "--top", "100"] + loud) == 0
    printed = capsys.readouterr()
    assert "KitReviecerx" in printed.out and not bidi.search(printed.out + printed.err)
    for args in (["info", path], ["info", "--json", path], ["deps", path], ["deps", "--json",
                                                                              path]):
        assert cli(["flutter"] + args) == 0
        printed = capsys.readouterr()
        assert not bidi.search(printed.out + printed.err), args


# ------------------------------------------------------------------ flutter decode
def test_flutter_decode(tmp_path, capsys):
    path = write_app(tmp_path, kit.build_apk(mode="debug"))
    out = tmp_path / "decoded"
    assert cli(["flutter", "decode", path, "--out", str(out)]) == 0
    files = all_files(out)
    assert {"AndroidManifest.xml", "_sca/build.txt", "_sca/signing.txt", "facts.json",
            "dart/lib/main.dart", "classes.dex", "res/xml/network_security_config.xml"} \
        <= set(files)
    assert json.loads((out / "facts.json").read_text(encoding="utf-8"))["build_mode"] == "debug"
    assert "Wrote %d files" % len(files) in capsys.readouterr().out
    # decoded text is written as it is: a decoded file is the app's own content
    assert kit.AWS_KEY in (out / "dart/lib/main.dart").read_text(encoding="utf-8")

    assert cli(["flutter", "decode", path, "--out", str(out)]) == 2      # not empty
    assert "not an empty folder" in capsys.readouterr().err
    assert cli(["flutter", "decode", path]) == 2
    assert all_files(tmp_path / "decoded") == files


def test_decode_never_writes_outside_its_folder(tmp_path, monkeypatch, capsys):
    hostile = ["../escape.txt", "a/../../escape.txt", "/abs.txt", "C:/drive.txt", "a\\b.txt",
               "con.txt", "x/NUL", "trailing./x.txt", "", "a//b.txt", "ok/fine.txt"]
    ctx = MobileContext(kind="apk", root=tmp_path / "x.apk", facts={"kind": "apk"})
    ctx.files = [SourceFile(Path("x"), rel, "config", "text\n", origin="decoded")
                 for rel in hostile]
    monkeypatch.setattr(pipeline, "inspect_mobile",
                        lambda *args, **kwargs: (ctx, ctx.files, [], "ok ()"))
    out = tmp_path / "out"
    assert cli(["flutter", "decode", "x.apk", "--out", str(out)]) == 1
    assert all_files(tmp_path) == ["out/facts.json", "out/ok/fine.txt"]
    assert capsys.readouterr().out.count("not written") == len(hostile) - 1


def test_output_path():
    folder = Path("C:/out") if os.name == "nt" else Path("/out")
    for rel in ("../x", "a/../b", "/abs", "C:/x", "a\\b", "con.txt", "x/aux", "lpt1",
                "a./b", "a /b", "", "a//b", "x?y", 'a"b', "a" * 401):
        assert output_path(folder, rel) is None, rel
    assert output_path(folder, "res/xml/a.xml") == folder / "res" / "xml" / "a.xml"
    assert output_path(folder, "assets/flutter_assets/.env") is not None
    assert output_path(folder, "console.txt") is not None


# ------------------------------------------------------------------ tools / doctor
def test_flutter_tools_and_doctor(monkeypatch, capsys):
    monkeypatch.setattr(tools, "availability", lambda: {
        "jadx": None, "apksigner": "C:/sdk/build-tools/36.1.0/apksigner.bat", "newtool": None})
    monkeypatch.setattr(tools, "hints", lambda: {})          # a missing hint never raises
    assert cli(["flutter", "tools"]) == 0
    text = capsys.readouterr().out
    assert "Mobile apps" in text and "[ok] apksigner" in text
    assert "[--] jadx       not found - optional" in text and "newtool" in text
    assert cli(["doctor"]) == 0
    text = capsys.readouterr().out
    assert "Mobile apps" in text and "checks of manifests" in text
    assert "C, Dart (built in)" in text


def test_real_tool_hints_are_shown(capsys):
    assert cli(["flutter", "tools"]) == 0
    text = capsys.readouterr().out
    for name in ("jadx", "apksigner", "aapt2", "flutter", "dart"):
        assert name in text


# ------------------------------------------------------------------ rules and files
def test_rules_show_edit_and_test_with_files(tmp_path, capsys):
    assert cli(["rules", "show", "FLUTTER-WEB-001"]) == 0
    assert "files:" in capsys.readouterr().out

    page = '<script src="http://cdn.example-analytics.com/sdk.js"></script>\n'
    for folder in ("web", "docs"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "index.html").write_text(page, encoding="utf-8")
    assert cli(["rules", "test", "FLUTTER-WEB-001", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "web/index.html:1" in text and "docs/index.html" not in text
    assert "1 line(s) matched" in text and "1 file(s) not read" in text

    try:
        assert cli(["rules", "edit", "FLUTTER-WEB-001", "--set",
                    "files=[**/web/*.html, 'docs/*.html']"]) == 0
        assert rulebook.get("FLUTTER-WEB-001").files == ["**/web/*.html", "docs/*.html"]
        capsys.readouterr()
        assert cli(["rules", "test", "FLUTTER-WEB-001", str(tmp_path)]) == 0
        assert "2 line(s) matched" in capsys.readouterr().out
    finally:
        cli(["rules", "reset", "FLUTTER-WEB-001"])
    assert rulebook.get("FLUTTER-WEB-001").files == ["**/web/index.html"]


def test_rules_test_on_an_app_package(tmp_path, capsys):
    path = write_app(tmp_path, kit.build_apk(mode="debug"))
    assert cli(["rules", "test", "DART-TLS-001", path]) == 0
    text = capsys.readouterr().out
    assert "dart/lib/main.dart:" in text and "1 line(s) matched" in text
    assert cli(["rules", "test", "DART-TLS-001", write_app(tmp_path, b"junk", "bad.apk")]) == 1


def test_coverage_mentions_file_rules(capsys):
    assert cli(["coverage"]) == 0
    assert "rules for named files only" in capsys.readouterr().out


# ------------------------------------------------------------------ real packages
@real_probe
def test_real_flutter_commands(tmp_path, capsys):
    for name in ("release.apk", "debug.apk", "release.aab"):
        path = str(PROBE_DIR / name)
        assert cli(["flutter", "info", path]) == 0
        assert "com.example.flutter_apk_probe" in capsys.readouterr().out
        assert cli(["flutter", "deps", path]) == 0
        assert "packages" in capsys.readouterr().out
        out = tmp_path / name.replace(".", "_")
        assert cli(["flutter", "decode", path, "--out", str(out)]) == 0
        files = all_files(out)
        assert "AndroidManifest.xml" in files and "facts.json" in files
    assert sorted(p.name for p in tmp_path.iterdir()) == ["debug_apk", "release_aab",
                                                          "release_apk"]


@real_probe
@with_jadx
def test_real_scan_with_apk_tools(tmp_path, capsys):
    out = tmp_path / "reports"
    assert cli(["scan", str(PROBE_DIR / "release.apk"), "--apk-tools", "--out", str(out),
                "--format", "json"] + FAST) == 0
    report = json.loads((out / "sca-report.json").read_text(encoding="utf-8"))
    assert report["app"]["tools"]["jadx"].startswith("ok")
    assert "java" in report["languages"]
