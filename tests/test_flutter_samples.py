"""Tests for the Flutter samples: samples/flutter_vulnerable_app and its ground truth
(samples/flutter_ground_truth.json), samples/flutter_safe_app, the probe app of
samples/flutter_apk_probe and tools/build_flutter_apks.py (without Flutter)."""
import importlib.util
import json
import os
import plistlib
import re
import sys
import xml.etree.ElementTree as ElementTree
import zipfile
from pathlib import Path

import pytest
import yaml

from sca.cwe import canonical

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
VULN = SAMPLES / "flutter_vulnerable_app"
SAFE = SAMPLES / "flutter_safe_app"
PROBE = SAMPLES / "flutter_apk_probe"
TRUTH = SAMPLES / "flutter_ground_truth.json"
TAG = re.compile(r"\[([A-Z]\d{2})\]")      # the tag pattern of evaluation/evaluate.py
TAG_KEYS = {"cwe", "also", "hard", "note", "anchor"}
ANCHOR_KEYS = {"file", "text", "near"}


def load_module(path, name):
    """Import a script that is not in a package (dataclasses need it in sys.modules)."""
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


build = load_module(ROOT / "tools" / "build_flutter_apks.py", "build_flutter_apks")


def truth_tags():
    return json.loads(TRUTH.read_text(encoding="utf-8"))["tags"]


def files_of(folder):
    return sorted(path for path in folder.rglob("*") if path.is_file())


def comment_tags(folder):
    """(tag, file, line) of every [X00] tag written in the files of a sample."""
    found = []
    for path in files_of(folder):
        rel = path.relative_to(folder).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            found += [(tag, rel, number) for tag in TAG.findall(line)]
    return found


def resolve_anchor(folder, anchor):
    """The line an anchor labels: the first line of anchor["file"] that contains
    anchor["text"], searching from the first line that contains anchor["near"] (from line 1
    without near); 0 when there is none."""
    lines = (folder / anchor["file"]).read_text(encoding="utf-8").splitlines()
    start = 0
    if anchor.get("near"):
        start = next((i for i, line in enumerate(lines) if anchor["near"] in line), len(lines))
    return next((i + 1 for i in range(start, len(lines)) if anchor["text"] in lines[i]), 0)


def labelled_lines():
    """tag -> (file, line) for every tag of the ground truth, written or anchored."""
    lines = {tag: (rel, number) for tag, rel, number in comment_tags(VULN)}
    for tag, spec in truth_tags().items():
        if "anchor" in spec:
            lines[tag] = (spec["anchor"]["file"], resolve_anchor(VULN, spec["anchor"]))
    return lines


# ------------------------------------------------------------------ ground truth
def test_tag_letters_are_new_and_read_by_the_evaluation():
    evaluate = load_module(ROOT / "evaluation" / "evaluate.py", "evaluate_for_flutter_tests")
    assert evaluate.TAG.pattern == TAG.pattern
    tags = truth_tags()
    assert {tag[0] for tag in tags} == {"D", "M", "G"}
    assert all(evaluate.TAG.fullmatch("[%s]" % tag) for tag in tags)
    old = json.loads((SAMPLES / "ground_truth.json").read_text(encoding="utf-8"))["tags"]
    assert not {tag[0] for tag in old} & {"D", "M", "G"}


def test_every_tag_is_defined_exactly_once():
    tags = truth_tags()
    written = [tag for tag, _rel, _line in comment_tags(VULN)]
    anchored = [tag for tag, spec in tags.items() if "anchor" in spec]
    assert sorted(set(written) - set(tags)) == []                  # in a file, not in the JSON
    for tag in tags:
        assert written.count(tag) + anchored.count(tag) == 1, tag


def test_anchors_resolve_to_one_line():
    for tag, spec in truth_tags().items():
        anchor = spec.get("anchor")
        if anchor is None:
            continue
        assert set(anchor) <= ANCHOR_KEYS and anchor["file"] and anchor["text"], tag
        assert "\\" not in anchor["file"] and not anchor["file"].startswith("/"), tag
        path = VULN / anchor["file"]
        assert path.is_file(), tag
        lines = path.read_text(encoding="utf-8").splitlines()
        if anchor.get("near"):           # the place to start from is unambiguous
            assert sum(anchor["near"] in line for line in lines) == 1, tag
        else:                            # without a starting place the text itself is unique
            assert sum(anchor["text"] in line for line in lines) == 1, tag
        number = resolve_anchor(VULN, anchor)
        assert number > 0 and anchor["text"] in lines[number - 1], tag
        assert not TAG.search(lines[number - 1]), tag


def test_tags_label_distinct_lines():
    lines = labelled_lines()
    assert len(set(lines.values())) == len(lines)


def test_neighbouring_tags_cannot_take_each_others_findings():
    # the evaluation accepts a finding up to one line away from a tag: two tags that close
    # must not share a CWE, and a safe decoy line needs a free line on both sides
    tags = truth_tags()
    lines = sorted((rel, number, tag) for tag, (rel, number) in labelled_lines().items())
    for (rel_a, line_a, a), (rel_b, line_b, b) in zip(lines, lines[1:]):
        if rel_a != rel_b or line_b - line_a > 1:
            continue
        cwes = [set(tags[t]["cwe"]) | set(tags[t].get("also", [])) for t in (a, b)]
        assert tags[a]["cwe"] and tags[b]["cwe"] and not cwes[0] & cwes[1], (a, b)


def test_tag_fields_and_canonical_cwe_ids():
    for tag, spec in truth_tags().items():
        assert set(spec) <= TAG_KEYS and set(spec) >= {"cwe", "note"}, tag
        assert isinstance(spec["note"], str) and spec["note"].strip(), tag
        assert isinstance(spec.get("hard", False), bool), tag
        for key in ("cwe", "also"):
            ids = spec.get(key, [])
            assert isinstance(ids, list) and len(ids) == len(set(ids)), tag
            for cwe in ids:
                assert re.fullmatch(r"CWE-[1-9]\d*", cwe) and canonical(cwe) == cwe, (tag, cwe)
        assert not set(spec.get("also", [])) & set(spec["cwe"]), tag
        if spec.get("hard"):
            assert spec["cwe"], tag


def test_dependency_tags_are_on_package_lines_of_the_lock():
    lock = (VULN / "pubspec.lock").read_text(encoding="utf-8").splitlines()
    tagged = [(tag, number) for tag, rel, number in comment_tags(VULN) if rel == "pubspec.lock"]
    assert sorted(tag for tag, _number in tagged) == sorted(t for t in truth_tags() if t[0] == "G")
    packages = yaml.safe_load("\n".join(lock))["packages"]
    for tag, number in tagged:
        match = re.fullmatch(r"  ([a-z0-9_]+): # \[G\d\d\]", lock[number - 1])
        assert match and match.group(1) in packages, tag


@pytest.mark.parametrize("app", [VULN, SAFE], ids=["vulnerable", "safe"])
def test_lock_lists_every_declared_dependency(app):
    spec = yaml.safe_load((app / "pubspec.yaml").read_text(encoding="utf-8"))
    packages = yaml.safe_load((app / "pubspec.lock").read_text(encoding="utf-8"))["packages"]
    kinds = {"dependencies": "direct main", "dev_dependencies": "direct dev",
             "dependency_overrides": "direct overridden"}
    for section, kind in kinds.items():
        for name in spec.get(section) or {}:
            assert packages[name]["dependency"] == kind, (section, name)


# ------------------------------------------------------------------ sample files
def test_safe_app_and_probe_have_no_tags():
    assert comment_tags(SAFE) == []
    assert comment_tags(PROBE) == []


@pytest.mark.parametrize("folder", [VULN, SAFE, PROBE], ids=["vulnerable", "safe", "probe"])
def test_sample_files_are_utf8_text(folder):
    files = files_of(folder)
    assert files
    for path in files:
        data = path.read_bytes()
        assert b"\x00" not in data, path
        data.decode("utf-8")


@pytest.mark.parametrize("folder", [VULN, SAFE, PROBE], ids=["vulnerable", "safe", "probe"])
def test_configuration_files_parse(folder):
    for path in files_of(folder):
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".xml":
            ElementTree.fromstring(text.encode("utf-8"))
        elif path.suffix == ".plist":
            assert isinstance(plistlib.loads(text.encode("utf-8")), dict)
        elif path.suffix in (".yaml", ".yml", ".lock"):
            assert isinstance(yaml.safe_load(text), dict), path


def test_both_apps_have_the_same_layout():
    for rel in ("pubspec.yaml", "pubspec.lock", "firestore.rules", "web/index.html",
                ".github/workflows/release.yml", "ios/Runner/Info.plist",
                "android/app/build.gradle.kts", "android/app/src/main/AndroidManifest.xml",
                "android/app/src/main/res/xml/network_security_config.xml",
                "android/app/src/main/res/xml/file_paths.xml", "lib/main.dart"):
        assert (VULN / rel).is_file() and (SAFE / rel).is_file(), rel
    dart = [{p.relative_to(app).as_posix() for p in (app / "lib").rglob("*.dart")}
            for app in (VULN, SAFE)]
    assert dart[0] == dart[1]
    assert not (SAFE / "android" / "key.properties").exists()
    assert not (SAFE / "assets" / ".env").exists()


def test_bundled_env_files_are_present():
    # the repository's .gitignore ignores ".env" files, so a checkout only has these two
    # sample assets when .gitignore lets samples/**/.env through
    for app in (VULN, PROBE):
        assert (app / "assets" / ".env").is_file(), "%s/assets/.env is missing" % app.name


def test_no_sample_folder_is_ignored_by_git():
    ignored = {line.strip().rstrip("/") for line in
               (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
               if line.strip().endswith("/") and not line.startswith(("#", "!"))}
    for folder in (VULN, SAFE, PROBE):
        names = {path.name for path in folder.rglob("*") if path.is_dir()}
        assert not names & ignored, (folder.name, names & ignored)


# ------------------------------------------------------------------ probe app and build tool
PROBE_FILES = {
    "README.md", "pubspec.yaml", "lib/main.dart", "assets/.env",
    "android/app/build.gradle.kts", "android/app/src/main/AndroidManifest.xml",
    "android/app/src/main/res/xml/network_security_config.xml",
    "android/app/src/main/res/xml/file_paths.xml",
    "android/app/src/main/kotlin/com/example/flutter_apk_probe/ProbeReceiver.kt",
}


def test_probe_ships_only_its_own_files():
    assert {p.relative_to(PROBE).as_posix() for p in files_of(PROBE)} == PROBE_FILES
    package = "%s.%s" % (build.ORG, build.PROJECT_NAME)
    gradle = (PROBE / "android" / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    assert 'namespace = "%s"' % package in gradle and 'applicationId = "%s"' % package in gradle
    assert 'signingConfig = signingConfigs.getByName("debug")' in gradle
    spec = yaml.safe_load((PROBE / "pubspec.yaml").read_text(encoding="utf-8"))
    assert spec["name"] == build.PROJECT_NAME and not spec.get("dev_dependencies")
    assert spec["dependencies"] == {"flutter": {"sdk": "flutter"}}
    source = (PROBE / "lib" / "main.dart").read_text(encoding="utf-8")
    imports = re.findall(r"^import '([^']+)';", source, re.MULTILINE)
    assert imports and all(i.startswith(("dart:", "package:flutter/")) for i in imports)


def test_build_modes_and_arguments(tmp_path):
    assert [m.name for m in build.parse_modes(" debug, aab,debug ")] == ["debug", "aab"]
    with pytest.raises(ValueError):
        build.parse_modes("debug,fast")
    assert len({mode.target for mode in build.MODES.values()}) == len(build.MODES)
    symbols = tmp_path / "symbols"
    for mode in build.MODES.values():
        arguments = build.build_arguments(mode, ["android-arm64"], symbols)
        assert arguments[:2] == ["build", "appbundle" if mode.name == "aab" else "apk"]
        assert "--no-pub" in arguments and "android-arm64" in arguments
        obfuscated = "--obfuscate" in arguments
        assert obfuscated == (mode.name == "obfuscated")
        assert ("--split-debug-info=%s" % symbols in arguments) == obfuscated
    assert "--release" in build.MODES["aab"].arguments
    assert build.MODES["profile"].engine == "profile"


def test_dry_run_prints_the_commands_and_writes_nothing(tmp_path, capsys):
    out = tmp_path / "out"
    flutter = tmp_path / "sdk" / "bin" / "flutter"
    flutter.parent.mkdir(parents=True)
    flutter.write_text("", encoding="utf-8")
    assert build.main(["--out", str(out), "--work", str(tmp_path / "work"), "--dry-run",
                       "--modes", "debug,obfuscated,aab", "--flutter", str(flutter)]) == 0
    printed = capsys.readouterr().out
    assert not out.exists() and not (tmp_path / "work").exists()
    assert "create --platforms=android --project-name flutter_apk_probe --org com.example" \
        in printed
    assert "pub get --offline" in printed
    assert "build apk --debug" in printed and "build appbundle --release" in printed
    assert "--obfuscate" in printed and "--split-debug-info=" in printed
    assert str(out / "release_obf.apk") in printed and "--stop" in printed

    # the API probe (samples/flutter_api_probe) is built the same way, under its own name
    assert build.main(["--out", str(out), "--work", str(tmp_path / "work"), "--dry-run",
                       "--app", "flutter_api_probe", "--flutter", str(flutter)]) == 0
    printed = capsys.readouterr().out
    assert "--project-name flutter_api_probe" in printed
    assert str(SAMPLES / "flutter_api_probe") in printed and not out.exists()


def test_api_probe_builds_offline_and_holds_no_key_in_one_piece():
    """samples/flutter_api_probe uses only the Flutter SDK, and the keys in formats that
    GitHub's push protection knows are written in parts (the compiler joins them)."""
    api = SAMPLES / "flutter_api_probe"
    spec = yaml.safe_load((api / "pubspec.yaml").read_text(encoding="utf-8"))
    assert spec["name"] == "flutter_api_probe" and spec["dependencies"] == {
        "flutter": {"sdk": "flutter"}}
    assert set(spec["flutter"]["assets"]) == {"assets/.env", "assets/config.json"}
    package = "%s.flutter_api_probe" % build.ORG
    gradle = (api / "android" / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    assert 'applicationId = "%s"' % package in gradle
    whole = re.compile(r"sk_live_\w{10}|AIza[\w-]{35}|hooks\.slack\.com/services/T\w+/B\w+/\w{8}"
                       r"|bot\d{6,}:AA")
    for path in files_of(api):
        assert not whole.search(path.read_text(encoding="utf-8")), path
    source = (api / "lib" / "main.dart").read_text(encoding="utf-8")
    assert "'sk_' 'live_'" in source and "'AIza' 'Sy" in source


def test_build_tool_never_writes_into_the_repository(tmp_path):
    for option in ("--out", "--work"):
        argv = ["--out", str(tmp_path), "--dry-run", option, str(ROOT / "samples" / "apks")]
        with pytest.raises(SystemExit) as stop:
            build.main(argv)
        assert stop.value.code == 2
    assert not (ROOT / "samples" / "apks").exists()


def make_launcher(sdk):
    launcher = sdk / "bin" / ("flutter.bat" if os.name == "nt" else "flutter")
    launcher.parent.mkdir(parents=True)
    launcher.write_text("", encoding="utf-8")
    launcher.chmod(0o755)
    return launcher


def test_find_flutter_order(tmp_path):
    explicit, from_root, on_path = (make_launcher(tmp_path / name)
                                    for name in ("explicit", "root", "path"))
    home = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    environ = dict(home, FLUTTER_ROOT=str(tmp_path / "root"), PATH=str(on_path.parent))
    assert build.find_flutter(str(explicit), environ) == explicit
    assert build.find_flutter(str(tmp_path / "explicit"), environ) == explicit   # SDK folder
    assert build.find_flutter(str(tmp_path / "missing"), environ) is None
    assert build.find_flutter(None, environ) == from_root
    found = build.find_flutter(None, dict(home, PATH=str(on_path.parent)))
    assert found is not None and found.parent == on_path.parent
    assert build.sdk_root(explicit) == (tmp_path / "explicit").resolve()


def test_engine_revision_and_versions(tmp_path):
    cache = tmp_path / "bin" / "cache"
    cache.mkdir(parents=True)
    assert build.engine_revision(tmp_path) == ""
    (cache / "engine.stamp").write_text("0cd610717bde95fd88343c64f81c11ba4e5c0010\n",
                                        encoding="utf-8")
    assert build.engine_revision(tmp_path) == "0cd610717bde95fd88343c64f81c11ba4e5c0010"
    (cache / "engine.stamp").write_text("not a revision", encoding="utf-8")
    assert build.engine_revision(tmp_path) == ""
    (cache / "flutter.version.json").write_text(json.dumps(
        {"flutterVersion": "3.44.8", "dartSdkVersion": "3.12.2", "channel": "stable"}),
        encoding="utf-8")
    assert build.sdk_version(tmp_path) == {"flutterVersion": "3.44.8", "dartSdkVersion": "3.12.2"}


def test_missing_engine_libraries(tmp_path):
    revision = "0cd610717bde95fd88343c64f81c11ba4e5c0010"
    cache = tmp_path / "caches" / "modules-2" / "files-2.1" / "io.flutter"
    for name in ("flutter_embedding_release", "arm64_v8a_release", "flutter_embedding_debug"):
        (cache / name / ("1.0.0-" + revision)).mkdir(parents=True)
    release, profile, debug = (build.MODES[name] for name in ("release", "profile", "debug"))
    assert build.missing_engine_libraries(release, ["android-arm64"], revision, tmp_path) == []
    assert build.missing_engine_libraries(profile, ["android-arm64"], revision, tmp_path) == [
        "io.flutter:flutter_embedding_profile:1.0.0-" + revision,
        "io.flutter:arm64_v8a_profile:1.0.0-" + revision]
    assert build.missing_engine_libraries(debug, ["android-arm64"], revision, tmp_path) == [
        "io.flutter:arm64_v8a_debug:1.0.0-" + revision]
    assert len(build.missing_engine_libraries(release, ["android-arm64"], "", tmp_path)) == 1


def test_missing_build_tools(tmp_path):
    android = tmp_path / "project" / "android"
    (android / "gradle" / "wrapper").mkdir(parents=True)
    (android / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.1.0-all.zip\n",
        encoding="utf-8")
    (android / "settings.gradle.kts").write_text(
        'plugins {\n    id("com.android.application") version "9.0.1" apply false\n'
        '    id("org.jetbrains.kotlin.android") version "2.3.20" apply false\n}\n',
        encoding="utf-8")
    gradle = tmp_path / "gradle"
    (gradle / "wrapper" / "dists" / "gradle-9.1.0-all").mkdir(parents=True)
    (gradle / "caches" / "modules-2" / "files-2.1" / "com.android.tools.build" / "gradle"
     / "9.0.1").mkdir(parents=True)
    assert build.missing_build_tools(tmp_path / "project", gradle) == [
        "Gradle plugin org.jetbrains.kotlin.android 2.3.20"]
    assert build.missing_build_tools(tmp_path / "project", tmp_path / "empty") == [
        "Gradle distribution gradle-9.1.0-all",
        "Gradle plugin com.android.application 9.0.1",
        "Gradle plugin org.jetbrains.kotlin.android 2.3.20"]


def test_shipped_files_check(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "main.dart").write_text("void main() {}\n", encoding="utf-8")
    (tmp_path / "pubspec.yaml").write_text("name: probe\n", encoding="utf-8")
    shipped = build.file_hashes(tmp_path)
    assert sorted(shipped) == ["lib/main.dart", "pubspec.yaml"]
    assert build.changed_files(tmp_path, shipped) == []
    (tmp_path / "pubspec.yaml").write_text("name: other\n", encoding="utf-8")
    (tmp_path / "lib" / "main.dart").unlink()
    (tmp_path / "README.md").write_text("added by flutter create\n", encoding="utf-8")
    assert build.changed_files(tmp_path, shipped) == ["lib/main.dart", "pubspec.yaml"]


def test_package_contents(tmp_path):
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as archive:
        for name in ("AndroidManifest.xml", "classes.dex", "classes2.dex",
                     "assets/flutter_assets/kernel_blob.bin", "lib/arm64-v8a/libflutter.so",
                     "META-INF/CERT.RSA", "META-INF/MANIFEST.MF"):
            archive.writestr(name, b"x")
    contents = build.package_contents(path)
    assert contents["kernel_blob"] and contents["libapp_abis"] == []
    assert contents["libflutter_abis"] == ["arm64-v8a"]
    assert contents["dex"] == ["classes.dex", "classes2.dex"]
    assert contents["signature_files"] == ["META-INF/CERT.RSA"] and contents["entries"] == 7


def test_downloads_in_a_build_log(tmp_path):
    log = tmp_path / "build.log"
    log.write_text("[  +3 ms] Downloading android-arm64-profile/windows-x64 tools...\n"
                   "Download https://dl.google.com/dl/android/maven2/a.pom, took 12 ms\n"
                   "Running Gradle task 'assembleRelease'...\n", encoding="utf-8")
    assert len(build.downloads_in(log)) == 2
    assert build.downloads_in(tmp_path / "missing.log") == []


APK_DIR = os.environ.get("SCA_FLUTTER_APK_DIR", "")


@pytest.mark.skipif(not APK_DIR, reason="set SCA_FLUTTER_APK_DIR to a folder of built APKs")
def test_built_packages_show_their_build_mode():
    folder = Path(APK_DIR)
    debug = build.package_contents(folder / "debug.apk")
    assert debug["kernel_blob"] and not debug["libapp_abis"]
    for name in ("release.apk", "release_obf.apk"):
        release = build.package_contents(folder / name)
        assert not release["kernel_blob"] and release["libapp_abis"], name
