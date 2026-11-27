"""Install-set coverage, provenance and exclusions using invented Android packages."""
from zipfile import ZipFile

import pytest

import flutter_kit as kit
from sca import splitinput
from sca.flutter import arsc, axml, zipread
from sca.pipeline import ScanOptions, inspect_mobile, run_scan
from sca.ui import hosted

OPTIONS = ScanOptions(save=False, use_ml=False, use_feedback=False, keep_decoded=True,
                      use_bandit=False, use_semgrep=False, use_gitleaks=False)


def feature(split="feature", package=kit.PACKAGE, version="7", localized=False):
    manifest = f'<manifest xmlns:android="{axml.ANDROID_URI}" package="{package}" split="{split}" android:versionCode="{version}"><application/></manifest>'
    root, error = kit.parse_xml_text(manifest)
    assert not error and root is not None
    assets = {"AndroidManifest.xml": axml.encode_axml(root)}
    if localized:
        assets["resources.arsc"] = arsc.build_arsc(package, [("string", "display", "Bonjour", "fr")])
    else:
        assets["classes.dex"] = kit.dex.build_dex(["FeatureOnlyToken"], [("Ltest/Feature;", None)])
        assets["assets/config.txt"] = b"Selected feature\n"
    return zipread.build_zip([(k, v, 0) for k, v in assets.items()])


def parts():
    return {"base.apk": kit.build_apk(mode="none", assets={"config.txt": "Base configuration\n"}),
            "split_feature.apk": feature(),
            "split_config.fr.apk": feature("config.fr", localized=True)}


def write_parts(folder, members):
    folder.mkdir()
    for name, data in members.items():
        (folder / name).write_bytes(data)
    (folder / "apk-info.txt").write_text("Metadata only", encoding="utf-8")


def verify(result, members):
    assert result.app["kind"] == "apks"
    rows = result.app["apk_members"]
    assert {r["name"] for r in rows} == set(members)
    assert all(r["status"] == "read" for r in rows)
    assert result.app["dex"]["files"] == 2
    owners = result.app["apk_file_members"]
    assert owners["assets/config.txt"] == "base.apk"
    assert owners["splits/split_feature.apk/assets/config.txt"] == "split_feature.apk"
    assert owners["splits/split_feature.apk/classes.dex"] == "split_feature.apk"
    assert owners["splits/split_config.fr.apk/res/values-fr/strings.xml"] == "split_config.fr.apk"
    return {(f.rule_id, f.file, f.line) for f in result.findings}


def test_folder_bundle_zip_and_upload_scan_the_same_members(tmp_path):
    members = parts()
    folder = tmp_path / "Exported app"
    write_parts(folder, members)
    assert splitinput.folder_apks(folder)[0] == folder / "base.apk"
    directory = run_scan(str(folder), OPTIONS)
    expected = verify(directory, members)
    assert directory.target == str(folder)
    ctx, files, _, _ = inspect_mobile(str(folder))
    assert ctx.facts["kind"] == "apks"
    assert any(sf.rel.endswith("values-fr/strings.xml") and "Bonjour" in sf.text for sf in files)
    single = run_scan(str(folder / "base.apk"), OPTIONS)
    assert single.app["kind"] == "apk" and single.app["dex"]["files"] == 1
    split_only = run_scan(str(folder / "split_config.fr.apk"), OPTIONS)
    assert split_only.app["base_missing"] and split_only.app["apk_members"][0]["status"] == "partial"
    assert not any(f.rule_id == "ANDROID-MANIFEST-003" for f in split_only.findings)
    uploads = [(name, memoryview(data)) for name, data in members.items()]
    local = splitinput.store_uploads(uploads, tmp_path / "stored", limit_bytes=1 << 20)
    assert splitinput.store_uploads(list(reversed(uploads)), local.parent, limit_bytes=1 << 20) == local
    assert verify(run_scan(str(local), OPTIONS), members) == expected
    package_zip = tmp_path / "export.zip"
    package_zip.write_bytes(local.read_bytes())
    assert verify(run_scan(str(package_zip), OPTIONS), members) == expected
    remote = hosted.scan_uploads(uploads, OPTIONS, lambda *_: None)
    assert verify(remote, members) == expected
    assert remote.scan_id is None


def test_exclusions_are_named_and_do_not_contribute_virtual_files(tmp_path):
    members = parts()
    members.update({"unrelated.apk": feature("other", "com.example.other"),
                    "split_wrongversion.apk": feature("old", version="94"),
                    "split_extra.apk": kit.build_apk(mode="none"),
                    "split_broken.apk": b"Broken archive."})
    folder = tmp_path / "export"
    write_parts(folder, members)
    scan = run_scan(str(folder), OPTIONS)
    excluded = {m["name"]: m["reason"] for m in scan.app["apk_members"] if m["status"] == "skipped"}
    assert excluded == {"unrelated.apk": "APK package does not match the base",
                        "split_wrongversion.apk": "APK version does not match the base",
                        "split_extra.apk": "APK has no declared split ID",
                        "split_broken.apk": "Unreadable APK archive"}
    assert not set(excluded).intersection(scan.app["apk_file_members"].values())


def test_source_zip_with_packaged_build_artifacts_keeps_source_route(tmp_path):
    archive = tmp_path / "source.zip"
    with ZipFile(archive, "w") as z:
        z.writestr("sample/src/Example.kt", "fun main() = println(42)")
        z.writestr("sample/build/base.apk", kit.build_apk(mode="none"))
    assert not splitinput.is_packaged_zip(archive)
    result = run_scan(str(archive), OPTIONS)
    assert not result.app and result.languages.get("kotlin") == 1


def test_incomplete_selection_and_ambiguous_or_unsafe_paths(tmp_path):
    folder = tmp_path / "group"
    write_parts(folder, {"a.apk": b"one", "b.apk": b"two"})
    with pytest.raises(splitinput.SplitInputError, match="base APK"):
        run_scan(str(folder), OPTIONS)
    for names in [("split_a.apk", "split_b.apk"), ("base.apk", "../other.apk"),
                  ("base.apk", "BASE.apk")]:
        with pytest.raises(splitinput.SplitInputError):
            splitinput.store_uploads([(n, memoryview(b"data")) for n in names],
                                     tmp_path / "stored", limit_bytes=16)
    with pytest.raises(splitinput.SplitInputError, match="combined size"):
        splitinput.store_uploads([(n, memoryview(b"data")) for n in ("base.apk", "split_a.apk")],
                                 tmp_path / "stored", limit_bytes=7)
    assert not (tmp_path / "stored").exists()
