from subprocess import CompletedProcess
import zipfile

import pytest

import importlib

env = importlib.import_module("sca.dynamic.environment")


def test_single_apk_never_installs_siblings(tmp_path):
    base = tmp_path / "base.apk"
    base.write_bytes(b"test-only")
    (tmp_path / "split.apk").write_bytes(b"test-only")
    with env.install_members(base) as files:
        assert files == [base]
    with env.install_members(tmp_path) as files:
        assert files == [base, tmp_path / "split.apk"]


def test_archive_paths_do_not_escape_and_size_is_bounded(tmp_path, monkeypatch):
    archive = tmp_path / "set.apks"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../../escape.apk", b"payload")
        z.writestr("base.apk", b"base")
    with env.install_members(archive) as files:
        assert len(files) == 2
        assert all(p.parent == files[0].parent and p.name.startswith("part-") for p in files)
        assert not (tmp_path / "escape.apk").exists()
    assert not files[0].exists()
    monkeypatch.setattr(env.splitinput, "MAX_SET_BYTES", 2)
    with pytest.raises(ValueError, match="size limit"):
        with env.install_members(archive):
            pass


def test_install_is_explicit_device_and_reports_failure(tmp_path, monkeypatch):
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"test-only")
    calls = []
    monkeypatch.setattr(env, "find_adb", lambda _: "adb")
    def run(adb, args, timeout=15):
        calls.append(args)
        return CompletedProcess(args, 1, "Failure [INSTALL_FAILED_MISSING_SPLIT]", "")
    monkeypatch.setattr(env, "_run", run)
    result = env.install_target(apk, "unit-device")
    assert not result["success"] and "MISSING_SPLIT" in result["errors"][0]
    assert calls == [["-s", "unit-device", "install", "-r", str(apk)]]
    result = env.install_target(apk, "bad;serial")
    assert not result["success"] and len(calls) == 1


@pytest.mark.parametrize("serial,avd", [("physical-device", "SCA_Dynamic_API36"),
                                       ("emulator-5582", "Ard_Production_QA_API35")])
def test_reconnect_does_not_modify_unrelated_devices(monkeypatch, serial, avd):
    calls = []
    monkeypatch.setattr(env, "find_adb", lambda _: "adb")
    def run(adb, args, timeout=15):
        calls.append(args)
        return CompletedProcess(args, 0, avd + "\nOK\n", "")
    monkeypatch.setattr(env, "_run", run)
    result = env.restart_lab_observer(serial)
    assert not result["success"]
    assert all("shell" not in call for call in calls)


def test_reconnect_refuses_mismatched_process_identity(monkeypatch):
    calls = []
    monkeypatch.setattr(env, "find_adb", lambda _: "adb")
    def run(adb, args, timeout=15):
        calls.append(args)
        value = ("SCA_Dynamic_API36\nOK\n" if "emu" in args else
                 "0\n" if "id" in args else "17.28.0\n" if "--version" in args else
                 "123\n" if "pidof" in args else "/data/local/tmp/another-service\0")
        return CompletedProcess(args, 0, value, "")
    monkeypatch.setattr(env, "_run", run)
    result = env.restart_lab_observer("emulator-5590")
    assert not result["success"]
    assert not any("kill" in call or "forward" in call for call in calls)
