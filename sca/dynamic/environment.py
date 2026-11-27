"""Explicit-device Android lab discovery and bounded installation of selected APKs."""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile

from .. import splitinput

DEFAULT_FRIDA_HOST = "127.0.0.1:37042"


def find_adb(adb_path=None) -> str | None:
    if adb_path:
        return str(Path(adb_path)) if Path(adb_path).is_file() else shutil.which(str(adb_path))
    roots = [os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME")]
    if os.environ.get("LOCALAPPDATA"):
        roots.append(str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk"))
    for root in roots:
        if root:
            path = Path(root) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
            if path.is_file():
                return str(path)
    return shutil.which("adb")


def _run(adb: str, args: list[str], timeout=15) -> subprocess.CompletedProcess:
    return subprocess.run([adb, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _serial(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", value):
        raise ValueError("Select an explicit connected Android device")
    return value


def environment(adb_path=None, frida_host=DEFAULT_FRIDA_HOST, serial=None) -> dict:
    adb = find_adb(adb_path)
    result = {"adb_path": adb, "devices": [], "available": False,
              "reasons": [], "capabilities": [], "frida_host": frida_host}
    if not adb:
        result["reasons"].append("Android platform-tools (adb) are not installed.")
        return result
    try:
        listed = _run(adb, ["devices", "-l"])
        for line in listed.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            fields = dict(p.split(":", 1) for p in parts[2:] if ":" in p)
            item = {"serial": parts[0], "state": parts[1],
                    "name": fields.get("model", parts[0]),
                    "kind": "emulator" if parts[0].startswith("emulator-") else "device"}
            if parts[0].startswith("emulator-") and parts[1] == "device":
                avd = _run(adb, ["-s", parts[0], "emu", "avd", "name"], timeout=5)
                item["name"] = avd.stdout.splitlines()[0] if avd.stdout else item["name"]
            result["devices"].append(item)
        result["devices"].sort(key=lambda d: not d["name"].startswith("SCA_Dynamic"))
        if not any(d["state"] == "device" for d in result["devices"]):
            result["reasons"].append("No authorized Android device is connected.")
        if serial and not any(d["serial"] == serial and d["state"] == "device" for d in result["devices"]):
            result["reasons"].append("The selected Android device is not connected or authorized.")
        if importlib.util.find_spec("frida") is None:
            result["reasons"].append("Install requirements-dynamic.txt to enable runtime capture.")
        host, port = frida_host.rsplit(":", 1)
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("The Frida endpoint must be loopback")
        try:
            with socket.create_connection((host, int(port)), timeout=1):
                pass
        except OSError:
            result["reasons"].append("The lab Frida server is not connected; start the lab first.")
        result["available"] = not result["reasons"]
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["reasons"].append(str(exc))
    return result


def forward_frida(serial: str, adb_path=None, port=37042) -> str:
    adb = find_adb(adb_path)
    if not adb:
        raise ValueError("Android platform-tools (adb) are not installed")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Invalid local forwarding port")
    process = _run(adb, ["-s", _serial(serial), "forward", f"tcp:{port}", "tcp:27042"])
    if process.returncode:
        raise ValueError(process.stderr or process.stdout)
    return f"127.0.0.1:{port}"


def restart_lab_observer(serial: str, adb_path=None) -> dict:
    """Restart only our existing observer on an identified, dedicated development AVD."""
    result = {"success": False, "errors": [], "serial": serial}
    try:
        serial = _serial(serial)
        adb = find_adb(adb_path)
        if not adb or not serial.startswith("emulator-"):
            raise ValueError("Observer reconnection requires the dedicated SCA_Dynamic emulator")
        avd = _run(adb, ["-s", serial, "emu", "avd", "name"])
        name = avd.stdout.splitlines()[0] if avd.stdout else ""
        if avd.returncode or not re.fullmatch(r"SCA_Dynamic[A-Za-z0-9_]*", name):
            raise ValueError("This device is not the dedicated SCA_Dynamic lab")
        uid = _run(adb, ["-s", serial, "shell", "id", "-u"])
        if uid.returncode or uid.stdout.strip() != "0":
            raise ValueError("Start the lab using tools/start_dynamic_lab.ps1 first")
        server_name = "sca-frida-server-17.28.0"
        remote = "/data/local/tmp/" + server_name
        version = _run(adb, ["-s", serial, "shell", remote, "--version"])
        if version.returncode or version.stdout.strip() != "17.28.0":
            raise ValueError("The pinned lab observer is missing; run tools/start_dynamic_lab.ps1")
        running = _run(adb, ["-s", serial, "shell", "pidof", server_name])
        for pid in running.stdout.split():
            if not pid.isdecimal():
                raise ValueError("Invalid lab observer process identifier")
            command = _run(adb, ["-s", serial, "shell", "cat", f"/proc/{pid}/cmdline"])
            if command.returncode or command.stdout.split("\0")[0] != remote:
                raise ValueError("The observer process identity could not be verified")
            stopped = _run(adb, ["-s", serial, "shell", "kill", pid])
            if stopped.returncode:
                raise ValueError(stopped.stderr or "The lab observer could not stop")
        for _ in range(10):
            if not _run(adb, ["-s", serial, "shell", "pidof", server_name]).stdout.strip():
                break
            time.sleep(0.1)
        started = _run(adb, ["-s", serial, "shell", remote, "-D", "-l", "127.0.0.1:27042"])
        if started.returncode:
            raise ValueError(started.stderr or started.stdout or "The lab observer could not start")
        result.update(success=True, frida_host=forward_frida(serial, adb), name=name)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["errors"].append(str(exc))
    return result


@contextmanager
def install_members(target: str | Path):
    """Do not infer sibling APKs when a single APK was selected."""
    path = Path(target).resolve(strict=True)
    if path.is_dir():
        members = splitinput.folder_apks(path)
        if not members:
            raise ValueError("Select a built APK or an APK set to run Android analysis")
        if sum(p.stat().st_size for p in members) > splitinput.MAX_SET_BYTES:
            raise ValueError("APK set exceeds the installation size limit")
        yield members
    elif path.suffix.lower() == ".apk":
        if path.stat().st_size > splitinput.MAX_SET_BYTES:
            raise ValueError("APK exceeds the installation size limit")
        yield [path]
    elif path.suffix.lower() in {".apks", ".xapk", ".apkm", ".zip"}:
        with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix="sca-install-") as temporary:
            members = [i for i in archive.infolist() if not i.is_dir() and i.filename.lower().endswith(".apk")]
            if not 1 <= len(members) <= splitinput.MAX_INNER_APKS:
                raise ValueError("Archive must contain a bounded APK install set")
            if sum(i.file_size for i in members) > splitinput.MAX_SET_BYTES:
                raise ValueError("APK set exceeds the installation size limit")
            staged, copied = [], 0
            for index, info in enumerate(members):
                # Use generated local names; archive paths are never extraction destinations.
                out = Path(temporary) / f"part-{index:03d}.apk"
                with archive.open(info) as source, out.open("wb") as destination:
                    for block in iter(lambda: source.read(1 << 20), b""):
                        copied += len(block)
                        if copied > splitinput.MAX_SET_BYTES:
                            raise ValueError("APK set exceeds the installation size limit")
                        destination.write(block)
                staged.append(out)
            yield staged
    else:
        raise ValueError("Build source code into an APK before Android runtime capture")


def install_target(target: str | Path, serial: str, adb_path=None) -> dict:
    result = {"success": False, "errors": [], "apks": [], "output": ""}
    try:
        adb = find_adb(adb_path)
        if not adb:
            raise ValueError("Android platform-tools (adb) are not installed")
        serial = _serial(serial)
        with install_members(target) as members:
            result["apks"] = [str(p) for p in members]
            operation = "install" if len(members) == 1 else "install-multiple"
            process = _run(adb, ["-s", serial, operation, "-r", *map(str, members)], timeout=240)
            result["output"] = (process.stdout + process.stderr).strip()
            result["success"] = process.returncode == 0 and "Success" in process.stdout
            if not result["success"]:
                result["errors"].append(result["output"] or "Android installation failed")
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired) as exc:
        result["errors"].append(str(exc))
    return result


def launch_target(package: str, serial: str, adb_path=None) -> dict:
    """Ask Android to launch the package's exported launcher; never interact with its UI."""
    result = {"success": False, "errors": [], "output": "", "activity": None}
    try:
        if not isinstance(package, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package):
            raise ValueError("Invalid Android package identifier")
        serial = _serial(serial)
        adb = find_adb(adb_path)
        if not adb:
            raise ValueError("Android platform-tools (adb) are not installed")
        resolved = _run(adb, ["-s", serial, "shell", "cmd", "package", "resolve-activity", "--brief",
                              "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", package])
        candidates = [line.strip() for line in resolved.stdout.splitlines()
                      if re.fullmatch(re.escape(package) + r"/[A-Za-z0-9_.$]+", line.strip())]
        if resolved.returncode or not candidates:
            raise ValueError("No Android launcher activity was resolved for the selected package")
        result["activity"] = candidates[-1]
        # Single-quote the validated component for Android's shell; '$' in an inner
        # activity name must remain literal rather than become a shell expansion.
        started = _run(adb, ["-s", serial, "shell", "am", "start", "-W", "-S", "-n",
                             "'" + candidates[-1] + "'"], timeout=35)
        result["output"] = (started.stdout + started.stderr).strip()
        result["success"] = started.returncode == 0 and "Error" not in result["output"]
        if not result["success"]:
            result["errors"].append(result["output"] or "Android could not launch the selected package")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result["errors"].append(str(exc))
    return result
