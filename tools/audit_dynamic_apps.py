"""Measure real Android startup observations against the previous static APK audit.

This tool never treats a static candidate as a runtime observation. It installs only
when --install is supplied, selects an explicit ADB serial, and does not log in,
grant permissions, clear app data, or exercise remote API endpoints itself.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import gc
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z")


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def input_inventory(inputs: Path, static_dir: Path) -> dict:
    apps = []
    for folder in sorted(inputs.iterdir()):
        if not folder.is_dir():
            continue
        apks = sorted(folder.glob("*.apk"), key=lambda p: (p.name != "base.apk", p.name))
        if not apks:
            continue
        report = json.loads((static_dir / (folder.name + ".report.json")).read_text(encoding="utf-8"))
        summary = json.loads((static_dir / (folder.name + ".summary.json")).read_text(encoding="utf-8"))
        facts = report.get("app", {})
        members, abi_names = [], set()
        for apk in apks:
            with zipfile.ZipFile(apk) as archive:
                names = archive.namelist()
                abis = sorted({name.split("/")[1] for name in names
                               if name.startswith("lib/") and name.count("/") >= 2})
            abi_names.update(abis)
            members.append({"name": apk.name, "path": str(apk.resolve()), "bytes": apk.stat().st_size,
                            "sha256": digest(apk), "abis": abis})
        apps.append({"app": folder.name, "folder": str(folder.resolve()),
                     "package": facts.get("package"), "version_name": facts.get("version_name"),
                     "version_code": facts.get("version_code"), "min_sdk": facts.get("min_sdk"),
                     "target_sdk": facts.get("target_sdk"), "flutter": bool(facts.get("flutter")),
                     "abis": sorted(abi_names), "apks": members,
                     "launchers": [item["name"] for item in facts.get("components", [])
                                   if item.get("launcher")],
                     "static_scan_id": summary.get("scan_id"),
                     "static_report": str((static_dir / (folder.name + ".report.json")).resolve())})
    return {"schema_version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
            "method": "Previous decoded manifest facts; current APK ZIP entries and SHA-256 digests.",
            "apps": apps}


def adb_call(adb: str, serial: str, *arguments: str, timeout: int = 30) -> dict:
    try:
        result = subprocess.run([adb, "-s", serial, *arguments], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        return {"returncode": result.returncode, "output": (result.stdout + result.stderr).strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": None, "output": str(exc)}


def inspect_device(adb: str, serial: str) -> dict:
    state = adb_call(adb, serial, "get-state")
    result = {"serial": serial, "state": state, "properties": {}}
    if state["returncode"] == 0 and state["output"] == "device":
        for name in ("ro.product.cpu.abilist", "ro.build.version.sdk", "ro.build.fingerprint",
                     "ro.kernel.qemu", "ro.dalvik.vm.native.bridge"):
            value = adb_call(adb, serial, "shell", "getprop", name)
            result["properties"][name] = value["output"] if value["returncode"] == 0 else "unavailable"
    return result


def url_key(value: str) -> str:
    try:
        parsed = urlsplit(value)
        # User-info and query values can be case-sensitive. HTML decoding can also
        # change a literal URL, so only the scheme and host spelling are normalized.
        userinfo, separator, hostport = parsed.netloc.rpartition("@")
        authority = userinfo + separator + hostport.lower() if separator else parsed.netloc.lower()
        return urlunsplit((parsed.scheme.lower(), authority, parsed.path,
                           parsed.query, parsed.fragment))
    except ValueError:
        return value


def compare_observations(capture: dict, static_report: dict) -> dict:
    inventory = static_report.get("app", {}).get("apis", {})
    addresses = {url_key(item["url"]) for item in inventory.get("endpoints", []) if item.get("url")}
    hosts = {str(item.get("host", "")).lower() for item in inventory.get("endpoints", [])}
    values = {str(item.get("value", "")) for item in inventory.get("keys", [])}
    output = []
    for item in capture.get("observations", []):
        kind, value = item.get("kind"), str(item.get("value", ""))
        present = (url_key(value) in addresses if kind == "url" else value.lower() in hosts
                   if kind == "host" else value in values if kind in ("credential", "crypto_key") else None)
        output.append({"observation_id": item.get("id"), "kind": kind,
                       "static_inventory_exact_match": present,
                       "comparison": "not_compared" if present is None else "also_in_static_inventory"
                       if present else "not_found_in_static_inventory",
                       "verified_source_locations": sum(bool(loc.get("verified"))
                                                        for loc in item.get("locations", [])),
                       "has_runtime_event_location": bool(item.get("evidence", {}).get("file"))})
    return {"method": "Exact full value comparison, with only URL scheme/host case normalized.",
            "interpretation": "Absent from a static inventory does not prove runtime generation; it may be encoded, omitted, or outside static coverage.",
            "observations": output,
            "counts": dict(Counter(item["comparison"] for item in output))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=Path.home() / "Desktop" / "Phone_APKs_2026-11-26")
    parser.add_argument("--static-dir", type=Path, default=REPO / "data/audits/2026-11-26-phone-apps/deep")
    parser.add_argument("--output", type=Path, default=REPO / "data/audits/2026-11-27-dynamic")
    parser.add_argument("--database", type=Path, default=REPO / "data/sca.db")
    parser.add_argument("--serial")
    parser.add_argument("--adb", default=shutil.which("adb"))
    parser.add_argument("--frida-host", default="127.0.0.1:27042")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--install", action="store_true", help="install the exact supplied APK members on the selected device")
    parser.add_argument("--save", action="store_true", help="link captures to static scans in the platform archive")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--java-only", action="store_true", help="disable the observer's native DNS/socket/TLS hooks for a labeled compatibility capture")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    inventory = input_inventory(args.inputs, args.static_dir)
    write_json(args.output / "input_inventory.json", inventory)
    print(json.dumps({"apps": len(inventory["apps"]), "apks": sum(len(a["apks"]) for a in inventory["apps"])}), flush=True)
    if args.inventory_only:
        return 0
    if not args.serial or not args.adb:
        parser.error("--serial and an available ADB executable are required for real captures")
    if not 5 <= args.duration <= 300:
        parser.error("--duration must be between 5 and 300 seconds")
    from sca.dynamic import CaptureOptions, run_capture
    from sca.dynamic.capture import AGENT
    from sca.dynamic.environment import install_target
    from sca.storage import Storage
    store = Storage(str(args.database))
    device = inspect_device(args.adb, args.serial)
    write_json(args.output / "device.json", device)
    summaries = []
    for app in inventory["apps"]:
        if args.only and app["app"] not in args.only:
            continue
        folder = args.output / app["app"]
        summary_path = folder / "summary.json"
        run_identity = {"apk_sha256": [item["sha256"] for item in app["apks"]],
                        "observer_sha256": digest(AGENT),
                        "capture_engine_sha256": digest(Path(REPO / "sca/dynamic/capture.py")),
                        "native_hooks": not args.java_only,
                        "static_scan_id": app.get("static_scan_id"), "serial": args.serial,
                        "frida_host": args.frida_host, "duration_seconds": args.duration,
                        "device_fingerprint": device["properties"].get("ro.build.fingerprint")}
        if args.resume and summary_path.exists():
            prior = json.loads(summary_path.read_text(encoding="utf-8"))
            if (prior.get("status") == "completed" and prior.get("run_identity") == run_identity
                    and (not args.save or prior.get("capture_id"))):
                summaries.append(prior)
                continue
        package = str(app.get("package") or "")
        record = {"app": app["app"], "package": package, "static_scan_id": app.get("static_scan_id"),
                  "serial": args.serial, "duration_requested": args.duration,
                  "run_identity": run_identity,
                  "interaction_profile": "startup only; no login, permissions or automated remote actions",
                  "status": "not_started", "observations": 0, "events": 0}
        print(json.dumps({"app": app["app"], "event": "started"}), flush=True)
        capture_started = False
        try:
            if not PACKAGE.fullmatch(package):
                raise ValueError("The saved manifest has no valid Android package identifier")
            if device["state"]["returncode"] != 0 or device["state"]["output"] != "device":
                record["status"] = "device_unavailable"
                record["device_error"] = device["state"]
            else:
                if args.install:
                    installed = install_target(app["folder"], serial=args.serial, adb_path=args.adb)
                    record["install"] = installed
                    if not installed.get("success"):
                        record["status"] = "install_failed"
                if record["status"] == "not_started":
                    static_scan = store.load_scan(app["static_scan_id"]) if app.get("static_scan_id") else None
                    options = CaptureOptions(package=package, serial=args.serial,
                                             duration_seconds=args.duration, spawn=True,
                                             frida_host=args.frida_host, adb_path=args.adb,
                                             native_hooks=not args.java_only)
                    capture_started = True
                    capture = run_capture(options, folder,
                                          decoded_files=static_scan.decoded_files if static_scan else None)
                    write_json(folder / "capture.json", capture)
                    static_report = json.loads(Path(app["static_report"]).read_text(encoding="utf-8"))
                    comparison = compare_observations(capture, static_report)
                    write_json(folder / "comparison.json", comparison)
                    record.update(status=capture.get("status", "failed"), session_id=capture.get("session_id"),
                                  observations=len(capture.get("observations", [])), events=len(capture.get("events", [])),
                                  kinds=dict(Counter(item.get("kind") for item in capture.get("observations", []))),
                                  comparison_counts=comparison["counts"], capabilities=capture.get("capabilities", {}),
                                  errors=capture.get("errors", []), limitations=capture.get("limitations", []))
                    if args.save:
                        record["capture_id"] = store.save_dynamic_session(app["static_scan_id"], capture)
                    del static_scan, static_report, capture, comparison
        except Exception as exc:
            record.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        finally:
            if capture_started:
                # Stop only the tested package so it cannot contaminate the next startup window.
                record["stop"] = adb_call(args.adb, args.serial, "shell", "am", "force-stop", package)
        write_json(summary_path, record)
        summaries.append(record)
        write_json(args.output / "summary.json", summaries)
        print(json.dumps({key: record.get(key) for key in ("app", "status", "observations", "events", "capture_id")}), flush=True)
        gc.collect()
    write_json(args.output / "summary.json", summaries)
    return int(any(item["status"] not in ("completed", "partial") for item in summaries))


if __name__ == "__main__":
    raise SystemExit(main())
