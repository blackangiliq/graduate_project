"""Build the probe app of samples/flutter_apk_probe into real APKs and an app bundle.

    python tools/build_flutter_apks.py --out D:/apks
    python tools/build_flutter_apks.py --out D:/apks --modes debug,profile,release,obfuscated,aab
    python tools/build_flutter_apks.py --out D:/apks --dry-run
    python tools/build_flutter_apks.py --out D:/apks_api --app flutter_api_probe --modes release

The probe holds only the files it changes. The tool copies it to a temporary folder outside
the repository, lets `flutter create` add the missing template files (existing files are never
overwritten, and the tool checks that the shipped ones are unchanged), builds every requested
mode and copies the results under fixed names into --out:

    debug       flutter build apk --debug                        debug.apk
    profile     flutter build apk --profile                      profile.apk
    release     flutter build apk --release                      release.apk
    obfuscated  flutter build apk --release --obfuscate          release_obf.apk and
                --split-debug-info=<folder>                      release_obf.<name>.symbols
    aab         flutter build appbundle --release                release.aab

--out also receives builds.json (sizes, SHA-256, build times, what each package contains) and
the build logs. The tool never writes into the repository. By default it builds only from the
local caches: pub resolves offline, and a mode whose Flutter engine libraries, Gradle
distribution or Gradle plugins are not cached is skipped with a message instead of being
downloaded (--allow-downloads lifts this). Flutter is found through --flutter, FLUTTER_ROOT,
PATH or the usual install folders.

The packages are test inputs for the analyzer: never install or run them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "samples" / "flutter_apk_probe"
PROJECT_NAME = "flutter_apk_probe"
# the sample apps that can be built (--app): the probe of the weaknesses, and the probe of
# the API and key inventory (servers, calls, keys and service identifiers)
APPS = ("flutter_apk_probe", "flutter_api_probe")
ORG = "com.example"
DEFAULT_MODES = "debug,release,obfuscated"
DEFAULT_PLATFORM = "android-arm64"
# folders that a build or an IDE may leave in the probe; they are not part of it
COPY_IGNORE = shutil.ignore_patterns("build", ".dart_tool", ".gradle", ".idea", "*.iml")
GLOBAL_FLAGS = ("--suppress-analytics", "--no-version-check")
ABI_OF_PLATFORM = {"android-arm": "armeabi_v7a", "android-arm64": "arm64_v8a",
                   "android-x64": "x86_64"}
DOWNLOAD = re.compile(r"\bDownload(?:ing)?\s+(?:https?://\S+|\S+ tools\b)")
PLUGIN = re.compile(r'id\("(com\.android\.application|org\.jetbrains\.kotlin\.android)"\)'
                    r'\s*version\s*"([^"]+)"')
PLUGIN_MODULE = {"com.android.application": "com.android.tools.build/gradle",
                 "org.jetbrains.kotlin.android": "org.jetbrains.kotlin/kotlin-gradle-plugin"}


@dataclass(frozen=True)
class Mode:
    name: str                  # value of --modes
    arguments: Tuple[str, ...]  # arguments of `flutter build`
    output: str                # what the build writes, under build/app/outputs/
    target: str                # file name in --out
    engine: str                # debug | profile | release: the engine libraries it needs


MODES: Dict[str, Mode] = {mode.name: mode for mode in (
    Mode("debug", ("apk", "--debug"), "flutter-apk/app-debug.apk", "debug.apk", "debug"),
    Mode("profile", ("apk", "--profile"), "flutter-apk/app-profile.apk", "profile.apk",
         "profile"),
    Mode("release", ("apk", "--release"), "flutter-apk/app-release.apk", "release.apk",
         "release"),
    Mode("obfuscated", ("apk", "--release", "--obfuscate"), "flutter-apk/app-release.apk",
         "release_obf.apk", "release"),
    Mode("aab", ("appbundle", "--release"), "bundle/release/app-release.aab", "release.aab",
         "release"),
)}


def parse_modes(text: str) -> List[Mode]:
    """The modes named in a comma list, in that order and without repeats."""
    names: List[str] = []
    for name in (part.strip().lower() for part in text.split(",")):
        if name and name not in names:
            names.append(name)
    unknown = [name for name in names if name not in MODES]
    if unknown or not names:
        raise ValueError("unknown mode %s; choose from %s"
                         % (", ".join(unknown) or "(none)", ", ".join(MODES)))
    return [MODES[name] for name in names]


def find_flutter(explicit: Optional[str] = None,
                 environ: Optional[Mapping[str, str]] = None) -> Optional[Path]:
    """The flutter launcher: --flutter, then FLUTTER_ROOT, then PATH, then the usual
    install folders (C:\\flutter on Windows, ~/flutter, ~/development/flutter)."""
    environ = os.environ if environ is None else environ
    launcher = "flutter.bat" if os.name == "nt" else "flutter"
    if explicit:                 # an explicit choice that does not exist is an error
        path = Path(explicit).expanduser()
        path = path / "bin" / launcher if path.is_dir() else path
        return path if path.is_file() else None
    candidates: List[Path] = []
    if environ.get("FLUTTER_ROOT"):
        candidates.append(Path(environ["FLUTTER_ROOT"]) / "bin" / launcher)
    found = shutil.which("flutter", path=environ.get("PATH", ""))
    if found:
        candidates.append(Path(found))
    home = Path(environ.get("USERPROFILE") or environ.get("HOME") or Path.home())
    candidates += [Path("C:/flutter/bin/flutter.bat"), home / "flutter" / "bin" / launcher,
                   home / "development" / "flutter" / "bin" / launcher]
    return next((path for path in candidates if path.is_file()), None)


def sdk_root(flutter: Path) -> Path:
    """The Flutter SDK folder of a launcher (<sdk>/bin/flutter)."""
    return flutter.resolve().parent.parent


def engine_revision(root: Path) -> str:
    """The engine revision the SDK uses, from its cache stamp; "" when unknown."""
    for stamp in (root / "bin" / "cache" / "engine.stamp",
                  root / "bin" / "internal" / "engine.version"):
        try:
            text = stamp.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if re.fullmatch(r"[0-9a-f]{40}", text):
            return text
    return ""


def sdk_version(root: Path) -> Dict[str, str]:
    """Flutter and Dart versions from bin/cache/flutter.version.json (empty if absent)."""
    try:
        data = json.loads((root / "bin" / "cache" / "flutter.version.json")
                          .read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    keys = ("flutterVersion", "dartSdkVersion", "frameworkRevision", "engineRevision")
    return {key: str(data[key]) for key in keys if key in data}


def gradle_home(environ: Optional[Mapping[str, str]] = None) -> Path:
    environ = os.environ if environ is None else environ
    if environ.get("GRADLE_USER_HOME"):
        return Path(environ["GRADLE_USER_HOME"])
    return Path.home() / ".gradle"


def missing_engine_libraries(mode: Mode, platforms: Sequence[str], revision: str,
                             gradle: Path) -> List[str]:
    """The Flutter engine libraries (Maven artifacts io.flutter:*) that a build of this mode
    would have to download because the Gradle cache does not hold them."""
    if not revision:
        return ["io.flutter engine libraries (the engine revision of the SDK is unknown)"]
    names = ["flutter_embedding_%s" % mode.engine]
    names += ["%s_%s" % (ABI_OF_PLATFORM[platform], mode.engine) for platform in platforms]
    cache = gradle / "caches" / "modules-2" / "files-2.1" / "io.flutter"
    version = "1.0.0-%s" % revision
    return ["io.flutter:%s:%s" % (name, version) for name in names
            if not (cache / name / version).is_dir()]


def missing_build_tools(project: Path, gradle: Path) -> List[str]:
    """The Gradle distribution and Gradle plugins of the generated Android project that are
    not in the local Gradle caches."""
    missing: List[str] = []
    android = project / "android"
    try:
        wrapper = (android / "gradle" / "wrapper" / "gradle-wrapper.properties").read_text(
            encoding="utf-8")
    except OSError:
        wrapper = ""
    url = re.search(r"distributionUrl=.*/(gradle-[^/\s]+)\.zip", wrapper)
    if url and not (gradle / "wrapper" / "dists" / url.group(1)).is_dir():
        missing.append("Gradle distribution %s" % url.group(1))
    try:
        settings = (android / "settings.gradle.kts").read_text(encoding="utf-8")
    except OSError:
        settings = ""
    modules = gradle / "caches" / "modules-2" / "files-2.1"
    for plugin, version in PLUGIN.findall(settings):
        if not (modules / PLUGIN_MODULE[plugin] / version).is_dir():
            missing.append("Gradle plugin %s %s" % (plugin, version))
    return missing


def file_hashes(folder: Path) -> Dict[str, str]:
    """SHA-256 of every file under a folder, by path relative to it."""
    return {path.relative_to(folder).as_posix(): sha256_of(path)
            for path in sorted(folder.rglob("*")) if path.is_file()}


def changed_files(project: Path, shipped: Mapping[str, str]) -> List[str]:
    """The shipped files that are now missing or different in the project copy."""
    changed = []
    for rel, digest in shipped.items():
        path = project / rel
        if not path.is_file() or sha256_of(path) != digest:
            changed.append(rel)
    return changed


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_inside(path: Path, folder: Path) -> bool:
    try:
        path.resolve().relative_to(folder.resolve())
    except ValueError:
        return False
    return True


def flutter_command(flutter: Path, *arguments: str, verbose: bool = False) -> List[str]:
    return [str(flutter), *GLOBAL_FLAGS, *(("--verbose",) if verbose else ()), *arguments]


def build_arguments(mode: Mode, platforms: Sequence[str], symbols: Path) -> List[str]:
    """Arguments of `flutter build` for one mode."""
    arguments = ["build", *mode.arguments, "--target-platform", ",".join(platforms), "--no-pub"]
    if mode.name == "obfuscated":
        arguments.append("--split-debug-info=%s" % symbols)
    return arguments


def package_contents(path: Path) -> Dict[str, object]:
    """What an APK or app bundle holds that shows its build mode: the Dart kernel of debug
    builds, the AOT library of profile and release builds, and the ABIs."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    libapp = sorted({name.split("/")[-2] for name in names if name.endswith("/libapp.so")})
    return {
        "entries": len(names),
        "kernel_blob": any(name.endswith("flutter_assets/kernel_blob.bin") for name in names),
        "libapp_abis": libapp,
        "libflutter_abis": sorted({name.split("/")[-2] for name in names
                                   if name.endswith("/libflutter.so")}),
        "dex": sorted(name for name in names if re.search(r"(^|/)classes\d*\.dex$", name)),
        "signature_files": sorted(name for name in names if name.startswith("META-INF/")
                                  and name.rsplit(".", 1)[-1] in ("RSA", "DSA", "EC")),
    }


def run(command: List[str], cwd: Path, log: Optional[Path], timeout: int) -> Tuple[int, float]:
    """Run a command with its output in the log file (or nowhere); returns (exit code,
    seconds). A command that runs past the timeout is stopped and returns -1."""
    print("  $ %s" % " ".join(command), flush=True)
    started = time.monotonic()
    handle = log.open("wb") if log is not None else None
    try:
        code = subprocess.run(command, cwd=str(cwd), timeout=timeout,
                              stdout=handle or subprocess.DEVNULL,
                              stderr=subprocess.STDOUT if handle else subprocess.DEVNULL
                              ).returncode
    except subprocess.TimeoutExpired:
        code = -1
    finally:
        if handle is not None:
            handle.close()
    return code, round(time.monotonic() - started, 1)


def downloads_in(log: Path) -> List[str]:
    """Lines of a verbose build log that show a download."""
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [line.strip()[:200] for line in text.splitlines() if DOWNLOAD.search(line)]


def remove_tree(folder: Path) -> None:
    shutil.rmtree(folder, ignore_errors=True)
    if folder.exists():
        print("note: could not remove %s completely (a process may still hold files)" % folder)


def plan(flutter: Path, project: Path, modes: Sequence[Mode], platforms: Sequence[str],
         symbols: Path, offline: bool) -> List[Tuple[str, Path, List[str]]]:
    """The commands of a full run, as (step name, working folder, command), in order. The
    project name is the name of the project folder (the sample's name)."""
    steps = [("create", project.parent, flutter_command(
        flutter, "create", "--platforms=android", "--project-name", project.name, "--org", ORG,
        "--no-pub", str(project))),
        ("pub-get", project,
         flutter_command(flutter, "pub", "get", *(("--offline",) if offline else ())))]
    steps += [(mode.name, project, flutter_command(
        flutter, *build_arguments(mode, platforms, symbols), verbose=True)) for mode in modes]
    android = project / "android"
    steps.append(("gradle-stop", android,
                  [str(android / ("gradlew.bat" if os.name == "nt" else "gradlew")), "--stop"]))
    return steps


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, help="folder for the packages (outside the "
                        "repository)")
    parser.add_argument("--modes", default=DEFAULT_MODES, help="comma list of: %s (default %s)"
                        % (", ".join(MODES), DEFAULT_MODES))
    parser.add_argument("--target-platform", default=DEFAULT_PLATFORM,
                        help="comma list of: %s (default %s)"
                        % (", ".join(ABI_OF_PLATFORM), DEFAULT_PLATFORM))
    parser.add_argument("--flutter", help="flutter launcher or SDK folder")
    parser.add_argument("--work", help="folder for the temporary project (default: system temp)")
    parser.add_argument("--keep", action="store_true", help="keep the temporary project")
    parser.add_argument("--allow-downloads", action="store_true",
                        help="let pub and Gradle download what the local caches lack")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per command")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the commands without running anything")
    parser.add_argument("--app", default=PROJECT_NAME, choices=APPS,
                        help="the sample app under samples/ to build (default %s)" % PROJECT_NAME)
    args = parser.parse_args(argv)
    source = ROOT / "samples" / args.app

    try:
        modes = parse_modes(args.modes)
    except ValueError as error:
        parser.error(str(error))
    platforms = [part.strip() for part in args.target_platform.split(",") if part.strip()]
    if not platforms or any(platform not in ABI_OF_PLATFORM for platform in platforms):
        parser.error("--target-platform takes %s" % ", ".join(ABI_OF_PLATFORM))
    out = Path(args.out).expanduser().resolve()
    work_parent = Path(args.work).expanduser().resolve() if args.work else \
        Path(tempfile.gettempdir())
    for name, folder in (("--out", out), ("--work", work_parent)):
        if is_inside(folder, ROOT):
            parser.error("%s must be outside the repository: %s" % (name, folder))

    flutter = find_flutter(args.flutter)
    if flutter is None and not args.dry_run:
        print("Flutter not found: pass --flutter, set FLUTTER_ROOT or put flutter on PATH.")
        return 1
    flutter = flutter or Path("flutter")
    offline = not args.allow_downloads
    if args.dry_run:
        project = work_parent / ("%s-<random>" % args.app) / args.app
        print("copy %s -> %s" % (source, project))
        for step, folder, command in plan(flutter, project, modes, platforms,
                                          project.parent / "symbols", offline):
            print("[%s] (in %s) %s" % (step, folder, " ".join(command)))
        for mode in modes:
            print("copy build/app/outputs/%s -> %s" % (mode.output, out / mode.target))
        return 0

    out.mkdir(parents=True, exist_ok=True)
    (out / "logs").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="%s-" % args.app, dir=str(work_parent)))
    root = sdk_root(flutter)
    report: Dict[str, object] = {"flutter": str(flutter), "sdk": sdk_version(root),
                                 "target_platform": platforms, "offline": offline,
                                 "app": args.app}
    print("Flutter %s at %s" % (sdk_version(root).get("flutterVersion", "?"), root))
    print("Work folder: %s" % work)
    try:
        builds = build_all(flutter, work, out, modes, platforms, offline, args.timeout, report,
                           source)
    finally:
        (out / "builds.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if args.keep:
            print("Kept %s" % work)
        else:
            remove_tree(work)
    built = [name for name, entry in builds.items() if entry.get("status") == "built"]
    print("Built %d of %d modes; details in %s" % (len(built), len(modes), out / "builds.json"))
    return 0 if len(built) == len(modes) else 1


def build_all(flutter: Path, work: Path, out: Path, modes: Sequence[Mode],
              platforms: Sequence[str], offline: bool, timeout: int,
              report: Dict[str, object], source: Path = PROBE) -> Dict[str, Dict[str, object]]:
    """Copy the sample app (the probe by default), complete it with `flutter create`,
    resolve it and build every mode. Returns one entry per mode (also stored in `report`)."""
    builds: Dict[str, Dict[str, object]] = {}
    report["builds"] = builds
    project = work / source.name
    symbols = work / "symbols"
    logs = out / "logs"
    shutil.copytree(source, project, ignore=COPY_IGNORE)
    shipped = file_hashes(project)
    report["shipped_files"] = sorted(shipped)
    steps = {step: (folder, command) for step, folder, command
             in plan(flutter, project, modes, platforms, symbols, offline)}
    code, _ = run(steps["create"][1], steps["create"][0], logs / "create.log", timeout)
    changed = changed_files(project, shipped)
    report["changed_by_create"] = changed
    if code != 0 or changed:
        print("flutter create failed (exit %d) or changed shipped files (%s); see %s"
              % (code, ", ".join(changed) or "none", logs / "create.log"))
        return builds
    print("flutter create kept the %d shipped files unchanged" % len(shipped))
    code, _ = run(steps["pub-get"][1], steps["pub-get"][0], logs / "pub-get.log", timeout)
    if code != 0:
        print("pub get failed; see %s" % (logs / "pub-get.log"))
        return builds
    gradle = gradle_home()
    revision = engine_revision(sdk_root(flutter))
    tools_missing = missing_build_tools(project, gradle) if offline else []
    for mode in modes:
        missing = tools_missing + missing_engine_libraries(mode, platforms, revision, gradle) \
            if offline else []
        folder, command = steps[mode.name]
        builds[mode.name] = entry = {"command": command}
        if missing:
            entry.update(status="skipped: needs downloads", missing=missing)
            print("[%s] skipped, not in the local caches: %s" % (mode.name, "; ".join(missing)))
            continue
        build_mode(mode, command, folder, out, symbols, timeout, entry)
    folder, command = steps["gradle-stop"]
    if Path(command[0]).is_file():
        run(command, folder, None, timeout)
    return builds


def build_mode(mode: Mode, command: List[str], project: Path, out: Path, symbols: Path,
               timeout: int, entry: Dict[str, object]) -> None:
    """Build one mode and copy its package (and symbol files) into `out`."""
    print("[%s] building" % mode.name)
    log = out / "logs" / ("%s.log" % mode.name)
    code, seconds = run(command, project, log, timeout)
    entry.update(seconds=seconds, log=str(log), downloads=downloads_in(log))
    output = project / "build" / "app" / "outputs" / mode.output
    if code != 0 or not output.is_file():
        entry["status"] = "failed (exit %d)" % code
        print("[%s] failed; see %s" % (mode.name, log))
        return
    target = out / mode.target
    shutil.copy2(output, target)
    entry.update(status="built", file=str(target), size=target.stat().st_size,
                 sha256=sha256_of(target), contents=package_contents(target))
    if mode.name == "obfuscated":
        copies = []
        for path in sorted(symbols.glob("*.symbols")):
            copy = out / ("release_obf.%s" % path.name)
            shutil.copy2(path, copy)
            copies.append(str(copy))
        entry["symbols"] = copies
    print("[%s] %s: %d bytes in %.1f s" % (mode.name, target.name, target.stat().st_size, seconds))


if __name__ == "__main__":
    sys.exit(main())
