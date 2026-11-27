"""Optional external tools for app packages: jadx (Java decompiler), apksigner (signature
verification), aapt2, flutter and dart. None of them is needed: the analyzer decodes app
packages itself and only adds what a tool gives when it is installed and asked for.

As in sca/engines/external.py, tools run with argument lists (no shell) and timeouts, their
output is read as UTF-8 with errors replaced, and every run gives a note that starts with
"ok" on success, "not installed (...)" when the tool is missing and "failed: ..." otherwise.
On Windows jadx and apksigner are .bat launchers, and cmd.exe parses their arguments again,
so they only get paths the analyzer made itself, and only when those paths hold no
character that cmd.exe treats specially.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

TOOLS = ("jadx", "apksigner", "aapt2", "flutter", "dart")
# no resources, no progress output, and no comments below warnings (an INFO comment names the
# local input file)
JADX_OPTIONS = ("--no-res", "--quiet", "--comments-level", "warn")
JADX_TIMEOUT = 300
APKSIGNER_TIMEOUT = 120
MAX_JAVA_FILES = 2_000
MARKER = ".sca-jadx.json"          # in a jadx output folder: what it was made from

_WINDOWS = os.name == "nt"
_LAUNCHER_SUFFIXES = (".bat", ".cmd", ".exe") if _WINDOWS else ("",)
# characters a path may hold to be passed through a .bat launcher (letters of any script,
# digits, space and the path separators); cmd.exe expands % and ! and splits at & | < > ^
_BATCH_SAFE = re.compile(r"[\w .\\/:()~-]+\Z")
NOT_INSTALLED = {
    "jadx": "not installed (optional: set SCA_JADX to the jadx launcher)",
    "apksigner": "not installed (optional: Android SDK build-tools)",
}
_HINTS = {
    "jadx": "optional: decompiles the app's own Java and Kotlin classes; install jadx 1.4 or "
            "newer and set SCA_JADX to its launcher (needs Java 11 or newer)",
    "apksigner": "optional: verifies APK signatures; part of the Android SDK build-tools "
                 "(set ANDROID_HOME; needs Java)",
    "aapt2": "optional: Android SDK build-tools; the analyzer does not need it",
    "flutter": "optional: the Flutter SDK (set FLUTTER_ROOT); not needed to analyze apps",
    "dart": "optional: comes with the Flutter SDK",
}


# ------------------------------------------------------------------ finding the tools
def availability() -> Dict[str, Optional[str]]:
    """Path of each tool in TOOLS, or None when it is not installed."""
    build_tools = _build_tools()
    flutter_root = os.environ.get("FLUTTER_ROOT", "")
    flutter_bin = Path(flutter_root) / "bin" if flutter_root else None
    dart_sdk = Path(flutter_root) / "bin" / "cache" / "dart-sdk" / "bin" if flutter_root else None
    return {
        "jadx": _jadx(),
        "apksigner": _launcher(build_tools, "apksigner") or shutil.which("apksigner"),
        "aapt2": _launcher(build_tools, "aapt2") or shutil.which("aapt2"),
        "flutter": _launcher(flutter_bin, "flutter") or shutil.which("flutter"),
        "dart": (_launcher(flutter_bin, "dart") or _launcher(dart_sdk, "dart")
                 or shutil.which("dart")),
    }


def hints() -> Dict[str, str]:
    """A short English note per tool: what it adds and how to install it."""
    return dict(_HINTS)


def _launcher(folder: Optional[Path], name: str) -> Optional[str]:
    """The launcher of a tool in folder (name.bat, name.cmd or name.exe on Windows, name
    elsewhere), or None."""
    if folder is None:
        return None
    for suffix in _LAUNCHER_SUFFIXES:
        path = folder / (name + suffix)
        if path.is_file():
            return str(path)
    return None


def _jadx() -> Optional[str]:
    """jadx from SCA_JADX (the launcher, its bin folder or the jadx folder), JADX_HOME or
    PATH."""
    for variable in ("SCA_JADX", "JADX_HOME"):
        value = os.environ.get(variable, "").strip()
        if not value:
            continue
        path = Path(value).expanduser()
        if path.is_file():
            return str(path)
        found = _launcher(path / "bin", "jadx") or _launcher(path, "jadx")
        if found:
            return found
    return shutil.which("jadx")


def _sdk_roots() -> List[Path]:
    roots = [os.environ.get("ANDROID_HOME", ""), os.environ.get("ANDROID_SDK_ROOT", "")]
    if os.environ.get("LOCALAPPDATA"):
        roots.append(os.path.join(os.environ["LOCALAPPDATA"], "Android", "Sdk"))
    home = Path.home()
    roots += [str(home / "Library" / "Android" / "sdk"), str(home / "Android" / "Sdk")]
    return [Path(root) for root in roots if root]


def _build_tools() -> Optional[Path]:
    """The newest build-tools folder of the first Android SDK found."""
    for root in _sdk_roots():
        folder = root / "build-tools"
        try:
            versions = [item for item in folder.iterdir() if item.is_dir()]
        except OSError:
            continue
        if versions:
            return max(versions, key=lambda item: _version_key(item.name))
    return None


def _version_key(name: str) -> Tuple[List[int], int]:
    """Order of build-tools folders: 36.1.0 > 36.0.0 > 36.0.0-rc1."""
    numbers = [int(part) for part in re.findall(r"\d+", name)]
    return numbers[:3], 0 if "rc" in name.lower() else 1


# ------------------------------------------------------------------ running a tool
def _is_batch(binary: str) -> bool:
    return Path(binary).suffix.lower() in (".bat", ".cmd")


def batch_safe(path: Path) -> bool:
    """True when a path can be passed to a .bat launcher without cmd.exe changing it."""
    return bool(_BATCH_SAFE.match(str(path)))


def _run(command: List[str], timeout: int) -> Tuple[Optional[int], str]:
    """(exit code, stdout and stderr) of a command; (None, reason) when it could not run or
    timed out. A launcher that times out is stopped with every process it started."""
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if _WINDOWS else \
        {"start_new_session": True}
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                   errors="replace", **options)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, str(exc)[:200]
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        process.communicate()
        return None, "timed out after %d s" % timeout
    return process.returncode, (out or "") + (err or "")


def _kill_tree(process: "subprocess.Popen[str]") -> None:
    """Stop a process and its children (a .bat launcher starts java)."""
    try:
        if _WINDOWS:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                           capture_output=True, timeout=30,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    if process.poll() is None:
        process.kill()


def _first_line(text: str, pattern: str = "") -> str:
    for line in text.splitlines():
        line = line.strip()
        if line and (not pattern or re.search(pattern, line)):
            return line[:200]
    return ""


# ------------------------------------------------------------------ apksigner
def apksigner_verify(apk: Path) -> Tuple[Optional[bool], str]:
    """Verify an APK's signature with apksigner: (True, note) when it verifies, (False, note)
    when apksigner rejects it, (None, note) when apksigner is missing or cannot run."""
    binary = availability()["apksigner"]
    if not binary:
        return None, NOT_INSTALLED["apksigner"]
    apk = Path(apk)
    if _is_batch(binary) and not batch_safe(apk):
        return None, "failed: the path of the APK copy holds characters a .bat launcher " \
                     "cannot take"
    code, output = _run([binary, "verify", "--verbose", str(apk)], APKSIGNER_TIMEOUT)
    if code is None:
        return None, "failed: %s" % output
    schemes = re.findall(r"Verified using (v[\d.]+) scheme[^:\n]*: true", output)
    if code == 0:
        return True, "ok (verified: %s)" % (", ".join(schemes) or "yes")
    if "DOES NOT VERIFY" in output or _first_line(output, r"^ERROR"):
        reason = _first_line(output, r"^ERROR") or "DOES NOT VERIFY"
        return False, "ok (does not verify: %s)" % reason
    return None, "failed: %s" % (_first_line(output) or "exit code %d" % code)


# ------------------------------------------------------------------ jadx
def jadx_decompile(apk: Path, out_dir: Path, classes: Sequence[str]) -> Tuple[List[Path], str]:
    """Decompile classes of an app with jadx into out_dir, as out_dir/<package
    path>/<Class>.java (nested classes are in the file of their outer class).

    apk is an APK, a DEX file or a folder of DEX files. An entry of classes is a class name
    ("com.example.app.MainActivity") or a package ending in ".*" (every class under it).
    Pass only paths the analyzer made: jadx works in a new folder next to out_dir, and
    out_dir is replaced. When out_dir already holds the result for the same input and
    classes (a repeated scan of the same app), jadx is not run again. Returns the Java files
    (at most MAX_JAVA_FILES) and a note."""
    binary = availability()["jadx"]
    if not binary:
        return [], NOT_INSTALLED["jadx"]
    apk, out_dir = Path(apk), Path(out_dir)
    inputs = [apk] if apk.is_file() else sorted(apk.glob("*.dex"))
    wanted = sorted({name.strip() for name in classes if name.strip()})
    if not inputs or not wanted:
        return [], "failed: nothing to decompile"
    if _is_batch(binary) and not all(batch_safe(path) for path in inputs + [out_dir]):
        return [], "failed: the work folder path holds characters a .bat launcher cannot take"
    key = _input_key(inputs, wanted)
    reused = _reuse(out_dir, key)
    if reused is not None:
        files, original_note = reused
        return files, original_note + " (from an earlier scan of this app)"
    shutil.rmtree(_long(out_dir), ignore_errors=True)
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="jadx-", dir=str(out_dir.parent)))
    try:
        code, output = _run([binary, *JADX_OPTIONS, "--output-dir-src", str(work)]
                            + [str(path) for path in inputs], JADX_TIMEOUT)
        if code is None:
            return [], "failed: %s" % output
        files, omitted = _keep(_long(work), out_dir, wanted)
    finally:
        shutil.rmtree(_long(work), ignore_errors=True)
    if not files:
        reason = _first_line(output, r"ERROR") or _first_line(output) or "no class decompiled"
        return [], "failed: %s" % reason
    errors = "; jadx reported errors" if code else ""
    limited = "; %d matching Java files omitted by the %d-file limit" % (omitted, MAX_JAVA_FILES) \
        if omitted else ""
    note = "ok (%d files%s%s)" % (len(files), errors, limited)
    try:
        (out_dir / MARKER).write_text(json.dumps({"key": key, "files": [
            path.relative_to(out_dir).as_posix() for path in files], "note": note,
            "omitted_files": omitted, "file_limit": MAX_JAVA_FILES}), encoding="utf-8")
    except OSError:
        pass
    return files, note


def _input_key(inputs: Sequence[Path], wanted: Sequence[str]) -> str:
    """What a jadx output folder was made from: the inputs, the classes and the options."""
    digest = hashlib.sha256(" ".join(JADX_OPTIONS).encode("utf-8") + b"\0")
    for path in inputs:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        digest.update(b"\0")
    digest.update("\n".join(wanted).encode("utf-8"))
    return digest.hexdigest()


def _reuse(out_dir: Path, key: str) -> Optional[Tuple[List[Path], str]]:
    """The files of an earlier run with the same key, or None."""
    try:
        data = json.loads((out_dir / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("key") != key:
        return None
    if data.get("file_limit", MAX_JAVA_FILES) != MAX_JAVA_FILES:
        return None
    files = [out_dir / rel for rel in data.get("files") or [] if isinstance(rel, str)]
    if not files or not all(path.is_file() for path in files):
        return None
    note = data.get("note")
    if not isinstance(note, str) or not note:
        note = "ok (%d files; original decompiler error and limit status unavailable)" % len(files)
    return files, note


def _keep(work: Path, out_dir: Path, wanted: Sequence[str]) -> Tuple[List[Path], int]:
    """Move the Java files of the wanted classes from jadx's output to out_dir."""
    exact = {name for name in wanted if not name.endswith(".*")}
    packages = tuple(name[:-1] for name in wanted if name.endswith(".*"))
    kept: List[Path] = []
    omitted = 0
    for path in sorted(work.rglob("*.java")):
        rel = path.relative_to(work).as_posix()
        name = rel[:-5].replace("/", ".")
        if name not in exact and not name.startswith(packages):
            continue
        if len(kept) >= MAX_JAVA_FILES:
            omitted += 1
            continue
        target = _long(out_dir) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(target))
        kept.append(out_dir / rel)
    return kept, omitted


def _long(path: Path) -> Path:
    """On Windows, the path in its extended form (\\\\?\\C:\\...), which may be longer than 260
    characters: jadx writes such paths for nested classes."""
    if not _WINDOWS or str(path).startswith("\\\\?\\"):
        return path
    return Path("\\\\?\\" + os.path.abspath(str(path)))
