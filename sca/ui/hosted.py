"""Upload-only entry point for a remotely hosted dashboard."""
from __future__ import annotations

import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from threading import Lock
from typing import Iterator, Sequence

from ..flutter import APP_SUFFIXES
from ..models import ScanResult
from ..pipeline import ProgressFn, ScanOptions, run_scan
from ..sourcearchive import ArchiveError, MAX_ENTRIES, MAX_EXPANDED_BYTES
from .. import splitinput
from ..walker import detect_language, skip_folder, strip_bidi

UPLOAD_SUFFIXES = (".zip", *APP_SUFFIXES)
MAX_UPLOAD_MIB = 50
UPLOAD_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_SCAN_LOCK = Lock()


class HostedBusy(RuntimeError):
    """The service is already scanning a file."""


class HostedInputError(ValueError):
    """The requested target cannot be scanned in hosted mode."""


@contextmanager
def _workspace() -> Iterator[Path]:
    if not _SCAN_LOCK.acquire(blocking=False):
        raise HostedBusy()
    try:
        with tempfile.TemporaryDirectory(prefix="sca-hosted-") as folder:
            yield Path(folder)
    finally:
        _SCAN_LOCK.release()


def _scan(target: Path, label: str, work: Path, options: ScanOptions,
          progress: ProgressFn) -> ScanResult:
    return run_scan(str(target), replace(
        options, work_dir=work, target_label=label, save=False, use_feedback=False,
        use_llm=False, use_ml=False, use_bandit=False, use_semgrep=False, use_gitleaks=False),
        progress)


def scan_upload(name: str, data: memoryview, options: ScanOptions,
                progress: ProgressFn) -> ScanResult:
    """Scan one uploaded file and remove the input and any work files on exit."""
    original = Path(strip_bidi(name.replace("\\", "/"))).name
    stem, suffix = Path(original).stem, Path(original).suffix.lower()
    if suffix not in UPLOAD_SUFFIXES or not data or len(data) > MAX_UPLOAD_MIB << 20:
        raise HostedInputError("Choose a source ZIP or an Android app package.")
    with _workspace() as work:
        safe_stem = UPLOAD_NAME.sub("_", stem).strip("._")[:60] or "app"
        target = work / ("input-" + safe_stem + suffix)
        target.write_bytes(data)
        result = _scan(target, original, work, options, progress)
        if result.app.get("name") in (target.name, target.stem):
            result.app["name"] = original if suffix != ".zip" else stem
        return result


def scan_uploads(uploads: Sequence[splitinput.Upload], options: ScanOptions,
                 progress: ProgressFn) -> ScanResult:
    """A related APK selection shares one temporary workspace and one scan budget."""
    if len(uploads) == 1:
        return scan_upload(*uploads[0], options, progress)
    with _workspace() as work:
        try:
            target = splitinput.store_uploads(uploads, work, limit_bytes=MAX_EXPANDED_BYTES)
        except ArchiveError as exc:
            raise HostedInputError(str(exc)) from exc
        result = _scan(target, "selected.apks", work, options, progress)
        result.app["name"] = "selected.apks"
        return result


def server_root() -> Path | None:
    """Directory selected by the server operator, mounted read-only in the deployment."""
    configured = os.environ.get("SCA_SCAN_ROOT")
    if configured:
        try:
            root = Path(configured).resolve(strict=True)
            if root.is_dir():
                return root
        except (OSError, RuntimeError):
            pass
    return None


def _safe_stat(path: Path) -> os.stat_result:
    info = path.lstat()
    if (not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise HostedInputError("Server projects cannot contain links or special files.")
    return info


def _validate_tree(target: Path, exclude_dirs: list[str]) -> None:
    def walk_error(error: OSError) -> None:
        raise error

    skip = {name.strip().lower() for name in exclude_dirs}
    entries = size = 0
    for folder, folders, files in os.walk(target, onerror=walk_error):
        base = Path(folder)
        entries += len(folders) + len(files)
        if entries > MAX_ENTRIES:
            raise HostedInputError("The server project exceeds the scan size limits.")
        for name in folders:
            _safe_stat(base / name)
        folders[:] = [name for name in folders if not skip_folder(base / name, skip)]
        for name in files:
            size += _safe_stat(base / name).st_size
            if size > MAX_EXPANDED_BYTES:
                raise HostedInputError("The server project exceeds the scan size limits.")


def scan_path(name: str, options: ScanOptions, progress: ProgressFn) -> ScanResult:
    """Scan a path in the configured server project directory."""
    root = server_root()
    location = Path(name)
    outside = "Choose a path inside the server project directory."
    if root is None or ".." in location.parts or not name.strip():
        raise HostedInputError(outside)
    if location.is_absolute():
        if not location.is_relative_to(root):
            raise HostedInputError(outside)
        location = location.relative_to(root)
    elif location.anchor:
        raise HostedInputError(outside)

    with _workspace() as work:
        target = root
        try:
            for part in location.parts:
                target /= part
                _safe_stat(target)
            if target.is_dir():
                _validate_tree(target, options.exclude_dirs)
            else:
                if target.suffix.lower() not in UPLOAD_SUFFIXES and not detect_language(target):
                    raise HostedInputError("Choose a source file, a source ZIP or an Android package.")
                if target.stat().st_size > MAX_UPLOAD_MIB << 20:
                    raise HostedInputError("The server project exceeds the scan size limits.")
        except OSError as exc:
            raise HostedInputError("The server path cannot be read.") from exc
        return _scan(target, location.as_posix(), work, options, progress)
