"""Recognize Android install sets and stage user-selected APKs without installing them."""
from __future__ import annotations

import hashlib
import io
import os
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Iterator, Sequence

from . import sourcearchive
from .flutter.zipread import MAX_INNER_APKS

BASE_NAMES = ("base.apk", "base-master.apk", "universal.apk")
MAX_SET_BYTES = 512 << 20
Upload = tuple[str, memoryview]


class SplitInputError(sourcearchive.ArchiveError):
    """The selected APKs cannot form a bounded install set."""


def _source_name(name: str) -> bool:
    path = PurePosixPath(name.lower())
    return (path.name in ("pubspec.yaml", "androidmanifest.xml", "package.json", "pyproject.toml")
            or path.suffix in (".java", ".kt", ".kts", ".dart", ".gradle", ".py", ".js", ".ts",
                               ".go", ".rs", ".cs", ".cpp", ".c", ".php", ".rb"))


def folder_apks(folder: Path) -> list[Path]:
    """Flat APK export folder, with the base first. A software project stays a source scan."""
    if not folder.is_dir():
        return []
    members = []
    with os.scandir(folder) as entries:
        for index, entry in enumerate(entries):
            if index >= sourcearchive.MAX_ENTRIES:
                return []   # large trees use the normal project walker
            if entry.is_dir(follow_symlinks=False):
                if entry.name.lower() in (".git", "src", "android", "ios", "app", "lib", "packages"):
                    return []
                continue
            if _source_name(entry.name):
                return []
            if entry.name.lower().endswith(".apk"):
                members.append(Path(entry.path))
    if not members:
        return []
    if len(members) > MAX_INNER_APKS:
        raise SplitInputError("Too many APKs in the selected set.")
    if len(members) > 1 and not any(p.name.lower() in BASE_NAMES for p in members):
        raise SplitInputError("Select a directory with a base APK and its splits, or choose one APK.")
    return sorted(members, key=lambda p: (p.name.lower() not in BASE_NAMES, p.name.casefold()))


def is_packaged_zip(path: Path) -> bool:
    """Use archive structure, not the .zip suffix: a source tree can include build artifacts."""
    try:
        with sourcearchive._BoundedReader(io.FileIO(path, "r")) as stream, zipfile.ZipFile(stream) as z:
            infos = z.infolist()
            if len(infos) > sourcearchive.MAX_ENTRIES:
                return False
            names = {i.filename for i in infos if not i.is_dir()}
            if ("AndroidManifest.xml" in names and
                    ("classes.dex" in names or "resources.arsc" in names)):
                return True
            if "BundleConfig.pb" in names and "base/manifest/AndroidManifest.xml" in names:
                return True
            apks = [PurePosixPath(n) for n in names if n.lower().endswith(".apk")]
            if not apks or any(_source_name(n) for n in names if not n.lower().endswith(".apk")):
                return False
            return (len(apks) == 1 or any(p.name.lower() in BASE_NAMES for p in apks)
                    or "manifest.json" in names or "toc.pb" in names)
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def _upload_members(uploads: Sequence[Upload], limit_bytes: int) -> list[Upload]:
    if not 1 < len(uploads) <= MAX_INNER_APKS:
        raise SplitInputError("Select the base APK and its split APKs together.")
    seen = set()
    total = 0
    for name, data in uploads:
        try:
            parts = sourcearchive._member_parts(zipfile.ZipInfo(name))
        except (sourcearchive.ArchiveError, IndexError, ValueError) as exc:
            raise SplitInputError("Select distinct APK filenames from the same app.") from exc
        if len(parts) != 1 or not name.lower().endswith(".apk") or name.casefold() in seen:
            raise SplitInputError("Select distinct APK filenames from the same app.")
        seen.add(name.casefold())
        if not data:
            raise SplitInputError("One of the selected APKs is empty.")
        total += len(data)
        if total > limit_bytes:
            raise SplitInputError("The selected APKs exceed the combined size limit.")
    if not seen.intersection(BASE_NAMES):
        raise SplitInputError("Select the base APK and its split APKs together.")
    return sorted(uploads, key=lambda f: (f[0].lower() not in BASE_NAMES, f[0].casefold()))


def store_uploads(uploads: Sequence[Upload], folder: Path, *, limit_bytes: int) -> Path:
    """Atomically publish an exact stored APK set under a stable local path for rescanning."""
    members = _upload_members(uploads, limit_bytes)
    folder.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with tempfile.NamedTemporaryFile(dir=folder, suffix=".part", delete=False) as stage:
        temporary = Path(stage.name)
    try:
        with zipfile.ZipFile(temporary, "w") as archive:
            for name, data in members:
                digest.update(name.encode("utf-8") + b"\0" + len(data).to_bytes(8, "big"))
                digest.update(data)
                archive.writestr(zipfile.ZipInfo(name), data)
        path = folder / (digest.hexdigest() + "-set.apks")
        os.replace(temporary, path)
        return path
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def scan_root(target: Path, work_dir: Path | None = None) -> Iterator[Path]:
    """Yield a scanner input without reading sibling files for a single APK selection."""
    if target.is_file() and target.suffix.lower() == ".zip" and is_packaged_zip(target):
        yield target
        return
    members = folder_apks(target) if target.is_dir() else []
    if not members:
        with sourcearchive.source_root(target, work_dir) as root:
            yield root
        return
    total = 0
    for member in members:
        info = member.lstat()
        if (not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise SplitInputError("An APK set cannot contain links or special files.")
        total += info.st_size
        if total > MAX_SET_BYTES:
            raise SplitInputError("The selected APKs exceed the combined size limit.")
    if len(members) == 1:
        yield members[0]
        return
    with tempfile.TemporaryDirectory(prefix="sca-apks-", dir=work_dir) as folder:
        packaged = Path(folder) / "selected.apks"
        with zipfile.ZipFile(packaged, "w") as archive:
            copied = 0
            for member in members:
                expected = member.lstat()
                with member.open("rb") as src:
                    opened = os.fstat(src.fileno())
                    if (not stat.S_ISREG(opened.st_mode) or not os.path.samestat(expected, opened)
                            or getattr(expected, "st_file_attributes", 0) &
                            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                        raise SplitInputError("An APK set cannot contain links or special files.")
                    with archive.open(zipfile.ZipInfo(member.name), "w") as out:
                        for block in iter(lambda: src.read(sourcearchive.CHUNK_SIZE), b""):
                            copied += len(block)
                            if copied > MAX_SET_BYTES:
                                raise SplitInputError("The selected APKs exceed the combined size limit.")
                            out.write(block)
        yield packaged
