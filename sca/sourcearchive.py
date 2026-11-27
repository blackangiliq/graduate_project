"""Extract a ZIP source project for the lifetime of one static operation."""
from __future__ import annotations

import io
import re
import stat
import tempfile
import unicodedata
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from zlib import error as DeflateError

MAX_ARCHIVE_BYTES = 250 << 20
MAX_DIRECTORY_BYTES = 4 << 20
MAX_ENTRIES = 15_000
MAX_ENTRY_BYTES = 32 << 20
MAX_EXPANDED_BYTES = 128 << 20
MAX_DEPTH = 24
CHUNK_SIZE = 1 << 20
INVALID_NAME = re.compile(r'[<>:"|?*\\\x00-\x1f\x7f]')
DEVICE_NAME = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])", re.I)


class ArchiveError(ValueError):
    """A source ZIP is invalid, unsafe to extract, or too large."""


class _BoundedReader(io.BufferedReader):
    """Limit the central-directory read zipfile makes before it can count the entries."""

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            data = super().read(MAX_DIRECTORY_BYTES + 1)
            if len(data) <= MAX_DIRECTORY_BYTES:
                return data
        elif size <= MAX_DIRECTORY_BYTES:
            return super().read(size)
        raise ArchiveError("The source ZIP directory is too large.")


def _member_parts(entry: zipfile.ZipInfo) -> tuple[str, ...]:
    # orig_filename preserves NULs that ZipInfo.filename otherwise silently truncates.
    name = entry.orig_filename
    parts = tuple(name.removesuffix("/").split("/"))
    if len(name) > 512 or len(parts) > MAX_DEPTH or any(
            part in ("", ".", "..") or part.endswith((".", " ")) or len(part) > 255
            or INVALID_NAME.search(part) or DEVICE_NAME.fullmatch(part.split(".", 1)[0].rstrip())
            for part in parts):
        raise ArchiveError("The source ZIP contains an unsafe path.")
    kind = stat.S_IFMT(entry.external_attr >> 16)
    if kind not in (0, stat.S_IFDIR if entry.is_dir() else stat.S_IFREG):
        raise ArchiveError("The source ZIP contains a link or a special file.")
    if entry.flag_bits & 1:
        raise ArchiveError("The source ZIP contains encrypted entries.")
    if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ArchiveError("The source ZIP must use stored or deflate compression.")
    return parts


def _plan(archive: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, tuple[str, ...]]]:
    entries = archive.infolist()
    if len(entries) > MAX_ENTRIES:
        raise ArchiveError("The source ZIP contains more than %d entries." % MAX_ENTRIES)

    paths: dict[tuple[str, ...], tuple[tuple[str, ...], bool]] = {}
    explicit: set[tuple[str, ...]] = set()
    files = []
    total = 0
    for entry in entries:
        parts = _member_parts(entry)
        normalized = tuple(unicodedata.normalize("NFC", part.casefold()) for part in parts)
        if normalized in explicit:
            raise ArchiveError("The source ZIP contains duplicate or conflicting paths.")
        explicit.add(normalized)
        for depth in range(1, len(parts) + 1):
            key = normalized[:depth]
            directory = depth < len(parts) or entry.is_dir()
            value = (parts[:depth], directory)
            if paths.setdefault(key, value) != value:
                raise ArchiveError("The source ZIP contains duplicate or conflicting paths.")

        if entry.is_dir():
            continue
        if entry.file_size > MAX_ENTRY_BYTES:
            raise ArchiveError("A file in the source ZIP exceeds %d MiB." % (MAX_ENTRY_BYTES >> 20))
        total += entry.file_size
        if total > MAX_EXPANDED_BYTES:
            raise ArchiveError("The source ZIP expands beyond %d MiB." % (MAX_EXPANDED_BYTES >> 20))
        # Finder adds this metadata tree when compressing a folder. It isn't project content.
        if parts[0] != "__MACOSX" and parts[-1] != ".DS_Store":
            files.append((entry, parts))
    if not files:
        raise ArchiveError("The source ZIP contains no project files.")
    return files


def _extract(target: Path, destination: Path) -> Path:
    try:
        if target.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ArchiveError("The source ZIP exceeds %d MiB." % (MAX_ARCHIVE_BYTES >> 20))
        with _BoundedReader(io.FileIO(target, "r")) as stream, zipfile.ZipFile(stream) as archive:
            files = _plan(archive)
            for entry, parts in files:
                output = destination.joinpath(*parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, output.open("xb") as extracted:
                    copied = 0
                    for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
                        copied += len(chunk)
                        if copied > entry.file_size:
                            raise ArchiveError("A file in the source ZIP exceeds its declared size.")
                        extracted.write(chunk)
                    if copied != entry.file_size:
                        raise ArchiveError("A file in the source ZIP is truncated.")
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError, ValueError, DeflateError) as exc:
        raise ArchiveError("The source ZIP could not be read or extracted.") from exc

    wrapper = files[0][1][0]
    if all(len(parts) > 1 and parts[0] == wrapper for _, parts in files):
        return destination / wrapper
    return destination


@contextmanager
def source_root(target: Path, work_dir: Path | None = None) -> Iterator[Path]:
    """Yield a folder or file. Only source ZIPs get a private, temporary extraction."""
    if not target.is_file() or target.suffix.lower() != ".zip":
        yield target
        return
    with tempfile.TemporaryDirectory(prefix="sca-source-", dir=work_dir) as folder:
        yield _extract(target, Path(folder))
