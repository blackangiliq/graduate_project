"""Reader for ZIP-based app packages: .apk, .aab and the split-APK sets .apks, .xapk, .apkm.

Python's zipfile is stricter than Android, and malware uses the difference: Android maps
every entry whose compression method is not deflate (8) as stored data of the declared
uncompressed size, ignores the encryption flag (AOSP libs/androidfw/AssetsProvider.cpp) and
takes the data offset from the local header. This reader does the same, so an app that
installs on a phone can be read here. It finds the end of central directory record by
scanning back over the archive comment and, like Android, uses the last valid one.

Everything is bounds-checked and capped: lengths are clamped to the file, inflated output
stops at a limit (zip bomb guard), the number and length of names are capped. Anomalies
(duplicate names, names that differ only in case, data before the archive, several end
records, bad local headers, unknown methods, the encryption flag, overlapping entries) are
reported in `warnings`. Entries are never extracted to disk.

An APK set (.apks, .xapk, .apkm) holds APKs as entries. An APK stored without compression,
as bundletool writes them, is read in place from the set's file; a compressed one is
inflated into memory, within smaller limits. The archives inside share the set's total read
limit.
"""
from __future__ import annotations

import fnmatch
import hashlib
import io
import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, List, Optional, Sequence, Tuple, Union

LOCAL_SIG = b"PK\x03\x04"
CENTRAL_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"
ZIP64_EOCD_SIG = b"PK\x06\x06"
EOCD_SIZE = 22
MAX_COMMENT = 65_535
DEFLATED = 8
STORED = 0
FLAG_ENCRYPTED = 0x0001
FLAG_UTF8 = 0x0800

# caps against hostile archives
DEFAULT_LIMIT = 512 << 20          # bytes read from one entry
DEFAULT_TOTAL_LIMIT = 4 << 30      # bytes read from one archive (entries can share their data)
MAX_ENTRIES = 100_000
MAX_NAME = 4_096
MAX_CENTRAL_DIRECTORY = 256 << 20
MAX_WARNINGS = 200
MAX_INNER_APKS = 64
MAX_INFLATED_APK = 256 << 20       # a compressed APK in a set is inflated into memory ...
MAX_INFLATED_APKS = 512 << 20      # ... and all of them together take at most this much
_CHUNK = 1 << 20
_PIECE = 16 << 20                  # output of one inflate call into a buffer
_MODULE_MANIFEST = re.compile(r"([^/]+)/manifest/AndroidManifest\.xml$")

Source = Union[str, os.PathLike, bytes, bytearray, memoryview]


class ZipError(Exception):
    """The archive or one of its entries cannot be read."""


@dataclass
class ZipEntry:
    """One entry of the central directory. Offsets are positions in the file."""

    name: str                   # normalised: "/" separators, no leading "/"
    method: int                 # 8 is deflate; any other method is read as stored data
    flags: int
    compressed_size: int
    size: int                   # declared uncompressed size
    crc: int
    local_offset: int           # position of the local header
    data_offset: int            # position of the data; -1 when the local header is unusable
    raw_name: str = ""          # the name as written in the central directory


class _Budget:
    """Bytes that may still be read from an archive and from the archives inside it."""

    __slots__ = ("left",)

    def __init__(self, left: int) -> None:
        self.left = left


class _Buffer(bytearray):
    """Data inflated by this module that an archive opened from it may use in place."""


@dataclass(frozen=True)
class _Slice:
    """`size` bytes at `offset` in the file of `archive`: an APK stored inside an APK set."""

    archive: "ZipArchive"
    offset: int
    size: int


class ZipArchive:
    """A ZIP archive opened from a path or from bytes (an APK inside an .apks set).

    `entries` lists every central directory entry in order; names() lists each name once.
    `cd_offset`, `cd_size` and `eocd_offset` are positions in the file of the central
    directory and of the end record (the APK Signing Block ends at `cd_offset`). At most
    `total_limit` bytes are read from the archive in all, so entries that share one zip bomb
    cannot multiply it; an archive inside another one shares the outer one's limit.
    """

    def __init__(self, source: Union[Source, _Slice], name: str = "",
                 total_limit: int = DEFAULT_TOTAL_LIMIT, budget: Optional[_Budget] = None):
        self._file: Optional[BinaryIO] = None
        self._data: Union[bytes, bytearray] = b""
        self._slice: Optional[_Slice] = None
        self._budget = budget if budget is not None else _Budget(total_limit)
        self.path = ""
        if isinstance(source, _Slice):
            self._slice = source
            self.size = source.size
            self.name = _short(name or "archive")
        elif isinstance(source, (bytes, bytearray, memoryview)):
            # an inflated APK of a set (_Buffer) is used in place, not copied again
            self._data = source if isinstance(source, _Buffer) else bytes(source)
            self.size = len(self._data)
            self.name = _short(name or "archive")
        else:
            self.path = os.fspath(source)
            self.name = _short(name or os.path.basename(self.path))
            try:
                self._file = open(self.path, "rb")
                self.size = os.fstat(self._file.fileno()).st_size
            except OSError as exc:
                self.close()
                raise ZipError(f"{self.name}: cannot open: {exc.strerror or exc}") from exc
        self.entries: List[ZipEntry] = []
        self.warnings: List[str] = []
        self.comment = b""
        self.cd_offset = self.cd_size = self.eocd_offset = 0
        self._by_name: Dict[str, List[ZipEntry]] = {}
        try:
            self._load()
        except BaseException:
            self.close()
            raise

    # ------------------------------------------------------------------ public API
    def names(self) -> List[str]:
        """Every entry name once, in central directory order."""
        return list(self._by_name)

    def get(self, name: str) -> Optional[ZipEntry]:
        """The entry with this name (normalised like the entry names), or None. With duplicate
        names, an entry written exactly so wins, then the first one."""
        found = self._by_name.get(_normalise(name))
        if not found:
            return None
        return next((entry for entry in found if entry.raw_name == name), found[0])

    def find(self, pattern: str) -> List[ZipEntry]:
        """Entries whose name matches a glob pattern (fnmatch, case-sensitive; "*" also
        matches "/"), in central directory order."""
        return [self.get(name) for name in self._by_name if fnmatch.fnmatchcase(name, pattern)]

    def read(self, name_or_entry: Union[str, ZipEntry], limit: int = DEFAULT_LIMIT,
             head: bool = False) -> bytes:
        """The uncompressed data of an entry, at most `limit` bytes.

        Deflate entries are inflated; every other method is read as stored data of the
        declared uncompressed size, as Android does. Output beyond `limit` (or beyond what is
        left of the archive's total limit) is dropped with a warning; with `head` only the
        first `limit` bytes are wanted and a longer entry is not reported. Raises ZipError
        when the entry does not exist, its local header is unusable, its deflate data is
        corrupt or the total limit is used up."""
        entry = name_or_entry if isinstance(name_or_entry, ZipEntry) else self.get(name_or_entry)
        if entry is None:
            raise ZipError(f"{self.name}: no entry named {_short(str(name_or_entry))!r}")
        label = _short(entry.name)
        if entry.data_offset < 0:
            raise ZipError(f"{self.name}: {label}: the local header is unusable")
        if self._budget.left <= 0:
            raise ZipError(f"{self.name}: {label}: the total read limit of this archive is used "
                           "up (zip bomb guard)")
        limit = max(0, min(limit, self._budget.left))
        if entry.method == DEFLATED:
            data = self._inflate(entry, label, limit, head)
        else:
            data = self.read_raw(entry.data_offset, min(entry.size, limit))
            if len(data) < min(entry.size, limit):
                self.warn(f"{label}: the data runs past the end of the file")
            elif entry.size > limit:
                if not head:
                    self.warn(f"{label}: {entry.size} bytes, more than the read limit of "
                              f"{limit}; the rest was not read")
            elif zlib.crc32(data) != entry.crc:
                self.warn(f"{label}: CRC mismatch")
        self._budget.left -= len(data)
        return data

    def _read_into_buffer(self, entry: ZipEntry, limit: int) -> bytearray:
        """A deflate entry inflated into one buffer of its declared size (at most `limit`),
        with no second copy of the data: an APK of a set that is kept in memory."""
        label = _short(entry.name)
        if entry.data_offset < 0:
            raise ZipError(f"{self.name}: {label}: the local header is unusable")
        if self._budget.left <= 0:
            raise ZipError(f"{self.name}: {label}: the total read limit of this archive is used "
                           "up (zip bomb guard)")
        size = max(0, min(entry.size, limit, self._budget.left))
        data = self._inflate(entry, label, size, out=_Buffer(size))
        self._budget.left -= len(data)
        return data

    def read_raw(self, offset: int, length: int) -> bytes:
        """`length` bytes of the file at `offset`, fewer at the end of the file."""
        offset = max(0, offset)
        length = max(0, min(length, self.size - offset))
        if not length:
            return b""
        if self._slice is not None:
            return self._slice.archive.read_raw(self._slice.offset + offset, length)
        if self._file is None:
            return bytes(memoryview(self._data)[offset:offset + length])    # one copy
        self._file.seek(offset)
        return self._file.read(length)

    def open_raw(self) -> BinaryIO:
        """The archive's file as a read-only, seekable binary file that reads on demand (for
        an APK inside a set: its bytes in the set's file), not a copy in memory."""
        return _RawFile(self)  # type: ignore[return-value]

    def sha256(self) -> str:
        """SHA-256 of the whole file, read in blocks."""
        digest = hashlib.sha256()
        if self._slice is not None:
            for offset in range(0, self.size, _CHUNK):
                digest.update(self.read_raw(offset, _CHUNK))
            return digest.hexdigest()
        if self._file is None:
            digest.update(self._data)
            return digest.hexdigest()
        self._file.seek(0)
        for block in iter(lambda: self._file.read(_CHUNK), b""):
            digest.update(block)
        return digest.hexdigest()

    def warn(self, message: str) -> None:
        message = f"{self.name}: {message}"
        if len(self.warnings) > MAX_WARNINGS or message in self.warnings:
            return
        if len(self.warnings) == MAX_WARNINGS:
            message = f"{self.name}: further warnings suppressed"
        self.warnings.append(message)

    def close(self) -> None:
        self._slice = None              # the outer archive owns the file
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> "ZipArchive":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------ central directory
    def _load(self) -> None:
        tail_start = max(0, self.size - EOCD_SIZE - MAX_COMMENT)
        tail = self.read_raw(tail_start, self.size - tail_start)
        candidates = [tail_start + m.start() for m in re.finditer(re.escape(EOCD_SIG), tail)]
        records = [record for record in map(self._end_record, reversed(candidates)) if record]
        if not records:
            raise ZipError(f"{self.name}: not a ZIP archive (no end of central directory)")
        exact = [record for record in records if record[5]]
        eocd, count, cd_size, cd_offset, bias, _, self.comment = (exact or records)[0]
        if not exact:
            self.warn("the end of central directory record and its comment do not end the "
                      "file (Android refuses such a file)")
        later = [pos for pos in candidates if pos > eocd]
        if later:
            self.warn(f"the archive comment holds {len(later)} more end of central directory "
                      "signature(s) (tampering)")
        if len(exact) > 1:
            self.warn(f"{len(exact)} valid end of central directory records; the last one is "
                      "used, as Android does")
        self.eocd_offset = eocd
        self.cd_offset = cd_offset + bias
        self.cd_size = cd_size
        if bias:
            self.warn(f"{bias} bytes precede the archive and its offsets do not count them")
        self._read_central_directory(count, bias)
        self._check_layout()

    def _end_record(self, pos: int) -> Optional[tuple]:
        """(eocd, entries, cd_size, cd_offset, bias, exact, comment) of the end record at
        `pos` when it points to a central directory, else None."""
        record = self.read_raw(pos, EOCD_SIZE)
        if len(record) < EOCD_SIZE:
            return None
        _, _, _, _, count, cd_size, cd_offset, comment_size = struct.unpack("<4s4H2IH", record)
        exact = pos + EOCD_SIZE + comment_size == self.size
        cd_end = pos
        if count == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
            zip64 = self._zip64_record(pos)
            if zip64:
                count, cd_size, cd_offset, cd_end = zip64
        if count == 0 and cd_size == 0:
            bias = 0
        elif self.read_raw(cd_offset, 4) == CENTRAL_SIG and cd_offset + cd_size <= cd_end:
            bias = 0
        else:
            bias = cd_end - cd_size - cd_offset    # data was put in front of the archive
            if bias <= 0 or self.read_raw(cd_offset + bias, 4) != CENTRAL_SIG:
                return None
        comment = self.read_raw(pos + EOCD_SIZE, comment_size)
        return pos, count, cd_size, cd_offset, bias, exact, comment

    def _zip64_record(self, eocd: int) -> Optional[Tuple[int, int, int, int]]:
        """(entries, cd_size, cd_offset, record position) from the ZIP64 end record."""
        locator = self.read_raw(eocd - 20, 20)
        if len(locator) < 20 or locator[:4] != ZIP64_LOCATOR_SIG:
            return None
        offset = struct.unpack_from("<Q", locator, 8)[0]
        if self.read_raw(offset, 4) != ZIP64_EOCD_SIG:
            offset = eocd - 20 - 56            # with data in front of the archive
        record = self.read_raw(offset, 56)
        if len(record) < 56 or record[:4] != ZIP64_EOCD_SIG:
            return None
        count, cd_size, cd_offset = struct.unpack_from("<3Q", record, 32)
        return count, cd_size, cd_offset, offset

    def _read_central_directory(self, declared: int, bias: int) -> None:
        length = self.cd_size
        if length > MAX_CENTRAL_DIRECTORY:
            self.warn(f"the central directory is {length} bytes; only {MAX_CENTRAL_DIRECTORY} "
                      "are read")
            length = MAX_CENTRAL_DIRECTORY
        cd = self.read_raw(self.cd_offset, length)
        pos = 0
        while pos + 46 <= len(cd):
            if len(self.entries) >= MAX_ENTRIES:
                self.warn(f"more than {MAX_ENTRIES} entries; the rest are ignored")
                break
            if cd[pos:pos + 4] != CENTRAL_SIG:
                self.warn(f"bad central directory signature at entry {len(self.entries)}; the "
                          "rest of the directory is ignored")
                break
            (flags, method, crc, compressed, size, name_len, extra_len, comment_len,
             local) = struct.unpack_from("<8xHH4xIIIHHH8xI", cd, pos)
            start = pos + 46
            pos = start + name_len + extra_len + comment_len
            if start + name_len > len(cd):
                self.warn("the central directory is truncated")
                break
            if name_len > MAX_NAME:
                self.warn(f"an entry name of {name_len} bytes was skipped")
                continue
            raw = cd[start:start + name_len]
            raw_name = _decode_name(raw, flags)
            extra = cd[start + name_len:start + name_len + extra_len]
            size, compressed, local = _zip64_values(extra, size, compressed, local)
            self._add(ZipEntry(_normalise(raw_name), method, flags, compressed, size, crc,
                               local + bias, -1, raw_name), raw)
        if declared != len(self.entries) and len(self.entries) < MAX_ENTRIES:
            self.warn(f"the end record declares {declared} entries but the central directory "
                      f"has {len(self.entries)}")

    def _add(self, entry: ZipEntry, raw_name: bytes) -> None:
        header = self.read_raw(entry.local_offset, 30)
        label = _short(entry.raw_name)
        if len(header) < 30 or header[:4] != LOCAL_SIG:
            self.warn(f"{label}: no local header at offset {entry.local_offset}")
        else:
            name_len, extra_len = struct.unpack_from("<HH", header, 26)
            entry.data_offset = entry.local_offset + 30 + name_len + extra_len
            if entry.data_offset > self.size:
                self.warn(f"{label}: the local header points past the end of the file")
                entry.data_offset = -1
            elif name_len != len(raw_name) or \
                    self.read_raw(entry.local_offset + 30, name_len) != raw_name:
                self.warn(f"{label}: the local header gives another name")
        self.entries.append(entry)
        self._by_name.setdefault(entry.name, []).append(entry)

    def _check_layout(self) -> None:
        """Warnings for names and layouts that Android refuses or that hide something."""
        lower: Dict[str, str] = {}
        for name, found in self._by_name.items():
            if len(found) > 1:
                self.warn(f"duplicate entry name {_short(name)!r} ({len(found)} entries)")
            other = lower.setdefault(name.lower(), name)
            if other != name:
                self.warn(f"entry names differ only in case: {_short(other)!r} and "
                          f"{_short(name)!r}")
            if not name:
                self.warn("an entry has an empty name")
            elif ".." in name.split("/") or re.match(r"[A-Za-z]:", name):
                self.warn(f"entry name {_short(name)!r} points outside the archive (zip slip)")
        for entry in self.entries:
            label = _short(entry.name)
            if entry.raw_name.startswith(("/", "\\")):
                self.warn(f"entry name {_short(entry.raw_name)!r} is an absolute path")
            if entry.flags & FLAG_ENCRYPTED:
                self.warn(f"{label}: the encryption flag is set; Android ignores it")
            if entry.method not in (STORED, DEFLATED):
                self.warn(f"{label}: compression method {entry.method}; Android reads the data "
                          "as stored")
            elif entry.method == STORED and entry.compressed_size != entry.size:
                self.warn(f"{label}: stored entry with different compressed and uncompressed "
                          "sizes")
        placed = sorted((e for e in self.entries if e.data_offset >= 0),
                        key=lambda e: (e.local_offset, e.data_offset))
        if placed and placed[0].local_offset > 0:
            head = self.read_raw(0, 8)
            if head.startswith(b"dex\n"):
                self.warn(f"a DEX file precedes the archive ({placed[0].local_offset} bytes): "
                          "Janus, CVE-2017-13156")
            else:
                self.warn(f"{placed[0].local_offset} bytes precede the first entry")
        overlaps = sum(1 for a, b in zip(placed, placed[1:])
                       if b.local_offset < a.data_offset + a.compressed_size)
        if overlaps:
            self.warn(f"{overlaps} entries overlap the data of another entry (zip bomb or "
                      "tampering)")

    # ------------------------------------------------------------------ inflating
    def _inflate(self, entry: ZipEntry, label: str, limit: int, head: bool = False,
                 out: Optional[bytearray] = None) -> Union[bytes, bytearray]:
        """At most `limit` bytes of a deflate entry; with `out` (a bytearray of `limit`
        bytes) inflated into it and it is returned, cut to the length read."""
        available = max(0, self.size - entry.data_offset)
        remaining = min(entry.compressed_size, available)
        if remaining < entry.compressed_size:
            self.warn(f"{label}: the compressed data runs past the end of the file")
        inflater = zlib.decompressobj(-15)
        pieces: List[bytes] = []
        view = memoryview(out) if out is not None else None
        total = crc = 0
        pos = entry.data_offset
        budget = limit + 1                  # one byte more tells that the entry is larger
        try:
            while not inflater.eof and total < budget:
                chunk = inflater.unconsumed_tail
                if not chunk and remaining > 0:
                    chunk = self.read_raw(pos, min(_CHUNK, remaining))
                    pos += len(chunk)
                    remaining = remaining - len(chunk) if chunk else 0
                # with no input left, an empty chunk still gives the output zlib holds back;
                # into a buffer, the pieces are small (the buffer is the only full copy)
                piece = inflater.decompress(chunk, budget - total if view is None
                                            else min(budget - total, _PIECE))
                if not piece and (not chunk or inflater.unconsumed_tail == chunk):
                    break
                if view is None:
                    pieces.append(piece)
                else:
                    fit = min(len(piece), limit - total)
                    if fit > 0:
                        view[total:total + fit] = piece[:fit] if fit < len(piece) else piece
                total += len(piece)
                crc = zlib.crc32(piece, crc)
        except zlib.error as exc:
            raise ZipError(f"{self.name}: {label}: corrupt deflate data ({exc})") from exc
        finally:
            if view is not None:
                view.release()
        if out is not None:
            del out[min(total, limit):]
            data: Union[bytes, bytearray] = out
        else:
            data = b"".join(pieces)
        if total > limit:
            if not head:
                self.warn(f"{label}: inflates to more than the read limit of {limit} bytes; "
                          "the rest was not read (zip bomb guard)")
            return data[:limit] if out is None else data
        if not inflater.eof:
            self.warn(f"{label}: the deflate data ends early")
        elif total != entry.size:
            self.warn(f"{label}: inflates to {total} bytes, not the declared {entry.size}")
        elif crc != entry.crc:
            self.warn(f"{label}: CRC mismatch")
        return data


class _RawFile(io.RawIOBase):
    """A read-only, seekable view of an archive's file (ZipArchive.open_raw)."""

    def __init__(self, archive: ZipArchive) -> None:
        super().__init__()
        self._archive = archive
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        bases = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._archive.size}
        if whence not in bases:
            raise ValueError(f"invalid whence ({whence})")
        if bases[whence] + offset < 0:
            raise ValueError(f"negative seek position {bases[whence] + offset}")
        self._pos = bases[whence] + offset
        return self._pos

    def readinto(self, buffer: "bytearray | memoryview") -> int:  # type: ignore[override]
        view = memoryview(buffer).cast("B")
        data = self._archive.read_raw(self._pos, len(view))
        view[:len(data)] = data
        self._pos += len(data)
        return len(data)


def _normalise(name: str) -> str:
    return name.replace("\\", "/").lstrip("/")


def _short(name: str, size: int = 120) -> str:
    """A name cut for a message (entry names can be 4096 characters long)."""
    return name if len(name) <= size else name[:size] + "..."


def _decode_name(raw: bytes, flags: int) -> str:
    if flags & FLAG_UTF8:
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp437")


def _zip64_values(extra: bytes, size: int, compressed: int, local: int) -> Tuple[int, int, int]:
    """Sizes and offset from the ZIP64 extra field, for the values marked 0xffffffff."""
    pos = 0
    while pos + 4 <= len(extra):
        tag, length = struct.unpack_from("<HH", extra, pos)
        if tag == 0x0001:
            values = extra[pos + 4:pos + 4 + length]
            at = 0
            fields = [size, compressed, local]
            for i in range(3):
                if fields[i] == 0xFFFFFFFF and at + 8 <= len(values):
                    fields[i] = struct.unpack_from("<Q", values, at)[0]
                    at += 8
            return fields[0], fields[1], fields[2]
        pos += 4 + length
    return size, compressed, local


def is_zip(path: Union[str, os.PathLike]) -> bool:
    """True when the file starts with a ZIP header or ends with an end of central directory
    record (an archive with data in front of it)."""
    try:
        with open(path, "rb") as handle:
            if handle.read(4) in (LOCAL_SIG, EOCD_SIG):
                return True
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - EOCD_SIZE - MAX_COMMENT))
            return EOCD_SIG in handle.read()
    except OSError:
        return False


# ------------------------------------------------------------------ containers
@dataclass
class Container:
    """An app package: one APK, an app bundle, or a set of split APKs.

    `apks` holds (label, archive) pairs: ("base", the APK) for an .apk; ("bundle", the
    bundle) for an .aab, whose files sit under module folders (base/manifest/
    AndroidManifest.xml, base/dex/, base/lib/, base/assets/, base/res/) listed in `modules`;
    for .apks/.xapk/.apkm, every APK inside, labelled like its installed file without
    ".apk" ("base", "split_config.arm64_v8a", ...), base first.
    """

    path: str
    kind: str                           # "apk", "aab", "apks", "xapk" or "apkm"
    archive: ZipArchive                 # the file itself
    apks: List[Tuple[str, ZipArchive]] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    apk_members: List[Dict[str, str]] = field(default_factory=list)
    member_by_archive: Dict[ZipArchive, Dict[str, str]] = field(default_factory=dict)

    def close(self) -> None:
        for _, archive in self.apks:
            archive.close()
        self.archive.close()

    def __enter__(self) -> "Container":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def open_container(path: Union[str, os.PathLike], limit: int = DEFAULT_LIMIT,
                   total_limit: int = DEFAULT_TOTAL_LIMIT) -> Container:
    """Open an app package. The kind comes from the content (AndroidManifest.xml at the root:
    an APK; module manifests or BundleConfig.pb: a bundle; APK entries: a split set) and the
    extension. Inner APKs larger than `limit` are skipped with a warning; stored ones are read
    in place, compressed ones are inflated into memory (at most MAX_INFLATED_APK each and
    MAX_INFLATED_APKS in all). At most `total_limit` bytes are read from the file and the
    APKs inside it together. Raises ZipError when the file is not a ZIP archive."""
    archive = ZipArchive(path, total_limit=total_limit)
    try:
        suffix = Path(path).suffix.lower()
        kind = _kind(archive, suffix)
        container = Container(os.fspath(path), kind, archive)
        if kind == "apk":
            container.apks.append(("base", archive))
            if archive.get("AndroidManifest.xml") is None:
                container.warnings.append(f"{archive.name}: no AndroidManifest.xml")
        elif kind == "aab":
            container.apks.append(("bundle", archive))
            container.modules = _modules(archive.names())
        else:
            _open_splits(container, limit)
        return container
    except BaseException:
        archive.close()
        raise


def _kind(archive: ZipArchive, suffix: str) -> str:
    names = archive.names()
    if archive.get("AndroidManifest.xml") is not None:
        return "apk"
    if archive.get("BundleConfig.pb") is not None or _modules(names):
        return "aab"
    if any(name.lower().endswith(".apk") for name in names):
        return {".xapk": "xapk", ".apkm": "apkm"}.get(suffix, "apks")
    return "aab" if suffix == ".aab" else "apk"


def _modules(names: Iterable[str]) -> List[str]:
    """Module folders of an app bundle (folders with manifest/AndroidManifest.xml), base first."""
    found = {m.group(1) for m in map(_MODULE_MANIFEST.match, names) if m}
    return sorted(found, key=lambda module: (module != "base", module))


def _open_splits(container: Container, limit: int) -> None:
    archive = container.archive
    entries = [e for e in archive.entries if e.name.lower().endswith(".apk")]
    bundletool = any(e.name.startswith("splits/") for e in entries)
    eligible = [e for e in entries if not bundletool or e.name.startswith("splits/")]
    # Prioritize the base even when a large set was written in another order.
    eligible.sort(key=lambda e: _split_label(e.name) != "base")
    selected = {id(e) for e in eligible[:MAX_INNER_APKS]}
    if len(eligible) > MAX_INNER_APKS:
        container.warnings.append(f"{archive.name}: {len(eligible)} APKs inside; only the first "
                                  f"{MAX_INNER_APKS} are read")
    opened: List[Tuple[str, ZipArchive]] = []
    inflated = 0
    seen_names = set()
    for entry in sorted(entries, key=lambda e: _split_label(e.name) != "base"):
        label = _short(entry.name)
        alternative = bundletool and not entry.name.startswith("splits/")
        record = {"name": label, "role": "alternative" if alternative else "split",
                  "status": "skipped", "reason": ""}
        if id(entry) not in selected:
            record["reason"] = "Alternative installation variant" if alternative else "APK count limit"
            if len(container.apk_members) < 4 * MAX_INNER_APKS:
                container.apk_members.append(record)
            continue
        container.apk_members.append(record)
        if entry.name.casefold() in seen_names:
            record["reason"] = "Duplicate APK member filename"
            container.warnings.append(f"{archive.name}: duplicate APK filename {label}; skipped")
            continue
        seen_names.add(entry.name.casefold())
        if entry.size > limit:
            record["reason"] = "APK size limit"
            container.warnings.append(f"{archive.name}: {label} is larger than the read limit "
                                      f"of {limit} bytes; skipped")
            continue
        try:
            if entry.method != DEFLATED:
                inner = _stored_apk(archive, entry, label)
            elif entry.size > MAX_INFLATED_APK or inflated + entry.size > MAX_INFLATED_APKS:
                record["reason"] = "Compressed APK size limit"
                container.warnings.append(
                    f"{archive.name}: {label} is compressed and {entry.size} bytes large; "
                    f"compressed APKs are inflated into memory, at most {MAX_INFLATED_APK} "
                    f"bytes each and {MAX_INFLATED_APKS} in all; skipped")
                continue
            else:
                data = archive._read_into_buffer(entry, MAX_INFLATED_APK)
                inflated += len(data)
                inner = ZipArchive(data, name=entry.name, budget=archive._budget)
        except ZipError as exc:
            record["reason"] = "Unreadable APK archive"
            container.warnings.append(f"{archive.name}: {label} is not readable: {exc}")
            continue
        opened.append((_split_label(entry.name), inner))
        container.member_by_archive[inner] = record
    if not any(label == "base" for label, _ in opened):
        # an .xapk names its base APK after the package: the one APK that is not a split
        index = next((i for i, (label, _) in enumerate(opened)
                      if not label.startswith("split_")), None)
        if index is not None:
            opened[index] = ("base", opened[index][1])
    used: Dict[str, int] = {}
    for label, inner in sorted(opened, key=lambda pair: (pair[0] != "base", pair[0])):
        used[label] = used.get(label, 0) + 1
        if label == "base" and used[label] == 1:
            container.member_by_archive[inner]["role"] = "base"
        container.apks.append((label if used[label] == 1 else f"{label}-{used[label]}", inner))
    if len(container.apk_members) < len(entries):
        container.warnings.append(f"{archive.name}: {len(entries) - len(container.apk_members)} "
                                  "more skipped APK names omitted from the member list")
    if not container.apks:
        container.warnings.append(f"{archive.name}: no readable APK inside")


def _stored_apk(archive: ZipArchive, entry: ZipEntry, label: str) -> ZipArchive:
    """An APK stored (not compressed) in a set, read in place from the set's file. Its CRC is
    checked in blocks, as a read of the entry would; that read counts against the set's
    total read limit."""
    if entry.data_offset < 0:
        raise ZipError(f"{archive.name}: {label}: the local header is unusable")
    budget = archive._budget
    if budget.left <= 0:
        raise ZipError(f"{archive.name}: {label}: the total read limit of this archive is used "
                       "up (zip bomb guard)")
    size = max(0, min(entry.size, archive.size - entry.data_offset))
    if size < entry.size:
        archive.warn(f"{label}: the data runs past the end of the file")
    elif size <= budget.left:
        crc = 0
        for offset in range(entry.data_offset, entry.data_offset + size, _CHUNK):
            crc = zlib.crc32(archive.read_raw(offset, min(_CHUNK, entry.data_offset + size
                                                          - offset)), crc)
        if crc != entry.crc:
            archive.warn(f"{label}: CRC mismatch")
    budget.left -= size
    return ZipArchive(_Slice(archive, entry.data_offset, size), name=entry.name, budget=budget)


def _split_label(entry_name: str) -> str:
    """The installed file name, without ".apk", of an APK in a split set: base.apk,
    base-master.apk and universal.apk give "base"; config.arm64_v8a.apk and
    base-arm64_v8a.apk give "split_config.arm64_v8a"; feature-master.apk gives
    "split_feature"."""
    stem = entry_name.rsplit("/", 1)[-1][:-4]
    if stem in ("base", "base-master", "universal"):
        return "base"
    if stem.startswith("split_"):
        return stem
    if stem.startswith("config."):
        return "split_" + stem
    module, dash, config = stem.partition("-")
    if dash and module == "base":
        return "split_config." + config
    if dash and config == "master":
        return "split_" + module
    if dash:
        return f"split_{module}.config.{config}"
    return stem


# ------------------------------------------------------------------ builder (for tests)
def build_zip(entries: Sequence[Tuple[str, bytes, int]], prepend: bytes = b"",
              comment: bytes = b"", extra_eocd: bool = False,
              encrypted_flag_names: Iterable[str] = (), adjust_offsets: bool = True) -> bytes:
    """A ZIP archive with real local headers and a central directory.

    `entries` are (name, data, method): method 8 is deflated, any other method is written as
    stored data under that method number (Android's view of an unknown method). Names may
    repeat. `prepend` goes before the first local header; with `adjust_offsets` the offsets
    count it (as `zip -A` does), otherwise they are relative to the archive. `extra_eocd` puts
    a fake end of central directory record into the comment; `encrypted_flag_names` get the
    encryption flag in both headers.
    """
    encrypted = set(encrypted_flag_names)
    base = len(prepend) if adjust_offsets else 0
    body = bytearray(prepend)
    central = bytearray()
    for name, data, method in entries:
        raw_name = name.encode("utf-8")
        flags = (FLAG_ENCRYPTED if name in encrypted else 0) | \
            (0 if raw_name.isascii() else FLAG_UTF8)
        if method == DEFLATED:
            packer = zlib.compressobj(6, zlib.DEFLATED, -15)
            payload = packer.compress(data) + packer.flush()
        else:
            payload = data
        crc = zlib.crc32(data)
        offset = len(body) - len(prepend) + base
        body += struct.pack("<4s5H3I2H", LOCAL_SIG, 20, flags, method, 0, 0x21, crc, len(payload),
                            len(data), len(raw_name), 0) + raw_name + payload
        central += struct.pack("<4s6H3I5HII", CENTRAL_SIG, 20, 20, flags, method, 0, 0x21, crc,
                               len(payload), len(data), len(raw_name), 0, 0, 0, 0, 0,
                               offset) + raw_name
    cd_offset = len(body) - len(prepend) + base
    if extra_eocd:
        comment = comment + struct.pack("<4s4H2IH", EOCD_SIG, 0, 0, 1, 1, 46, 0x7FFFFFF0, 0)
    count = min(len(entries), 0xFFFF)       # no ZIP64 records: larger counts are clamped
    end = struct.pack("<4s4H2IH", EOCD_SIG, 0, 0, count, count, len(central), cd_offset,
                      len(comment))
    return bytes(body + central + end + comment)
