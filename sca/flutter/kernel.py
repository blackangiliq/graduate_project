"""Recovers the Dart sources that a Flutter debug build ships in kernel_blob.bin.

A debug APK carries the app as a Dart kernel file (assets/flutter_assets/kernel_blob.bin,
the app.dill of the build). flutter_tools compiles it with the source text embedded, so
every library of the app, of its pub packages and of the Flutter framework is in the file
as full source, comments included; only the dart: SDK libraries are left out. The absolute
file URIs of the sources also show where the app was built (user names, project folders)
and which version of each pub package was used.

Format (Dart pkg/kernel/binary.md): the file is one or more kernel components laid end to
end (incremental builds write one component per package group, then the app, then a small
entry component that names main()). A component starts with the magic 0x90ABCDEF, the
format version and a 10-character SDK hash, and ends with its ComponentIndex: fixed
UInt32 section offsets, the library offsets, the library count and the component size, so
the file can be walked from its end. The last library offset is where the source table
(UriSource) starts: a UInt32 count, one SourceInfo per source (file URI, source text,
lineStarts, import URI, ...) and a UInt32 offset per SourceInfo. Variable-length integers
(UInt) take 1, 2 or 4 bytes, big-endian, chosen by the two top bits of the first byte.

A component whose index or source table does not check out is carved instead: a
length-prefixed URI followed by a length-prefixed source text whose lineStarts list fits
the text. A kernel file from an app package is untrusted: reads are bounds-checked, sizes
and counts are capped and problems become warnings. This module never raises on bad data.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote

KERNEL_MAGIC = 0x90ABCDEF
_MAGIC = struct.pack(">I", KERNEL_MAGIC)
_HEADER = 18                    # magic, format version, 10-byte SDK hash
_MIN_COMPONENT = 32

# caps against hostile files
MAX_BLOB = 512 << 20
MAX_COMPONENTS = 10_000
MAX_SOURCES = 20_000
MAX_SOURCE_BYTES = 8 << 20
MAX_URI = 4096
MAX_BUILD_PATHS = 20
MAX_WARNINGS = 50
_MAX_TABLE = 100_000            # SourceInfo records one source table may declare
_MAX_CARVE_TRIES = 1_000_000    # URI-like positions the carver looks at
_MAX_NAMES = 1_000_000          # canonical names / string table entries read for main()

# ComponentIndex fields before the library offsets, by format version: Dart 3.8 (format
# 124) dropped compilationMode, Dart 2.14 (format 69) is the oldest layout handled here.
_INDEX_FIELDS = ("source_table", "constant_table", "constant_table_index", "canonical_names",
                 "metadata_payloads", "metadata_mappings", "string_table", "component_index",
                 "main_method")

_URI_START = re.compile(rb"file:///|package:|dart:|org-dartlang-[a-z-]+:")
_URI_BAD = re.compile(r"[\x00-\x20\x7f]")
# pub cache layout: hosted/<host>/<name>-<version>/... and git/<name>-<commit>/...
_HOSTED = re.compile(r"/hosted/[^/]+/([a-z0-9_]+)-(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)/")
_GIT = re.compile(r"/git/([a-z0-9_]+)-[0-9a-f]{40}/")
_CACHE_ROOT = re.compile(r"/(?:hosted/[^/]+/[^/]+|git/[^/]+-[0-9a-f]{40})/")
_FLUTTER_ROOT = "/packages/flutter/lib/"
_U32 = struct.Struct(">I")


class _Bad(Exception):
    """A structure that does not check out; the caller records it and moves on."""


@dataclass
class KernelComponent:
    """One component of the kernel file."""

    format_version: int
    sdk_hash: str                 # short git hash of the Dart SDK, "0000000000" for local builds
    library_count: int
    offset: int = 0               # where the component starts in the file
    size: int = 0
    source_count: int = 0


@dataclass
class KernelSource:
    """One source file found in the kernel."""

    uri: str                      # file URI, e.g. file:///C:/work/app/lib/main.dart
    import_uri: str               # e.g. package:app/main.dart ("" when the kernel has none)
    text: str                     # the embedded source ("" when it is not embedded)
    line_count: int               # lines of text

    @property
    def package(self) -> str:
        """Name of the package the source belongs to ("" outside a package: URI)."""
        if not self.import_uri.startswith("package:"):
            return ""
        return self.import_uri[8:].split("/", 1)[0]

    @property
    def path(self) -> str:
        """Path of the source inside its package's lib folder ("main.dart", "src/a.dart"),
        made safe for use as a relative path: no empty, "." or ".." segments and no
        control characters. "" outside a package: URI."""
        if not self.package:
            return ""
        rest = self.import_uri[8:].split("/", 1)[1] if "/" in self.import_uri[8:] else ""
        rest = re.sub(r"[\x00-\x1f\x7f\\:]", "_", rest)
        return "/".join(part for part in rest.split("/") if part not in ("", ".", ".."))


@dataclass
class KernelInfo:
    """What parse_kernel() found."""

    components: List[KernelComponent] = field(default_factory=list)
    sources: List[KernelSource] = field(default_factory=list)
    main_package: str = ""        # package of the library that holds main(), e.g. "vuln_probe"
    packages: Dict[str, Optional[str]] = field(default_factory=dict)  # pub packages -> version
    build_paths: List[str] = field(default_factory=list)  # file URIs of the build machine
    warnings: List[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append("kernel: " + message)
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append("kernel: further warnings suppressed")


def parse_kernel(blob: bytes) -> KernelInfo:
    """Parse a kernel file (kernel_blob.bin / app.dill) and recover its sources. Never
    raises on bad data: problems are in .warnings."""
    info = KernelInfo()
    data = blob if isinstance(blob, bytes) else bytes(blob)
    if len(data) > MAX_BLOB:
        info.warn("file of %d bytes is larger than the %d MiB limit; not read"
                  % (len(data), MAX_BLOB >> 20))
        return info
    spans = _component_spans(data, info)
    main: Optional[Tuple[int, Dict[str, int]]] = None
    unread: List[Tuple[int, int]] = []
    for start, end in spans:
        try:
            main = _read_component(data, start, end, info) or main
        except _Bad as exc:
            info.warn("component at 0x%x: %s; its sources are carved instead" % (start, exc))
            unread.append((start, end))
    if not spans and data:
        info.warn("no kernel component found (magic 0x90ABCDEF)")
    covered = sorted(set(spans) - set(unread))
    gaps = _gaps(covered, len(data))
    if gaps and len(info.sources) < MAX_SOURCES:
        before = len(info.sources)
        _carve(data, gaps, info)
        if len(info.sources) > before:
            info.warn("%d sources recovered by carving" % (len(info.sources) - before))
    _summarize(info, _main_library(data, *main) if main else "")
    return info


def app_sources(info: KernelInfo) -> List[KernelSource]:
    """The sources of the app itself: import URI package:<main_package>/..."""
    if not info.main_package:
        return []
    prefix = "package:%s/" % info.main_package
    return [s for s in info.sources if s.import_uri.startswith(prefix)]


# ------------------------------------------------------------------ primitives

def _u32(buf: bytes, pos: int) -> int:
    return _U32.unpack_from(buf, pos)[0]


def _read_uint(buf: bytes, pos: int, limit: int) -> Tuple[int, int]:
    """Kernel UInt at pos -> (value, next position)."""
    if pos >= limit:
        raise _Bad("integer past the end of its section")
    b0 = buf[pos]
    if b0 < 0x80:
        return b0, pos + 1
    if b0 < 0xC0:
        if pos + 2 > limit:
            raise _Bad("integer past the end of its section")
        return ((b0 & 0x3F) << 8) | buf[pos + 1], pos + 2
    if pos + 4 > limit:
        raise _Bad("integer past the end of its section")
    return (((b0 & 0x3F) << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8)
            | buf[pos + 3]), pos + 4


def _skip_uints(buf: bytes, pos: int, count: int, limit: int) -> int:
    """Position after `count` UInts starting at pos."""
    for _ in range(count):
        if pos >= limit:
            raise _Bad("list past the end of its section")
        b0 = buf[pos]
        pos += 1 if b0 < 0x80 else (2 if b0 < 0xC0 else 4)
    if pos > limit:
        raise _Bad("list past the end of its section")
    return pos


def _read_bytes(buf: bytes, pos: int, limit: int, cap: int) -> Tuple[int, int, int]:
    """A UInt length and that many bytes -> (start of the bytes, length, next position)."""
    length, pos = _read_uint(buf, pos, limit)
    if length > cap or pos + length > limit:
        raise _Bad("string of %d bytes past the end of its section" % length)
    return pos, length, pos + length


def _uri(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    if _URI_BAD.search(text):
        raise _Bad("URI with control characters")
    return text


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


# ------------------------------------------------------------------ components

def _component_spans(data: bytes, info: KernelInfo) -> List[Tuple[int, int]]:
    """(start, end) of every component: walked back from the end of the file by the size
    each component ends with; whatever lies before the first component reached is searched
    for the magic, and a candidate counts only when its own trailing size fits."""
    spans: List[Tuple[int, int]] = []
    end = len(data)
    while end >= _MIN_COMPONENT and len(spans) < MAX_COMPONENTS:
        size = _u32(data, end - 4)
        start = end - size
        if size < _MIN_COMPONENT or start < 0 or data[start:start + 4] != _MAGIC:
            break
        spans.append((start, end))
        end = start
    spans.reverse()
    if end > 0:
        if spans:
            info.warn("%d bytes before the first component at 0x%x are not a component"
                      % (end, end))
        starts = []
        for match in re.compile(re.escape(_MAGIC)).finditer(data, 0, end):
            starts.append(match.start())
            if len(starts) + len(spans) >= MAX_COMPONENTS:
                break
        bounds = starts + [end]
        for i, start in enumerate(starts):
            stop = bounds[i + 1]
            if stop - start >= _MIN_COMPONENT and _u32(data, stop - 4) == stop - start:
                spans.append((start, stop))
        spans.sort()
    if len(spans) >= MAX_COMPONENTS:
        info.warn("more than %d components; the rest are not read" % MAX_COMPONENTS)
    return spans


def _gaps(spans: Sequence[Tuple[int, int]], size: int) -> List[Tuple[int, int]]:
    """Parts of the file outside the given spans (sorted, non-overlapping)."""
    gaps, pos = [], 0
    for start, end in spans:
        if start - pos >= 16:
            gaps.append((pos, start))
        pos = max(pos, end)
    if size - pos >= 16:
        gaps.append((pos, size))
    return gaps


def _read_component(data: bytes, start: int, end: int,
                    info: KernelInfo) -> Optional[Tuple[int, Dict[str, int]]]:
    """Read one component's sources into info. Returns (start, index fields) when the
    component names a main() method, else None; the main library is looked up only for the
    last component that names one (the entry component), so a file of many components that
    each name a main() is not read many times."""
    size = end - start
    version = _u32(data, start + 4)
    sdk_hash = data[start + 8:start + _HEADER].decode("ascii", "replace")
    library_count = _u32(data, end - 8)
    if library_count > (size - _HEADER - 12) // 4:
        raise _Bad("library count %d does not fit the component" % library_count)
    offsets_pos = end - 8 - 4 * (library_count + 1)      # libraryOffsets[]
    table = _u32(data, end - 12)                          # last library offset = source table
    if not _HEADER < table <= offsets_pos - start - 4:
        raise _Bad("source table offset %d is outside the component" % table)
    count = _u32(data, start + table)
    if count > _MAX_TABLE:
        raise _Bad("source table declares %d sources" % count)
    # the fixed index fields come before the library offsets; the source table ends where
    # the next section (the constant table) starts, so one of them is the table's end
    fixed = [_u32(data, offsets_pos - 4 * k) for k in range(1, 13)
             if offsets_pos - 4 * k >= start + _HEADER]
    offsets, index = _source_offsets(data, start, table, count, fixed, size)
    budget = MAX_SOURCES - len(info.sources)
    if len(offsets) > budget:
        info.warn("more than %d sources; the rest are not read" % MAX_SOURCES)
        offsets = offsets[:max(budget, 0)]
    bounds = [start + off for off in offsets[1:]] + [start + index]
    sources = [_read_source(data, start + off, limit, info)
               for off, limit in zip(offsets, bounds)]
    info.sources.extend(sources)
    info.components.append(KernelComponent(version, sdk_hash, library_count, start, size,
                                           len(sources)))
    fields = _main_fields(data, start, end, offsets_pos, version)
    return (start, fields) if fields else None


def _source_offsets(data: bytes, start: int, table: int, count: int,
                    fixed: Iterable[int], size: int) -> Tuple[List[int], int]:
    """The UInt32 offsets of the SourceInfo records and where that index starts (both
    relative to the component), validated: the first record follows the count, the
    offsets increase and stay before the index."""
    for end_candidate in sorted({v for v in fixed if table + 4 <= v <= size}):
        index = end_candidate - 4 * count
        if count == 0:
            if end_candidate == table + 4:
                return [], index
            continue
        if index < table + 4 + count:              # every record takes at least one byte
            continue
        offsets = list(struct.unpack_from(">%dI" % count, data, start + index))
        if (offsets[0] == table + 4 and offsets[-1] < index
                and all(a < b for a, b in zip(offsets, offsets[1:]))):
            return offsets, index
    raise _Bad("source table index not found")


def _read_source(data: bytes, pos: int, limit: int, info: KernelInfo) -> KernelSource:
    """One SourceInfo record: uri, source, lineStarts, importUri (later fields skipped)."""
    try:
        upos, ulen, pos = _read_bytes(data, pos, limit, MAX_URI)
        spos, slen, pos = _read_bytes(data, pos, limit, limit)
        lines, pos = _read_uint(data, pos, limit)
        pos = _skip_uints(data, pos, lines, limit)
        ipos, ilen, pos = _read_bytes(data, pos, limit, MAX_URI)
        uri = _uri(data[upos:upos + ulen])
        import_uri = _uri(data[ipos:ipos + ilen])
    except _Bad as exc:
        raise _Bad("source record: %s" % exc) from None
    if slen > MAX_SOURCE_BYTES:
        info.warn("source of %s has %d bytes, more than the %d MiB limit; left out"
                  % (uri, slen, MAX_SOURCE_BYTES >> 20))
        text = ""
    else:
        text = data[spos:spos + slen].decode("utf-8", "replace")
    return KernelSource(uri, import_uri, text, _line_count(text))


def _main_fields(data: bytes, start: int, end: int, offsets_pos: int,
                 version: int) -> Optional[Dict[str, int]]:
    """The ComponentIndex fields when they check out and name a main() method, else None."""
    if version >= 124:
        count = 9
    elif version >= 69:
        count = 10                                    # compilationMode follows mainMethod
    else:
        return None
    first = offsets_pos - 4 * count
    if first < start + _HEADER:
        return None
    fields = dict(zip(_INDEX_FIELDS, struct.unpack_from(">9I", data, first)))
    order = [fields[name] for name in _INDEX_FIELDS[:-1]]
    if not fields["main_method"] or order != sorted(order) or order[-1] > end - start:
        return None
    return fields


def _main_library(data: bytes, start: int, fields: Dict[str, int]) -> str:
    """Import URI of the library whose main() a component names (mainMethodReference,
    resolved through the canonical names and the string table), or "". A canonical name
    comes after its parent, so the names after the main method are not read."""
    try:
        names = _canonical_names(data, start + fields["canonical_names"],
                                 start + fields["metadata_payloads"], fields["main_method"])
        strings = _string_table(data, start + fields["string_table"],
                                start + fields["component_index"])
        index = fields["main_method"] - 1
        for _ in range(64):                           # walk up to the library
            if not 0 <= index < len(names):
                return ""
            parent, name = names[index]
            if parent == 0:
                return strings[name] if 0 <= name < len(strings) else ""
            index = parent - 1
    except _Bad:
        return ""
    return ""


def _canonical_names(data: bytes, pos: int, limit: int, wanted: int) -> List[Tuple[int, int]]:
    """The first `wanted` (parent, name) entries of the canonical name table."""
    count, pos = _read_uint(data, pos, limit)
    if count > min(_MAX_NAMES, limit - pos):
        raise _Bad("canonical name count")
    names = []
    for _ in range(min(count, wanted)):
        parent, pos = _read_uint(data, pos, limit)
        name, pos = _read_uint(data, pos, limit)
        names.append((parent, name))
    return names


def _string_table(data: bytes, pos: int, limit: int) -> List[str]:
    count, pos = _read_uint(data, pos, limit)
    if count > min(_MAX_NAMES, limit - pos):
        raise _Bad("string table count")
    ends = []
    for _ in range(count):
        value, pos = _read_uint(data, pos, limit)
        ends.append(value)
    strings, previous = [], 0
    for value in ends:
        if value < previous or pos + value > limit:
            raise _Bad("string table offsets")
        strings.append(data[pos + previous:pos + value].decode("utf-8", "replace"))
        previous = value
    return strings


# ------------------------------------------------------------------ carving

def _carve(data: bytes, gaps: Sequence[Tuple[int, int]], info: KernelInfo) -> None:
    """Find SourceInfo records without the index in the parts of the file that no
    component covers: a UInt-prefixed URI, a UInt-prefixed UTF-8 source, then a lineStarts
    list whose length and sum fit the source (one entry per line plus one or two), then the
    import URI. The bytes examined and the URI-like strings looked at are budgeted for the
    whole file, so a file full of URI-like strings that claim long URIs or sources cannot
    keep it busy."""
    seen = set()
    budget = 2 * sum(hi - lo for lo, hi in gaps) + (16 << 20)
    tries = 0
    for lo, hi in gaps:
        for match in _URI_START.finditer(data, lo, hi):
            if len(info.sources) >= MAX_SOURCES:
                info.warn("more than %d sources; the rest are not read" % MAX_SOURCES)
                return
            if tries >= _MAX_CARVE_TRIES or budget < 0:
                info.warn("carving stopped at 0x%x: too many URI-like strings" % match.start())
                return
            tries += 1
            uri_at = match.start()
            for width in (1, 2, 4):
                record = uri_at - width
                if record < lo or record in seen:
                    continue
                source, cost = _carve_record(data, record, uri_at, hi)
                budget -= cost
                if source is not None:
                    seen.add(record)
                    info.sources.append(source)
                    break


def _carve_record(data: bytes, record: int, uri_at: int,
                  hi: int) -> Tuple[Optional[KernelSource], int]:
    """The record at `record` if it checks out, and the work spent on it (URI and source
    bytes scanned, plus 16 per lineStarts entry read one by one). The cheap checks come
    first."""
    cost = 0
    try:
        upos, ulen, pos = _read_bytes(data, record, hi, MAX_URI)
        if upos != uri_at or ulen < 6:
            return None, cost
        cost = ulen
        uri = _uri(data[upos:upos + ulen])
        spos, slen, pos = _read_bytes(data, pos, hi, MAX_SOURCE_BYTES)
        lines, pos = _read_uint(data, pos, hi)
        if slen == 0 or not 1 <= lines <= slen + 2:
            return None, cost
        cost += slen
        raw = data[spos:spos + slen]
        newlines = raw.count(b"\n")
        if lines not in (newlines + 1, newlines + 2):
            return None, cost
        cost += 16 * lines
        total = 0
        for _ in range(lines):
            if pos >= hi:
                return None, cost
            b0 = data[pos]
            if b0 < 0x80:
                total += b0
                pos += 1
            else:
                delta, pos = _read_uint(data, pos, hi)
                total += delta
        ipos, ilen, pos = _read_bytes(data, pos, hi, MAX_URI)
        cost += ilen
        import_uri = _uri(data[ipos:ipos + ilen])
        if total > slen + 1 or (import_uri and not _URI_START.match(import_uri.encode("utf-8"))):
            return None, cost
        text = raw.decode("utf-8")
    except (_Bad, UnicodeDecodeError):
        return None, cost
    return KernelSource(uri, import_uri, text, _line_count(text)), cost


# ------------------------------------------------------------------ summary

def _summarize(info: KernelInfo, main_uri: str) -> None:
    """Main package, pub packages with versions and build-machine paths."""
    if main_uri.startswith("package:"):
        info.main_package = main_uri[8:].split("/", 1)[0]
    else:
        info.main_package = _guess_main_package(info.sources)
    packages: Dict[str, Optional[str]] = {}
    roots: List[str] = []
    main_root = ""
    flutter_root = _flutter_root(info.sources)
    for source in info.sources:
        if not source.uri.startswith("file:///"):
            continue
        path = unquote(source.uri)
        hosted, git = _HOSTED.search(path), _GIT.search(path)
        if hosted:
            packages.setdefault(hosted.group(1), hosted.group(2))
        elif git:
            packages.setdefault(git.group(1), None)
        root = _build_root(path, flutter_root)
        if root not in roots:
            roots.append(root)
        if not main_root and info.main_package and source.package == info.main_package:
            main_root = root
    info.packages = dict(sorted(packages.items()))
    if main_root:
        roots.remove(main_root)
        roots.insert(0, main_root)
    info.build_paths = roots[:MAX_BUILD_PATHS]


def _flutter_root(sources: Sequence[KernelSource]) -> str:
    """Folder of the Flutter SDK the app was built with, as a decoded file URI."""
    for source in sources:
        if source.import_uri.startswith("package:flutter/") and _FLUTTER_ROOT in source.uri:
            return unquote(source.uri.split(_FLUTTER_ROOT, 1)[0])
    return ""


def _build_root(path: str, flutter_root: str) -> str:
    """The folder a file URI reveals: the pub cache, the Flutter SDK, else the package
    folder (the part before /lib/) or the file's folder."""
    cache = _CACHE_ROOT.search(path)
    if cache:
        return path[:cache.start()]
    if flutter_root and path.startswith(flutter_root + "/"):
        return flutter_root
    if "/lib/" in path:
        return path.split("/lib/", 1)[0]
    return path.rsplit("/", 1)[0]


def _guess_main_package(sources: Sequence[KernelSource]) -> str:
    """Without a main() reference: the package whose files are neither in the pub cache
    nor in the Flutter SDK, preferring one with a main.dart."""
    flutter_root = _flutter_root(sources)
    local: List[str] = []
    for source in sources:
        name = source.package
        path = unquote(source.uri)
        if (not name or not path.startswith("file:///") or _CACHE_ROOT.search(path)
                or (flutter_root and path.startswith(flutter_root + "/"))):
            continue
        if source.path == "main.dart":
            return name
        if name not in local:
            local.append(name)
    return local[0] if len(local) == 1 else ""


# ------------------------------------------------------------------ builder for tests

def build_kernel(sources: Sequence[Tuple[str, str, str]], *, components: int = 1,
                 main: Optional[str] = None, format_version: int = 130,
                 sdk_hash: str = "0000000000") -> bytes:
    """A kernel file with the given (file_uri, import_uri, text) sources split over
    `components` components: real component framing, a one-byte body per library, the
    UriSource table with its index, the canonical names and string table needed to name
    main() when `main` (an import URI) is given, and the ComponentIndex trailer."""
    groups: List[List[Tuple[str, str, str]]] = [[] for _ in range(max(components, 1))]
    for i, source in enumerate(sources):
        groups[min(i * len(groups) // max(len(sources), 1), len(groups) - 1)].append(source)
    blobs = []
    for i, group in enumerate(groups):
        last = i == len(groups) - 1
        blobs.append(_build_component(group, main if last else None, format_version,
                                      sdk_hash))
    return b"".join(blobs)


def _uint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return struct.pack(">H", 0x8000 | value)
    return struct.pack(">I", 0xC0000000 | value)


def _line_starts(text: str) -> List[int]:
    """Line starts in UTF-16 code units, then the end of the text plus one, as the front
    end writes them."""
    starts, units = [0], 0
    for char in text:
        units += 2 if ord(char) > 0xFFFF else 1
        if char == "\n":
            starts.append(units)
    return starts + [units + 1]


def _build_component(sources: Sequence[Tuple[str, str, str]], main: Optional[str],
                     version: int, sdk_hash: str) -> bytes:
    out = bytearray(_MAGIC + struct.pack(">I", version))
    out += sdk_hash.encode("ascii")[:10].ljust(10, b"0")
    out += _uint(0)                                         # problemsAsJson
    library_offsets = []
    for _ in sources:
        library_offsets.append(len(out))
        out += b"\x00"                                      # library body
    table = len(out)
    library_offsets.append(table)
    out += struct.pack(">I", len(sources))
    record_offsets = []
    for file_uri, import_uri, text in sources:
        record_offsets.append(len(out))
        uri, body, imp = (file_uri.encode("utf-8"), text.encode("utf-8"),
                          import_uri.encode("utf-8"))
        out += _uint(len(uri)) + uri + _uint(len(body)) + body
        starts = _line_starts(text)
        out += _uint(len(starts))
        previous = 0
        for value in starts:
            out += _uint(value - previous)
            previous = value
        out += _uint(len(imp)) + imp + _uint(0)             # importUri, constructorCoverage
    for offset in record_offsets:
        out += struct.pack(">I", offset)
    constant_table = len(out)
    out += _uint(0)                                         # constants
    constant_index = len(out)
    out += struct.pack(">I", 0)
    canonical = len(out)
    strings = [""]
    main_ref = 0
    if main:
        strings += [main, "@methods", "main"]
        out += _uint(3) + _uint(0) + _uint(1) + _uint(1) + _uint(2) + _uint(2) + _uint(3)
        main_ref = 3
    else:
        out += _uint(0)
    payloads = len(out)
    mappings = len(out)
    out += struct.pack(">I", 0)                             # metadataMappings (RList)
    string_table = len(out)
    encoded = [s.encode("utf-8") for s in strings]
    ends, total = [], 0
    for item in encoded:
        total += len(item)
        ends.append(total)
    out += _uint(len(ends)) + b"".join(_uint(v) for v in ends) + b"".join(encoded)
    index_start = len(out)
    fields = [table, constant_table, constant_index, canonical, payloads, mappings,
              string_table, index_start, main_ref]
    if version < 124:
        fields.append(0)                                    # compilationMode
    words = len(fields) + len(library_offsets) + 2
    out += b"\x00" * ((-(len(out) + 4 * words)) % 8)        # 8-byte aligned component size
    for value in fields + library_offsets + [len(sources)]:
        out += struct.pack(">I", value)
    out += struct.pack(">I", len(out) + 4)
    return bytes(out)
