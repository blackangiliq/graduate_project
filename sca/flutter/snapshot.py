"""Reads the compiled Dart code of a Flutter app: libapp.so, the AOT snapshot of a release
or profile build, and libflutter.so, the engine.

ELF (both files): ELF32 and ELF64 in either byte order. The section table, the program
headers and the dynamic symbols are read with bounds checks; a truncated or damaged file
gives what could be read plus warnings.

Snapshot (libapp.so): gen_snapshot exports the snapshot parts as dynamic symbols:
_kDartVmSnapshotData and _kDartIsolateSnapshotData (with ...Instructions, ...Bss and
_kDartSnapshotBuildId) up to Dart 3.12, and _kDartSnapshotData, _kDartSnapshotText,
_kDartSnapshotBss and _kDartSnapshotBuildId from Dart 3.13. Snapshot data starts with a
header (runtime/vm/snapshot.h): int32 magic 0xdcdcf5f5, int64 length, int64 kind, the
32-character snapshot hash that ties it to one Dart VM version, then the features string
("product no-code_comments ... arm64 android compressed-pointers"). The first feature gives
the build mode: "product" is a release build and "release" a profile build. When the
symbols are missing the headers are found by their magic.

Strings: with compressed pointers (arm64 and x86_64 on Android) the string objects are
serialized into the snapshot data as WriteUnsigned((length << 1) | two_byte) followed by
the Latin-1 or UTF-16LE characters (runtime/vm/app_snapshot.cc, datastream.h). A regular
expression finds runs of such records and they are decoded record by record, so a release
libapp.so is read in a fraction of a second. Without compressed pointers (armeabi-v7a)
strings are image objects instead, and printable runs of the snapshot data are used.

Engine (libflutter.so): the Dart VM version string and the engine revision (see
_engine_revision for how it is told apart from the Skia revision).

Everything here only reads bytes; nothing is loaded or run.
"""
from __future__ import annotations

import re
import struct
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

# ------------------------------------------------------------------ ELF

EM_NAMES = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
_EM_BY_NAME = {"x86": 3, "arm": 40, "x86_64": 62, "aarch64": 183, "riscv": 243}
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = 1, 2, 3, 7, 8, 11
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
PT_LOAD, PT_NOTE = 1, 4
NT_GNU_BUILD_ID = 3

MAX_SECTIONS = 10_000
MAX_SEGMENTS = 1_000
MAX_SYMBOLS = 200_000
MAX_NAME = 4096
MAX_NAME_BYTES = 1 << 20        # name bytes decoded beyond twice the size of a string table
MAX_NOTES = 64
MAX_CODE_RANGES = 16
MAX_WARNINGS = 50


class ElfError(ValueError):
    """The data is not an ELF file."""


@dataclass
class ElfSection:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass
class ElfSegment:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass
class ElfSymbol:
    name: str
    value: int
    size: int
    info: int
    shndx: int


class _Pieces:
    """Lookups in (start, length, target) parts that may overlap. The parts become disjoint
    pieces where the first part holding a key wins, as a search in order would find it, so a
    lookup is a binary search however many sections the file has."""

    def __init__(self, parts: Sequence[Tuple[int, int, int]]) -> None:
        self.starts: List[int] = []
        self.pieces: List[Tuple[int, int, int]] = []     # (start, end, target of start)
        for start, length, target in reversed(parts):    # earlier parts are laid over later ones
            if length <= 0:
                continue
            end = start + length
            i = bisect_right(self.starts, start) - 1
            if i < 0 or self.pieces[i][1] <= start:
                i += 1
            j = bisect_left(self.starts, end)              # pieces i..j-1 overlap the part
            new = []
            if i < j and self.pieces[i][0] < start:
                first, _, value = self.pieces[i]
                new.append((first, start, value))
            new.append((start, end, target))
            if i < j and self.pieces[j - 1][1] > end:
                first, last, value = self.pieces[j - 1]
                new.append((end, last, value + end - first))
            self.pieces[i:j] = new
            self.starts[i:j] = [piece[0] for piece in new]

    def find(self, key: int) -> Optional[int]:
        """The target of a key, or None when no part holds it."""
        i = bisect_right(self.starts, key) - 1
        if i >= 0 and key < self.pieces[i][1]:
            start, _, target = self.pieces[i]
            return target + key - start
        return None


class ElfFile:
    """A parsed ELF file. Build it with parse_elf()."""

    def __init__(self, data: bytes, bits: int, little: bool, machine: int,
                 elf_type: int) -> None:
        self.data = data
        self.bits = bits
        self.little = little
        self.machine = machine
        self.type = elf_type
        self.sections: List[ElfSection] = []
        self.segments: List[ElfSegment] = []
        self.symbols: List[ElfSymbol] = []          # the dynamic symbols (.dynsym)
        self.warnings: List[str] = []
        self._maps: Optional[Tuple[_Pieces, _Pieces]] = None   # file -> memory, memory -> file

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append("ELF: " + message)

    @property
    def arch(self) -> str:
        """"aarch64", "arm", "x86_64", "x86", "riscv64" ... from the machine field."""
        if self.machine == 243:
            return "riscv%d" % self.bits
        return EM_NAMES.get(self.machine, "machine-%d" % self.machine)

    def section(self, name: str) -> Optional[ElfSection]:
        return next((s for s in self.sections if s.name == name), None)

    def has_section(self, name: str) -> bool:
        return self.section(name) is not None

    def symbol(self, name: str) -> Optional[ElfSymbol]:
        """The dynamic symbol with this name, or None."""
        return next((s for s in self.symbols if s.name == name), None)

    def _mapped(self) -> List[Tuple[int, int, int]]:
        """(virtual address, file offset, size in the file) of every mapped part: the
        PT_LOAD segments, or the allocated sections when there are none."""
        loads = [(s.vaddr, s.offset, s.filesz) for s in self.segments if s.type == PT_LOAD]
        return loads or [(s.addr, s.offset, s.size) for s in self.sections
                         if s.flags & SHF_ALLOC and s.type != SHT_NOBITS]

    def _pieces(self) -> Tuple[_Pieces, _Pieces]:
        """The mapped parts as two lookup tables, built once: file offset -> virtual address
        and virtual address -> file offset (only the bytes that are in the file)."""
        if self._maps is None:
            mapped = self._mapped()
            size = len(self.data)
            self._maps = (_Pieces([(base, length, start) for start, base, length in mapped]),
                          _Pieces([(start, max(0, min(length, size - base)), base)
                                   for start, base, length in mapped]))
        return self._maps

    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        """File offset of a virtual address; None when the address has no bytes in the
        file."""
        return self._pieces()[1].find(vaddr)

    def offset_to_vaddr(self, offset: int) -> Optional[int]:
        """Virtual address of a file offset; None when that part of the file is not
        mapped."""
        return self._pieces()[0].find(offset)

    def section_range(self, section: ElfSection) -> Tuple[int, int]:
        """(start, end) of a section's bytes in the file, clamped to the file; empty for
        NOBITS."""
        start = min(section.offset, len(self.data))
        if section.type == SHT_NOBITS:
            return start, start
        return start, min(section.offset + section.size, len(self.data))

    def symbol_range(self, symbol: ElfSymbol) -> Optional[Tuple[int, int]]:
        """(start, end) of a symbol's bytes in the file, or None."""
        start = self.vaddr_to_offset(symbol.value)
        if start is None:
            return None
        return start, min(start + symbol.size, len(self.data))

    def build_id(self) -> str:
        """The GNU build ID (hex) from the note sections or PT_NOTE segments."""
        size = len(self.data)
        spans = [self.section_range(s) for s in self.sections if s.type == SHT_NOTE]
        if not spans:
            spans = [(min(p.offset, size), min(p.offset + p.filesz, size))
                     for p in self.segments if p.type == PT_NOTE]
        word = struct.Struct(("<" if self.little else ">") + "III")
        for start, end in spans:
            pos = start
            for _ in range(MAX_NOTES):
                if pos + 12 > end:
                    break
                namesz, descsz, note_type = word.unpack_from(self.data, pos)
                name_at = pos + 12
                desc_at = name_at + ((namesz + 3) & ~3)
                if desc_at + descsz > end:
                    break
                if (note_type == NT_GNU_BUILD_ID
                        and self.data[name_at:name_at + namesz].rstrip(b"\0") == b"GNU"):
                    return self.data[desc_at:desc_at + descsz].hex()
                pos = desc_at + ((descsz + 3) & ~3)
        return ""

    def code_ranges(self) -> List[Tuple[int, int, int]]:
        """(file start, file end, virtual address) of the code: .text, else every executable
        section, else every executable PT_LOAD segment; repeated ranges once, at most
        MAX_CODE_RANGES."""
        text = self.section(".text")
        sections = [text] if text is not None else [
            s for s in self.sections if s.flags & SHF_EXECINSTR]
        ranges = []
        for section in sections:
            start, end = self.section_range(section)
            if end > start:
                ranges.append((start, end, section.addr))
        if not ranges:
            for seg in self.segments:
                if seg.type == PT_LOAD and seg.flags & 1 and seg.offset < len(self.data):
                    ranges.append((seg.offset, min(seg.offset + seg.filesz, len(self.data)),
                                   seg.vaddr))
        return list(dict.fromkeys(ranges))[:MAX_CODE_RANGES]


def parse_elf(data: bytes) -> ElfFile:
    """Parse an ELF file. Raises ElfError only when the data is not ELF at all; damaged or
    truncated tables give warnings and whatever could be read."""
    data = data if isinstance(data, bytes) else bytes(data)
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    little = {1: True, 2: False}.get(data[5])
    if bits is None or little is None:
        raise ElfError("unknown ELF class or byte order")
    order = "<" if little else ">"
    header = struct.Struct(order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"))
    if len(data) < 16 + header.size:
        raise ElfError("truncated ELF header")
    (elf_type, machine, _version, _entry, phoff, shoff, _flags, _ehsize, phentsize, phnum,
     shentsize, shnum, shstrndx) = header.unpack_from(data, 16)
    elf = ElfFile(data, bits, little, machine, elf_type)
    _read_sections(elf, order, shoff, shentsize, shnum, shstrndx)
    _read_segments(elf, order, phoff, phentsize, phnum)
    _read_dynsym(elf, order)
    return elf


_DART_SYMBOL = re.compile(rb"_{0,4}kDart[0-9A-Za-z_]{1,64}")


class _Names:
    """The names of an ELF string table (start..end of the file), decoded once per offset
    and within a byte budget, so entries that share or overlap one long name cost no more
    than the table. The names of the Dart snapshot symbols are read whatever the budget."""

    def __init__(self, data: bytes, start: int, end: int) -> None:
        self.data, self.start, self.end = data, start, end
        self.budget = 2 * max(0, end - start) + MAX_NAME_BYTES
        self.cache: Dict[int, str] = {}

    def get(self, offset: int) -> str:
        """The NUL-terminated name at offset, at most MAX_NAME bytes; "" outside the table
        or past the budget."""
        pos = self.start + offset
        name = self.cache.get(pos)
        if name is None:
            name = self.cache[pos] = self._decode(pos)
        return name

    def _decode(self, pos: int) -> str:
        if not 0 <= pos < self.end:
            return ""
        limit = min(self.end, pos + MAX_NAME)
        stop = self.data.find(b"\0", pos, limit)
        stop = limit if stop < 0 else stop
        if stop - pos > self.budget and not _DART_SYMBOL.fullmatch(self.data, pos, stop):
            return ""
        self.budget -= stop - pos
        return self.data[pos:stop].decode("utf-8", "replace")


def _table(elf: ElfFile, what: str, offset: int, entsize: int, count: int,
           layout: struct.Struct, cap: int) -> List[tuple]:
    """Fixed-size entries of a table, as many as fit in the file and under the cap."""
    if not count or not offset:
        return []
    if entsize < layout.size:
        elf.warn("%s entries of %d bytes are too small" % (what, entsize))
        return []
    fit = max(0, (len(elf.data) - offset) // entsize) if offset < len(elf.data) else 0
    usable = min(count, cap, fit)
    if usable < count:
        elf.warn("%s: %d of %d entries readable" % (what, usable, count))
    return [layout.unpack_from(elf.data, offset + i * entsize) for i in range(usable)]


def _read_sections(elf: ElfFile, order: str, shoff: int, shentsize: int, shnum: int,
                   shstrndx: int) -> None:
    layout = struct.Struct(order + ("IIIIIIIIII" if elf.bits == 32 else "IIQQQQIIQQ"))
    if shoff and (shnum == 0 or shstrndx == 0xFFFF):
        # extended numbering: the real values are in section 0
        first = _table(elf, "section table", shoff, shentsize, 1, layout, 1)
        if first:
            shnum = shnum or first[0][5]
            shstrndx = first[0][6] if shstrndx == 0xFFFF else shstrndx
    raw = _table(elf, "section table", shoff, shentsize, shnum, layout, MAX_SECTIONS)
    names_start = names_end = 0
    if raw and shstrndx < len(raw):
        names_start = raw[shstrndx][4]
        names_end = min(names_start + raw[shstrndx][5], len(elf.data))
    elif raw:
        elf.warn("section name table index %d is out of range" % shstrndx)
    names = _Names(elf.data, names_start, names_end)
    for name, kind, flags, addr, offset, size, link, _info, _align, entsize in raw:
        elf.sections.append(ElfSection(names.get(name), kind, flags, addr, offset, size, link,
                                       entsize))


def _read_segments(elf: ElfFile, order: str, phoff: int, phentsize: int,
                   phnum: int) -> None:
    if elf.bits == 32:
        layout = struct.Struct(order + "IIIIIIII")
        for kind, offset, vaddr, _paddr, filesz, memsz, flags, _align in _table(
                elf, "program headers", phoff, phentsize, phnum, layout, MAX_SEGMENTS):
            elf.segments.append(ElfSegment(kind, flags, offset, vaddr, filesz, memsz))
    else:
        layout = struct.Struct(order + "IIQQQQQQ")
        for kind, flags, offset, vaddr, _paddr, filesz, memsz, _align in _table(
                elf, "program headers", phoff, phentsize, phnum, layout, MAX_SEGMENTS):
            elf.segments.append(ElfSegment(kind, flags, offset, vaddr, filesz, memsz))


def _read_dynsym(elf: ElfFile, order: str) -> None:
    table = next((s for s in elf.sections if s.type == SHT_DYNSYM), None)
    if table is None:
        return
    if not 0 <= table.link < len(elf.sections):
        elf.warn("dynamic symbols have no string table")
        return
    names = _Names(elf.data, *elf.section_range(elf.sections[table.link]))
    # positions of name, value, size, info and section index in Elf32_Sym / Elf64_Sym
    if elf.bits == 32:
        layout, fields = struct.Struct(order + "IIIBBH"), (0, 1, 2, 3, 5)
    else:
        layout, fields = struct.Struct(order + "IBBHQQ"), (0, 4, 5, 1, 3)
    entsize = table.entsize or layout.size
    for row in _table(elf, ".dynsym", table.offset, entsize, table.size // entsize, layout,
                      MAX_SYMBOLS):
        name, value, size, info, shndx = (row[i] for i in fields)
        elf.symbols.append(ElfSymbol(names.get(name), value, size, info, shndx))


# ------------------------------------------------------------------ snapshot header

SNAPSHOT_MAGIC = 0xDCDCF5F5
_SNAPSHOT_MAGIC = struct.pack("<I", SNAPSHOT_MAGIC)
# Snapshot::Kind numbering (runtime/vm/snapshot.h); Dart 3.13 removed kFullCore
KINDS_UP_TO_3_12 = {0: "kFull", 1: "kFullCore", 2: "kFullJIT", 3: "kFullAOT", 4: "kModule"}
KINDS_FROM_3_13 = {0: "kFull", 1: "kFullJIT", 2: "kFullAOT", 3: "kModule"}
_AOT_KINDS = {0: "kFull", 2: "kFullAOT", 3: "kFullAOT"}  # an AOT ELF, Dart version unknown
_JIT_KINDS = ("kFullJIT", "kFullCore")
_ARCH_FEATURES = {"ia32", "x64", "arm", "arm64", "arm64e", "riscv32", "riscv64"}
_HASH = re.compile(rb"[0-9A-Za-z]{32}")
MAX_FEATURES = 1024

# the Dart snapshot data symbols, by Dart version, without the leading underscore
_DATA_SYMBOLS_3_13 = ("kDartSnapshotData",)
_DATA_SYMBOLS_3_12 = ("kDartVmSnapshotData", "kDartIsolateSnapshotData")


@dataclass
class SnapshotHeader:
    """The header of one Dart snapshot data blob."""

    offset: int                   # where the header starts in the file
    length: int                   # the header's length field
    kind: int
    kind_name: str                # "kFullAOT", "kFullCore" ...; "" when the number is ambiguous
    version_hash: str             # 32 characters, one per Dart VM version
    features: List[str]
    body: int                     # where the snapshot contents start, after the features

    @property
    def build_mode(self) -> str:
        """"release" (product AOT), "profile" (release AOT), "debug" (a JIT snapshot, only
        used by debug builds) or "unknown"."""
        if self.kind_name in _JIT_KINDS:
            return "debug"
        return build_mode(self.features)


def build_mode(features: Sequence[str]) -> str:
    """Flutter build mode of an AOT snapshot from its first feature."""
    first = features[0] if features else ""
    return {"product": "release", "release": "profile"}.get(first, "unknown")


def read_snapshot_header(data: bytes, offset: int = 0,
                         kinds: Optional[Dict[int, str]] = None) -> Optional[SnapshotHeader]:
    """The snapshot header at offset (e.g. a whole isolate_snapshot_data file), or None.
    `kinds` maps kind numbers to names when the Dart version is known; without it only
    numbers that mean the same in every version are named (and kind 1, which is kFullCore
    without code and kFullJIT with code)."""
    if offset < 0 or offset + 52 > len(data) or data[offset:offset + 4] != _SNAPSHOT_MAGIC:
        return None
    length, kind = struct.unpack_from("<qq", data, offset + 4)
    raw_hash = data[offset + 20:offset + 52]
    if not _HASH.fullmatch(raw_hash):
        return None
    end = data.find(b"\0", offset + 52, offset + 52 + MAX_FEATURES)
    if end < 0:
        return None
    features = data[offset + 52:end].decode("ascii", "replace").split()
    if kinds is not None:
        name = kinds.get(kind, "")
    elif kind == 1:
        name = "kFullJIT" if _ARCH_FEATURES & set(features) else "kFullCore"
    else:
        name = {0: "kFull"}.get(kind, "")
    return SnapshotHeader(offset, length, kind, name, raw_hash.decode("ascii"), features,
                          end + 1)


# ------------------------------------------------------------------ Dart string objects

MAX_STRINGS = 200_000
MAX_STRING_CHARS = 1 << 20
MAX_WALK = 64 << 20             # bytes of one snapshot data range searched for strings
MIN_DART_STRINGS = 100          # fewer means the layout is not the compressed one
# Search work allowed in one range: a unit (about a microsecond) per 32 bytes, at least
# _MIN_WORK. A candidate that is not a run costs a unit, a run one plus a unit per 4 lengths
# tried walking back plus one per record dropped as noise. Real snapshot data needs about 4
# units per KiB; bytes built to look like records would need 500.
_WORK_SHIFT = 5
_MIN_WORK = 1 << 16
_TEXT = rb"[\t\n\r\x20-\x7e]"
# Where a run of string records may start: four short strings in a row (a one-byte prefix
# 0x80 + 2 * length, then 1..63 characters), or a long string (a two-byte prefix, then 64
# characters or more). The pattern does not tie a prefix to its length, which keeps the
# search fast; the records are checked when they are decoded.
_RUN = re.compile(rb"(?:[\x82-\xfe]" + _TEXT + rb"{1,63}){4}|[\x00-\x7f][\x80-\xff](?="
                  + _TEXT + rb"{64})")
_RUN_RECORDS = 4                # records a short-string start must really decode to
_BAD_ONE_BYTE = re.compile(rb"[^\t\n\r\x20-\x7e\xa0-\xff]")
_BAD_TWO_BYTE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_ASCII_TEXT = re.compile(r"[\t\n\r\x20-\x7e]+\Z")


def _string_record(data: bytes, pos: int, end: int) -> Optional[Tuple[str, int]]:
    """The serialized string at pos -> (text, next position), or None. The length is
    WriteUnsigned: 7-bit groups, low first, the last byte marked by +0x80."""
    value = shift = 0
    while True:
        if pos >= end or shift > 21:
            return None
        byte = data[pos]
        pos += 1
        if byte >= 0x80:
            value |= (byte - 0x80) << shift
            break
        value |= byte << shift
        shift += 7
    if shift and value < 1 << shift:           # not the shortest form: not a length
        return None
    length = value >> 1
    if not 0 < length <= MAX_STRING_CHARS:
        return None
    if value & 1:                              # TwoByteString, UTF-16LE
        stop = pos + 2 * length
        if stop > end:
            return None
        try:
            text = data[pos:stop].decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        if ord(max(text)) < 0x100 or _BAD_TWO_BYTE.search(text):
            return None                        # the VM would have used a OneByteString
        return text, stop
    stop = pos + length
    if stop > end or _BAD_ONE_BYTE.search(data, pos, stop):
        return None
    return data[pos:stop].decode("latin-1"), stop


def _records_before(data: bytes, pos: int, low: int) -> Tuple[List[str], int]:
    """Short string records that end exactly at pos, walking back (nearest last), and the
    number of lengths tried."""
    found: List[str] = []
    steps = 0
    while len(found) < 64:
        hit = None
        for length in range(1, 64):
            steps += 1
            for prefix, start in ((0x80 + 2 * length, pos - length - 1),
                                  (0x81 + 2 * length, pos - 2 * length - 1)):
                if start >= low and data[start] == prefix:
                    record = _string_record(data, start, pos)
                    if record is not None and record[1] == pos:
                        hit = (record[0], start)
                        break
            if hit or pos - length - 1 < low:
                break
        if hit is None:
            break
        found.append(hit[0])
        pos = hit[1]
    found.reverse()
    return found, steps


def dart_snapshot_strings(data: bytes, start: int = 0, end: Optional[int] = None,
                          limit: int = MAX_STRINGS) -> List[str]:
    """String objects serialized in snapshot data between start and end, in file order.
    A run of records is taken from where the regular expression finds it, extended back
    over short records just before it, and decoded forward until a record does not check
    out; strings that are not plain ASCII at either end of a run are dropped as likely
    noise. The search work is bounded by the size of the range (see _WORK_SHIFT)."""
    end = len(data) if end is None else min(end, len(data))
    out: List[str] = []
    pos = max(0, start)
    work = max(_MIN_WORK, (end - pos) >> _WORK_SHIFT)
    while len(out) < limit and work > 0:
        match = _RUN.search(data, pos, end)
        if match is None:
            break
        first = cursor = match.start()
        run: List[str] = []
        while len(run) < limit:
            record = _string_record(data, cursor, end)
            if record is None:
                break
            run.append(record[0])
            cursor = record[1]
        if len(run) < (1 if data[first] < 0x80 else _RUN_RECORDS):
            work -= 1
            pos = first + 1                    # the candidate is not a run of records
            continue
        before, steps = _records_before(data, first, pos)
        run[:0] = before
        low, high = 0, len(run)
        while low < high and not _ASCII_TEXT.match(run[low]):
            low += 1
        while high > low and not _ASCII_TEXT.match(run[high - 1]):
            high -= 1
        work -= 1 + steps // 4 + len(run) - (high - low)
        out.extend(run[low:high])
        pos = cursor
    return out[:limit]


def ascii_strings(data: bytes, min_len: int = 6, limit: int = MAX_STRINGS,
                  start: int = 0, end: Optional[int] = None) -> List[str]:
    """Printable ASCII runs (tab included) of at least min_len characters, like strings(1)."""
    pattern = re.compile(rb"[\t\x20-\x7e]{%d,}" % max(1, min_len))
    out: List[str] = []
    for match in pattern.finditer(data, start, len(data) if end is None else end):
        out.append(match.group().decode("ascii"))
        if len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------ libapp.so

_PRIVATE_NAME = re.compile(r"_[A-Za-z0-9$_]+@\d+\Z")
_SHORT_PRIVATE_NAME = re.compile(r"_[A-Za-z0-9$]{1,4}@\d+\Z")
MIN_PRIVATE_NAMES = 50          # fewer private names are too few to judge obfuscation


@dataclass
class ObfuscationInfo:
    """Fingerprint of Dart obfuscation (--obfuscate) in the snapshot strings."""

    obfuscated: Optional[bool] = None      # None: could not be judged
    package_uri_count: int = 0             # distinct "package:..." strings
    dart_uri_count: int = 0                # distinct "dart:..." strings
    short_private_names: int = 0           # names like "_Xb@5048458"
    private_names: int = 0                 # every "_name@library" string
    note: str = ""


@dataclass
class SnapshotInfo:
    """What analyze_libapp() found in libapp.so."""

    kind: int = -1
    kind_name: str = ""
    version_hash: str = ""
    features: List[str] = field(default_factory=list)
    build_mode: str = "unknown"            # release | profile | unknown
    arch: str = ""                         # ELF machine: aarch64, arm, x86_64, x86 ...
    build_id: str = ""
    symbols_present: bool = False          # a .symtab or .debug_* section is in the file
    strings: List[str] = field(default_factory=list)
    strings_source: str = ""               # "dart" (string objects) or "ascii" (printable runs)
    package_uris: List[str] = field(default_factory=list)
    obfuscation: ObfuscationInfo = field(default_factory=ObfuscationInfo)
    warnings: List[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append("libapp.so: " + message)


def analyze_libapp(data: bytes) -> SnapshotInfo:
    """Read the AOT snapshot in libapp.so: kind, hash, features and build mode, debug
    symbols, the strings of the Dart code and the obfuscation fingerprint. Never raises on
    bad data: problems are in .warnings."""
    data = data if isinstance(data, bytes) else bytes(data)
    info = SnapshotInfo()
    header: Optional[SnapshotHeader] = None
    ranges: List[Tuple[int, int]] = []
    try:
        elf: Optional[ElfFile] = parse_elf(data)
    except ElfError as exc:
        elf = None
        info.warn(str(exc))
    if elf is not None:
        for message in elf.warnings:
            info.warn(message)
        info.arch = elf.arch
        info.build_id = elf.build_id()
        info.symbols_present = any(
            s.type == SHT_SYMTAB or s.name.startswith((".debug_", ".zdebug_"))
            for s in elf.sections)
        header, ranges = _snapshot_from_symbols(elf, info)
    if header is None:
        header, ranges = _snapshot_by_magic(data, info)
    if header is None:
        info.warn("no Dart snapshot found")
    else:
        info.kind, info.kind_name = header.kind, header.kind_name
        info.version_hash, info.features = header.version_hash, header.features
        info.build_mode = build_mode(header.features)
    for start, end in ranges:
        if end - start > MAX_WALK:
            info.warn("snapshot data of %d bytes is over the %d-byte limit; strings are read "
                      "from its start only" % (end - start, MAX_WALK))
    ranges = [(start, min(end, start + MAX_WALK)) for start, end in ranges]
    info.strings, info.strings_source = _snapshot_strings(data, ranges)
    info.package_uris = [s for s in info.strings if s.startswith("package:")]
    info.obfuscation = _obfuscation(info.strings)
    return info


def _snapshot_from_symbols(elf: ElfFile, info: SnapshotInfo
                           ) -> Tuple[Optional[SnapshotHeader], List[Tuple[int, int]]]:
    """Header of the isolate snapshot and the data ranges, from the exported symbols."""
    symbols = {s.name.lstrip("_"): s for s in elf.symbols if s.name}
    if _DATA_SYMBOLS_3_13[0] in symbols:
        names, kinds = _DATA_SYMBOLS_3_13, KINDS_FROM_3_13
    elif _DATA_SYMBOLS_3_12[1] in symbols:
        names, kinds = _DATA_SYMBOLS_3_12, KINDS_UP_TO_3_12
    else:
        if elf.symbols:
            info.warn("no Dart snapshot symbols")
        return None, []
    header = None
    ranges = []
    for name in names:
        symbol = symbols.get(name)
        if symbol is None:
            info.warn("symbol _%s is missing" % name)
            continue
        span = elf.symbol_range(symbol)
        if span is None:
            info.warn("symbol _%s has no data in the file" % name)
            continue
        found = read_snapshot_header(elf.data, span[0], kinds)
        if found is None:
            info.warn("no snapshot header at symbol _%s" % name)
            continue
        ranges.append((found.body, span[1]))
        header = found                          # the isolate snapshot comes last
    return header, ranges


def _snapshot_by_magic(data: bytes, info: SnapshotInfo
                       ) -> Tuple[Optional[SnapshotHeader], List[Tuple[int, int]]]:
    """Snapshot headers found by their magic when the symbols are missing: the largest one
    is the isolate snapshot; each runs to the next header or the end of the file."""
    headers = []
    pos = data.find(_SNAPSHOT_MAGIC)
    while pos >= 0 and len(headers) < 16:
        found = read_snapshot_header(data, pos, _AOT_KINDS)
        if found is not None:
            headers.append(found)
        pos = data.find(_SNAPSHOT_MAGIC, pos + 4)
    if not headers:
        return None, []
    info.warn("snapshot found by its magic, not by the exported symbols")
    bounds = [h.offset for h in headers[1:]] + [len(data)]
    ranges = [(h.body, stop) for h, stop in zip(headers, bounds)]
    return max(headers, key=lambda h: h.length), ranges


def _snapshot_strings(data: bytes, ranges: Sequence[Tuple[int, int]]
                      ) -> Tuple[List[str], str]:
    """Distinct strings of the snapshot data in file order, and where they came from."""
    found = _distinct(s for start, end in ranges
                      for s in dart_snapshot_strings(data, start, end))
    if len(found) >= MIN_DART_STRINGS:
        return found, "dart"
    spans = list(ranges) or [(0, len(data))]
    return _distinct(s for start, end in spans
                     for s in ascii_strings(data, start=start, end=end)), "ascii"


def _distinct(strings: Iterable[str]) -> List[str]:
    seen: Dict[str, None] = {}
    for text in strings:
        if text not in seen:
            seen[text] = None
            if len(seen) >= MAX_STRINGS:
                break
    return list(seen)


def _obfuscation(strings: Sequence[str]) -> ObfuscationInfo:
    """--obfuscate renames classes, members and libraries: the private names become short
    ("_Xb@5048458") and almost all package: URIs of the libraries go (4 of 380 are left in
    the obfuscated build of the probe app). The verdict is based
    on the share of short private names (2% in a plain release build of the probe app, 83%
    with --obfuscate); a snapshot with too few names is not judged."""
    result = ObfuscationInfo()
    result.package_uri_count = sum(1 for s in strings if s.startswith("package:"))
    result.dart_uri_count = sum(1 for s in strings if s.startswith("dart:"))
    private = [s for s in strings if _PRIVATE_NAME.match(s)]
    result.private_names = len(private)
    result.short_private_names = sum(1 for s in private if _SHORT_PRIVATE_NAME.match(s))
    if len(private) < MIN_PRIVATE_NAMES:
        result.note = "too few Dart names in the snapshot to judge obfuscation"
        return result
    share = result.short_private_names / len(private)
    if share >= 0.5:
        result.obfuscated = True
    elif share <= 0.25:
        result.obfuscated = False
    result.note = "%d of %d private names are short; %d package: URIs" % (
        result.short_private_names, len(private), result.package_uri_count)
    return result


# ------------------------------------------------------------------ libflutter.so

_DART_VERSION = re.compile(
    rb"\x00(\d+\.\d+\.\d+[0-9A-Za-z.+-]*) \(([a-z]+)\) \(([^()\x00]{1,80})\) on "
    rb"\"([0-9A-Za-z_]+)\"\x00")
_REVISION = re.compile(rb"(?<=\x00)[0-9a-f]{40}(?=\x00)")
MAX_REVISIONS = 64              # 40-hex strings read (a real engine has two)
MAX_LITERALS = 64               # occurrences of "skia" looked at
MAX_MARKERS = 4                 # occurrences of "flutter_engine" looked at (a real engine has one)
# Work spent looking for the code that uses the markers: bytes of code searched, instructions
# checked as possible references (a unit each, more for one that needs a search back: about a
# microsecond per unit; the engines of Flutter 3.44 need up to 2,500 on arm64, 70,000 on
# x86-64 and 360,000 on armeabi-v7a, where address loads are frequent) and references
# followed (a real engine has two).
_MAX_CODE_SCAN = 512 << 20
_MAX_REF_WORK = 2_000_000
_MAX_REFS = 256


@dataclass
class EngineInfo:
    """What analyze_libflutter() found in libflutter.so."""

    dart_version: str = ""                 # "3.12.2"
    channel: str = ""                      # "stable"
    engine_revision: str = ""              # 40-hex git revision of the engine
    warnings: List[str] = field(default_factory=list)
    version_string: str = ""               # the Dart VM version line as embedded
    skia_revision: str = ""
    revision_candidates: List[str] = field(default_factory=list)   # the 40-hex strings

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append("libflutter.so: " + message)


def analyze_libflutter(data: bytes) -> EngineInfo:
    """Dart version, channel and engine revision of a Flutter engine library. Never raises
    on bad data: problems are in .warnings."""
    data = data if isinstance(data, bytes) else bytes(data)
    info = EngineInfo()
    try:
        elf: Optional[ElfFile] = parse_elf(data)
    except ElfError as exc:
        elf = None
        info.warn(str(exc))
    start, end = 0, len(data)
    if elf is not None:
        for message in elf.warnings:
            info.warn(message)
        rodata = elf.section(".rodata")
        if rodata is not None:
            start, end = elf.section_range(rodata)
    version = _DART_VERSION.search(data, max(0, start - 1), end)
    if version is None and (start, end) != (0, len(data)):
        version = _DART_VERSION.search(data)
    if version is None:
        info.warn("no Dart version string")
    else:
        info.dart_version = version.group(1).decode("ascii")
        info.channel = version.group(2).decode("ascii")
        info.version_string = version.group(0).strip(b"\0").decode("ascii", "replace")
    revisions: Dict[int, str] = {}
    for match in _REVISION.finditer(data, start, end):
        if len(revisions) == MAX_REVISIONS:
            info.warn("more than %d revision strings; the rest are not read" % MAX_REVISIONS)
            break
        revisions[match.start()] = match.group().decode("ascii")
    info.revision_candidates = list(dict.fromkeys(revisions.values()))
    if not revisions:
        info.warn("no 40-character revision string")
        return info
    engine, skia = _engine_revision(elf, data, revisions, (start, end)) if elf else ("", "")
    info.engine_revision, info.skia_revision = engine, skia
    if not engine:
        info.warn("the engine revision could not be told apart from the other revision "
                  "strings: " + ", ".join(info.revision_candidates))
    return info


def _engine_revision(elf: ElfFile, data: bytes, revisions: Dict[int, str],
                     rodata: Tuple[int, int]) -> Tuple[str, str]:
    """(engine revision, Skia revision) read from the code that builds the shader cache
    folder, or ("", "") when that code does not show them.

    The engine embeds two 40-hex git hashes: its own revision (FLUTTER_ENGINE_VERSION) and
    the Skia revision (SKIA_VERSION). In an Android libflutter.so the only code that uses
    them is MakeCacheDirectory and FreeOldCacheDirectory in
    engine/src/flutter/common/graphics/persistent_cache.cc, which build the folder
    {"flutter_engine", GetFlutterEngineVersion(), "skia", GetSkiaVersion()}; the other user,
    PrintUsage, is only linked into flutter_tester. So the revision whose address the code
    loads next after the address of the "flutter_engine" literal is the engine revision,
    and the one loaded next after "skia" is the Skia revision. In release builds the
    getters are inlined and the code loads the addresses directly; in debug builds it calls
    GetFlutterEngineVersion(), a function that only returns the address. The answer counts
    only when every reference agrees. Checked on engine 0cd610717b (Flutter 3.44.8) for
    arm64, armeabi-v7a and x86_64 in debug, profile and release mode, against
    bin/internal/engine.version of the SDK. A file that needs more work than _MAX_CODE_SCAN,
    _MAX_REF_WORK or _MAX_REFS allow gives ("", "")."""
    decoder = _DECODERS.get(elf.arch)
    if decoder is None or not elf.little:
        return "", ""
    markers = _addresses(elf, data, rodata, b"\x00flutter_engine\x00", 1, MAX_MARKERS)
    skia = set(_addresses(elf, data, rodata, b"skia\x00", 0, MAX_LITERALS))
    candidates = {}
    for offset, text in revisions.items():
        address = elf.offset_to_vaddr(offset)
        if address is not None:
            candidates[address] = text
    engine_votes: Counter = Counter()
    skia_votes: Counter = Counter()
    scan, work, followed = _MAX_CODE_SCAN, _MAX_REF_WORK, 0
    for start, end, base in elf.code_ranges():
        code = _Code(data, start, end, base)
        for marker in markers:
            scan -= end - start
            if scan < 0:
                return "", ""
            refs, spent = decoder.refs(code, marker, work)
            work -= spent
            followed += len(refs)
            if work < 0 or followed > _MAX_REFS:
                return "", ""
            for ref in refs:
                after_skia = False
                for kind, target in decoder.events(code, ref):
                    if kind == "call":
                        target = decoder.getter(code, target)
                    if target in skia:
                        after_skia = True
                    elif target in candidates:
                        if after_skia:
                            skia_votes[candidates[target]] += 1
                            break
                        engine_votes[candidates[target]] += 1
    if len(engine_votes) != 1:
        return "", ""
    engine = next(iter(engine_votes))
    if engine in skia_votes:
        return "", ""
    others = [revision for revision in skia_votes if revision != engine]
    return engine, others[0] if len(others) == 1 else ""


def _addresses(elf: ElfFile, data: bytes, span: Tuple[int, int], literal: bytes,
               skip: int, limit: int) -> List[int]:
    """Virtual addresses of the first `limit` occurrences of a literal in a file range (plus
    skip)."""
    found: List[int] = []
    pos = data.find(literal, *span)
    for _ in range(limit):
        if pos < 0:
            break
        address = elf.offset_to_vaddr(pos + skip)
        if address is not None:
            found.append(address)
        pos = data.find(literal, pos + 1, span[1])
    return found


_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_I32 = struct.Struct("<i")


class _Code:
    """A range of machine code in the file (little-endian) and its virtual address."""

    def __init__(self, data: bytes, start: int, end: int, base: int) -> None:
        self.data, self.start, self.end, self.base = data, start, end, base

    def va(self, offset: int) -> int:
        return self.base + offset - self.start

    def offset(self, address: int) -> Optional[int]:
        """File offset of an address inside this range, or None."""
        offset = self.start + address - self.base
        return offset if self.start <= offset < self.end else None

    def u16(self, offset: int) -> int:
        return _U16.unpack_from(self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return _U32.unpack_from(self.data, offset)[0]


class _Arm64:
    """AArch64: an address is built by ADRP (its 4 KiB page) and ADD (the offset in the
    page); calls are BL."""

    WINDOW = 48                     # instructions followed after a reference

    @staticmethod
    def _page(code: _Code, pos: int, reg: int, low: int) -> Optional[int]:
        """Page that the nearest ADRP into reg before pos (up to 64 instructions back, not
        before low) computes."""
        at = pos - 4
        while at >= max(low, pos - 256):
            word = code.u32(at)
            if (word & 0x9F000000) == 0x90000000 and (word & 31) == reg:
                imm = ((word >> 29) & 3) | (((word >> 5) & 0x7FFFF) << 2)
                if imm & 0x100000:
                    imm -= 0x200000
                return (code.va(at) & ~0xFFF) + (imm << 12)
            at -= 4
        return None

    @classmethod
    def refs(cls, code: _Code, target: int, limit: int) -> Tuple[List[int], int]:
        """Offsets of the code that builds the address target, and the work spent (see
        _MAX_REF_WORK; more than limit when the search stopped there)."""
        # ADD Xd, Xn, #imm12 is [Rn/Rd bits, imm12 low six bits << 2 | Rn high bits,
        # imm12 >> 6, 0x91] in memory: search the two fixed bytes, then check the rest
        imm = target & 0xFFF
        low = (imm & 0x3F) << 2
        found = []
        work = 0
        for match in re.compile(re.escape(bytes([imm >> 6, 0x91]))).finditer(
                code.data, code.start + 2, code.end):
            work += 1
            if work > limit:
                break
            pos = match.start() - 2
            if (pos - code.start) & 3 or not low <= code.data[pos + 1] <= low | 3:
                continue
            work += 16                                       # the search back for the ADRP
            reg = (code.u32(pos) >> 5) & 31
            if cls._page(code, pos, reg, code.start) == target & ~0xFFF:
                found.append(pos)
        return found, work

    @classmethod
    def events(cls, code: _Code, ref: int) -> List[Tuple[str, int]]:
        found = []
        for pos in range(ref + 4, min(code.end - 3, ref + 4 * cls.WINDOW), 4):
            word = code.u32(pos)
            if (word & 0xFFC00000) == 0x91000000:            # ADD (immediate)
                page = cls._page(code, pos, (word >> 5) & 31, code.start)
                if page is not None:
                    found.append(("load", page + ((word >> 10) & 0xFFF)))
            elif (word & 0xFC000000) == 0x94000000:          # BL
                imm = word & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                found.append(("call", code.va(pos) + 4 * imm))
        return found

    @classmethod
    def getter(cls, code: _Code, address: int) -> Optional[int]:
        """The address a function returns when all it does is build one and return."""
        start = code.offset(address)
        if start is None:
            return None
        result = None
        for pos in range(start, min(code.end - 3, start + 24), 4):
            word = code.u32(pos)
            if word == 0xD65F03C0:                           # RET
                return result
            if (word & 0xFFC00000) == 0x91000000 and (word & 31) == 0:
                page = cls._page(code, pos, (word >> 5) & 31, start)
                if page is not None:
                    result = page + ((word >> 10) & 0xFFF)
        return None


_LEA_RIP = re.compile(rb"(?=[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d])")
_CALL_REL32 = re.compile(rb"\xe8")


class _X64:
    """x86-64: an address is loaded by LEA reg, [RIP + disp32]; calls are CALL rel32.
    Instructions are not decoded: the bytes after a reference are searched for these two
    forms, and only targets that are known strings or getters count."""

    WINDOW = 192                    # bytes followed after a reference

    @staticmethod
    def _lea_target(code: _Code, pos: int) -> int:
        return code.va(pos) + 7 + _I32.unpack_from(code.data, pos + 3)[0]

    @classmethod
    def refs(cls, code: _Code, target: int, limit: int) -> Tuple[List[int], int]:
        found = []
        work = 0
        for match in _LEA_RIP.finditer(code.data, code.start, code.end - 7):
            work += 1
            if work > limit:
                break
            if cls._lea_target(code, match.start()) == target:
                found.append(match.start())
        return found, work

    @classmethod
    def events(cls, code: _Code, ref: int) -> List[Tuple[str, int]]:
        start, stop = ref + 7, min(code.end - 7, ref + 7 + cls.WINDOW)
        found = [(m.start(), "load", cls._lea_target(code, m.start()))
                 for m in _LEA_RIP.finditer(code.data, start, stop)]
        found += [(m.start(), "call",
                   code.va(m.start()) + 5 + _I32.unpack_from(code.data, m.start() + 1)[0])
                  for m in _CALL_REL32.finditer(code.data, start, stop)]
        return [(kind, target) for _pos, kind, target in sorted(found)]

    @classmethod
    def getter(cls, code: _Code, address: int) -> Optional[int]:
        start = code.offset(address)
        if start is None or start + 16 > code.end:
            return None
        head = code.data[start:start + 16]
        lea = head.find(b"\x48\x8d\x05")                     # lea rax, [rip + disp32]
        if 0 <= lea <= 8 and b"\xc3" in head[lea + 7:lea + 10]:
            return cls._lea_target(code, start + lea)
        return None


_ADD_PC = re.compile(rb"[\x78-\x7f\xf8-\xff]\x44")


class _Thumb:
    """ARM Thumb-2 (armeabi-v7a): an address is loaded as an offset from a literal pool
    (LDR Rd, [PC, #imm]) and completed by ADD Rd, PC; calls are BL."""

    WINDOW = 96                     # halfwords followed after a reference

    @staticmethod
    def _literal(code: _Code, pos: int, reg: int, low: int) -> Optional[int]:
        """Value that the nearest PC-relative LDR into reg before pos (up to 16 halfwords
        back, not before low) loads from its literal pool."""
        at = pos - 2
        while at >= max(low, pos - 32):
            half = code.u16(at)
            if reg < 8 and half >> 8 == 0x48 | reg:          # LDR Rt, [PC, #imm8 * 4]
                literal = ((code.va(at) + 4) & ~3) + (half & 0xFF) * 4
            elif at + 4 <= pos and half in (0xF8DF, 0xF85F) and code.u16(at + 2) >> 12 == reg:
                imm = code.u16(at + 2) & 0xFFF                # LDR.W Rt, [PC, #+-imm12]
                literal = ((code.va(at) + 4) & ~3) + (imm if half == 0xF8DF else -imm)
            else:
                at -= 2
                continue
            offset = code.offset(literal)
            if offset is None or offset + 4 > code.end:
                return None
            return code.u32(offset)
        return None

    @staticmethod
    def _add_pc_reg(half: int) -> int:
        return (half & 7) | ((half >> 4) & 8)

    @classmethod
    def refs(cls, code: _Code, target: int, limit: int) -> Tuple[List[int], int]:
        found = []
        work = 0
        for match in _ADD_PC.finditer(code.data, code.start, code.end):
            work += 1
            if work > limit:
                break
            pos = match.start()
            if (pos - code.start) & 1:
                continue
            work += 4                                        # the search back for the LDR
            value = cls._literal(code, pos, cls._add_pc_reg(code.data[pos]), code.start)
            if value is not None and (value + code.va(pos) + 4) & 0xFFFFFFFF == target:
                found.append(pos)
        return found, work

    @classmethod
    def events(cls, code: _Code, ref: int) -> List[Tuple[str, int]]:
        found = []
        pos = ref + 2
        stop = min(code.end - 4, ref + 2 * cls.WINDOW)
        while pos < stop:
            half = code.u16(pos)
            if half >> 11 in (0x1D, 0x1E, 0x1F):               # a 32-bit instruction
                second = code.u16(pos + 2)
                if half >> 11 == 0x1E and second & 0xD000 == 0xD000:   # BL
                    sign = (half >> 10) & 1
                    imm = ((sign << 24) | ((1 - (((second >> 13) & 1) ^ sign)) << 23)
                           | ((1 - (((second >> 11) & 1) ^ sign)) << 22)
                           | ((half & 0x3FF) << 12) | ((second & 0x7FF) << 1))
                    if sign:
                        imm -= 1 << 25
                    found.append(("call", code.va(pos) + 4 + imm))
                pos += 4
                continue
            if half & 0xFF78 == 0x4478:                         # ADD Rd, PC
                value = cls._literal(code, pos, cls._add_pc_reg(half), code.start)
                if value is not None:
                    found.append(("load", (value + code.va(pos) + 4) & 0xFFFFFFFF))
            pos += 2
        return found

    @classmethod
    def getter(cls, code: _Code, address: int) -> Optional[int]:
        start = code.offset(address & ~1)
        if start is None:
            return None
        result = None
        for pos in range(start, min(code.end - 1, start + 12), 2):
            half = code.u16(pos)
            if half == 0x4770:                                  # BX LR
                return result
            if half & 0xFF78 == 0x4478 and cls._add_pc_reg(half) == 0:
                value = cls._literal(code, pos, 0, start)
                if value is not None:
                    result = (value + code.va(pos) + 4) & 0xFFFFFFFF
        return None


_DECODERS = {"aarch64": _Arm64, "x86_64": _X64, "arm": _Thumb}


# ------------------------------------------------------------------ builders for tests

def _write_unsigned(value: int) -> bytes:
    """The VM's WriteUnsigned: 7-bit groups, low first, the last one plus 0x80."""
    out = bytearray()
    while value > 0x7F:
        out.append(value & 0x7F)
        value >>= 7
    out.append(value + 0x80)
    return bytes(out)


def build_snapshot_data(features: Sequence[str], strings: Sequence[str],
                        version_hash: str, *, kind: int = 3) -> bytes:
    """Snapshot data for tests: the header, bytes that are not strings, the strings
    serialized as the VM writes them (Latin-1, or UTF-16LE when a character does not fit),
    then more bytes that are not strings."""
    body = bytearray(range(16))
    for text in strings:
        if all(ord(char) < 0x100 for char in text):
            body += _write_unsigned(len(text) << 1) + text.encode("latin-1")
        else:
            units = text.encode("utf-16-le")
            body += _write_unsigned((len(units) // 2) << 1 | 1) + units
    body += bytes(16)
    head = (version_hash.encode("ascii")[:32].ljust(32, b"0")
            + " ".join(features).encode("ascii") + b"\0")
    length = 20 + len(head) + len(body) - 4
    return _SNAPSHOT_MAGIC + struct.pack("<qq", length, kind) + head + bytes(body)




def build_elf(symbols: Dict[str, bytes], *,
              sections: Sequence[Union[str, Tuple[str, bytes]]] = (),
              arch: str = "aarch64", bits: int = 64, little: bool = True,
              build_id: bytes = b"", vaddr_offset: int = 0x1000) -> bytes:
    """An ELF shared object for tests: each symbol's bytes in .rodata, exported through
    .dynsym and .dynstr. `sections` adds sections by name (empty) or as (name, bytes): a
    ".text" one is code, .symtab, .debug_* and .comment are not loaded, the rest is data.
    `build_id` adds a GNU build-id note. One PT_LOAD segment maps the file at its offset
    plus vaddr_offset."""
    order = "<" if little else ">"
    wide = bits == 64
    header_size, ph_size, sh_size, sym_size = (64, 56, 64, 24) if wide else (52, 32, 40, 16)
    phnum = 2 if build_id else 1
    out = bytearray(header_size + ph_size * phnum)
    names = bytearray(b"\0")
    rows: List[Tuple[int, ...]] = [(0,) * 9]

    def add(name: str, kind: int, flags: int, blob: bytes, link: int = 0, info: int = 0,
            align: int = 4, entsize: int = 0) -> int:
        """Append a section's bytes and its header row (name, type, flags, offset, size,
        link, info, alignment, entry size); returns the section's index."""
        out.extend(bytes((-len(out)) % align))
        rows.append((len(names), kind, flags, len(out), len(blob), link, info, align, entsize))
        names.extend(name.encode("ascii") + b"\0")
        out.extend(blob)
        return len(rows) - 1

    rodata = bytearray()
    placed = []                                  # (symbol name, offset in .rodata, size)
    for name, blob in symbols.items():
        rodata += bytes((-len(rodata)) % 16)
        placed.append((name, len(rodata), len(blob)))
        rodata += blob
    rodata_index = add(".rodata", SHT_PROGBITS, SHF_ALLOC, bytes(rodata), align=16)
    note_index = 0
    if build_id:
        note = struct.pack(order + "III", 4, len(build_id), NT_GNU_BUILD_ID) + b"GNU\0"
        note_index = add(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC,
                         note + build_id + bytes((-len(build_id)) % 4))
    dynstr = bytearray(b"\0")
    dynsym = bytearray(sym_size)
    for name, offset, size in placed:
        value = rows[rodata_index][3] + offset + vaddr_offset
        if wide:
            dynsym += struct.pack(order + "IBBHQQ", len(dynstr), 0x11, 0, rodata_index, value,
                                  size)
        else:
            dynsym += struct.pack(order + "IIIBBH", len(dynstr), value, size, 0x11, 0,
                                  rodata_index)
        dynstr += name.encode("utf-8") + b"\0"
    dynstr_index = add(".dynstr", SHT_STRTAB, SHF_ALLOC, bytes(dynstr), align=1)
    add(".dynsym", SHT_DYNSYM, SHF_ALLOC, bytes(dynsym), dynstr_index, 1, 8, sym_size)
    for extra in sections:
        name, blob = (extra, b"") if isinstance(extra, str) else extra
        if name == ".symtab":
            add(name, SHT_SYMTAB, 0, blob, align=8, entsize=sym_size)
        elif name.startswith((".debug", ".zdebug", ".comment")):
            add(name, SHT_PROGBITS, 0, blob, align=1)
        elif name.startswith(".note"):
            add(name, SHT_NOTE, SHF_ALLOC, blob)
        else:
            add(name, SHT_PROGBITS, SHF_ALLOC | (SHF_EXECINSTR if name == ".text" else 0), blob)
    shstrndx = len(rows)
    name_at = len(names)
    names.extend(b".shstrtab\0")
    rows.append((name_at, SHT_STRTAB, 0, len(out), len(names), 0, 0, 1, 0))
    out.extend(names)
    out.extend(bytes((-len(out)) % 8))
    shoff = len(out)
    for name_at, kind, flags, offset, size, link, info, align, entsize in rows:
        addr = offset + vaddr_offset if flags & SHF_ALLOC else 0
        out += struct.pack(order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII"), name_at, kind,
                           flags, addr, offset, size, link, info, align, entsize)
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1 if little else 2, 1]) + bytes(9)
    out[:header_size] = ident + struct.pack(
        order + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), 3, _EM_BY_NAME.get(arch, 0),
        1, 0, header_size, shoff, 0, header_size, ph_size, phnum, sh_size, len(rows), shstrndx)
    segments = [(PT_LOAD, 5, 0, shoff)]          # type, flags (read, execute), offset, size
    if build_id:
        segments.append((PT_NOTE, 4, rows[note_index][3], rows[note_index][4]))
    for i, (kind, flags, offset, size) in enumerate(segments):
        vaddr = offset + vaddr_offset
        if wide:
            row = struct.pack(order + "IIQQQQQQ", kind, flags, offset, vaddr, vaddr, size, size,
                              0x1000)
        else:
            row = struct.pack(order + "IIIIIIII", kind, offset, vaddr, vaddr, size, size, flags,
                              0x1000)
        out[header_size + i * ph_size:header_size + (i + 1) * ph_size] = row
    return bytes(out)
