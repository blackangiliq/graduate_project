"""Reader for resources.arsc, the compiled resource table of an Android app.

The table maps resource ids such as 0x7f0b0000 to a type and a name ("string/app_name")
and to a value in every configuration (default, "night", "fr", "hdpi" ...). The app
analysis uses it to give the files under res/ their logical names (release builds shorten
res/xml/network_security_config.xml to res/Zn.xml), to turn @0x7f... references in the
manifest into @xml/name and to read the string resources.

Layout (AOSP frameworks/base libs/androidfw/include/androidfw/ResourceTypes.h): a table
chunk holds one global string pool with every string value, then package chunks. A
package holds a pool of type names, a pool of entry names (keys), one typeSpec chunk per
type and one type chunk per type and configuration. Type chunks come in three forms
(32-bit offsets, FLAG_OFFSET16 and FLAG_SPARSE) and entries in two (full and compact).

A resource table from an app package is untrusted: every read is bounds-checked, every
count is capped, and a malformed table gives warnings and whatever could be read. This
module never raises on bad data.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Sequence, Tuple

# chunk types
RES_STRING_POOL = 0x0001
RES_TABLE = 0x0002
RES_TABLE_PACKAGE = 0x0200
RES_TABLE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC = 0x0202
# chunks a package may hold besides types: library, overlayable, overlayable policy, staged alias
_PACKAGE_CHUNKS = {RES_STRING_POOL, RES_TABLE_TYPE, RES_TABLE_TYPE_SPEC,
                   0x0203, 0x0204, 0x0205, 0x0206}

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_DYNAMIC_REFERENCE = 0x07
TYPE_DYNAMIC_ATTRIBUTE = 0x08
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1C
TYPE_INT_COLOR_RGB4 = 0x1F
TYPE_BAG = -1               # not a Res_value type: a complex entry (style, array, plurals)

FLAG_SPARSE = 0x01          # ResTable_type flags
FLAG_OFFSET16 = 0x02
ENTRY_COMPLEX = 0x0001      # ResTable_entry flags
ENTRY_COMPACT = 0x0008
NO_ENTRY = 0xFFFFFFFF
UTF8_FLAG = 0x100

# caps against hostile tables
MAX_WARNINGS = 50
MAX_CHUNKS = 200_000
MAX_PACKAGES = 64
MAX_VALUES = 1_000_000
MAX_POOL_STRINGS = 2_000_000
MAX_STRING_BYTES = 1 << 20
MAX_REFERENCE_CHARS = 1 << 20    # rendered "@type/name" characters beyond twice the table size
MAX_NAME = 200
MAX_REF_DEPTH = 10

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9_.$-]")
_UNSAFE_CONFIG = re.compile(r"[^A-Za-z0-9+_.=-]")
_DIMENSION_UNITS = ("px", "dp", "sp", "pt", "in", "mm")
_FRACTION_UNITS = ("%", "%p")


class ResValue(NamedTuple):
    """The value of a resource in one configuration."""

    config: str          # qualifiers such as "night", "fr-rCA" or "hdpi"; "" is the default
    data_type: int       # a TYPE_* constant; TYPE_BAG for a style, array or plurals
    data: int            # the raw 32-bit data
    text: str            # readable form: the string, "@xml/name", "true", "#ff1d873b", "4dp"


@dataclass
class ResEntry:
    """A resource: its type, its name and its values in every configuration."""

    type: str
    name: str
    values: List[ResValue] = field(default_factory=list)
    id: int = 0

    def default(self) -> Optional[ResValue]:
        """The value in the default configuration, if there is one."""
        return next((v for v in self.values if not v.config), None)


@dataclass
class ResPackage:
    """One package chunk of the table (an app has one, id 0x7f)."""

    id: int
    name: str
    types: Dict[int, str] = field(default_factory=dict)    # type id -> "string", "xml" ...
    entries: List[ResEntry] = field(default_factory=list)


class ResourceTable:
    """A parsed resources.arsc. Build it with parse_arsc()."""

    def __init__(self) -> None:
        self.packages: List[ResPackage] = []
        self.warnings: List[str] = []
        self._by_id: Dict[int, ResEntry] = {}
        self._package_names: Dict[int, str] = {}
        self._main_package = 0x7F

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append("resources.arsc: " + message)
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append("resources.arsc: further warnings suppressed")

    def entries(self) -> Iterator[ResEntry]:
        """Every resource of every package, in id order."""
        for package in self.packages:
            yield from package.entries

    def lookup(self, res_id: int) -> Optional[ResEntry]:
        """The resource with this id, or None."""
        return self._by_id.get(res_id)

    def name_of(self, res_id: int) -> Optional[str]:
        """"@type/name" of a resource ("@package:type/name" outside the app package), or None
        when the table does not define it. Fits axml.decode_axml(resolve_ref=...)."""
        entry = self._by_id.get(res_id)
        if entry is None or not entry.type or not entry.name:
            return None
        package_id = res_id >> 24
        if package_id == self._main_package:
            return f"@{entry.type}/{entry.name}"
        return f"@{self._package_names.get(package_id, '')}:{entry.type}/{entry.name}"

    def file_paths(self) -> Dict[str, str]:
        """Path in the app package of every file resource -> "type/name", for example
        {"res/Zn.xml": "drawable/launch_background"}. As in aapt2, a file resource is a string
        value starting with "res/" outside the string type. Paths are as written in the
        table; the first resource that names a path wins."""
        paths: Dict[str, str] = {}
        for entry in self.entries():
            if entry.type == "string":
                continue
            for value in entry.values:
                if value.data_type == TYPE_STRING and value.text.startswith("res/"):
                    paths.setdefault(value.text, f"{entry.type}/{entry.name}")
        return paths

    def strings(self, default_config_only: bool = True) -> Dict[str, str]:
        """String resources, name -> value. With default_config_only, only values of the
        default configuration (res/values/strings.xml); otherwise a string defined only in
        other configurations (values-fr, values-v21 ...) gives its first value. References to
        other resources are followed."""
        result: Dict[str, str] = {}
        for entry in self.entries():
            if entry.type != "string" or entry.name in result:
                continue
            value = entry.default()
            if value is None and not default_config_only and entry.values:
                value = entry.values[0]
            if value is not None and value.data_type != TYPE_BAG:
                result[entry.name] = self._resolved_text(value)
        return result

    def _resolved_text(self, value: ResValue) -> str:
        for _ in range(MAX_REF_DEPTH):
            if value.data_type not in (TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE):
                return value.text
            target = self._by_id.get(value.data)
            nxt = target.default() if target is not None else None
            if nxt is None or nxt.data_type == TYPE_BAG:
                return value.text
            value = nxt
        return value.text


def parse_arsc(data: bytes) -> ResourceTable:
    """Parse resources.arsc. Never raises on bad data: problems are in .warnings and a
    table that cannot be read at all comes back empty."""
    table = ResourceTable()
    _Parser(bytes(data), table).run()
    return table


class _Pool:
    """A string pool chunk. Strings are decoded on first use within a byte budget, so a
    hostile pool whose offsets all point into one long string costs no more than the pool."""

    def __init__(self, buf: bytes, start: int, limit: int, where: str,
                 warn: Callable[[str], None]) -> None:
        self.count = 0
        self._buf = buf
        self._where = where
        self._warn = warn
        self._cache: Dict[int, str] = {}
        self._offsets: Tuple[int, ...] = ()
        self._utf8 = False
        self._data = self._end = self._budget = 0
        self._noted: set = set()
        if start < 0 or limit - start < 28:
            warn(f"{where}: string pool header is missing or truncated")
            return
        kind, header, size, count, styles, flags, strings_start, styles_start = \
            struct.unpack_from("<HHIIIIII", buf, start)
        if kind != RES_STRING_POOL or header < 28 or header > size:
            warn(f"{where}: not a valid string pool (type {kind:#06x}, header {header}, "
                 f"size {size})")
            return
        if size > limit - start:
            warn(f"{where}: string pool runs past its parent chunk; truncated")
            size = limit - start
            if header > size:
                return
        fit = (size - header) // 4
        if header <= strings_start <= size:
            fit = min(fit, (strings_start - header) // 4)
        if count > fit:
            warn(f"{where}: string count {count} does not fit the pool; clamped to {fit}")
            count = fit
        if count > MAX_POOL_STRINGS:
            warn(f"{where}: {count} strings; only the first {MAX_POOL_STRINGS} are read")
            count = MAX_POOL_STRINGS
        if count and not header <= strings_start < size:
            warn(f"{where}: string data offset {strings_start} is outside the pool")
            return
        self.count = count
        self._offsets = struct.unpack_from(f"<{count}I", buf, start + header)
        self._utf8 = bool(flags & UTF8_FLAG)
        self._data = start + strings_start
        styled = styles and strings_start < styles_start <= size
        self._end = start + (styles_start if styled else size)
        self._budget = 2 * (self._end - self._data) + MAX_STRING_BYTES

    def get(self, index: int) -> str:
        """String number index, or "" when it is missing or malformed."""
        text = self._cache.get(index)
        if text is None:
            if not 0 <= index < self.count:
                self._note("index", f"string index {index} is out of range ({self.count} strings)")
                return ""
            text = self._cache[index] = self._decode(self._data + self._offsets[index])
        return text

    def _note(self, kind: str, message: str) -> None:
        if kind not in self._noted:
            self._noted.add(kind)
            self._warn(f"{self._where}: {message}")

    def _decode(self, pos: int) -> str:
        buf, end = self._buf, self._end
        if not self._data <= pos < end:
            self._note("offset", "a string offset points outside the pool")
            return ""
        if self._utf8:
            pos, _ = self._length8(pos)              # length in UTF-16 units, not needed
            pos, length = self._length8(pos)
            stop, step = pos + length, 0
            while stop < end and buf[stop] != 0:      # AAPT wrote lengths above 0x7FFF truncated
                step += 1
                stop = pos + ((step << 15) | length)
            if stop >= end:
                self._note("nul", "a string is not NUL-terminated")
                return ""
        else:
            if pos + 2 > end:
                return ""
            length = buf[pos] | buf[pos + 1] << 8
            pos += 2
            if length & 0x8000 and pos + 2 <= end:
                length = (length & 0x7FFF) << 16 | buf[pos] | buf[pos + 1] << 8
                pos += 2
            stop = pos + 2 * length
            if stop + 2 > end:
                self._note("nul", "a string runs past the end of the pool; truncated")
                stop = end - (end - pos) % 2
        if stop - pos > MAX_STRING_BYTES:
            self._note("long", f"a string is longer than {MAX_STRING_BYTES} bytes; truncated")
            stop = pos + MAX_STRING_BYTES
        self._budget -= stop - pos
        if self._budget < 0:
            self._note("budget", "strings overlap far more than a real pool allows; rest not read")
            return ""
        return buf[pos:stop].decode("utf-8" if self._utf8 else "utf-16-le", "replace")

    def _length8(self, pos: int) -> Tuple[int, int]:
        buf = self._buf
        if pos >= self._end:
            return pos, 0
        length = buf[pos]
        if length & 0x80 and pos + 1 < self._end:
            return pos + 2, (length & 0x7F) << 8 | buf[pos + 1]
        return pos + 1, length


class _RawPackage:
    """Values of one package chunk before names are resolved."""

    def __init__(self, package: ResPackage, type_pool: Optional[_Pool], key_pool: Optional[_Pool],
                 type_id_offset: int) -> None:
        self.package = package
        self.type_pool = type_pool
        self.key_pool = key_pool
        self.type_id_offset = type_id_offset
        self.keys: Dict[int, int] = {}                           # res id -> key index
        self.values: Dict[int, List[Tuple[str, int, int]]] = {}  # res id -> (config, type, data)
        self.chunks: set = set()                                 # (type id, config) read


class _Parser:
    def __init__(self, buf: bytes, table: ResourceTable) -> None:
        self.buf = buf
        self.table = table
        self.warn = table.warn
        self.pool: Optional[_Pool] = None
        self.raw: List[_RawPackage] = []
        self.value_count = 0
        self.noted: set = set()
        self.references: Dict[int, str] = {}     # res id << 1 | attribute -> rendered name
        self.name_budget = 2 * len(buf) + MAX_REFERENCE_CHARS

    def note(self, kind: str, message: str) -> None:
        """Warn once per kind of anomaly, so a hostile table cannot flood the warnings."""
        if kind not in self.noted:
            self.noted.add(kind)
            self.warn(message)

    def run(self) -> None:
        buf, size = self.buf, len(self.buf)
        if size < 12:
            self.warn("not a resource table (too short)")
            return
        kind, header, total = struct.unpack_from("<HHI", buf, 0)
        if kind != RES_TABLE or header < 12 or header > size:
            self.warn(f"not a resource table (root chunk type {kind:#06x}, header {header})")
            return
        if total > size:
            self.warn(f"the table claims {total} bytes but the file has {size}; truncated")
            total = size
        elif total < size:
            self.warn(f"{size - total} bytes after the end of the table")
        if total < header:
            self.warn("the table size is smaller than its header")
            return
        declared = struct.unpack_from("<I", buf, 8)[0]
        packages = 0
        for start, kind, chunk_header, length in self._chunks(header, total, "table"):
            if kind == RES_STRING_POOL:
                if self.pool is None:
                    self.pool = _Pool(buf, start, start + length, "value strings", self.warn)
                else:
                    self.note("pools", "more than one value string pool; extra pools ignored")
            elif kind == RES_TABLE_PACKAGE:
                packages += 1
                if packages <= MAX_PACKAGES:
                    self._package(start, chunk_header, length)
                else:
                    self.note("packages",
                              f"more than {MAX_PACKAGES} packages; the rest are ignored")
            else:
                self.note(f"table-{kind}", f"unknown chunk type {kind:#06x} in the table")
        if packages != declared:
            self.warn(f"the table declares {declared} package(s) but holds {packages}")
        if self.pool is None:
            self.warn("the table has no value string pool")
        self._finish()

    def _chunks(self, pos: int, end: int, where: str) -> Iterator[Tuple[int, int, int, int]]:
        """Yield (start, type, header size, size) of every chunk in buf[pos:end]."""
        buf, count = self.buf, 0
        while pos + 8 <= end:
            kind, header, size = struct.unpack_from("<HHI", buf, pos)
            if header < 8 or size < header:
                self.warn(f"{where}: malformed chunk at offset {pos:#x} (header {header}, "
                          f"size {size}); the rest is skipped")
                return
            if size > end - pos:
                self.warn(f"{where}: chunk at offset {pos:#x} runs past its parent; truncated")
                size = end - pos
                if header > size:
                    return
            if size % 4 or header % 4:
                self.note("align", f"{where}: chunk at offset {pos:#x} is not 4-byte aligned")
            count += 1
            if count > MAX_CHUNKS:
                self.warn(f"{where}: more than {MAX_CHUNKS} chunks; the rest are skipped")
                return
            yield pos, kind, header, size
            pos += size

    def _package(self, start: int, header: int, size: int) -> None:
        buf, end = self.buf, start + size
        if header < 284:
            self.warn(f"package chunk at offset {start:#x} has a short header ({header} bytes)")
            return
        package_id = struct.unpack_from("<I", buf, start + 8)[0]
        name = _clean(buf[start + 12:start + 268].decode("utf-16-le", "replace").split("\0", 1)[0])
        type_strings, _, key_strings, _ = struct.unpack_from("<4I", buf, start + 268)
        type_id_offset = struct.unpack_from("<I", buf, start + 284)[0] if header >= 288 else 0
        where = f"package {name}"
        if package_id > 0xFF:
            self.warn(f"{where}: package id {package_id:#x} is out of range")
            return
        type_pool = key_pool = None
        if 0 < type_strings < size:
            type_pool = _Pool(buf, start + type_strings, end, f"{where} type names", self.warn)
        else:
            self.warn(f"{where}: type name pool offset {type_strings} is outside the package")
        if 0 < key_strings < size:
            key_pool = _Pool(buf, start + key_strings, end, f"{where} entry names", self.warn)
        else:
            self.warn(f"{where}: entry name pool offset {key_strings} is outside the package")
        raw = _RawPackage(ResPackage(id=package_id, name=name), type_pool, key_pool, type_id_offset)
        for chunk, kind, chunk_header, length in self._chunks(start + header, end, where):
            if kind == RES_TABLE_TYPE:
                self._type_chunk(raw, chunk, chunk_header, length, where)
            elif kind not in _PACKAGE_CHUNKS:
                self.note(f"package-{kind}", f"{where}: unknown chunk type {kind:#06x}")
        self.raw.append(raw)

    def _type_chunk(self, raw: _RawPackage, start: int, header: int, size: int, where: str) -> None:
        buf, end = self.buf, start + size
        if header < 24:
            self.note("type-header", f"{where}: a type chunk has a short header ({header} bytes)")
            return
        type_id, flags, _, count, entries_start, config_size = \
            struct.unpack_from("<BBHIII", buf, start + 8)
        if type_id == 0:
            self.note("type-id", f"{where}: a type chunk has type id 0")
            return
        if config_size > header - 20:
            self.note("config", f"{where}: a configuration is larger than its type chunk header")
            config_size = header - 20
        config = _config_name(buf, start + 20, config_size)
        if (type_id, config) in raw.chunks:
            self.note("dup", f"{where}: type {type_id} has two chunks for the configuration "
                             f"'{config or 'default'}'; the second is skipped")
            return
        raw.chunks.add((type_id, config))
        sparse = bool(flags & FLAG_SPARSE)
        width = 2 if flags & FLAG_OFFSET16 and not sparse else 4
        fit = min((size - header) // width, 0x10000)
        if count > fit:
            self.note("count", f"{where}: type {type_id} claims {count} entries but its chunk "
                               f"holds at most {fit}; clamped")
            count = fit
        if count and entries_start > size:
            self.note("entries", f"{where}: the entries of type {type_id} start outside its chunk")
            return
        index = start + header
        if sparse:
            pairs = struct.unpack_from(f"<{2 * count}H", buf, index)
            slots = [(pairs[i], pairs[i + 1] * 4) for i in range(0, 2 * count, 2)]
            if any(a[0] >= b[0] for a, b in zip(slots, slots[1:])):
                self.note("sparse", f"{where}: the sparse entries of type {type_id} are not in "
                                    "order; a repeated index keeps its first entry")
                first: Dict[int, int] = {}
                for slot, offset in slots:
                    first.setdefault(slot, offset)
                slots = sorted(first.items())
        elif width == 2:
            slots = [(i, o * 4) for i, o in enumerate(struct.unpack_from(f"<{count}H", buf, index))
                     if o != 0xFFFF]
        else:
            slots = [(i, o) for i, o in enumerate(struct.unpack_from(f"<{count}I", buf, index))
                     if o != NO_ENTRY]
        base = raw.package.id << 24 | type_id << 16
        entries = start + entries_start
        for slot, offset in slots:
            if self.value_count >= MAX_VALUES:
                self.note("values", f"more than {MAX_VALUES} values; the rest are skipped")
                return
            pos = entries + offset
            if offset & 3 or pos + 8 > end:
                self.note("entry", f"{where}: an entry of type {type_id} is misaligned or outside "
                                   "its chunk; skipped")
                continue
            size_or_key, entry_flags, key_or_data = struct.unpack_from("<HHI", buf, pos)
            if entry_flags & ENTRY_COMPACT:
                key, data_type, data = size_or_key, entry_flags >> 8, key_or_data
            elif size_or_key < 8:
                self.note("entry", f"{where}: an entry of type {type_id} has size {size_or_key}")
                continue
            elif entry_flags & ENTRY_COMPLEX:
                key, data_type, data = key_or_data, TYPE_BAG, 0
            else:
                key, value_at = key_or_data, pos + size_or_key
                if value_at + 8 > end:
                    self.note("entry", f"{where}: a value of type {type_id} runs past its chunk")
                    continue
                data_type, data = buf[value_at + 3], struct.unpack_from("<I", buf, value_at + 4)[0]
            res_id = base | slot
            values = raw.values.get(res_id)
            if values is None:
                values = raw.values[res_id] = []
                raw.keys[res_id] = key
            elif raw.keys[res_id] != key:
                self.note("key", f"{where}: resource {res_id:#010x} has different names in "
                                 "different configurations")
            values.append((config, data_type, data))
            self.value_count += 1

    def _finish(self) -> None:
        """Name every resource, then render the values (references need every name). Until
        then an entry holds its raw (config, type, data) values, replaced one by one, so a
        table of a million values is not held twice."""
        table = self.table
        for raw in self.raw:
            package, types, keys = raw.package, raw.type_pool, raw.key_pool
            table.packages.append(package)
            table._package_names.setdefault(package.id, package.name)
            for index in range(min(types.count, 0xFF) if types else 0):
                package.types[index + 1 + raw.type_id_offset] = _clean(types.get(index))
            names: Dict[int, str] = {}           # key index -> name, shared by its resources
            for res_id in sorted(raw.values):
                if res_id in table._by_id:
                    self.note("twice", f"resource {res_id:#010x} is defined by two packages; "
                                       "the first is kept")
                    continue
                type_id = res_id >> 16 & 0xFF
                type_name = package.types.get(type_id, "")
                if not type_name:
                    self.note("type-name", f"package {package.name}: type {type_id} has no name")
                key = raw.keys[res_id]
                name = names.get(key)
                if name is None:
                    name = names[key] = _clean(keys.get(key)) if keys else ""
                table._by_id[res_id] = entry = ResEntry(type_name, name, raw.values[res_id],
                                                        res_id)
                package.entries.append(entry)
            raw.values, raw.keys = {}, {}
        if table.packages and all(p.id != 0x7F for p in table.packages):
            table._main_package = table.packages[0].id
        for entry in table.entries():
            values = entry.values
            for i, (config, data_type, data) in enumerate(values):
                values[i] = ResValue(config, data_type, data, self._render(data_type, data))

    def _render(self, data_type: int, data: int) -> str:
        if data_type == TYPE_STRING:
            return self.pool.get(data) if self.pool else ""
        if data_type in (TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE):
            return "@null" if data == 0 else self._reference("@", data)
        if data_type in (TYPE_ATTRIBUTE, TYPE_DYNAMIC_ATTRIBUTE):
            return self._reference("?", data)
        if data_type == TYPE_INT_BOOLEAN:
            return "true" if data else "false"
        if data_type == TYPE_INT_DEC:
            return str(data - (1 << 32) if data & 0x80000000 else data)
        if TYPE_INT_COLOR_ARGB8 <= data_type <= TYPE_INT_COLOR_RGB4:
            return f"#{data:08x}"
        if data_type == TYPE_FLOAT:
            return f"{struct.unpack('<f', struct.pack('<I', data))[0]:g}"
        if data_type == TYPE_DIMENSION:
            return _complex(data, _DIMENSION_UNITS, 1)
        if data_type == TYPE_FRACTION:
            return _complex(data, _FRACTION_UNITS, 100)
        if data_type == TYPE_NULL:
            return "@empty" if data == 1 else ""
        if data_type == TYPE_BAG:
            return ""
        return f"0x{data:08x}"

    def _reference(self, sigil: str, res_id: int) -> str:
        """"@type/name" ("?type/name" for an attribute) of a resource id, made once per id;
        past a budget of characters, or for an id the table does not define, "@0x7f010000"."""
        key = res_id << 1 | (sigil == "?")
        text = self.references.get(key)
        if text is None:
            name = self.table.name_of(res_id)
            if name and len(name) > self.name_budget:
                self.note("names", "references name more resources than a real table does; the "
                                   "rest are given as ids")
                name = None
            if name:
                self.name_budget -= len(name)
                text = sigil + name[1:]
            else:
                text = f"{sigil}0x{res_id:08x}"
            self.references[key] = text
        return text


def _clean(name: str) -> str:
    """A resource, type or package name made safe to use in a file path."""
    return _UNSAFE_NAME.sub("_", name[:MAX_NAME])


def _complex(data: int, units: Sequence[str], scale: int) -> str:
    """A dimension or fraction value (TypedValue.complexToFloat)."""
    mantissa = data & 0xFFFFFF00
    if mantissa & 0x80000000:
        mantissa -= 1 << 32
    value = mantissa * (1.0, 1 / (1 << 7), 1 / (1 << 15), 1 / (1 << 23))[data >> 4 & 3] / 256
    unit = data & 0xF
    return f"{value * scale:g}{units[unit] if unit < len(units) else ''}"


# qualifier names in the order ResTable_config::toString() writes them
_DENSITY = {120: "ldpi", 160: "mdpi", 213: "tvdpi", 240: "hdpi", 320: "xhdpi", 480: "xxhdpi",
            640: "xxxhdpi", 0xFFFE: "anydpi", 0xFFFF: "nodpi"}
_LAYOUTDIR = {0x40: "ldltr", 0x80: "ldrtl"}
_SCREENSIZE = {1: "small", 2: "normal", 3: "large", 4: "xlarge"}
_SCREENLONG = {0x10: "notlong", 0x20: "long"}
_ROUND = {1: "notround", 2: "round"}
_WIDECG = {1: "nowidecg", 2: "widecg"}
_HDR = {4: "lowdr", 8: "highdr"}
_ORIENTATION = {1: "port", 2: "land", 3: "square"}
_UI_TYPE = {2: "desk", 3: "car", 4: "television", 5: "appliance", 6: "watch", 7: "vrheadset"}
_NIGHT = {0x10: "notnight", 0x20: "night"}
_TOUCH = {1: "notouch", 2: "stylus", 3: "finger"}
_KEYSHIDDEN = {1: "keysexposed", 2: "keyshidden", 3: "keyssoft"}
_KEYBOARD = {1: "nokeys", 2: "qwerty", 3: "12key"}
_NAVHIDDEN = {4: "navexposed", 8: "navhidden"}
_NAVIGATION = {1: "nonav", 2: "dpad", 3: "trackball", 4: "wheel"}
_GENDER = {1: "neuter", 2: "feminine", 3: "masculine"}
_CONFIG = struct.Struct("<4xHH2s2sBBHBBBBHHHHBBHHH4s8sBBxxB8s")     # ResTable_config after size


def _config_name(buf: bytes, pos: int, size: int) -> str:
    """Qualifier string of a ResTable_config ("" for the default configuration). Fields past
    the end of an older, shorter config struct count as zero."""
    raw = buf[pos:pos + max(0, min(size, 64))]
    raw += bytes(64 - len(raw))
    (mcc, mnc, language, country, orientation, touch, density, keyboard, navigation, input_flags,
     inflection, screen_w, screen_h, sdk, minor, layout, ui_mode, sw_dp, w_dp, h_dp, script,
     variant, layout2, color, script_computed, numbering) = _CONFIG.unpack_from(raw)
    parts: List[str] = []

    def pick(value: int, names: Dict[int, str], label: str) -> None:
        if value:
            parts.append(names.get(value, f"{label}={value}"))

    if mcc:
        parts.append(f"mcc{mcc}")
    if mnc:
        parts.append(f"mnc{mnc}")
    if language[0]:
        parts.append(_locale(language, country, script, variant, script_computed, numbering))
    pick(inflection & 3, _GENDER, "grammaticalGender")
    pick(layout & 0xC0, _LAYOUTDIR, "layoutDir")
    parts.extend(f"{prefix}{value}dp" for prefix, value in (("sw", sw_dp), ("w", w_dp), ("h", h_dp))
                 if value)
    pick(layout & 0x0F, _SCREENSIZE, "screenLayoutSize")
    pick(layout & 0x30, _SCREENLONG, "screenLayoutLong")
    pick(layout2 & 0x03, _ROUND, "screenRound")
    pick(color & 0x03, _WIDECG, "wideColorGamut")
    pick(color & 0x0C, _HDR, "hdr")
    pick(orientation, _ORIENTATION, "orientation")
    pick(ui_mode & 0x0F, _UI_TYPE, "uiModeType")
    pick(ui_mode & 0x30, _NIGHT, "uiModeNight")
    if density:
        parts.append(_DENSITY.get(density, f"{density}dpi"))
    pick(touch, _TOUCH, "touchscreen")
    pick(input_flags & 0x03, _KEYSHIDDEN, "keysHidden")
    pick(keyboard, _KEYBOARD, "keyboard")
    pick(input_flags & 0x0C, _NAVHIDDEN, "inputFlagsNavHidden")
    pick(navigation, _NAVIGATION, "navigation")
    if screen_w or screen_h:
        parts.append(f"{screen_w}x{screen_h}")
    if sdk or minor:
        parts.append(f"v{sdk}" + (f".{minor}" if minor else ""))
    return _UNSAFE_CONFIG.sub("?", "-".join(parts))


def _code(packed: bytes, base: int) -> str:
    """A language or region code: two ASCII letters, or three letters packed in 15 bits."""
    first, second = packed[0], packed[1]
    if first & 0x80:
        letters = (second & 0x1F, (second & 0xE0) >> 5 | (first & 0x03) << 3, (first & 0x7C) >> 2)
        return "".join(chr(base + c) for c in letters)
    return bytes(b for b in (first, second) if b).decode("latin-1")


def _locale(language: bytes, country: bytes, script: bytes, variant: bytes,
            script_computed: int, numbering: bytes) -> str:
    lang = _code(language, ord("a"))
    region = _code(country, ord("0")) if country[0] else ""
    script_given = bool(script[0]) and not script_computed
    if not script_given and not variant[0] and not numbering[0]:
        return lang + (f"-r{region}" if region else "")
    parts = ["b+" + lang]                                  # modified BCP 47: b+sr+Latn
    if script_given:
        parts.append(script.decode("latin-1"))
    if region:
        parts.append(region)
    if variant[0]:
        parts.append(variant.split(b"\0", 1)[0].decode("latin-1"))
    if numbering[0]:
        parts.append("u+nu+" + numbering.split(b"\0", 1)[0].decode("latin-1"))
    return "+".join(parts)


# ------------------------------------------------------------------ builder for tests

def _build_config(qualifiers: str) -> bytes:
    """ResTable_config for a few res/ folder qualifiers ("fr-rCA", "night", "hdpi", "v21")."""
    config = bytearray(64)
    struct.pack_into("<I", config, 0, 64)
    densities = {name: value for value, name in _DENSITY.items()}
    ui_types = {name: value for value, name in _UI_TYPE.items()}
    for token in filter(None, qualifiers.split("-")):
        screen_dp = re.fullmatch(r"(sw|w|h)(\d+)dp", token)
        if re.fullmatch(r"[a-z]{2}", token):
            config[8:10] = token.encode()
        elif re.fullmatch(r"r[A-Z]{2}", token):
            config[10:12] = token[1:].encode()
        elif token in ("ldltr", "ldrtl"):
            config[28] |= 0x40 if token == "ldltr" else 0x80
        elif screen_dp:
            struct.pack_into("<H", config, {"sw": 30, "w": 32, "h": 34}[screen_dp.group(1)],
                             int(screen_dp.group(2)))
        elif token in ("port", "land", "square"):
            config[12] = ("port", "land", "square").index(token) + 1
        elif token in ui_types:
            config[29] |= ui_types[token]
        elif token in ("night", "notnight"):
            config[29] |= 0x20 if token == "night" else 0x10
        elif token in densities:
            struct.pack_into("<H", config, 14, densities[token])
        elif re.fullmatch(r"\d+dpi", token):
            struct.pack_into("<H", config, 14, int(token[:-3]))
        elif re.fullmatch(r"v\d+", token):
            struct.pack_into("<H", config, 24, int(token[1:]))
        else:
            raise ValueError(f"build_arsc does not support the qualifier {token!r}")
    return bytes(config)


def _build_pool(strings: Sequence[str], utf8: bool) -> bytes:
    data, offsets = bytearray(), []
    for text in strings:
        offsets.append(len(data))
        units = len(text.encode("utf-16-le", "surrogatepass")) // 2
        if utf8:
            raw = text.encode("utf-8", "surrogatepass")
            for length in (units, len(raw)):
                data += bytes([length] if length < 0x80 else [0x80 | length >> 8, length & 0xFF])
            data += raw + b"\0"
        else:
            data += struct.pack("<H", units) if units < 0x8000 else \
                struct.pack("<HH", 0x8000 | units >> 16, units & 0xFFFF)
            data += text.encode("utf-16-le", "surrogatepass") + b"\0\0"
    data += bytes(-len(data) % 4)
    strings_start = 28 + 4 * len(strings)
    header = struct.pack("<HHIIIIII", RES_STRING_POOL, 28, strings_start + len(data),
                         len(strings), 0, UTF8_FLAG if utf8 else 0, strings_start, 0)
    return header + struct.pack(f"<{len(offsets)}I", *offsets) + bytes(data)


def _build_value(value: object, pool: Dict[str, int]) -> Tuple[int, object]:
    if isinstance(value, bool):
        return TYPE_INT_BOOLEAN, 0xFFFFFFFF if value else 0
    if isinstance(value, int):
        return TYPE_INT_DEC, value & 0xFFFFFFFF
    if isinstance(value, str):
        return TYPE_STRING, pool.setdefault(value, len(pool))
    if isinstance(value, dict):
        return TYPE_BAG, [(int(k), TYPE_INT_DEC, int(v) & 0xFFFFFFFF) for k, v in value.items()]
    if isinstance(value, tuple) and len(value) == 2:
        return int(value[0]), int(value[1]) & 0xFFFFFFFF
    raise ValueError(f"build_arsc cannot encode {value!r}")


def _build_entry(key: int, data_type: int, data: object, compact: bool) -> bytes:
    if data_type == TYPE_BAG:
        items = b"".join(struct.pack("<IHBBI", name, 8, 0, t, d) for name, t, d in data)
        return struct.pack("<HHIII", 16, ENTRY_COMPLEX, key, 0, len(data)) + items
    if compact and key < 0x10000:
        return struct.pack("<HHI", key, data_type << 8 | ENTRY_COMPACT, data)
    return struct.pack("<HHIHBBI", 8, 0, key, 8, 0, data_type, data)


def build_arsc(package_name: str, entries: Sequence[tuple], *, package_id: int = 0x7F,
               utf8: bool = True, sparse: bool = False, offset16: bool = False,
               compact: bool = False) -> bytes:
    """A resources.arsc for tests. Each entry is (type, name, value) or (type, name, value,
    qualifiers). A value is a str (a string, or a file path such as "res/xml/a.xml"), an int,
    a bool, a dict (a bag such as a style: attribute id -> int) or a (data_type, data) pair
    for any other Res_value. Qualifiers use the res/ folder syntax for a few qualifiers
    ("fr-rCA", "night", "hdpi", "v21"). Types and entries get ids in order of appearance;
    sparse, offset16 and compact select the newer type chunk and entry encodings."""
    pool: Dict[str, int] = {}
    types: Dict[str, Dict[str, int]] = {}             # type -> name -> entry index
    keys: Dict[str, int] = {}
    configs: Dict[str, Dict[str, Dict[int, Tuple[int, object]]]] = {}
    for item in entries:
        type_name, name, value = item[:3]
        qualifiers = item[3] if len(item) > 3 else ""
        slots = types.setdefault(type_name, {})
        index = slots.setdefault(name, len(slots))
        keys.setdefault(name, len(keys))
        by_config = configs.setdefault(type_name, {}).setdefault(qualifiers, {})
        by_config[index] = _build_value(value, pool)
    chunks = bytearray()
    for type_id, (type_name, slots) in enumerate(types.items(), 1):
        count = len(slots)
        key_of = {index: keys[name] for name, index in slots.items()}
        chunks += struct.pack("<HHIBBHI", RES_TABLE_TYPE_SPEC, 16, 16 + 4 * count, type_id, 0,
                              len(configs[type_name]), count) + bytes(4 * count)
        for qualifiers, values in configs[type_name].items():
            blob, offsets = bytearray(), {}
            for index in sorted(values):
                offsets[index] = len(blob)
                blob += _build_entry(key_of[index], *values[index], compact=compact)
            if sparse:
                table = b"".join(struct.pack("<HH", i, offsets[i] // 4) for i in sorted(offsets))
                n = len(offsets)
            elif offset16:
                table = b"".join(struct.pack("<H", offsets[i] // 4 if i in offsets else 0xFFFF)
                                 for i in range(count))
                table += bytes(-len(table) % 4)
                n = count
            else:
                table = b"".join(struct.pack("<I", offsets.get(i, NO_ENTRY)) for i in range(count))
                n = count
            flags = FLAG_SPARSE if sparse else FLAG_OFFSET16 if offset16 else 0
            header = 20 + 64
            chunks += struct.pack("<HHIBBHII", RES_TABLE_TYPE, header,
                                  header + len(table) + len(blob), type_id, flags, 0, n,
                                  header + len(table))
            chunks += _build_config(qualifiers) + table + blob
    type_pool = _build_pool(list(types), utf8=False)
    key_pool = _build_pool(list(keys), utf8)
    name = package_name.encode("utf-16-le")[:254].ljust(256, b"\0")
    body = type_pool + key_pool + bytes(chunks)
    package = struct.pack("<HHII", RES_TABLE_PACKAGE, 288, 288 + len(body), package_id) + name + \
        struct.pack("<5I", 288, len(types), 288 + len(type_pool), len(keys), 0) + body
    values = _build_pool(sorted(pool, key=pool.get), utf8)
    root = struct.pack("<HHII", RES_TABLE, 12, 12 + len(values) + len(package), 1)
    return root + values + package
