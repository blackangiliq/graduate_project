"""Reader for DEX files (classes.dex, classes2.dex ...), the compiled Java and Kotlin code of an
Android app.

The app analysis reads the identifier tables only: the strings (a strings dump for the
secrets engine), the type names, the classes defined with their superclasses and the method
references. In a Flutter app the business logic is Dart code in libapp.so, so the DEX files
hold the Flutter embedding, the plugins and any native Android code. FlutterJNI and
GeneratedPluginRegistrant keep their names in release builds, where R8 renames most other
classes, so they mark a Flutter app.

Layout (source.android.com/docs/core/runtime/dex-format): a 0x70-byte header (0x78 from
version 041) gives the size and offset of each id table. A string id points to a string data
item: a ULEB128 length in UTF-16 units, the MUTF-8 bytes and a NUL. Version 041 files can be
containers of several logical DEX files that follow each other; their offsets count from the
start of the container and d8 makes them share one string table. The other id tables of a
logical DEX file lie inside it.

A DEX file from an app package is untrusted: every read is bounds-checked, every table is
capped (over all the logical files of a container too), and a malformed file gives warnings
and whatever could be read. This module never raises on bad data.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

MAGIC = b"dex\n"
ENDIAN_CONSTANT = 0x12345678
NO_INDEX = 0xFFFFFFFF
HEADER_SIZE = 0x70
HEADER_SIZE_V41 = 0x78
ACC_PUBLIC = 0x0001

# caps against hostile files
MAX_STRINGS = 2_000_000
MAX_IDS = 1_000_000             # entries of the type, method and class tables
MAX_STRING_BYTES = 1 << 20      # one string
MAX_SECTIONS = 256              # logical DEX files in a version 041 container
MAX_WARNINGS = 50

FLUTTER_JNI = "Lio/flutter/embedding/engine/FlutterJNI;"
PLUGIN_REGISTRANT = "Lio/flutter/plugins/GeneratedPluginRegistrant;"
FLUTTER_ACTIVITY = "Lio/flutter/embedding/android/FlutterActivity;"
FLUTTER_FRAGMENT_ACTIVITY = "Lio/flutter/embedding/android/FlutterFragmentActivity;"
# packages of the Flutter engine's own plugin API (PlatformPlugin, TextInputPlugin ...)
_ENGINE_PACKAGES = ("io.flutter.embedding.", "io.flutter.plugin.")
_PRIMITIVES = {"V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char", "I": "int",
               "J": "long", "F": "float", "D": "double"}


class _Section(NamedTuple):
    """(offset, count) of the id tables of one logical DEX file."""

    strings: Tuple[int, int]
    types: Tuple[int, int]
    methods: Tuple[int, int]
    classes: Tuple[int, int]


class DexFile:
    """A parsed DEX file. Build it with parse_dex(), which decodes the id tables and lets go
    of the input bytes, so the DexFile objects of an app can be kept for the whole analysis."""

    def __init__(self, data: bytes, name: str = "classes.dex") -> None:
        self.name = name
        self.version = ""             # "035" ... "041"; "" when the file is not a DEX file
        self.size = len(data)
        self.sections = 0             # logical DEX files (more than one only in a container)
        self.warnings: List[str] = []
        self._data = data
        self._parts: List[_Section] = []
        self._noted: set = set()
        self._taken: Dict[str, int] = {}          # table kind -> entries read in all sections
        self._shared: Dict[int, Tuple[int, Tuple[int, int]]] = {}   # string ids, by offset
        self._cache: Dict[int, str] = {}          # string data offset -> text
        self._budget = len(data) + MAX_STRING_BYTES
        self._string_tables: Dict[Tuple[int, int], List[str]] = {}
        self._type_tables: Dict[Tuple[Tuple[int, int], Tuple[int, int]], List[str]] = {}
        self._strings: List[str] = []
        self._types: List[str] = []
        self._classes: List[Tuple[str, str, int]] = []
        self._method_ids: List[Tuple[bytes, List[str], List[str]]] = []   # table, types, strings
        self._methods: Optional[List[Tuple[str, str]]] = None

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(f"{self.name}: {message}")
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append(f"{self.name}: further warnings suppressed")

    def _note(self, kind: str, message: str) -> None:
        """Warn once per kind of anomaly, so a hostile file cannot flood the warnings."""
        if kind not in self._noted:
            self._noted.add(kind)
            self.warn(message)

    def strings(self) -> List[str]:
        """Every string of the string table, in table order. The sections of a container
        can share one string table; it is listed once."""
        return self._strings

    def type_names(self) -> List[str]:
        """Type descriptors ("Lcom/example/MainActivity;", "[I") of every type the code
        defines or references."""
        return self._types

    def class_defs(self) -> List[Tuple[str, str, int]]:
        """(class descriptor, superclass descriptor or "", access flags) of every class the
        file defines."""
        return self._classes

    def method_refs(self) -> List[Tuple[str, str]]:
        """(class descriptor, method name) of every method the code defines or calls; decoded
        on first use from the method id tables kept by parse_dex()."""
        if self._methods is None:
            self._methods = []
            for items, types, strings in self._method_ids:
                for class_idx, _, name_idx in struct.iter_unpack("<HHI", items):
                    name = self._string(strings, name_idx)
                    self._methods.append((self._type(types, class_idx), name))
            self._method_ids = []
        return self._methods

    def _decode(self) -> None:
        """Decode the strings, types and classes of every section, keep the bytes of the
        method id tables and drop the rest of the input."""
        tables = dict.fromkeys(part.strings for part in self._parts)
        self._strings = [s for table in tables for s in self._table_strings(table)]
        keys = dict.fromkeys((part.types, part.strings) for part in self._parts)
        self._types = [t for key in keys for t in self._table_types(*key)]
        data = self._data
        for part in self._parts:
            types = self._table_types(part.types, part.strings)
            offset, count = part.classes
            for class_idx, flags, super_idx in struct.iter_unpack(
                    "<III20x", data[offset:offset + 32 * count]):
                superclass = "" if super_idx == NO_INDEX else self._type(types, super_idx)
                self._classes.append((self._type(types, class_idx), superclass, flags))
            offset, count = part.methods
            if count:
                self._method_ids.append((data[offset:offset + 8 * count], types,
                                         self._table_strings(part.strings)))
        self._data = b""
        self._cache, self._string_tables, self._type_tables = {}, {}, {}

    def _type(self, types: List[str], index: int) -> str:
        if index < len(types):
            return types[index]
        self._note("type-index", f"a type index ({index}) is out of range ({len(types)} types)")
        return ""

    def _string(self, strings: List[str], index: int) -> str:
        if index < len(strings):
            return strings[index]
        self._note("string-index",
                   f"a string index ({index}) is out of range ({len(strings)} strings)")
        return ""

    def _table_strings(self, table: Tuple[int, int]) -> List[str]:
        """The strings of the string id table at (offset, count)."""
        strings = self._string_tables.get(table)
        if strings is None:
            offset, count = table
            offsets = struct.unpack_from(f"<{count}I", self._data, offset)
            strings = self._string_tables[table] = [self._string_at(o) for o in offsets]
        return strings

    def _table_types(self, table: Tuple[int, int], strings_table: Tuple[int, int]) -> List[str]:
        """The descriptors of the type id table at (offset, count)."""
        types = self._type_tables.get((table, strings_table))
        if types is None:
            strings = self._table_strings(strings_table)
            offset, count = table
            indexes = struct.unpack_from(f"<{count}I", self._data, offset)
            types = [self._string(strings, i) for i in indexes]
            self._type_tables[(table, strings_table)] = types
        return types

    def _string_at(self, offset: int) -> str:
        """The string data item at offset; shared offsets are decoded once. The bytes
        decoded are budgeted: string data items of a real file do not overlap."""
        text = self._cache.get(offset)
        if text is not None:
            return text
        data, size = self._data, len(self._data)
        pos, stop = offset, min(offset + 5, size)      # skip the ULEB128 length (at most 5 bytes)
        while pos < stop and data[pos] & 0x80:
            pos += 1
        pos += 1
        if offset < HEADER_SIZE or pos > size:
            self._note("string-offset",
                       f"a string offset ({offset:#x}) points outside the string data")
            text = ""
        elif self._budget < 0:
            text = ""
        else:
            end = data.find(b"\0", pos, pos + MAX_STRING_BYTES)
            if end < 0:
                end = min(size, pos + MAX_STRING_BYTES)
                self._note("string-end", "a string has no terminating NUL within "
                                         f"{MAX_STRING_BYTES} bytes; truncated")
            self._budget -= end - pos
            if self._budget < 0:
                self._note("budget",
                           "strings overlap far more than a real file allows; rest not read")
                text = ""
            else:
                text = _mutf8(data[pos:end])
        self._cache[offset] = text
        return text

    def _read_headers(self) -> None:
        data, size = self._data, len(self._data)
        if size < HEADER_SIZE or data[:4] != MAGIC or data[7] != 0 or not data[4:7].isdigit():
            self.warn("not a DEX file (bad magic or too short)")
            return
        self.version = data[4:7].decode("ascii")
        start = 0
        while start is not None and len(self._parts) < MAX_SECTIONS:
            start = self._header(start)
        if start is not None:
            self.warn(f"more than {MAX_SECTIONS} DEX files in one container; the rest are skipped")
        self.sections = len(self._parts)

    def _header(self, start: int) -> Optional[int]:
        """Read the header at start; return where the next header of a container starts."""
        data, size = self._data, len(self._data)
        if start + HEADER_SIZE > size or data[start:start + 4] != MAGIC:
            self.warn(f"no DEX header at offset {start:#x} of the container")
            return None
        file_size, header_size, endian = struct.unpack_from("<III", data, start + 0x20)
        if endian != ENDIAN_CONSTANT:
            self.warn(f"unsupported byte order (endian tag {endian:#010x}); not read")
            return None
        fields = struct.unpack_from("<12I", data, start + 0x38)
        container = data[start + 4:start + 7].isdigit() and int(data[start + 4:start + 7]) >= 41 \
            and header_size >= HEADER_SIZE_V41 and start + HEADER_SIZE_V41 <= size
        if header_size not in (HEADER_SIZE, HEADER_SIZE_V41):
            self._note("header-size", f"unusual header size {header_size}")
        # the type, method and class tables of a DEX file in a container lie inside it
        end = start + file_size if container and HEADER_SIZE <= file_size <= size - start else size
        self._parts.append(_Section(
            self._string_ids(fields[0], fields[1]),
            self._table(fields[2], fields[3], 4, MAX_IDS, "type ids", start, end),
            self._table(fields[8], fields[9], 8, MAX_IDS, "method ids", start, end),
            self._table(fields[10], fields[11], 32, MAX_IDS, "class definitions", start, end)))
        if not container:
            if file_size != size:
                self.warn(f"the header gives a file size of {file_size} bytes but the file has "
                          f"{size}")
            elif zlib.adler32(memoryview(data)[12:]) != struct.unpack_from("<I", data, 8)[0]:
                self.warn("the checksum in the header does not match the file "
                          "(changed after the build?)")
            return None
        container_size, header_offset = struct.unpack_from("<II", data, start + 0x70)
        if start == 0 and container_size != size:
            self.warn(f"the header gives a container size of {container_size} bytes but the "
                      f"file has {size}")
        if header_offset != start:
            self._note("header-offset",
                       f"the DEX header at {start:#x} says it is at {header_offset:#x}")
        following = start + file_size
        if file_size < HEADER_SIZE or following >= min(container_size, size):
            return None
        return following

    def _string_ids(self, count: int, offset: int) -> Tuple[int, int]:
        """The string id table at offset. It may lie anywhere: the DEX files of a container
        share it, and a shared table is read once."""
        shared = self._shared.get(offset)
        if shared is not None and count:
            if count != shared[0]:
                self._note("shared", f"the DEX files of the container give the string ids table "
                                     f"at {offset:#x} different sizes; the first is used")
            return shared[1]
        table = self._table(count, offset, 4, MAX_STRINGS, "string ids", 0, len(self._data))
        if table[1]:
            self._shared[offset] = (count, table)
        return table

    def _table(self, count: int, offset: int, item: int, cap: int, what: str, low: int,
               high: int) -> Tuple[int, int]:
        """(offset, readable count) of an id table that must lie between low and high,
        clamped to that range and to what is left of cap after the tables read before."""
        if count == 0:
            return 0, 0
        if offset < HEADER_SIZE or offset >= len(self._data):
            self.warn(f"the {what} table starts outside the file (offset {offset:#x})")
            return 0, 0
        if not low + HEADER_SIZE <= offset < high:
            self._note("outside-" + what,
                       f"the {what} table at {offset:#x} is outside its DEX file "
                       f"({low:#x} to {high:#x}) in the container; not read")
            return 0, 0
        fit = (high - offset) // item
        if count > fit:
            self.warn(f"the {what} table claims {count} entries but the file holds at most "
                      f"{fit}; clamped")
            count = fit
        left = cap - self._taken.get(what, 0)
        if count > left:
            self.warn(f"the {what} table has {count} entries; only the first {left} are read "
                      f"(at most {cap} in one file)")
            count = left
        self._taken[what] = self._taken.get(what, 0) + count
        return offset, count


def parse_dex(data: bytes, name: str = "classes.dex") -> DexFile:
    """Parse a DEX file. Never raises on bad data: problems are in .warnings and a file that
    cannot be read at all gives empty tables. name labels the warnings. The DexFile does not
    keep the input bytes."""
    dex = DexFile(bytes(data), name)
    dex._read_headers()
    dex._decode()
    return dex


def _mutf8(raw: bytes) -> str:
    """Decode Modified UTF-8: NUL is C0 80 and a character outside the BMP is a pair of
    3-byte surrogates. A lone surrogate becomes U+FFFD."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        text = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "replace")
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def descriptor_to_java(descriptor: str) -> str:
    """A type descriptor as Java writes it: "Lcom/a/B;" -> "com.a.B", "[I" -> "int[]"."""
    base = descriptor.lstrip("[")
    dims = len(descriptor) - len(base)
    if base.startswith("L") and base.endswith(";") and len(base) > 2:
        base = base[1:-1].replace("/", ".")
    else:
        base = _PRIMITIVES.get(base, base)
    return base + "[]" * dims


def flutter_markers(dexes: Iterable[DexFile]) -> Dict[str, bool]:
    """Which Flutter embedding classes the DEX files define or reference. "flutter" is true
    when any of them, or any other io.flutter class, is there."""
    types = {t for dex in dexes for t in dex.type_names()}
    markers = {
        "flutter_jni": FLUTTER_JNI in types,
        "plugin_registrant": PLUGIN_REGISTRANT in types,
        "flutter_activity": FLUTTER_ACTIVITY in types,
        "flutter_fragment_activity": FLUTTER_FRAGMENT_ACTIVITY in types,
    }
    markers["flutter"] = any(markers.values()) or any(t.startswith("Lio/flutter/") for t in types)
    return markers


def plugin_classes(dexes: Iterable[DexFile]) -> List[str]:
    """Java names of the Flutter plugin classes the DEX files define: top-level classes whose
    name ends with "Plugin", outside the Flutter engine's own packages. Which plugins
    GeneratedPluginRegistrant registers is only in its code, which is not decoded here, and
    R8 renames plugin classes in release builds, so this list can be incomplete."""
    found = set()
    for dex in dexes:
        for descriptor, _, _ in dex.class_defs():
            name = descriptor_to_java(descriptor)
            simple = name.rsplit(".", 1)[-1]
            if simple.endswith("Plugin") and simple != "Plugin" and "$" not in name \
                    and not name.startswith(_ENGINE_PACKAGES):
                found.add(name)
    return sorted(found)


# ------------------------------------------------------------------ builder for tests

def _mutf8_encode(text: str) -> bytes:
    out = bytearray()
    units = text.encode("utf-16-le", "surrogatepass")
    for i in range(0, len(units), 2):
        unit = units[i] | units[i + 1] << 8
        if 0 < unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out += bytes([0xC0 | unit >> 6, 0x80 | unit & 0x3F])
        else:
            out += bytes([0xE0 | unit >> 12, 0x80 | unit >> 6 & 0x3F, 0x80 | unit & 0x3F])
    return bytes(out)


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _proto_parts(proto: str) -> Tuple[str, List[str]]:
    """("V", ["Ljava/lang/String;", "I"]) for "(Ljava/lang/String;I)V"."""
    params, _, result = proto[1:].partition(")")
    types, pos = [], 0
    while pos < len(params):
        end = pos
        while params[end] == "[":
            end += 1
        end = params.index(";", end) + 1 if params[end] == "L" else end + 1
        types.append(params[pos:end])
        pos = end
    return result, types


def _shorty(descriptor: str) -> str:
    return "L" if descriptor[0] in "L[" else descriptor[0]


def _build_section(strings: Sequence[str], classes: Sequence[Tuple[str, Optional[str]]],
                   methods: Sequence[Tuple[str, str, str]], version: str, base: int,
                   container_size: int) -> bytes:
    protos = {proto: _proto_parts(proto) for _, _, proto in methods}
    types = {desc for desc, _ in classes} | {sup for _, sup in classes if sup}
    types |= {cls for cls, _, _ in methods}
    for result, params in protos.values():
        types |= {result, *params}
    shorties = {proto: _shorty(result) + "".join(_shorty(p) for p in params)
                for proto, (result, params) in protos.items()}
    pool = set(strings) | types | {name for _, name, _ in methods} | set(shorties.values())
    pool_list = sorted(pool, key=lambda s: s.encode("utf-16-be", "surrogatepass"))
    string_idx = {s: i for i, s in enumerate(pool_list)}
    type_list = sorted(types, key=string_idx.get)
    type_idx = {t: i for i, t in enumerate(type_list)}
    proto_list = sorted(protos, key=lambda p: (type_idx[protos[p][0]],
                                               [type_idx[t] for t in protos[p][1]]))
    proto_idx = {p: i for i, p in enumerate(proto_list)}
    method_list = sorted(set(methods),
                         key=lambda m: (type_idx[m[0]], string_idx[m[1]], proto_idx[m[2]]))

    header_size = HEADER_SIZE_V41 if int(version) >= 41 else HEADER_SIZE
    string_ids = header_size
    type_ids = string_ids + 4 * len(pool_list)
    proto_ids = type_ids + 4 * len(type_list)
    method_ids = proto_ids + 12 * len(proto_list)
    class_defs = method_ids + 8 * len(method_list)
    data_off = class_defs + 32 * len(classes)

    data = bytearray()
    params_at: Dict[str, int] = {}
    for proto in proto_list:
        params = protos[proto][1]
        if params:
            params_at[proto] = data_off + len(data)
            data += struct.pack(f"<I{len(params)}H", len(params), *(type_idx[t] for t in params))
            data += bytes(-len(data) % 4)
    string_at = []
    for text in pool_list:
        string_at.append(data_off + len(data))
        units = len(text.encode("utf-16-le", "surrogatepass")) // 2
        data += _uleb128(units) + _mutf8_encode(text) + b"\0"
    data += bytes(-len(data) % 4)
    map_off = data_off + len(data)
    sections = [(0x0000, 1, 0), (0x0001, len(pool_list), string_ids),
                (0x0002, len(type_list), type_ids), (0x0003, len(proto_list), proto_ids),
                (0x0005, len(method_list), method_ids), (0x0006, len(classes), class_defs),
                (0x2002, len(pool_list), string_at[0] if string_at else 0), (0x1000, 1, map_off)]
    if params_at:
        sections.insert(-2, (0x1001, len(params_at), min(params_at.values())))
    sections = [(kind, count, base + off) for kind, count, off in sections if count]
    data += struct.pack("<I", len(sections))
    data += b"".join(struct.pack("<HHII", kind, 0, count, off) for kind, count, off in sections)

    body = bytearray()
    body += b"".join(struct.pack("<I", base + at) for at in string_at)
    body += b"".join(struct.pack("<I", string_idx[t]) for t in type_list)
    for proto in proto_list:
        result, _ = protos[proto]
        body += struct.pack("<III", string_idx[shorties[proto]], type_idx[result],
                            base + params_at[proto] if proto in params_at else 0)
    for cls, name, proto in method_list:
        body += struct.pack("<HHI", type_idx[cls], proto_idx[proto], string_idx[name])
    for desc, sup in classes:
        body += struct.pack("<8I", type_idx[desc], ACC_PUBLIC, type_idx[sup] if sup else NO_INDEX,
                            0, NO_INDEX, 0, 0, 0)
    file_size = data_off + len(data)
    header = bytearray(header_size)
    header[:8] = MAGIC + version.encode("ascii") + b"\0"
    struct.pack_into("<III", header, 0x20, file_size, header_size, ENDIAN_CONSTANT)
    struct.pack_into("<III", header, 0x2C, 0, 0, base + map_off)
    tables = [(len(pool_list), string_ids), (len(type_list), type_ids),
              (len(proto_list), proto_ids), (0, 0), (len(method_list), method_ids),
              (len(classes), class_defs)]
    struct.pack_into("<12I", header, 0x38,
                     *(n for count, off in tables for n in (count, base + off if count else 0)))
    struct.pack_into("<II", header, 0x68, len(data), base + data_off)
    if header_size == HEADER_SIZE_V41:
        struct.pack_into("<II", header, 0x70, container_size or file_size, base)
    out = header + body + data
    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(out[12:]))
    return bytes(out)


def build_dex(strings: Sequence[str] = (), classes: Sequence[Tuple[str, Optional[str]]] = (),
              methods: Sequence[Tuple[str, str, str]] = (), *, version: str = "035") -> bytes:
    """A DEX file for tests: a valid header, the id tables and the string data (no code).
    classes are (descriptor, superclass descriptor or None); methods are (class descriptor,
    name, prototype such as "(Ljava/lang/String;)V"). Every descriptor and name also becomes
    a string; strings are sorted as the format requires, so indexes are not the input order."""
    return _build_section(strings, classes, methods, version, 0, 0)


def build_dex_container(sections: Sequence[Tuple[Sequence[str], Sequence[Tuple[str, Optional[str]]],
                                                  Sequence[Tuple[str, str, str]]]]) -> bytes:
    """A version 041 container for tests: one logical DEX file per (strings, classes,
    methods) section, each following the previous one, every offset counted from the start
    of the container."""
    sizes = [len(_build_section(*part, "041", 0, 0)) for part in sections]
    total, out = sum(sizes), bytearray()
    for part in sections:
        out += _build_section(*part, "041", len(out), total)
    return bytes(out)
