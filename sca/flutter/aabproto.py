"""Decoder for the protobuf XML of Android App Bundles (.aab).

An app bundle stores AndroidManifest.xml (base/manifest/AndroidManifest.xml) and its XML
resources (base/res/xml/...) as protobuf messages of type aapt.pb.XmlNode instead of binary
XML. Field numbers (AOSP frameworks/base tools/aapt2/Resources.proto):
    XmlNode       1 element, 2 text, 3 source
    XmlElement    1 namespace_declaration, 2 namespace_uri, 3 name, 4 attribute, 5 child
    XmlNamespace  1 prefix, 2 uri, 3 source
    XmlAttribute  1 namespace_uri, 2 name, 3 value, 4 source, 5 resource_id, 6 compiled_item
    Item          1 ref, 2 str, 3 raw_str, 4 styled_str, 5 file, 6 id, 7 prim
    Reference     1 type (0 reference, 1 attribute), 2 id, 3 name
    Primitive     1 null, 2 empty, 3 float, 4/5 deprecated float dimension/fraction,
                  6 int_decimal, 7 int_hexadecimal, 8 boolean, 9-12 colors,
                  13 dimension, 14 fraction

A small wire-format reader (varint, 64-bit, length-delimited, 32-bit) does the work; no
generated code. The result is the same AxmlDocument as the binary XML decoder gives. The
message is untrusted: reads are bounds-checked, nesting and element numbers are capped, a
malformed part is skipped with a warning, and only data without any element raises
ProtoError.
"""
from __future__ import annotations

import re
import struct
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .axml import (ANDROID_ATTR_IDS, KNOWN_PREFIXES, LAUNCH_MODES, PROTECTION_FLAGS,
                   PROTECTION_LEVELS, TYPE_DIMENSION, TYPE_FLOAT, TYPE_FRACTION, TYPE_INT_BOOLEAN,
                   TYPE_INT_COLOR_ARGB4, TYPE_INT_COLOR_ARGB8, TYPE_INT_COLOR_RGB4,
                   TYPE_INT_COLOR_RGB8, TYPE_INT_DEC, TYPE_INT_HEX, AxmlDocument, AxmlError,
                   Namespaces, format_value)
from .xmltree import XmlNode, render_xml

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_BYTES = 2
WIRE_FIXED32 = 5

# caps against hostile messages (the output grows at most linearly with the message: unlike
# binary XML, protobuf strings cannot share bytes)
MAX_MESSAGE = 16 << 20
MAX_DEPTH = 200
MAX_NODES = 100_000
MAX_WARNINGS = 100

Field = Tuple[int, int, Union[int, memoryview]]

# Primitive field number -> Res_value type of its 32-bit value
_PRIMITIVE_TYPES = {3: TYPE_FLOAT, 6: TYPE_INT_DEC, 7: TYPE_INT_HEX, 8: TYPE_INT_BOOLEAN,
                    9: TYPE_INT_COLOR_ARGB8, 10: TYPE_INT_COLOR_RGB8, 11: TYPE_INT_COLOR_ARGB4,
                    12: TYPE_INT_COLOR_RGB4, 13: TYPE_DIMENSION, 14: TYPE_FRACTION}


class ProtoError(AxmlError):
    """The data is not a protobuf XML message that can be decoded."""


def read_varint(data: Union[bytes, memoryview], pos: int, end: int) -> Tuple[int, int]:
    """(value, next position) of the varint at `pos`."""
    value = shift = 0
    while True:
        if pos >= end:
            raise ProtoError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift >= 70:
            raise ProtoError("varint longer than 10 bytes")


def iter_fields(data: Union[bytes, memoryview]) -> Iterator[Field]:
    """(field number, wire type, value) of every field of a message: an int for varint and
    fixed fields, a memoryview of the bytes for length-delimited ones. Raises ProtoError on
    malformed data (groups, field number 0, lengths past the end)."""
    view = memoryview(data)
    pos, end = 0, len(view)
    while pos < end:
        key, pos = read_varint(view, pos, end)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ProtoError("field number 0")
        if wire == WIRE_VARINT:
            value, pos = read_varint(view, pos, end)
            yield number, wire, value
        elif wire == WIRE_FIXED64 or wire == WIRE_FIXED32:
            width = 8 if wire == WIRE_FIXED64 else 4
            if pos + width > end:
                raise ProtoError("truncated fixed-width field")
            yield number, wire, int.from_bytes(view[pos:pos + width], "little")
            pos += width
        elif wire == WIRE_BYTES:
            length, pos = read_varint(view, pos, end)
            if length > end - pos:
                raise ProtoError("length-delimited field runs past the end")
            yield number, wire, view[pos:pos + length]
            pos += length
        else:
            raise ProtoError(f"unsupported wire type {wire}")


def decode_proto_xml(data: bytes) -> AxmlDocument:
    """Decode an aapt.pb.XmlNode message (AndroidManifest.xml or an XML resource of an app
    bundle). Values come from the attribute's `value` text when it has one, else from its
    compiled item (references as "@type/name" or "@0x7f...", booleans, numbers). Raises
    ProtoError when the message holds no element."""
    if len(data) > MAX_MESSAGE:
        raise ProtoError(f"message larger than {MAX_MESSAGE} bytes")
    decoder = _Decoder()
    root = decoder.root(bytes(data))
    namespaces = dict(decoder.names.by_prefix)
    text = render_xml(root, namespaces)
    return AxmlDocument(root, namespaces, text, decoder.warnings)


class _Decoder:
    def __init__(self) -> None:
        self.warnings: List[str] = []
        self.names = Namespaces(self.warn)
        self.nodes = 0

    def warn(self, message: str) -> None:
        if len(self.warnings) > MAX_WARNINGS or message in self.warnings:
            return
        if len(self.warnings) == MAX_WARNINGS:
            message = "further warnings suppressed"
        self.warnings.append(message)

    def fields(self, data: memoryview, what: str) -> List[Field]:
        """The fields of a message; the ones before a malformed part when it has one."""
        found: List[Field] = []
        try:
            for item in iter_fields(data):
                found.append(item)
        except ProtoError as exc:
            self.warn(f"malformed {what} ({exc}); the rest of it is skipped")
        return found

    def root(self, data: bytes) -> XmlNode:
        element = next((value for number, wire, value in self.fields(memoryview(data), "XmlNode")
                        if number == 1 and wire == WIRE_BYTES), None)
        if element is None:
            raise ProtoError("no XML element")
        return self.element(element, 0)

    def element(self, data: memoryview, depth: int) -> XmlNode:
        self.nodes += 1
        uri = name = ""
        attributes: List[memoryview] = []
        children: List[memoryview] = []
        for number, wire, value in self.fields(data, "XmlElement"):
            if wire != WIRE_BYTES:
                continue
            if number == 1:
                self.declare(value)
            elif number == 2:
                uri = _text(value)
            elif number == 3:
                name = _text(value)
            elif number == 4:
                attributes.append(value)
            elif number == 5:
                children.append(value)
        name = self.names.cut(name)
        if not name:
            self.warn("an element has no name")
            name = "unknown"
        node = XmlNode(f"{self.names.prefix_of(uri)}:{name}" if uri else name)
        for attribute in attributes:
            key, text = self.attribute(node.tag, attribute)
            if key in node.attrs:
                self.warn(f"<{node.tag}> has attribute {key} twice; the first value is kept")
            else:
                node.attrs[key] = text
        texts: List[str] = []
        for child in children:
            element, text = None, None
            for number, wire, value in self.fields(child, "XmlNode"):
                if number == 1 and wire == WIRE_BYTES:
                    element = value
                elif number == 2 and wire == WIRE_BYTES:
                    text = _text(value)
            if element is not None:
                if depth + 1 >= MAX_DEPTH:
                    self.warn(f"elements nested deeper than {MAX_DEPTH} levels are skipped")
                elif self.nodes >= MAX_NODES:
                    self.warn(f"more than {MAX_NODES} elements; the rest is ignored")
                else:
                    node.children.append(self.element(element, depth + 1))
            elif text:
                texts.append(text)
        node.text = "".join(texts).strip()
        return node

    def declare(self, data: memoryview) -> None:
        prefix = uri = ""
        for number, wire, value in self.fields(data, "XmlNamespace"):
            if number == 1 and wire == WIRE_BYTES:
                prefix = _text(value)
            elif number == 2 and wire == WIRE_BYTES:
                uri = _text(value)
        if not uri:
            self.warn(f"namespace prefix '{self.names.cut(prefix)}' has an empty URI")
            return
        self.names.prefix_of(uri, prefix)

    def attribute(self, tag: str, data: memoryview) -> Tuple[str, str]:
        uri = name = value = ""
        res_id = 0
        item: Optional[memoryview] = None
        for number, wire, field_value in self.fields(data, "XmlAttribute"):
            if number == 1 and wire == WIRE_BYTES:
                uri = _text(field_value)
            elif number == 2 and wire == WIRE_BYTES:
                name = _text(field_value)
            elif number == 3 and wire == WIRE_BYTES:
                value = _text(field_value)
            elif number == 5 and wire == WIRE_VARINT:
                res_id = field_value & 0xFFFFFFFF
            elif number == 6 and wire == WIRE_BYTES:
                item = field_value
        key = self.names.attribute_name(tag, uri, name, res_id)
        if not value and item is not None:
            value = self.item(item, key)
        return key, value

    def item(self, data: memoryview, key: str) -> str:
        """Text of a compiled Item."""
        for number, wire, value in self.fields(data, "Item"):
            if wire != WIRE_BYTES:
                continue
            if number == 1:
                return self.reference(value)
            if number in (2, 3, 4, 5):         # str, raw_str, styled_str, file: field 1 text
                return next((_text(v) for n, w, v in self.fields(value, "Item value")
                             if n == 1 and w == WIRE_BYTES), "")
            if number == 7:
                return self.primitive(value, key)
        return ""

    def reference(self, data: memoryview) -> str:
        kind = res_id = 0
        name = ""
        for number, wire, value in self.fields(data, "Reference"):
            if number == 1 and wire == WIRE_VARINT:
                kind = value
            elif number == 2 and wire == WIRE_VARINT:
                res_id = value & 0xFFFFFFFF
            elif number == 3 and wire == WIRE_BYTES:
                name = _text(value)
        sign = "?" if kind == 1 else "@"
        if name:
            package, colon, rest = name.partition(":")
            if colon and package != "android":
                name = rest                     # the app's own package is implied
            return sign + name
        if not res_id:
            return "@null"
        return f"{sign}0x{res_id:08x}"

    def primitive(self, data: memoryview, key: str) -> str:
        for number, wire, value in self.fields(data, "Primitive"):
            if number in (1, 2):                # null, empty
                return ""
            if number in (4, 5) and wire == WIRE_FIXED32:     # deprecated float forms
                return f"{struct.unpack('<f', struct.pack('<I', value))[0]:g}"
            data_type = _PRIMITIVE_TYPES.get(number)
            if data_type is not None and isinstance(value, int):
                if data_type == TYPE_INT_BOOLEAN:
                    value = 1 if value else 0
                return format_value(data_type, value & 0xFFFFFFFF, key)
        return ""


def _text(value: Union[int, memoryview]) -> str:
    if isinstance(value, int):
        return ""
    return bytes(value).decode("utf-8", "replace")


# ------------------------------------------------------------------ encoder (for tests)
def encode_proto_xml(root: XmlNode, *, namespaces: Optional[Dict[str, str]] = None,
                     attr_ids: Optional[Dict[str, int]] = None, keep_raw: bool = True) -> bytes:
    """An aapt.pb.XmlNode message for a tree, as bundletool reads it from an app bundle.

    Every attribute gets its `value` text (unless `keep_raw` is false and the value has a
    compiled form) and, when its text has one, a compiled item: booleans, decimal numbers,
    launchMode and protectionLevel names, "@0x..." references. `android:` attributes get
    their resource ids from ANDROID_ATTRS, `attr_ids` adds ids by full name; `namespaces`
    (prefix -> URI) defaults to android, tools and app for the prefixes in use.
    """
    ids = {f"android:{name}": res_id for name, res_id in ANDROID_ATTR_IDS.items()}
    ids.update(attr_ids or {})
    if namespaces is None:
        known = {prefix: uri for uri, prefix in KNOWN_PREFIXES.items()}
        used = {name.split(":", 1)[0] for node in root.iter() for name in [node.tag, *node.attrs]
                if ":" in name}
        namespaces = {prefix: known[prefix] for prefix in sorted(used) if prefix in known}
    return _field_bytes(1, _encode_element(root, namespaces, ids, keep_raw, True))


def _encode_element(node: XmlNode, namespaces: Dict[str, str], ids: Dict[str, int],
                    keep_raw: bool, is_root: bool) -> bytes:
    out = bytearray()
    if is_root:
        for prefix, uri in namespaces.items():
            out += _field_bytes(1, _field_text(1, prefix) + _field_text(2, uri))
    uri, local = _split(node.tag, namespaces)
    if uri:
        out += _field_text(2, uri)
    out += _field_text(3, local)
    for key, value in node.attrs.items():
        uri, local = _split(key, namespaces)
        attribute = bytearray()
        if uri:
            attribute += _field_text(1, uri)
        attribute += _field_text(2, local)
        compiled = _compiled_item(local, value)
        if keep_raw or compiled is None:
            attribute += _field_text(3, value)
        if key in ids:
            attribute += _field_varint(5, ids[key])
        if compiled is not None:
            attribute += _field_bytes(6, compiled)
        out += _field_bytes(4, bytes(attribute))
    for child in node.children:
        out += _field_bytes(5, _field_bytes(1, _encode_element(child, namespaces, ids, keep_raw,
                                                               False)))
    if node.text:
        out += _field_bytes(5, _field_text(2, node.text))
    return bytes(out)


def _compiled_item(local: str, value: str) -> Optional[bytes]:
    """The Item message of a value that aapt2 compiles, or None for plain text."""
    if value in ("true", "false"):
        return _field_bytes(7, _field_varint(8, 1 if value == "true" else 0))
    if local == "launchMode" and value in LAUNCH_MODES.values():
        number = next(k for k, v in LAUNCH_MODES.items() if v == value)
        return _field_bytes(7, _field_varint(6, number))
    if local == "protectionLevel":
        levels = {name: number for number, name in PROTECTION_LEVELS.items()}
        flags = {name: bit for bit, name in PROTECTION_FLAGS}
        parts = value.split("|")
        if all(part in levels or part in flags for part in parts):
            number = 0
            for part in parts:
                number |= levels.get(part, 0) | flags.get(part, 0)
            return _field_bytes(7, _field_varint(7, number))
    if re.fullmatch(r"@0x[0-9a-fA-F]{8}", value):
        return _field_bytes(1, _field_varint(2, int(value[3:], 16)))
    if re.fullmatch(r"-?[0-9]{1,10}", value) and -(1 << 31) <= int(value) < (1 << 31):
        return _field_bytes(7, _field_varint(6, int(value) & 0xFFFFFFFFFFFFFFFF))
    return None


def _split(name: str, namespaces: Dict[str, str]) -> Tuple[str, str]:
    """(namespace URI, local name) of a prefixed name; a name whose prefix is not declared
    is kept whole."""
    prefix, colon, local = name.partition(":")
    if colon and prefix in namespaces:
        return namespaces[prefix], local
    return "", name


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field_varint(number: int, value: int) -> bytes:
    return _varint(number << 3 | WIRE_VARINT) + _varint(value)


def _field_bytes(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | WIRE_BYTES) + _varint(len(payload)) + payload


def _field_text(number: int, text: str) -> bytes:
    return _field_bytes(number, text.encode("utf-8"))
