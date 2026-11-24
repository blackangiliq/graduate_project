"""Tests for the app-package format readers of the Flutter / Android module: the ZIP reader
and its containers, the XML tree and renderer, the binary XML (AXML) decoder and the protobuf
XML decoder of app bundles. Inputs are built with the modules' own builders and then bent
the way malformed or hostile packages are; the real APK checks run only when the
SCA_FLUTTER_APK_DIR environment variable points to a folder with the lab APKs."""
import hashlib
import io
import os
import random
import struct
import time
import tracemalloc
import zipfile
import zlib
from pathlib import Path

import pytest

from sca.flutter import aabproto, axml
from sca.flutter.aabproto import ProtoError, decode_proto_xml, encode_proto_xml, iter_fields
from sca.flutter.axml import (ANDROID_URI, AxmlError, decode_axml, encode_axml, format_value,
                              protection_level_name)
from sca.flutter.xmltree import XmlNode, parse_xml_text, render_xml
from sca.flutter.zipread import (ZipArchive, ZipEntry, ZipError, build_zip, is_zip,
                                 open_container)

APK_DIR = os.environ.get("SCA_FLUTTER_APK_DIR", "")


def manifest_tree():
    """A small manifest with the attribute kinds the checks read."""
    activity = XmlNode("activity", {
        "android:name": ".MainActivity", "android:exported": "true",
        "android:launchMode": "singleTop", "android:taskAffinity": "",
        "android:theme": "@0x7f0c0000", "android:configChanges": "0x40003fb4"},
        [XmlNode("intent-filter", {}, [
            XmlNode("action", {"android:name": "android.intent.action.MAIN"}),
            XmlNode("category", {"android:name": "android.intent.category.LAUNCHER"}),
            XmlNode("data", {"android:scheme": "myapp", "android:host": "open"})])])
    application = XmlNode("application", {
        "android:label": "Démo app", "android:debuggable": "true",
        "android:allowBackup": "false", "android:usesCleartextTraffic": "true",
        "android:networkSecurityConfig": "@0x7f0f0000", "android:description": "--5",
        "android:process": "٣"}, [activity])
    return XmlNode("manifest", {
        "android:versionCode": "7", "android:versionName": "1.2.3",
        "package": "com.example.demo"}, [
        XmlNode("uses-sdk", {"android:minSdkVersion": "21", "android:targetSdkVersion": "34"}),
        XmlNode("uses-permission", {"android:name": "android.permission.CAMERA"}),
        XmlNode("permission", {"android:name": "com.example.demo.P",
                               "android:protectionLevel": "signature|privileged"}),
        application])


def same_tree(a, b, lines=False):
    if (a.tag, a.attrs, a.text) != (b.tag, b.attrs, b.text) or len(a.children) != len(b.children):
        return False
    if lines and (a.line, a.attr_lines) != (b.line, b.attr_lines):
        return False
    return all(same_tree(x, y, lines) for x, y in zip(a.children, b.children))


def chain(depth):
    root = node = XmlNode("n0")
    for i in range(1, depth):
        child = XmlNode(f"n{i}")
        node.children.append(child)
        node = child
    return root


# ------------------------------------------------------------------ binary XML surgery
def chunks(data):
    """The chunks inside the root chunk of binary XML."""
    out, pos = [], struct.unpack_from("<H", data, 2)[0]
    while pos < len(data):
        size = struct.unpack_from("<I", data, pos + 4)[0]
        out.append(bytearray(data[pos:pos + size]))
        pos += size
    return out


def assemble(parts):
    body = b"".join(bytes(p) for p in parts)
    return struct.pack("<HHI", axml.RES_XML, 8, 8 + len(body)) + body


def chunk_type(chunk):
    return struct.unpack_from("<H", chunk, 0)[0]


def first_start_with_attributes(parts, count=2):
    return next(i for i, c in enumerate(parts) if chunk_type(c) == axml.RES_XML_START_ELEMENT
                and struct.unpack_from("<H", c, 16 + 12)[0] >= count)


def relayout(chunk, attr_start, attr_size):
    """A start-element chunk with its attributes moved to another start and stride."""
    header_size = struct.unpack_from("<H", chunk, 2)[0]
    ext = bytes(chunk[header_size:header_size + 20])
    count = struct.unpack_from("<H", ext, 12)[0]
    first = header_size + 20
    attrs = [bytes(chunk[first + 20 * i:first + 20 * i + 20]) for i in range(count)]
    ext = ext[:8] + struct.pack("<HH", attr_start, attr_size) + ext[12:]
    body = ext + b"\0" * (attr_start - 20) + b"".join(a + b"\0" * (attr_size - 20) for a in attrs)
    out = bytearray(chunk[:header_size]) + body
    struct.pack_into("<I", out, 4, len(out))
    return out


# ------------------------------------------------------------------ xmltree
SOURCE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application
        android:label="App"
        android:usesCleartextTraffic="true"
        android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <data android:scheme="myapp" />
            </intent-filter>
        </activity>
        <meta-data android:name="k"
                   android:value="v" />
    </application>
</manifest>
"""


def test_parse_xml_text_keeps_prefixes_and_lines():
    root, error = parse_xml_text(SOURCE_MANIFEST)
    assert error == "" and root.tag == "manifest" and root.line == 2
    assert root.get("xmlns:android") == ANDROID_URI and root.line_of("package") == 3
    application = root.find("application")
    assert application.line == 4 and application.get("android:usesCleartextTraffic") == "true"
    assert application.line_of("android:allowBackup") == 7
    assert application.line_of("android:debuggable") == 4          # absent: the start tag
    activity = application.find("activity")
    assert activity.line_of("android:exported") == 8 and activity.get("missing", "d") == "d"
    assert [n.tag for n in root.iter()] == ["manifest", "application", "activity",
                                            "intent-filter", "data", "meta-data"]
    assert [n.line for n in root.iter("data")] == [10]
    assert application.findall("meta-data")[0].line_of("android:value") == 14
    assert root.find("nothing") is None and application.findall("nothing") == []


def test_parse_xml_text_counts_lines_like_splitlines():
    text = ('<a>\r\n<b x="1"\r\n   y="2" />\r\n<!-- \u2028 -->\n<c\n z="é" />'
            '\n<d>  text \n</d></a>')
    root, error = parse_xml_text(text)
    lines = text.splitlines()
    assert error == ""
    b, c, d = root.children
    assert "x=" in lines[b.line_of("x") - 1] and "y=" in lines[b.line_of("y") - 1]
    assert lines[c.line - 1] == "<c" and "z=" in lines[c.line_of("z") - 1]
    assert d.text == "text"


@pytest.mark.parametrize("text, message", [
    ("<a><b></a>", "line 1"),
    ('<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>', "entity"),
    ('<!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>', "entity"),
    ("", "line 1"),
])
def test_parse_xml_text_refuses_bad_xml_and_entities(text, message):
    root, error = parse_xml_text(text)
    assert root is None and message in error


def test_parse_xml_text_caps_nesting():
    root, error = parse_xml_text("<a>" * 5000 + "</a>" * 5000)
    assert root is None and "nested deeper" in error
    root, error = parse_xml_text("<a>" * 150 + "</a>" * 150)
    assert root is not None and error == ""


def test_render_xml_one_attribute_per_line():
    tree = XmlNode("manifest", {"package": "p", "android:x": 'a"b<c>&\nd\x01\u2028'}, [
        XmlNode("uses-sdk", {"android:minSdkVersion": "21"}),
        XmlNode("string", {"name": "k"}, text="AIza value"),
        XmlNode("empty"),
        XmlNode("bad name\n", {"1x": "v"})])
    text = render_xml(tree, {"android": ANDROID_URI})
    lines = text.splitlines()
    assert lines[0] == '<?xml version="1.0" encoding="utf-8"?>' and lines[1] == "<manifest"
    assert lines[2] == f'    xmlns:android="{ANDROID_URI}"'
    assert tree.line == 2 and lines[tree.line_of("package") - 1] == '    package="p"'
    assert lines[tree.line_of("android:x") - 1] == \
        '    android:x="a&quot;b&lt;c&gt;&amp;&#10;d\ufffd&#8232;">'
    sdk, string, empty, bad = tree.children
    assert lines[sdk.line - 1] == "    <uses-sdk"
    assert sdk.line_of("android:minSdkVersion") == sdk.line + 1
    assert lines[sdk.line] == '        android:minSdkVersion="21" />'
    assert lines[string.line_of("name") - 1] == '        name="k">AIza value</string>'
    assert lines[empty.line - 1] == "    <empty />" and lines[bad.line - 1] == "    <bad_name_"
    assert lines[-1] == "</manifest>" and text.endswith("\n")
    parsed, error = parse_xml_text(text)
    assert error == "" and parsed.children[1].text == "AIza value"


def test_render_xml_round_trips_through_parse_xml_text():
    tree = manifest_tree()
    text = render_xml(tree, {"android": ANDROID_URI})
    parsed, error = parse_xml_text(text)
    assert error == ""
    del parsed.attrs["xmlns:android"]
    del parsed.attr_lines["xmlns:android"]
    assert same_tree(tree, parsed, lines=True)


def test_render_xml_deep_tree_without_recursion():
    tree = chain(5000)
    lines = render_xml(tree).splitlines()
    assert len(lines) == 1 + 2 * 4999 + 1           # header, start and end tags, the leaf
    assert max(len(line) for line in lines) < 200     # indentation stops growing
    assert list(tree.iter())[-1].line == 5001 and lines[5000].endswith("<n4999 />")


# ------------------------------------------------------------------ binary XML
@pytest.mark.parametrize("utf8", [False, True])
def test_axml_round_trip(utf8):
    tree = manifest_tree()
    tree.find("application").find("activity").text = "inline text"
    data = encode_axml(tree, utf8=utf8)
    assert struct.unpack_from("<HHI", data, 0) == (axml.RES_XML, 8, len(data))
    doc = decode_axml(data)
    assert doc.warnings == [] and doc.namespaces == {"android": ANDROID_URI}
    assert same_tree(tree, doc.root)
    application = doc.root.find("application")
    lines = doc.text.splitlines()
    assert lines[application.line_of("android:debuggable") - 1].strip() == \
        'android:debuggable="true"'
    assert doc.root.get("package") == "com.example.demo"


def test_axml_booleans_are_written_as_all_ones_and_read_as_any_non_zero():
    data = bytearray(encode_axml(XmlNode("application", {"android:debuggable": "true"})))
    assert struct.pack("<BI", axml.TYPE_INT_BOOLEAN, 0xFFFFFFFF) in data
    data = data.replace(struct.pack("<BI", axml.TYPE_INT_BOOLEAN, 0xFFFFFFFF),
                        struct.pack("<BI", axml.TYPE_INT_BOOLEAN, 1))
    assert decode_axml(bytes(data)).root.get("android:debuggable") == "true"


def test_axml_resolves_references():
    names = {0x7F0F0000: "@xml/network_security_config"}
    doc = decode_axml(encode_axml(manifest_tree()), resolve_ref=names.get)
    application = doc.root.find("application")
    assert application.get("android:networkSecurityConfig") == "@xml/network_security_config"
    assert application.find("activity").get("android:theme") == "@0x7f0c0000"

    def broken(res_id):
        raise RuntimeError("resolver failure")
    doc = decode_axml(encode_axml(manifest_tree()), resolve_ref=broken)
    assert doc.root.find("application").get("android:networkSecurityConfig") == "@0x7f0f0000"


def test_axml_attribute_names_follow_resource_ids():
    tree = XmlNode("activity", {"android:hidden": "true", "android:name": "A"})
    data = encode_axml(tree, attr_ids={"android:hidden": 0x01010010})
    doc = decode_axml(data)
    assert doc.root.attrs == {"android:exported": "true", "android:name": "A"}
    assert any("resource id of android:exported" in w for w in doc.warnings)
    # a known name on the id of another attribute is not trusted
    doc = decode_axml(encode_axml(XmlNode("a", {"android:debuggable": "true"}),
                                  attr_ids={"android:debuggable": 0x010104F8}))
    assert doc.root.attrs == {"android:attr_010104f8": "true"}
    # an android attribute without an id is invisible to Android's package parser
    doc = decode_axml(encode_axml(XmlNode("a", {"android:debuggable": "true"}),
                                  attr_ids={"android:debuggable": 0}))
    assert doc.root.get("android:debuggable") == "true"
    assert any("no resource id" in w for w in doc.warnings)


def test_axml_namespace_prefixes():
    tree = XmlNode("root", {"app:layout": "x", "tools:ignore": "y", "custom:v": "z"})
    data = encode_axml(tree, namespaces={"android": "urn:fake", "app": axml.APP_URI,
                                         "tools": axml.TOOLS_URI, "custom": "urn:custom"})
    doc = decode_axml(data)
    assert doc.root.attrs == {"app:layout": "x", "tools:ignore": "y", "custom:v": "z"}
    assert doc.namespaces["ns1"] == "urn:fake"        # "android" is kept for the real URI
    assert doc.namespaces["custom"] == "urn:custom"


def test_format_value():
    assert format_value(axml.TYPE_INT_BOOLEAN, 0xFFFFFFFF) == "true"
    assert format_value(axml.TYPE_INT_BOOLEAN, 0) == "false"
    assert format_value(axml.TYPE_INT_DEC, 0xFFFFFFFE) == "-2"
    assert format_value(axml.TYPE_INT_HEX, 0x10) == "0x00000010"
    assert format_value(axml.TYPE_INT_HEX, 2, "android:protectionLevel") == "signature"
    assert format_value(axml.TYPE_INT_DEC, 2, "android:launchMode") == "singleTask"
    assert format_value(axml.TYPE_INT_DEC, 9, "android:launchMode") == "9"
    assert format_value(axml.TYPE_REFERENCE, 0) == "@null"
    assert format_value(axml.TYPE_REFERENCE, 0x7F010000) == "@0x7f010000"
    assert format_value(axml.TYPE_ATTRIBUTE, 0x01010000) == "?android:attr/theme"
    names = {0x7F040000: "@attr/x"}
    assert format_value(axml.TYPE_ATTRIBUTE, 0x7F040000, "", names.get) == "?attr/x"
    assert format_value(axml.TYPE_INT_COLOR_RGB8, 0xFF1D873B) == "#ff1d873b"
    assert format_value(axml.TYPE_FLOAT, struct.unpack("<I", struct.pack("<f", 1.5))[0]) == "1.5"
    assert format_value(axml.TYPE_DIMENSION, 16 << 8 | 1) == "16dp"
    assert format_value(axml.TYPE_FRACTION, 1 << 30 | 3 << 4 | 1) == "50%p"
    assert format_value(0x42, 7) == "0x00000007"
    assert protection_level_name(0x12) == "signature|privileged"
    assert protection_level_name(0x40000003) == "signatureOrSystem|0x40000000"


def test_axml_honours_header_sizes_and_attribute_layout():
    data = encode_axml(manifest_tree())
    parts = chunks(data)
    index = first_start_with_attributes(parts)
    parts[index] = relayout(parts[index], 24, 28)
    for i, part in enumerate(parts):         # 4 more bytes in every node header
        if axml.RES_XML_START_NAMESPACE <= chunk_type(part) <= axml.RES_XML_CDATA:
            header_size, size = struct.unpack_from("<HI", part, 2)
            parts[i] = part[:2] + struct.pack("<HI", header_size + 4, size + 4) + \
                part[8:header_size] + b"\0" * 4 + part[header_size:]
    doc = decode_axml(assemble(parts))
    assert same_tree(manifest_tree(), doc.root)
    assert any("unusual attribute layout" in w for w in doc.warnings)


def test_axml_tolerates_appended_data_unknown_chunks_and_wrong_root_type():
    data = encode_axml(manifest_tree())
    doc = decode_axml(data + b"APPENDED" * 10)
    assert same_tree(manifest_tree(), doc.root)
    assert any("follow the end of the document" in w for w in doc.warnings)
    parts = chunks(data)
    index = first_start_with_attributes(parts)
    junk = struct.pack("<HHIII", 0x0177, 16, 24, 0, 0xFFFFFFFF) + b"\x01" * 8
    other = struct.pack("<HHI", 0x0042, 8, 16) + b"\x02" * 8
    doc = decode_axml(assemble(parts[:index] + [junk, other] + parts[index:]))
    assert same_tree(manifest_tree(), doc.root)
    assert any("0x0177" in w for w in doc.warnings) and any("0x0042" in w for w in doc.warnings)
    wrong = bytearray(data)
    struct.pack_into("<H", wrong, 0, 0x0000)
    doc = decode_axml(bytes(wrong))
    assert same_tree(manifest_tree(), doc.root) and "root chunk" in doc.warnings[0]


def test_axml_unsorted_and_duplicate_attributes_are_reported():
    tree = XmlNode("activity", {"android:exported": "true", "android:alias": "false",
                                "android:name": "A"})
    data = encode_axml(tree, attr_ids={"android:alias": 0x01010010})
    doc = decode_axml(data)
    assert doc.root.get("android:exported") == "true"      # the first value wins
    assert any("twice" in w for w in doc.warnings)
    parts = chunks(data)
    index = first_start_with_attributes(parts)
    chunk = parts[index]
    attrs = [chunk[36 + 20 * i:56 + 20 * i] for i in range(3)]
    parts[index] = chunk[:36] + b"".join(reversed(attrs))
    doc = decode_axml(assemble(parts))
    assert any("not sorted by resource id" in w for w in doc.warnings)


def test_axml_attributes_declared_in_the_same_place_are_read_once():
    data = encode_axml(XmlNode("manifest", {"package": "p"},
                               [XmlNode("e", {"android:name": "a", "android:value": "b"})]))
    parts = chunks(data)
    index = first_start_with_attributes(parts)
    start = parts[index]
    struct.pack_into("<HHH", start, 16 + 8, 20, 0, 4096)   # 4096 attributes of size 0
    elements = (bytes(start) + bytes(parts[index + 1])) * 3000
    started = time.perf_counter()
    doc = decode_axml(assemble(parts[:index] + [elements] + parts[index + 2:]))
    assert time.perf_counter() - started < 3
    assert len(doc.root.children) == 3000 and doc.root.children[0].attrs == {"android:name": "a"}
    assert any("in the same place" in w for w in doc.warnings)


def test_axml_second_root_and_unclosed_elements():
    data = encode_axml(XmlNode("manifest", {"package": "p"}, [XmlNode("application")]))
    parts = chunks(data)
    starts = [p for p in parts if chunk_type(p) == axml.RES_XML_START_ELEMENT]
    doc = decode_axml(assemble(parts + [starts[0], starts[1]]))
    assert doc.root.tag == "manifest" and len(doc.root.children) == 1
    assert any("second top-level element" in w for w in doc.warnings)
    doc = decode_axml(assemble([p for p in parts if chunk_type(p) != axml.RES_XML_END_ELEMENT]))
    assert [n.tag for n in doc.root.iter()] == ["manifest", "application"]
    assert any("not closed" in w for w in doc.warnings)


def test_axml_huge_string_count_is_clamped():
    data = bytearray(encode_axml(manifest_tree()))
    pool = struct.unpack_from("<H", data, 2)[0]
    struct.pack_into("<I", data, pool + 8, 0xFFFFFFF0)
    started = time.perf_counter()
    doc = decode_axml(bytes(data))
    assert time.perf_counter() - started < 2
    assert any("strings but only" in w for w in doc.warnings)
    assert doc.root.tag == "manifest"


def test_axml_long_strings_and_truncated_utf8_lengths():
    long_value = "x" * 33_000                 # the UTF-8 length is written truncated, as aapt did
    doc = decode_axml(encode_axml(XmlNode("a", {"k": long_value}), utf8=True))
    assert doc.root.get("k") == "x" * axml.MAX_STRING_CHARS
    assert any("longer than" in w for w in doc.warnings)
    doc = decode_axml(encode_axml(XmlNode("a", {"k": "y" * 20_000}), utf8=True))
    assert doc.root.get("k") == "y" * 20_000 and doc.warnings == []
    doc = decode_axml(encode_axml(XmlNode("a", {"k": "م" * 40_000})))
    assert len(doc.root.get("k")) == axml.MAX_STRING_CHARS


def test_axml_shared_long_string_is_bounded():
    count = 2000
    attrs = {f"a{i}": f"v{i}" for i in range(count)}
    attrs["long"] = "x" * 30_000
    data = bytearray(encode_axml(XmlNode("m", attrs), utf8=True))
    # pool: "m", then name and value of each attribute; point every value at the long string
    offsets = 8 + 28
    long_value = struct.unpack_from("<I", data, offsets + 4 * (2 + 2 * count))[0]
    for i in range(count):
        struct.pack_into("<I", data, offsets + 4 * (2 + 2 * i), long_value)
    started = time.perf_counter()
    doc = decode_axml(bytes(data))
    assert time.perf_counter() - started < 3
    assert len(doc.text) < axml.MAX_TOTAL_CHARS + (1 << 20)
    assert any("characters; the rest is not read" in w for w in doc.warnings)


def test_axml_long_names_are_cut():
    doc = decode_axml(encode_axml(XmlNode("e" * 1000, {"n" * 5000: "v"},
                                          [XmlNode("x", {"n" * 5000: "w"})])))
    assert doc.root.tag == "e" * axml.MAX_NAME_CHARS
    assert list(doc.root.attrs) == ["n" * axml.MAX_NAME_CHARS]
    assert max(len(w) for w in doc.warnings) < 1000


def axml_with_pool(pool_strings, ids, nodes):
    """Binary XML whose string pool holds pool_strings (UTF-16) and the string ids `ids`
    (offsets into those strings, in bytes), followed by `nodes`."""
    body = b""
    for text in pool_strings:
        raw = text.encode("utf-16-le")
        units = len(raw) // 2
        body += struct.pack("<HH", 0x8000 | units >> 16, units & 0xFFFF) + raw + b"\0\0"
    body += b"\0" * (-len(body) % 4)
    start = 28 + 4 * len(ids)
    pool = struct.pack("<HHI5I", axml.RES_STRING_POOL, 28, start + len(body), len(ids), 0, 0,
                       start, 0)
    content = pool + struct.pack("<%dI" % len(ids), *ids) + body + b"".join(nodes)
    return struct.pack("<HHI", axml.RES_XML, 8, 8 + len(content)) + content


def element_chunk(name_index, end=False):
    if end:
        return axml._node(axml.RES_XML_END_ELEMENT, 1,
                          struct.pack("<II", axml.NO_INDEX, name_index))
    return axml._node(axml.RES_XML_START_ELEMENT, 1,
                      struct.pack("<IIHHHHHH", axml.NO_INDEX, name_index, 20, 20, 0, 0, 0, 0))


def decode_traced(data):
    """decode_axml(data) and the peak memory it allocated."""
    tracemalloc.start()
    try:
        return decode_axml(data), tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_axml_string_ids_sharing_one_long_string_are_decoded_once():
    # 4000 ids point at one string of 32768 characters, used as namespace prefixes and URIs
    # and as the element name: decoded once (names only up to MAX_NAME_CHARS), not 4000 times
    namespaces = [axml._node(axml.RES_XML_START_NAMESPACE, 1, struct.pack("<II", i, i + 1))
                  for i in range(0, 4000, 2)]
    data = axml_with_pool(["一" * 32768], [0] * 4000,
                          namespaces + [element_chunk(0), element_chunk(0, True)])
    started = time.perf_counter()
    doc, peak = decode_traced(data)
    assert time.perf_counter() - started < 2
    assert peak < 8 << 20
    assert doc.root.tag == "一" * axml.MAX_NAME_CHARS and len(doc.namespaces) == 1


def test_axml_overlapping_strings_are_budgeted():
    # ids at every other position inside one long string: each reads 19968 characters (the
    # length 0x4e00 that "一" spells); text chunks use 2000 of them
    texts = [axml._node(axml.RES_XML_CDATA, 1, struct.pack("<IHBBI", i, 8, 0, 0, 0))
             for i in range(1, 2001)]
    data = axml_with_pool(["一" * 32768], [2 * i for i in range(2001)],
                          [element_chunk(0)] + texts + [element_chunk(0, True)])
    doc, peak = decode_traced(data)
    assert any("overlap far more" in w for w in doc.warnings)
    assert len(doc.root.text) < 2 << 20 and peak < 24 << 20


def test_axml_every_chunk_counts_toward_the_chunk_cap(monkeypatch):
    monkeypatch.setattr(axml, "MAX_NODES", 1000)
    parts = chunks(encode_axml(XmlNode("manifest", {"package": "p"})))   # pool, map, start, end
    flood = [element_chunk(0, True)] * 5000                      # end tags without start tags
    doc = decode_axml(assemble(parts + flood))
    assert doc.root.tag == "manifest" and any("more than 1000 chunks" in w for w in doc.warnings)
    namespace = axml._node(axml.RES_XML_START_NAMESPACE, 1, struct.pack("<II", 0, 0))
    with pytest.raises(AxmlError):                         # the element comes after the cap
        decode_axml(assemble(parts[:2] + [namespace] * 1000 + parts[2:]))


def test_axml_deep_nesting_is_capped():
    doc = decode_axml(encode_axml(chain(300)))
    assert len(list(doc.root.iter())) == axml.MAX_DEPTH
    assert any("nested deeper" in w for w in doc.warnings)


@pytest.mark.parametrize("data", [b"", b"\x03\x00", b"<?xml version='1.0'?><a/>",
                                  b"\xef\xbb\xbf<manifest/>", b"\x00" * 64])
def test_axml_rejects_what_is_not_binary_xml(data):
    with pytest.raises(AxmlError):
        decode_axml(data)


def test_axml_truncated_documents_decode_or_raise():
    data = encode_axml(manifest_tree())
    for cut in range(0, len(data), 3):
        try:
            doc = decode_axml(data[:cut])
        except AxmlError:
            continue
        assert doc.root is not None and doc.warnings


def test_axml_random_mutations_decode_or_raise():
    data = encode_axml(manifest_tree(), utf8=False)
    rng = random.Random(20261123)
    decoded = 0
    started = time.perf_counter()
    for _ in range(500):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        if rng.random() < 0.2:
            del mutated[rng.randrange(len(mutated)):]
        try:
            doc = decode_axml(bytes(mutated))
        except AxmlError:
            continue
        decoded += 1
        assert isinstance(doc.text, str) and doc.root is not None
    assert decoded > 100
    assert time.perf_counter() - started < 10


# ------------------------------------------------------------------ protobuf XML (app bundles)
def test_proto_round_trip():
    tree = manifest_tree()
    tree.find("application").text = "hello"
    doc = decode_proto_xml(encode_proto_xml(tree))
    assert doc.warnings == [] and doc.namespaces == {"android": ANDROID_URI}
    assert same_tree(tree, doc.root)
    activity = doc.root.find("application").find("activity")
    assert doc.text.splitlines()[activity.line_of("android:exported") - 1].strip() == \
        'android:exported="true"'


def test_proto_compiled_items_without_raw_values():
    tree = manifest_tree()
    doc = decode_proto_xml(encode_proto_xml(tree, keep_raw=False))
    assert same_tree(tree, doc.root)


def varint(value):
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field(number, payload):
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def text_field(number, text):
    return field(number, text.encode("utf-8"))


def varint_field(number, value):
    return varint(number << 3) + varint(value)


def fixed32_field(number, value):
    return varint(number << 3 | 5) + struct.pack("<I", value)


def attribute(name, item=b"", value=None, res_id=0, uri=ANDROID_URI):
    body = text_field(1, uri) + text_field(2, name)
    if value is not None:
        body += text_field(3, value)
    if res_id:
        body += varint_field(5, res_id)
    if item:
        body += field(6, item)
    return field(4, body)


def element(name, *parts):
    return text_field(3, name) + b"".join(parts)


def test_proto_items():
    float_bits = struct.unpack("<I", struct.pack("<f", 2.5))[0]
    reference = field(1, varint_field(2, 0x7F0F0000) + text_field(3, "com.example:xml/nsc"))
    attr_ref = field(1, varint_field(1, 1) + text_field(3, "android:attr/colorPrimary"))
    root = element(
        "application",
        attribute("networkSecurityConfig", reference, res_id=0x01010527),
        attribute("theme", attr_ref, res_id=0x01010000),
        attribute("icon", field(1, varint_field(2, 0x7F0A0000)), res_id=0x01010002),
        attribute("debuggable", field(7, varint_field(8, 1)), res_id=0x0101000F),
        attribute("priority", field(7, varint_field(6, (-5) & 0xFFFFFFFFFFFFFFFF)),
                  res_id=0x0101001C),
        attribute("scale", field(7, fixed32_field(3, float_bits)), uri=""),
        attribute("color", field(7, varint_field(9, 0xFF00FF00)), uri=""),
        attribute("size", field(7, varint_field(13, 16 << 8 | 1)), uri=""),
        attribute("label", field(2, text_field(1, "Label")), res_id=0x01010001),
        attribute("hidden", field(7, varint_field(8, 1)), res_id=0x01010010),
        attribute("empty", field(7, field(2, b"")), uri=""),
    )
    doc = decode_proto_xml(field(1, root))
    assert doc.root.attrs == {
        "android:networkSecurityConfig": "@xml/nsc",
        "android:theme": "?android:attr/colorPrimary", "android:icon": "@0x7f0a0000",
        "android:debuggable": "true", "android:priority": "-5", "scale": "2.5",
        "color": "#ff00ff00", "size": "16dp", "android:label": "Label",
        "android:exported": "true", "empty": ""}
    assert any("resource id of android:exported" in w for w in doc.warnings)


@pytest.mark.parametrize("data", [b"", b"\x0a", b"\x0a\x05abc", b"\x08" + b"\xff" * 11,
                                  b"\x03\x00", b"\x00\x01", b"\x12\x02hi"])
def test_proto_rejects_malformed_or_empty_messages(data):
    with pytest.raises(ProtoError):
        decode_proto_xml(data)


def test_proto_malformed_parts_are_skipped():
    good = attribute("name", value="A", res_id=0x01010003)
    bad = field(4, b"\x0a\x09short")          # a string field longer than its message
    doc = decode_proto_xml(field(1, element("activity", good, bad)))
    assert doc.root.attrs == {"android:name": "A", "unknown": ""}
    assert any("malformed XmlAttribute" in w for w in doc.warnings)


def test_proto_wire_reader():
    assert aabproto.read_varint(b"\xff" * 9 + b"\x01", 0, 10) == ((1 << 64) - 1, 10)
    with pytest.raises(ProtoError):
        aabproto.read_varint(b"\xff" * 10 + b"\x01", 0, 11)
    message = b"\x08\x96\x01" + b"\x11" + b"\x01" * 8 + b"\x1a\x02hi" + b"\x25\x04\x00\x00\x00"
    fields = list(iter_fields(message))
    assert [(n, w) for n, w, _ in fields] == [(1, 0), (2, 1), (3, 2), (4, 5)]
    assert fields[0][2] == 150 and fields[1][2] == 0x0101010101010101
    assert bytes(fields[2][2]) == b"hi" and fields[3][2] == 4


def test_proto_deep_nesting_is_capped():
    message = field(1, element("leaf"))
    for _ in range(400):
        message = field(1, element("n", field(5, message)))
    doc = decode_proto_xml(message)
    assert len(list(doc.root.iter())) == aabproto.MAX_DEPTH
    assert any("nested deeper" in w for w in doc.warnings)


def test_proto_random_mutations_decode_or_raise():
    data = encode_proto_xml(manifest_tree())
    rng = random.Random(7)
    started = time.perf_counter()
    for _ in range(300):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        try:
            doc = decode_proto_xml(bytes(mutated))
        except ProtoError:
            continue
        assert isinstance(doc.text, str)
    assert time.perf_counter() - started < 10


# ------------------------------------------------------------------ ZIP reader
def test_build_and_read_zip(tmp_path):
    manifest = encode_axml(manifest_tree())
    entries = [("AndroidManifest.xml", manifest, 8), ("resources.arsc", b"\x02\x00" * 100, 0),
               ("assets/flutter_assets/a.txt", b"hello " * 500, 8), ("res/", b"", 0),
               ("lib/arm64-v8a/libapp.so", b"\x7fELF" + bytes(300), 0)]
    data = build_zip(entries)
    path = tmp_path / "app.apk"
    path.write_bytes(data)
    for source in (data, path, str(path)):
        with ZipArchive(source) as archive:
            assert archive.names() == [name for name, _, _ in entries]
            assert archive.warnings == [] and archive.size == len(data)
            for name, content, _ in entries:
                assert archive.read(name) == content
            entry = archive.get("AndroidManifest.xml")
            assert isinstance(entry, ZipEntry) and entry.method == 8
            assert entry.size == len(manifest) and entry.crc == zlib.crc32(manifest)
            assert entry.data_offset == entry.local_offset + 30 + len("AndroidManifest.xml")
            assert [e.name for e in archive.find("lib/*/*.so")] == ["lib/arm64-v8a/libapp.so"]
            assert archive.find("*.dex") == [] and archive.get("missing") is None
            assert archive.sha256() == hashlib.sha256(data).hexdigest()
            assert archive.read("assets/flutter_assets/a.txt", limit=5) == b"hello"
            assert archive.cd_offset < archive.eocd_offset == len(data) - 22
            with pytest.raises(ZipError):
                archive.read("missing")
    with zipfile.ZipFile(path) as reference:     # the builder writes archives zipfile accepts
        assert reference.read("assets/flutter_assets/a.txt") == b"hello " * 500
        assert reference.testzip() is None
    assert is_zip(path) and not is_zip(tmp_path / "missing.apk")


def test_method_12_with_encryption_flag_reads_stored_bytes():
    manifest = encode_axml(manifest_tree())
    entries = [("AndroidManifest.xml", manifest, 0x000C), ("classes.dex", b"dex\n035", 0)]
    data = build_zip(entries, encrypted_flag_names=["AndroidManifest.xml"])
    with pytest.raises((NotImplementedError, RuntimeError, OSError, zipfile.BadZipFile)):
        with zipfile.ZipFile(io.BytesIO(data)) as reference:    # what Python's zipfile does
            reference.read("AndroidManifest.xml")
    with ZipArchive(data, name="konfety.apk") as archive:
        assert archive.read("AndroidManifest.xml") == manifest
        assert decode_axml(archive.read("AndroidManifest.xml")).root.get("package") == \
            "com.example.demo"
        text = " ".join(archive.warnings)
        assert "compression method 12" in text and "encryption flag" in text
        assert all(w.startswith("konfety.apk: ") for w in archive.warnings)


def test_duplicate_names_and_names_differing_in_case():
    data = build_zip([("classes.dex", b"first", 0), ("classes.dex", b"second", 0),
                      ("Classes.dex", b"third", 0), ("res/a.xml", b"a", 8)])
    with ZipArchive(data) as archive:
        assert archive.read("classes.dex") == b"first"
        assert archive.names() == ["classes.dex", "Classes.dex", "res/a.xml"]
        assert len(archive.entries) == 4
        text = " ".join(archive.warnings)
        assert "duplicate entry name 'classes.dex'" in text and "differ only in case" in text


def test_names_are_normalised_for_lookup():
    data = build_zip([("\\assets\\a.txt", b"a", 0), ("/res/b.xml", b"b", 0),
                      ("../evil.so", b"c", 0), ("ok/é.txt", b"d", 8)])
    with ZipArchive(data) as archive:
        assert archive.read("assets/a.txt") == b"a" and archive.read("res/b.xml") == b"b"
        assert archive.get("/res/b.xml").raw_name == "/res/b.xml"
        assert archive.read("ok/é.txt") == b"d"
        text = " ".join(archive.warnings)
        assert "absolute path" in text and "zip slip" in text


@pytest.mark.parametrize("adjust", [True, False])
def test_janus_dex_prepended_before_the_archive(adjust, tmp_path):
    prefix = b"dex\n035\0" + bytes(120)
    data = build_zip([("AndroidManifest.xml", b"m" * 40, 8), ("classes.dex", b"d" * 30, 0)],
                     prepend=prefix, adjust_offsets=adjust)
    with ZipArchive(data) as archive:
        assert archive.read("AndroidManifest.xml") == b"m" * 40
        assert archive.read("classes.dex") == b"d" * 30
        assert any("Janus" in w for w in archive.warnings)
        assert archive.entries[0].local_offset == len(prefix)
    path = tmp_path / "janus.apk"
    path.write_bytes(data)
    assert is_zip(path)


def test_fake_end_record_in_the_comment():
    data = build_zip([("AndroidManifest.xml", b"m", 0)], comment=b"note", extra_eocd=True)
    with ZipArchive(data) as archive:
        assert archive.read("AndroidManifest.xml") == b"m"
        assert archive.comment.startswith(b"note")
        assert any("comment holds" in w for w in archive.warnings)


def test_zip_bomb_guard_and_limits():
    data = build_zip([("big.bin", bytes(5 << 20), 8), ("stored.bin", b"s" * 1000, 0)])
    with ZipArchive(data) as archive:
        assert len(archive.read("big.bin", limit=1 << 20)) == 1 << 20
        assert any("zip bomb guard" in w for w in archive.warnings)
        assert archive.read("stored.bin", limit=10) == b"s" * 10
        assert any("read limit" in w for w in archive.warnings)
        assert len(archive.read("big.bin")) == 5 << 20


def test_total_read_limit_of_an_archive():
    data = bytearray(build_zip([("bomb.bin", bytes(1 << 20), 8)] +
                               [(f"assets/copy{i}.txt", b"x", 0) for i in range(10)]))
    first = data.index(b"PK\x01\x02")
    crc, compressed, size = struct.unpack_from("<III", data, first + 16)
    cd = first
    for _ in range(10):         # every copy points at the bomb (a non-recursive zip bomb)
        cd = data.index(b"PK\x01\x02", cd + 4)
        struct.pack_into("<H", data, cd + 10, 8)
        struct.pack_into("<III", data, cd + 16, crc, compressed, size)
        struct.pack_into("<I", data, cd + 42, 0)
    with ZipArchive(bytes(data), total_limit=3 << 20) as archive:
        assert any("overlap" in w for w in archive.warnings)
        sizes = []
        with pytest.raises(ZipError, match="total read limit"):
            for entry in archive.entries:
                sizes.append(len(archive.read(entry)))
        assert sizes == [1 << 20] * 3


def test_long_entry_names_are_cut_in_messages():
    name = "a/" + "n" * 4000
    data = build_zip([(name, b"1", 0), (name, b"2", 0)], encrypted_flag_names=[name])
    with ZipArchive(data, name="x" * 3000) as archive:
        assert archive.read(name) == b"1" and archive.warnings
        assert max(len(w) for w in archive.warnings) < 400


def test_overlapping_entries_and_bad_local_headers():
    data = bytearray(build_zip([("a.txt", b"a" * 50, 0), ("b.txt", b"b" * 50, 0)]))
    cd = data.index(b"PK\x01\x02", data.index(b"PK\x01\x02") + 4)
    struct.pack_into("<I", data, cd + 42, 0)           # b.txt now points at a.txt's header
    with ZipArchive(bytes(data)) as archive:
        assert any("overlap" in w for w in archive.warnings)
        assert any("local header gives another name" in w for w in archive.warnings)
    data = bytearray(build_zip([("a.txt", b"a" * 50, 0), ("b.txt", b"b" * 50, 0)]))
    second = data.index(b"PK\x03\x04", 10)             # break the local header of b.txt
    data[second:second + 4] = b"XXXX"
    with ZipArchive(bytes(data)) as archive:
        assert archive.read("a.txt") == b"a" * 50
        assert archive.get("b.txt").data_offset == -1
        with pytest.raises(ZipError):
            archive.read("b.txt")
        assert any("no local header" in w for w in archive.warnings)


def test_corrupt_deflate_data():
    data = bytearray(build_zip([("x.bin", random.Random(3).randbytes(1000) * 3, 8)]))
    start = 30 + len("x.bin")
    for i in range(start + 5, start + 40):
        data[i] ^= 0xA5
    with ZipArchive(bytes(data)) as archive:
        try:
            archive.read("x.bin")
        except ZipError as exc:
            assert "x.bin" in str(exc)
        else:
            assert archive.warnings


def test_truncated_and_random_archives():
    data = build_zip([("AndroidManifest.xml", b"m" * 300, 8), ("classes.dex", b"d" * 200, 0)],
                     comment=b"c" * 10)
    for cut in range(0, len(data), 7):
        try:
            archive = ZipArchive(data[:cut])
        except ZipError:
            continue
        with archive:
            for entry in archive.entries:
                try:
                    archive.read(entry)
                except ZipError:
                    pass
    rng = random.Random(5)
    for _ in range(300):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        try:
            archive = ZipArchive(bytes(mutated))
        except ZipError:
            continue
        with archive:
            for entry in archive.entries:
                try:
                    archive.read(entry, limit=1 << 20)
                except ZipError:
                    pass
    with pytest.raises(ZipError):
        ZipArchive(b"not a zip at all")
    with pytest.raises(ZipError):
        ZipArchive(Path("does/not/exist.apk"))


def test_zip64_end_records_and_extra_fields():
    data = bytearray(build_zip([("a.txt", b"zip64 data", 0)]))
    eocd = len(data) - 22
    count, cd_size, cd_offset = struct.unpack_from("<HII", data, eocd + 10)
    # rewrite the central directory entry with 0xffffffff markers and a ZIP64 extra field
    central = bytearray(data[cd_offset:eocd])
    extra = struct.pack("<HHQQQ", 0x0001, 24, 10, 10, 0)
    struct.pack_into("<II", central, 20, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into("<H", central, 30, len(extra))
    struct.pack_into("<I", central, 42, 0xFFFFFFFF)
    central += extra
    record = struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, len(central),
                         cd_offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, cd_offset + len(central), 1)
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                      0)
    with ZipArchive(bytes(data[:cd_offset]) + bytes(central) + record + locator + end) as archive:
        assert archive.read("a.txt") == b"zip64 data" and archive.warnings == []
        assert archive.cd_offset == cd_offset and archive.cd_size == len(central)


def make_apk():
    manifest = encode_axml(XmlNode("manifest", {"package": "com.example.demo"}))
    return build_zip([("AndroidManifest.xml", manifest, 8), ("classes.dex", b"dex", 0)])


def test_open_container_kinds(tmp_path):
    apk = tmp_path / "app.apk"
    apk.write_bytes(make_apk())
    with open_container(apk) as container:
        assert container.kind == "apk" and [label for label, _ in container.apks] == ["base"]

    bundle = tmp_path / "app.aab"
    manifest = encode_proto_xml(XmlNode("manifest", {"package": "com.example.demo"}))
    bundle.write_bytes(build_zip([("BundleConfig.pb", b"", 0),
                                  ("feature/manifest/AndroidManifest.xml", manifest, 8),
                                  ("base/manifest/AndroidManifest.xml", manifest, 8),
                                  ("base/lib/arm64-v8a/libapp.so", b"elf", 0)]))
    with open_container(bundle) as container:
        assert container.kind == "aab" and container.modules == ["base", "feature"]
        (label, archive), = container.apks
        assert label == "bundle"
        doc = decode_proto_xml(archive.read("base/manifest/AndroidManifest.xml"))
        assert doc.root.get("package") == "com.example.demo"

    apks = tmp_path / "app.apks"
    apks.write_bytes(build_zip([("toc.pb", b"", 0),
                                ("splits/base-arm64_v8a.apk", make_apk(), 0),
                                ("splits/base-master.apk", make_apk(), 0),
                                ("splits/base-xxhdpi.apk", make_apk(), 8),
                                ("standalones/standalone-arm64_v8a.apk", make_apk(), 0)]))
    with open_container(apks) as container:
        assert container.kind == "apks"
        assert [label for label, _ in container.apks] == \
            ["base", "split_config.arm64_v8a", "split_config.xxhdpi"]
        assert container.archive.read("toc.pb") == b""

    xapk = tmp_path / "app.xapk"
    xapk.write_bytes(build_zip([("manifest.json", b"{}", 8),
                                ("config.arm64_v8a.apk", make_apk(), 0),
                                ("com.example.demo.apk", make_apk(), 0),
                                ("icon.png", b"png", 0), ("broken.apk", b"not a zip", 0)]))
    with open_container(xapk) as container:
        assert container.kind == "xapk"
        assert [label for label, _ in container.apks] == ["base", "split_config.arm64_v8a"]
        assert any("broken.apk is not readable" in w for w in container.warnings)

    apkm = tmp_path / "app.apkm"
    apkm.write_bytes(build_zip([("info.json", b"{}", 0), ("base.apk", make_apk(), 0),
                                ("split_config.en.apk", make_apk(), 0)]))
    with open_container(apkm, limit=10) as container:
        assert container.kind == "apkm" and container.apks == []
        assert any("larger than the read limit" in w for w in container.warnings)

    plain = tmp_path / "plain.apk"
    plain.write_bytes(build_zip([("classes.dex", b"dex", 0)]))
    with open_container(plain) as container:
        assert container.kind == "apk" and any("no AndroidManifest" in w
                                               for w in container.warnings)

    other = tmp_path / "notes.txt"
    other.write_text("hello")
    assert not is_zip(other)
    with pytest.raises(ZipError):
        open_container(other)


# ------------------------------------------------------------------ real APKs
@pytest.mark.skipif(not (APK_DIR and Path(APK_DIR, "release.apk").is_file()),
                    reason="set SCA_FLUTTER_APK_DIR to the folder with the lab APKs")
@pytest.mark.parametrize("name, entries, elements", [("debug.apk", 145, 30),
                                                     ("release.apk", 63, 29),
                                                     ("release_obf.apk", 63, 29)])
def test_real_apks(name, entries, elements):
    path = Path(APK_DIR, name)
    with ZipArchive(path) as archive, zipfile.ZipFile(path) as reference:
        assert len(archive.entries) == entries and archive.warnings == []
        assert archive.names() == reference.namelist()
        for entry in ("AndroidManifest.xml", "resources.arsc", "classes.dex"):
            assert archive.read(entry) == reference.read(entry)
        doc = decode_axml(archive.read("AndroidManifest.xml"))
    assert doc.warnings == [] and len(list(doc.root.iter())) == elements
    root = doc.root
    assert root.get("package") == "com.example.vuln_probe"
    assert root.get("android:versionCode") == "1"
    assert root.find("uses-sdk").attrs == {"android:minSdkVersion": "24",
                                           "android:targetSdkVersion": "36"}
    application = root.find("application")
    activity = application.find("activity")
    assert activity.get("android:exported") == "true"
    assert activity.get("android:launchMode") == "singleTop"
    assert activity.get("android:taskAffinity") == ""
    assert root.find("permission").get("android:protectionLevel") == "signature"
    permissions = [n.get("android:name") for n in root.findall("uses-permission")]
    debug = name == "debug.apk"
    assert application.get("android:debuggable") == ("true" if debug else None)
    assert ("android.permission.INTERNET" in permissions) == debug
    lines = doc.text.splitlines()
    assert lines[activity.line_of("android:exported") - 1].strip() == 'android:exported="true"'


@pytest.mark.skipif(not (APK_DIR and Path(APK_DIR, "release.aab").is_file()),
                    reason="set SCA_FLUTTER_APK_DIR to a folder with release.aab")
def test_real_bundle():
    with open_container(Path(APK_DIR, "release.aab")) as container:
        assert container.kind == "aab" and container.modules == ["base"]
        archive = container.apks[0][1]
        assert archive.warnings == [] and archive.get("base/lib/arm64-v8a/libapp.so")
        doc = decode_proto_xml(archive.read("base/manifest/AndroidManifest.xml"))
    assert doc.warnings == [] and len(list(doc.root.iter())) == 29
    application = doc.root.find("application")
    assert application.get("android:icon") == "@mipmap/ic_launcher"
    activity = application.find("activity")
    assert activity.get("android:exported") == "true"
    assert activity.get("android:launchMode") == "singleTop"
    assert doc.root.find("permission").get("android:protectionLevel") == "signature"
