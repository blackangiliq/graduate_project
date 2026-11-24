"""Tests for the decoders of resources, code and signatures in an Android app package:
resources.arsc (sca/flutter/arsc.py), DEX files (sca/flutter/dex.py) and APK signatures
(sca/flutter/signing.py).

Inputs are built with the modules' build_* helpers; hostile inputs are cut, inflated or
corrupted copies of them. The checks on the real Flutter APKs run only when the environment
variable SCA_FLUTTER_APK_DIR names a folder holding debug.apk, release.apk and release_obf.apk.
"""
import hashlib
import io
import os
import struct
import time
import tracemalloc
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from sca.flutter import arsc, dex, signing

APK_DIR = Path(os.environ.get("SCA_FLUTTER_APK_DIR", "") or "missing")
APKS = ("debug.apk", "release.apk", "release_obf.apk")
real_apks = pytest.mark.skipif(not all((APK_DIR / name).is_file() for name in APKS),
                               reason="SCA_FLUTTER_APK_DIR does not hold the lab APKs")

DEBUG_DN = {"CN": "Android Debug", "O": "Android", "C": "US"}
DEBUG_SHA256 = "0bf4121176c930311721926c09120cdf5879c32958ff8044cd4055760b795c82"


def patch(data, offset, fmt, *values):
    out = bytearray(data)
    struct.pack_into(fmt, out, offset, *values)
    return bytes(out)


def chunks(data, start, end):
    """(offset, type, header size, size) of the chunks in data[start:end]."""
    found = []
    while start + 8 <= end:
        kind, header, size = struct.unpack_from("<HHI", data, start)
        found.append((start, kind, header, size))
        start += max(size, 8)
    return found


def package_chunks(data):
    package = next(c for c in chunks(data, 12, len(data)) if c[1] == arsc.RES_TABLE_PACKAGE)
    return package, chunks(data, package[0] + package[2], package[0] + package[3])


def type_chunks(data):
    return [c for c in package_chunks(data)[1] if c[1] == arsc.RES_TABLE_TYPE]


# ------------------------------------------------------------------ resources.arsc

TABLE = [
    ("string", "app_name", "Demo"),
    ("string", "app_name", "Démo", "fr"),
    ("string", "google_api_key", "AIzaSyExample"),
    ("string", "alias", (arsc.TYPE_REFERENCE, 0x7F010000)),
    ("string", "only_french", "Bonjour", "fr"),
    ("xml", "network_security_config", "res/Zn.xml"),
    ("bool", "debug", True),
    ("integer", "retries", -3),
    ("drawable", "launch_background", "res/drawable-v21/launch_background.xml", "v21"),
    ("style", "LaunchTheme", {0x01010054: 5}),
    ("color", "accent", (arsc.TYPE_INT_COLOR_ARGB8, 0xFF1D873B)),
    ("dimen", "padding", (arsc.TYPE_DIMENSION, 4 << 8 | 1)),
    ("string", "path_like", "res/not/a/file.xml"),
]
STRING, XML, BOOL, INTEGER, DRAWABLE, STYLE, COLOR, DIMEN = (0x7F000000 | n << 16 for n in range(1, 9))


def check_table(table):
    assert table.warnings == []
    assert [(p.id, p.name) for p in table.packages] == [(0x7F, "com.example.demo")]
    app_name = table.lookup(STRING)
    assert (app_name.type, app_name.name) == ("string", "app_name")
    assert [(v.config, v.text) for v in app_name.values] == [("", "Demo"), ("fr", "Démo")]
    assert table.name_of(XML) == "@xml/network_security_config"
    assert table.name_of(STRING | 0xFF) is None
    assert table.file_paths() == {"res/Zn.xml": "xml/network_security_config",
                                  "res/drawable-v21/launch_background.xml": "drawable/launch_background"}
    assert table.strings() == {"app_name": "Demo", "google_api_key": "AIzaSyExample", "alias": "Demo",
                               "path_like": "res/not/a/file.xml"}
    assert table.strings(default_config_only=False)["only_french"] == "Bonjour"
    texts = {table.lookup(rid).name: table.lookup(rid).values[0].text
             for rid in (BOOL, INTEGER, COLOR, DIMEN, STRING | 2)}
    assert texts == {"debug": "true", "retries": "-3", "accent": "#ff1d873b", "padding": "4dp",
                     "alias": "@string/app_name"}
    assert table.lookup(STYLE).values[0].data_type == arsc.TYPE_BAG
    assert table.lookup(DRAWABLE).default() is None
    assert table.lookup(DRAWABLE).values[0].config == "v21"


@pytest.mark.parametrize("options", [
    {}, {"utf8": False}, {"sparse": True}, {"offset16": True}, {"compact": True},
    {"utf8": False, "sparse": True, "compact": True}])
def test_arsc_round_trip_in_every_encoding(options):
    check_table(arsc.parse_arsc(arsc.build_arsc("com.example.demo", TABLE, **options)))


def test_arsc_configuration_names_follow_aapt2():
    qualifiers = ["fr-rCA", "night", "hdpi", "v21", "sw600dp", "land", "ldrtl", "fr-rCA-night-hdpi-v21",
                  "anydpi", "640dpi", "television"]
    entries = [("string", "s", q, q) for q in qualifiers]
    table = arsc.parse_arsc(arsc.build_arsc("com.example", entries))
    configs = [v.config for v in table.lookup(0x7F010000).values]
    assert configs == ["fr-rCA", "night", "hdpi", "v21", "sw600dp", "land", "ldrtl",
                       "fr-rCA-night-hdpi-v21", "anydpi", "xxxhdpi", "television"]
    assert table.warnings == []


def test_arsc_reference_chains_and_cycles_end():
    entries = [("string", "a", (arsc.TYPE_REFERENCE, 0x7F010001)),
               ("string", "b", (arsc.TYPE_REFERENCE, 0x7F010002)),
               ("string", "c", "end"),
               ("string", "x", (arsc.TYPE_REFERENCE, 0x7F010004)),
               ("string", "y", (arsc.TYPE_REFERENCE, 0x7F010003)),
               ("string", "self", (arsc.TYPE_REFERENCE, 0x7F010005)),
               ("string", "dangling", (arsc.TYPE_REFERENCE, 0x7F0100FF)),
               ("string", "framework", (arsc.TYPE_REFERENCE, 0x01040000)),
               ("string", "empty", (arsc.TYPE_REFERENCE, 0))]
    strings = arsc.parse_arsc(arsc.build_arsc("com.example", entries)).strings()
    assert strings["a"] == strings["b"] == "end"
    assert strings["x"] in ("@string/x", "@string/y") and strings["self"] == "@string/self"
    assert strings["dangling"] == "@0x7f0100ff" and strings["framework"] == "@0x01040000"
    assert strings["empty"] == "@null"


def test_arsc_long_utf8_string_with_truncated_length_like_old_aapt():
    text = "a" * 0x8005             # the 15-bit length field keeps only 5
    table = arsc.parse_arsc(arsc.build_arsc("com.example", [("string", "long", text)]))
    assert table.strings() == {"long": text} and table.warnings == []


def test_arsc_names_are_made_safe_for_paths():
    table = arsc.parse_arsc(arsc.build_arsc("com.example", [("xml", "../../evil name", "res/a.xml")]))
    assert table.file_paths() == {"res/a.xml": "xml/.._.._evil_name"}


@pytest.mark.parametrize("data", [b"", b"\x02\x00", b"\x00" * 64, b"PK\x03\x04" + bytes(60),
                                  bytes(range(256)) * 4, struct.pack("<HHII", 2, 12, 12, 0)])
def test_arsc_garbage_gives_warnings_not_errors(data):
    table = arsc.parse_arsc(data)
    assert table.warnings and table.packages == [] and table.strings() == {} and table.file_paths() == {}


def test_arsc_every_truncation_and_corrupted_byte_is_survived():
    data = arsc.build_arsc("com.example.demo", TABLE)
    for cut in range(0, len(data), 5):
        assert arsc.parse_arsc(data[:cut]).warnings
    for pos in range(len(data)):
        for value in (0x00, 0xFF):
            table = arsc.parse_arsc(patch(data, pos, "<B", value))
            table.strings(), table.file_paths(), table.name_of(STRING), table.strings(False)


def test_arsc_huge_counts_are_clamped():
    data = arsc.build_arsc("com.example.demo", TABLE)
    table = arsc.parse_arsc(patch(data, 12 + 8, "<I", 0xFFFFFFFF))        # value pool string count
    assert any("clamped" in w for w in table.warnings)
    assert table.lookup(XML).values[0].text == "res/Zn.xml"
    first = type_chunks(data)[0]
    table = arsc.parse_arsc(patch(data, first[0] + 12, "<I", 0xFFFFFFFF))  # entry count of a type
    assert any("claims 4294967295 entries" in w for w in table.warnings)
    assert table.name_of(XML) == "@xml/network_security_config"


def test_arsc_offsets_outside_their_chunk_are_skipped():
    data = arsc.build_arsc("com.example", [("string", "a", "x"), ("string", "b", "y")])
    chunk = type_chunks(data)[0]
    bad = patch(data, chunk[0] + chunk[2] + 4, "<I", 0x7FFFFFF0)          # offset of entry 1
    table = arsc.parse_arsc(bad)
    assert table.strings() == {"a": "x"} and any("outside" in w for w in table.warnings)
    bad = patch(data, chunk[0] + 16, "<I", 0xFFFFFFF0)                     # entriesStart
    assert arsc.parse_arsc(bad).strings() == {}
    package = package_chunks(data)[0]
    bad = patch(data, package[0] + 268, "<I", 0xFFFFFFF0)                  # type name pool offset
    assert any("type name pool" in w for w in arsc.parse_arsc(bad).warnings)


def test_arsc_zero_size_and_runaway_chunks_stop_the_walk():
    data = arsc.build_arsc("com.example", [("string", "a", "x")])
    chunk = type_chunks(data)[0]
    table = arsc.parse_arsc(patch(data, chunk[0] + 4, "<I", 0))
    assert any("malformed chunk" in w for w in table.warnings)
    table = arsc.parse_arsc(patch(data, chunk[0] + 4, "<I", 0x7FFFFFFF))
    assert any("runs past its parent" in w for w in table.warnings)
    assert arsc.parse_arsc(data + b"tail").warnings == ["resources.arsc: 4 bytes after the end of the table"]
    assert any("declares 3 package" in w for w in arsc.parse_arsc(patch(data, 8, "<I", 3)).warnings)


def test_arsc_unterminated_string_and_duplicate_configurations():
    data = arsc.build_arsc("com.example", [("string", "a", "x")])
    pool = 12
    count, = struct.unpack_from("<I", data, pool + 8)
    strings_start, = struct.unpack_from("<I", data, pool + 20)
    end = pool + struct.unpack_from("<I", data, pool + 4)[0]
    bad = bytearray(data)
    bad[pool + strings_start + 2:end] = b"z" * (end - pool - strings_start - 2)   # no NUL left
    table = arsc.parse_arsc(bytes(bad))
    assert count == 1 and table.strings() == {"a": ""}
    assert any("not NUL-terminated" in w for w in table.warnings)

    data = arsc.build_arsc("com.example", [("string", "a", "x"), ("string", "a", "y", "fr")])
    twice = data.replace(b"fr\x00\x00", b"\x00\x00\x00\x00", 1)            # both chunks default
    table = arsc.parse_arsc(twice)
    assert table.strings() == {"a": "x"} and any("two chunks" in w for w in table.warnings)


def test_arsc_sparse_entries_out_of_order_keep_the_first():
    data = arsc.build_arsc("com.example", [("string", "a", "x"), ("string", "b", "y")], sparse=True)
    chunk = type_chunks(data)[0]
    table = arsc.parse_arsc(patch(data, chunk[0] + chunk[2] + 4, "<H", 0))   # second pair: index 0
    assert table.strings() == {"a": "x"} and any("not in order" in w for w in table.warnings)


def test_arsc_value_cap(monkeypatch):
    monkeypatch.setattr(arsc, "MAX_VALUES", 3)
    table = arsc.parse_arsc(arsc.build_arsc("com.example", [("string", f"s{i}", "v") for i in range(10)]))
    assert len(list(table.entries())) == 3 and any("more than 3 values" in w for w in table.warnings)


def one_type_table(offsets, entries, *, type_name="t" * 196, key="k" * 200):
    """A table with one type (`offsets` is its entry offset table, `entries` the entry data)
    and one entry name that every entry uses."""
    type_pool = arsc._build_pool([type_name], utf8=False)
    key_pool = arsc._build_pool([key], utf8=True)
    header = 20 + 64
    chunk = struct.pack("<HHIBBHII", arsc.RES_TABLE_TYPE, header, header + len(offsets) + len(entries),
                        1, 0, 0, len(offsets) // 4, header + len(offsets))
    body = type_pool + key_pool + chunk + arsc._build_config("") + offsets + entries
    package = struct.pack("<HHII", arsc.RES_TABLE_PACKAGE, 288, 288 + len(body), 0x7F) + \
        "com.evil".encode("utf-16-le").ljust(256, b"\0") + \
        struct.pack("<5I", 288, 1, 288 + len(type_pool), 1, 0) + body
    values = arsc._build_pool([], utf8=True)
    return struct.pack("<HHII", arsc.RES_TABLE, 12, 12 + len(values) + len(package), 1) + values + package


def compact_reference(target):
    return struct.pack("<HHI", 0, arsc.TYPE_REFERENCE << 8 | arsc.ENTRY_COMPACT, target)


def test_arsc_entries_sharing_one_entry_share_names_and_texts():
    # 4096 slots point at one entry (key 0, a reference to 0x7f010000): one name and one
    # rendered "@type/name" for all of them, not a copy each
    table = arsc.parse_arsc(one_type_table(bytes(4 * 4096), compact_reference(0x7F010000)))
    entries = list(table.entries())
    assert len(entries) == 4096 and table.warnings == []
    assert entries[0].values[0].text == "@" + "t" * 196 + "/" + "k" * 200
    assert all(e.name is entries[0].name for e in entries)
    assert all(e.values[0].text is entries[0].values[0].text for e in entries)


def test_arsc_rendered_reference_names_are_budgeted(monkeypatch):
    # 512 entries each referencing the next: 400 characters of name each, from 12 bytes
    monkeypatch.setattr(arsc, "MAX_REFERENCE_CHARS", 0)
    count = 512
    offsets = b"".join(struct.pack("<I", 8 * i) for i in range(count))
    entries = b"".join(compact_reference(0x7F010000 + (i + 1) % count) for i in range(count))
    data = one_type_table(offsets, entries)
    table = arsc.parse_arsc(data)
    texts = [e.values[0].text for e in table.entries()]
    assert sum(map(len, texts)) < 2 * len(data) + 20 * count
    assert texts[0].startswith("@t") and texts[-1] == "@0x7f010000"
    assert any("references name more resources" in w for w in table.warnings)


def test_arsc_warnings_are_capped():
    data = bytearray(arsc.build_arsc("com.example", [("string", "a", "x")]))
    package = package_chunks(bytes(data))[0]
    junk = b"".join(struct.pack("<HHI", 0x7000 + n, 8, 8) for n in range(200))  # 200 unknown chunk kinds
    data[package[0] + package[3]:package[0] + package[3]] = junk
    struct.pack_into("<I", data, package[0] + 4, package[3] + len(junk))
    struct.pack_into("<I", data, 4, len(data))
    warnings = arsc.parse_arsc(bytes(data)).warnings
    assert len(warnings) == arsc.MAX_WARNINGS + 1 and warnings[-1].endswith("further warnings suppressed")


# ------------------------------------------------------------------ DEX

SPECIAL = ["hello", "AIzaSyExampleKey", "ñandú", "nul\0inside", "emoji 😀", "lone \ud800 surrogate"]
CLASSES = [("Lcom/example/app/MainActivity;", "Lio/flutter/embedding/android/FlutterActivity;"),
           ("Lio/flutter/plugins/GeneratedPluginRegistrant;", "Ljava/lang/Object;"),
           ("Lcom/baseflow/permissionhandler/PermissionHandlerPlugin;", "Ljava/lang/Object;"),
           ("Lio/flutter/plugins/pathprovider/PathProviderPlugin;", "Ljava/lang/Object;"),
           ("Lio/flutter/plugin/platform/PlatformPlugin;", "Ljava/lang/Object;"),
           ("Lio/flutter/embedding/engine/plugins/FlutterPlugin;", None),
           ("Lcom/example/app/FooPlugin$Handler;", "Ljava/lang/Object;"),
           ("Lcom/example/app/Plugin;", "Ljava/lang/Object;")]
METHODS = [("Lio/flutter/plugins/GeneratedPluginRegistrant;", "registerWith",
            "(Lio/flutter/embedding/engine/FlutterEngine;)V"),
           ("Lio/flutter/embedding/engine/FlutterJNI;", "nativeAttach",
            "(Lio/flutter/embedding/engine/FlutterJNI;)J"),
           ("Landroid/webkit/WebView;", "addJavascriptInterface", "(Ljava/lang/Object;Ljava/lang/String;)V"),
           ("Lcom/example/app/MainActivity;", "<init>", "()V")]


def test_dex_round_trip():
    parsed = dex.parse_dex(dex.build_dex(SPECIAL, CLASSES, METHODS))
    assert parsed.version == "035" and parsed.sections == 1 and parsed.warnings == []
    strings = parsed.strings()
    assert set(SPECIAL[:5]) <= set(strings) and "lone \N{REPLACEMENT CHARACTER} surrogate" in strings
    assert strings == sorted(strings, key=lambda s: s.encode("utf-16-be", "surrogatepass"))
    assert "Ljava/lang/String;" in parsed.type_names() and "J" in parsed.type_names()
    assert parsed.class_defs() == [(desc, sup or "", dex.ACC_PUBLIC) for desc, sup in CLASSES]
    assert set(parsed.method_refs()) == {(cls, name) for cls, name, _ in METHODS}
    assert parsed.strings() is parsed.strings()                       # decoded once


def test_dex_helpers():
    assert dex.descriptor_to_java("Lcom/a/B;") == "com.a.B"
    assert dex.descriptor_to_java("[[Lcom/a/B$C;") == "com.a.B$C[][]"
    assert dex.descriptor_to_java("[I") == "int[]" and dex.descriptor_to_java("Z") == "boolean"
    assert dex.descriptor_to_java("") == "" and dex.descriptor_to_java("Q") == "Q"
    parsed = [dex.parse_dex(dex.build_dex(classes=CLASSES[:4], methods=METHODS))]
    assert dex.flutter_markers(parsed) == {"flutter_jni": True, "plugin_registrant": True,
                                           "flutter_activity": True, "flutter_fragment_activity": False,
                                           "flutter": True}
    plain = [dex.parse_dex(dex.build_dex(["x"], [("Lcom/a/Main;", "Landroid/app/Activity;")]))]
    assert not any(dex.flutter_markers(plain).values())
    other = dex.parse_dex(dex.build_dex(classes=[("Lio/flutter/Log;", None)]))
    assert dex.flutter_markers([other])["flutter"]
    everything = [dex.parse_dex(dex.build_dex(classes=CLASSES)), plain[0]]
    assert dex.plugin_classes(everything) == ["com.baseflow.permissionhandler.PermissionHandlerPlugin",
                                              "io.flutter.plugins.pathprovider.PathProviderPlugin"]


def test_dex_version_041_and_containers():
    single = dex.parse_dex(dex.build_dex(["only"], CLASSES[:1], version="041"))
    assert (single.version, single.sections, single.warnings) == ("041", 1, [])
    assert "only" in single.strings()
    data = dex.build_dex_container([
        (["first"], [("Lcom/a/A;", "Ljava/lang/Object;")], []),
        (["second"], [("Lcom/b/B;", None)], [("Lcom/b/B;", "run", "()V")]),
        (["third"], [], [])])
    parsed = dex.parse_dex(data)
    assert (parsed.sections, parsed.warnings) == (3, [])
    assert {"first", "second", "third"} <= set(parsed.strings())
    assert parsed.class_defs() == [("Lcom/a/A;", "Ljava/lang/Object;", 1), ("Lcom/b/B;", "", 1)]
    assert parsed.method_refs() == [("Lcom/b/B;", "run")]


@pytest.mark.parametrize("data", [b"", b"dex\n", b"dex\n035\0" + bytes(10), b"\x7fELF" + bytes(200),
                                  b"dex\nabc\0" + bytes(200), bytes(range(256)) * 3])
def test_dex_garbage_gives_warnings_not_errors(data):
    parsed = dex.parse_dex(data)
    assert parsed.warnings and parsed.strings() == [] and parsed.class_defs() == []
    assert parsed.method_refs() == [] and dex.flutter_markers([parsed])["flutter"] is False


def test_dex_every_truncation_and_corrupted_byte_is_survived():
    data = dex.build_dex(SPECIAL, CLASSES, METHODS)
    for cut in range(0, len(data), 11):
        parsed = dex.parse_dex(data[:cut])
        parsed.strings(), parsed.type_names(), parsed.class_defs(), parsed.method_refs()
        assert parsed.warnings
    for pos in range(0, len(data), 3):
        parsed = dex.parse_dex(patch(data, pos, "<B", data[pos] ^ 0xFF))
        parsed.strings(), parsed.type_names(), parsed.class_defs(), parsed.method_refs()
        assert parsed.warnings                                             # at least the checksum


def test_dex_huge_counts_and_outside_offsets():
    data = dex.build_dex(SPECIAL, CLASSES, METHODS)
    parsed = dex.parse_dex(patch(data, 0x38, "<I", 0xFFFFFFFF))           # string_ids_size
    assert any("string ids table claims 4294967295" in w for w in parsed.warnings)
    assert len(parsed.strings()) < 1000
    parsed = dex.parse_dex(patch(data, 0x3C, "<I", 0xFFFFFFF0))           # string_ids_off
    assert parsed.strings() == [] and any("outside the file" in w for w in parsed.warnings)
    for offset in (0x40, 0x58, 0x60):                                       # types, methods, classes
        parsed = dex.parse_dex(patch(data, offset, "<I", 0x7FFFFFFF))
        parsed.class_defs(), parsed.method_refs()
        assert any("clamped" in w for w in parsed.warnings)
    parsed = dex.parse_dex(patch(data, 0x28, "<I", 0x78563412))           # big-endian tag
    assert parsed.strings() == [] and any("byte order" in w for w in parsed.warnings)


def test_dex_bad_indexes_and_string_offsets():
    data = dex.build_dex(["a"], [("Lcom/A;", "Lcom/B;")], [("Lcom/A;", "m", "()V")])
    class_defs, = struct.unpack_from("<I", data, 0x64)
    method_ids, = struct.unpack_from("<I", data, 0x5C)
    string_ids, = struct.unpack_from("<I", data, 0x3C)
    bad = patch(data, class_defs, "<I", 999)                                # class type index
    bad = patch(bad, method_ids + 4, "<I", 12345)                           # method name index
    bad = patch(bad, string_ids, "<I", 0x10)                                # string data inside header
    parsed = dex.parse_dex(bad)
    assert parsed.class_defs()[0][0] == "" and parsed.method_refs()[0][1] == ""
    assert parsed.strings()[0] == ""
    text = " ".join(parsed.warnings)
    assert "type index (999)" in text and "string index (12345)" in text and "outside the string data" in text
    assert "checksum" in text


def test_dex_unterminated_and_overlapping_strings_are_bounded(monkeypatch):
    long_string = "a" * 20_000
    data = dex.build_dex([long_string])
    string_ids, = struct.unpack_from("<I", data, 0x3C)
    target, = struct.unpack_from("<I", data, string_ids)
    cut = data[:target + 5_000]                                              # string loses its NUL
    parsed = dex.parse_dex(cut)
    assert parsed.strings() == ["a" * (5_000 - 3)]                          # 3-byte ULEB128 length skipped
    assert any("no terminating NUL" in w for w in parsed.warnings)

    count = 5_000                                                            # ids into one long string
    moved = 0x70 + 4 * count
    table = b"".join(struct.pack("<I", moved + 3 + n) for n in range(count))
    hostile = bytearray(data[:0x70]) + table + data[target:]
    struct.pack_into("<II", hostile, 0x38, count, 0x70)
    struct.pack_into("<I", hostile, 0x20, len(hostile))
    started = time.perf_counter()
    parsed = dex.parse_dex(bytes(hostile))
    assert len(parsed.strings()) == count and time.perf_counter() - started < 10
    assert any("overlap" in w for w in parsed.warnings)

    monkeypatch.setattr(dex, "MAX_STRINGS", 2)
    parsed = dex.parse_dex(dex.build_dex(["x", "y", "z"]))
    assert len(parsed.strings()) == 2 and any("only the first 2" in w for w in parsed.warnings)


def test_dex_container_sections_sharing_one_string_table():
    data = bytearray(dex.build_dex_container([(["one", "two"], [], []), (["three"], [], [])]))
    second = struct.unpack_from("<I", data, 0x20)[0]
    data[second + 0x38:second + 0x40] = data[0x38:0x40]                    # as d8 writes containers
    parsed = dex.parse_dex(bytes(data))
    assert (parsed.sections, parsed.strings(), parsed.warnings) == (2, ["one", "two"], [])


def test_dex_container_tables_outside_their_section_are_not_read():
    # the second DEX file of the container points at the class table of the first: read once
    data = bytearray(dex.build_dex_container([
        (["first"], [("Lcom/a/A;", "Ljava/lang/Object;")], []),
        (["second"], [("Lcom/b/B;", None)], [])]))
    second = struct.unpack_from("<I", data, 0x20)[0]
    data[second + 0x60:second + 0x68] = data[0x60:0x68]                    # class_defs size, offset
    parsed = dex.parse_dex(bytes(data))
    assert parsed.class_defs() == [("Lcom/a/A;", "Ljava/lang/Object;", 1)]
    assert any("class definitions table" in w and "outside its DEX file" in w for w in parsed.warnings)


def test_dex_container_sharing_one_string_table_with_other_sizes():
    data = bytearray(dex.build_dex_container([(["one", "two"], [], []), (["three"], [], [])]))
    second = struct.unpack_from("<I", data, 0x20)[0]
    data[second + 0x38:second + 0x40] = struct.pack("<II", 1, struct.unpack_from("<I", data, 0x3C)[0])
    parsed = dex.parse_dex(bytes(data))
    assert parsed.strings() == ["one", "two"]
    assert any("different sizes" in w for w in parsed.warnings)


def test_dex_id_caps_hold_over_every_file_of_a_container(monkeypatch):
    monkeypatch.setattr(dex, "MAX_STRINGS", 5)
    parsed = dex.parse_dex(dex.build_dex_container([(["a", "b"], [], []), (["c", "d"], [], []),
                                                    (["e", "f"], [], [])]))
    assert parsed.strings() == ["a", "b", "c", "d", "e"]
    assert any("only the first 1 are read" in w for w in parsed.warnings)


def test_dex_file_does_not_keep_its_input():
    data = dex.build_dex(SPECIAL, CLASSES, METHODS) + bytes(8 << 20)
    tracemalloc.start()
    try:
        parsed = dex.parse_dex(bytearray(data))                            # a copy: bytes(data)
        held = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    assert held < 1 << 20
    assert set(SPECIAL[:5]) <= set(parsed.strings()) and len(parsed.class_defs()) == len(CLASSES)
    assert set(parsed.method_refs()) == {(cls, name) for cls, name, _ in METHODS}
    assert parsed.size == len(data)


def test_dex_container_with_bad_next_header():
    data = bytearray(dex.build_dex_container([(["one"], [], []), (["two"], [], [])]))
    second = struct.unpack_from("<I", data, 0x20)[0]
    data[second:second + 4] = b"XXXX"
    parsed = dex.parse_dex(bytes(data))
    assert parsed.sections == 1 and "one" in parsed.strings()
    assert any("no DEX header" in w for w in parsed.warnings)


# ------------------------------------------------------------------ certificates

def test_certificate_fields():
    der = signing.build_certificate(DEBUG_DN, version=1)
    cert = signing.parse_certificate(der)
    assert cert.subject == cert.issuer == "C=US, O=Android, CN=Android Debug"      # as apksigner prints it
    assert cert.subject_parts == DEBUG_DN and cert.serial == "1"
    assert (cert.valid_from, cert.valid_to) == ("2026-03-10", "2056-03-02")
    assert cert.sha256 == hashlib.sha256(der).hexdigest() and cert.sha1 == hashlib.sha1(der).hexdigest()
    assert (cert.key_algorithm, cert.key_bits, cert.key) == ("RSA", 2048, "RSA 2048")
    assert cert.signature_algorithm == "sha256WithRSAEncryption"
    assert cert.is_debug and cert.warnings == []
    assert cert.as_dict() == {"subject": cert.subject, "issuer": cert.issuer, "sha256": cert.sha256,
                              "valid_from": "2026-03-10", "valid_to": "2056-03-02", "key": "RSA 2048",
                              "signature_algorithm": "sha256WithRSAEncryption", "debug": True}
    assert signing.parse_certificate(signing.build_certificate(DEBUG_DN, version=3)).subject == cert.subject


def test_certificate_names_in_rfc4514_order():
    # keytool writes the RDNs C, O, CN and prints them reversed, as apksigner does
    keytool = signing.build_certificate({"C": "SA", "O": "Example Org", "CN": "DSA Signer"},
                                        key_algorithm="DSA", key_bits=2048, sig_alg="dsa-with-sha256")
    cert = signing.parse_certificate(keytool)
    assert cert.subject == cert.issuer == "CN=DSA Signer, O=Example Org, C=SA"
    assert list(cert.subject_parts) == ["C", "O", "CN"] and not cert.is_debug
    issued = signing.parse_certificate(signing.build_certificate({"CN": "App"}, {"CN": "CA", "O": "Org"}))
    assert (issued.subject, issued.issuer) == ("CN=App", "O=Org, CN=CA")


@pytest.mark.parametrize("kwargs, key, algorithm", [
    ({"key_algorithm": "EC", "key_bits": 256, "sig_alg": "ecdsa-with-SHA256"}, "EC 256", "ecdsa-with-SHA256"),
    ({"key_algorithm": "EC", "key_bits": 384, "sig_alg": "ecdsa-with-SHA384"}, "EC 384", "ecdsa-with-SHA384"),
    ({"key_algorithm": "DSA", "key_bits": 1024, "sig_alg": "dsa-with-sha1"}, "DSA 1024", "dsa-with-sha1"),
    ({"key_bits": 1024, "sig_alg": "sha1WithRSAEncryption"}, "RSA 1024", "sha1WithRSAEncryption"),
    ({"key_bits": 4096, "sig_alg": "md5WithRSAEncryption"}, "RSA 4096", "md5WithRSAEncryption")])
def test_certificate_keys_and_algorithms(kwargs, key, algorithm):
    cert = signing.parse_certificate(signing.build_certificate({"CN": "Release"}, **kwargs))
    assert (cert.key, cert.signature_algorithm, cert.is_debug) == (key, algorithm, False)


def test_certificate_debug_rule_and_dates():
    not_self_signed = signing.build_certificate(DEBUG_DN, {"CN": "Some CA"})
    assert not signing.parse_certificate(not_self_signed).is_debug
    no_country = signing.build_certificate({"CN": "Android Debug", "O": "Android"})
    assert not signing.parse_certificate(no_country).is_debug
    old = signing.parse_certificate(signing.build_certificate(
        {"CN": "x"}, not_before="1999-12-31", not_after="2049-12-31", serial=0x1234567890ABCDEF00))
    assert (old.valid_from, old.valid_to, old.serial) == ("1999-12-31", "2049-12-31", "1234567890abcdef00")
    far = signing.parse_certificate(signing.build_certificate({"CN": "x"}, not_after="2100-02-28"))
    assert far.valid_to == "2100-02-28"


def test_certificate_names_are_escaped_on_one_line():
    two_lines = "line\nbreak\N{LINE SEPARATOR}x"
    cert = signing.parse_certificate(signing.build_certificate(
        {"CN": "Doe, John", "O": "#hash", "OU": " lead ", "L": two_lines, "ST": "a+b=c;<>\"\\"}))
    assert cert.subject == ("ST=a\\+b=c\\;\\<\\>\\\"\\\\, L=line\\0abreak\\e2\\80\\a8x, OU=\\ lead\\ , "
                            "O=\\#hash, CN=Doe\\, John")
    assert cert.subject_parts["CN"] == "Doe, John" and cert.subject_parts["L"] == two_lines
    assert len(cert.subject.splitlines()) == 1


def der(tag, content):
    """Minimal DER encoder for hand-made test structures."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    raw = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def test_certificate_multi_valued_rdn_and_unknown_attribute():
    cn = der(0x30, der(0x06, bytes.fromhex("550403")) + der(0x0C, b"Ann"))
    other = der(0x30, der(0x06, bytes.fromhex("2b06010401823701")) + der(0x04, b"\x01\x02"))
    name = der(0x30, der(0x31, cn + other))
    algorithm = der(0x30, der(0x06, bytes.fromhex("2a864886f70d01010b")) + der(0x05, b""))
    validity = der(0x30, der(0x17, b"260310000000Z") + der(0x18, b"20360310000000Z"))
    modulus = der(0x02, b"\x00\xc0" + bytes(255))
    key = der(0x30, der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + der(0x05, b""))
              + der(0x03, b"\x00" + der(0x30, modulus + der(0x02, b"\x01\x00\x01"))))
    tbs = der(0x30, der(0x02, b"\x05") + algorithm + name + validity + name + key)
    cert = signing.parse_certificate(der(0x30, tbs + algorithm + der(0x03, b"\x00" + bytes(256))))
    assert cert.subject == cert.issuer == "CN=Ann+1.3.6.1.4.1.311.1=#04020102"
    assert cert.subject_parts == {"CN": "Ann", "1.3.6.1.4.1.311.1": "#04020102"}
    assert (cert.key, cert.serial) == ("RSA 2048", "5")
    assert (cert.valid_from, cert.valid_to, cert.warnings) == ("2026-03-10", "2036-03-10", [])


@pytest.mark.parametrize("data, message", [
    (b"", "truncated"),
    (b"\x30", "truncated"),
    (b"\x30\x80" + bytes(10), "indefinite"),
    (b"\x30\x85\x00\x00\x00\x00\x05\x00", "too long"),
    (b"\x30\x06\x30\x06\x30\x06", "runs past"),
    (b"\x02\x01\x01", "not a certificate"),
    (b"\x30\x03\x02\x01\x01", "not a certificate"),
    (b"\x3f\xff\xff\xff\xff\xff\x00", "tag is too long"),
])
def test_certificate_hostile_der(data, message):
    with pytest.raises(signing.CertificateError, match=message):
        signing.parse_certificate(data)


def test_certificate_deep_nesting_and_element_floods():
    nested = b"\x05\x00"
    for _ in range(10_000):
        nested = der(0x30, nested)
    with pytest.raises(signing.CertificateError):
        signing.parse_certificate(nested)
    flood = der(0x30, der(0x30, b"\x30\x00" * 20_000))
    with pytest.raises(signing.CertificateError, match="more than 10000 elements"):
        signing.parse_certificate(flood)
    good = signing.build_certificate({"CN": "x"})
    cert = signing.parse_certificate(good + b"junk")
    assert cert.sha256 == hashlib.sha256(good).hexdigest()
    assert cert.warnings == ["4 bytes follow the certificate"]


# ------------------------------------------------------------------ signatures of an APK

def make_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + bytes(100))
        archive.writestr("classes.dex", dex.build_dex(["x"]))
    return buffer.getvalue()


DEBUG_CERT = signing.build_certificate(DEBUG_DN, version=1)
RELEASE_CERT = signing.build_certificate({"CN": "Release", "O": "Example", "C": "SA"}, serial=77)
ROTATED_CERT = signing.build_certificate({"CN": "Release 2026", "O": "Example", "C": "SA"}, serial=78)


def signed(pairs):
    return signing.sign_zip(make_zip(), signing.build_signing_block(pairs))


def test_unsigned_archive():
    info = signing.read_signatures(make_zip())
    assert (info.schemes, info.signers, info.block_ids, info.warnings) == ([], [], [], [])
    assert not info.has_block


def test_v2_signature_from_every_kind_of_source(tmp_path):
    apk = signed([(signing.V2_BLOCK_ID, signing.build_v2_block([DEBUG_CERT]))])
    path = tmp_path / "app.apk"
    path.write_bytes(apk)
    handle = open(path, "rb")
    handle.seek(17)
    for source in (apk, bytearray(apk), memoryview(apk), path, str(path), handle):
        info = signing.read_signatures(source)
        assert info.schemes == ["v2"] and info.has_block and info.block_ids == [signing.V2_BLOCK_ID]
        assert [c.sha256 for c in info.signers] == [hashlib.sha256(DEBUG_CERT).hexdigest()]
        assert info.signers[0].schemes == ["v2"] and info.is_debug and info.warnings == []
    assert handle.tell() == 17 and not handle.closed
    handle.close()
    with zipfile.ZipFile(io.BytesIO(apk)) as archive:                      # still a valid ZIP
        assert archive.read("classes.dex")[:4] == b"dex\n"


def test_every_scheme_and_shared_certificates():
    pairs = [(signing.V2_BLOCK_ID, signing.build_v2_block([RELEASE_CERT])),
             (signing.V3_BLOCK_ID, signing.build_v3_block([RELEASE_CERT])),
             (signing.V31_BLOCK_ID, signing.build_v3_block([[ROTATED_CERT, RELEASE_CERT]], min_sdk=33)),
             (signing.SOURCE_STAMP_V2_ID, b"stamp"),
             (signing.DEPENDENCY_INFO_ID, b"\x00" * 40),
             (signing.VERITY_PADDING_ID, b"\x00" * 100)]
    v1 = {"META-INF/CERT.RSA": signing.build_pkcs7([RELEASE_CERT]), "META-INF/CERT.SF": b"ignored"}
    info = signing.read_signatures(signed(pairs), v1)
    assert info.schemes == ["v1", "v2", "v3", "v3.1", "source-stamp"]
    assert info.block_ids == [pid for pid, _ in pairs] and info.warnings == []
    assert [(c.subject, c.schemes) for c in info.signers] == [
        ("C=SA, O=Example, CN=Release", ["v1", "v2", "v3"]),
        ("C=SA, O=Example, CN=Release 2026", ["v3.1"])]
    assert not info.is_debug


def test_v1_only_signature_blocks():
    chain = signing.build_pkcs7([RELEASE_CERT, DEBUG_CERT])
    info = signing.read_signatures(make_zip(), {"META-INF/RELEASE.rsa": chain})
    assert info.schemes == ["v1"] and not info.has_block
    assert [c.subject for c in info.signers] == ["C=SA, O=Example, CN=Release"]   # the signer, not the chain
    ber = signing.build_pkcs7([DEBUG_CERT], indefinite=True)
    info = signing.read_signatures(make_zip(), {"META-INF/CERT.EC": ber, "META-INF/MANIFEST.MF": b"x"})
    assert info.schemes == ["v1"] and info.is_debug and info.warnings == []
    info = signing.read_signatures(make_zip(), {"META-INF/A.DSA": b"", "META-INF/B.RSA": b"\x30\x80\x30\x80"})
    assert info.schemes == ["v1"] and info.signers == [] and len(info.warnings) == 2


def test_pkcs7_hostile_blocks():
    deep = b"\x30\x80" * 10_000 + b"\x00\x00" * 10_000
    signed_data = der(0x06, bytes.fromhex("2a864886f70d010702"))
    for block, message in ((deep, "nested more than 32"), (b"\x30\x03\x06\x01\x2a", "not a ContentInfo"),
                           (der(0x30, der(0x06, b"\x2a\x86\x48") + der(0xA0, b"")), "not SignedData"),
                           (der(0x30, signed_data + der(0xA0, b"")), "SignedData is missing"),
                           (der(0x30, signed_data + der(0xA0, der(0x30, b""))), "holds no certificate")):
        info = signing.read_signatures(make_zip(), {"META-INF/CERT.RSA": block})
        assert info.schemes == ["v1"] and info.signers == [] and any(message in w for w in info.warnings)
    garbage_cert = signing.build_pkcs7([DEBUG_CERT]).replace(DEBUG_CERT[20:40], b"\xff" * 20)
    embedded = signing.build_pkcs7([signing.build_pkcs7([DEBUG_CERT])])   # a block as a certificate
    for block in (garbage_cert, embedded):
        info = signing.read_signatures(make_zip(), {"META-INF/CERT.RSA": block})
        assert info.signers == [] and any("cannot be read" in w for w in info.warnings)


def block_offset(apk):
    eocd = apk.rfind(b"PK\x05\x06")
    cd_offset, = struct.unpack_from("<I", apk, eocd + 16)
    size, = struct.unpack_from("<Q", apk, cd_offset - 24)
    return cd_offset - size - 8, cd_offset


def test_signing_block_whose_size_fields_disagree():
    apk = signed([(signing.V2_BLOCK_ID, signing.build_v2_block([DEBUG_CERT]))])
    start, cd_offset = block_offset(apk)
    info = signing.read_signatures(patch(apk, start, "<Q", 12345))
    assert info.has_block and info.schemes == [] and info.block_ids == []
    assert any("size fields disagree" in w for w in info.warnings)
    for size in (0, 23, cd_offset, 1 << 63):
        info = signing.read_signatures(patch(apk, cd_offset - 24, "<Q", size))
        assert info.has_block and info.schemes == [] and any("out of range" in w for w in info.warnings)


def test_signing_block_with_bad_pairs():
    pairs = [(signing.VERITY_PADDING_ID, b"\x00" * 8),
             (signing.V2_BLOCK_ID, signing.build_v2_block([DEBUG_CERT]))]
    apk = signed(pairs)
    start, _ = block_offset(apk)
    for length in (0, 3, 1 << 40):
        info = signing.read_signatures(patch(apk, start + 8, "<Q", length))
        assert info.schemes == [] and any("bad size" in w for w in info.warnings)
    twice = signed([(signing.V2_BLOCK_ID, signing.build_v2_block([DEBUG_CERT])),
                    (signing.V2_BLOCK_ID, signing.build_v2_block([RELEASE_CERT]))])
    info = signing.read_signatures(twice)
    assert [c.subject_parts["CN"] for c in info.signers] == ["Android Debug"]
    assert any("twice" in w for w in info.warnings)


@pytest.mark.parametrize("value, message", [
    (b"", "truncated"),
    (struct.pack("<I", 0xFFFFFFFF), "runs past"),
    (struct.pack("<II", 8, 0xFFFFFFF0) + bytes(4), "runs past"),
    (struct.pack("<I", 0), "no signer"),
    (signing.build_v2_block([[]]), "lists no certificate"),
    (signing.build_v2_block([b"\x30\x03\x02\x01\x01"]), "cannot be read"),
])
def test_scheme_values_that_are_malformed(value, message):
    info = signing.read_signatures(signed([(signing.V2_BLOCK_ID, value)]))
    assert info.schemes == ["v2"] and info.signers == [] and any(message in w for w in info.warnings)


def test_signing_caps(monkeypatch):
    monkeypatch.setattr(signing, "MAX_SIGNERS", 2)
    info = signing.read_signatures(signed([(signing.V2_BLOCK_ID, signing.build_v2_block(
        [DEBUG_CERT, RELEASE_CERT, ROTATED_CERT]))]))
    assert len(info.signers) == 2 and any("more than 2 signers" in w for w in info.warnings)
    monkeypatch.setattr(signing, "MAX_PAIRS", 3)
    info = signing.read_signatures(signed([(0x1000 + n, b"x") for n in range(5)]))
    assert info.block_ids == [0x1000, 0x1001, 0x1002] and any("more than 3 pairs" in w for w in info.warnings)
    monkeypatch.setattr(signing, "MAX_SCHEME_VALUE", 10)
    info = signing.read_signatures(signed([(signing.V3_BLOCK_ID, signing.build_v3_block([DEBUG_CERT]))]))
    assert info.schemes == ["v3"] and info.signers == [] and any("not read" in w for w in info.warnings)


def test_archives_that_are_not_plain_zips(tmp_path):
    apk = signed([(signing.V2_BLOCK_ID, signing.build_v2_block([DEBUG_CERT]))])
    for data in (b"", b"PK\x05\x06", bytes(range(256)) * 300):
        info = signing.read_signatures(data)
        assert info.schemes == [] and any("end of central directory" in w for w in info.warnings)
    info = signing.read_signatures(apk + b"trailing bytes")
    assert info.schemes == ["v2"] and any("does not end the file" in w for w in info.warnings)
    eocd = apk.rfind(b"PK\x05\x06")
    info = signing.read_signatures(patch(apk, eocd + 12, "<I", 0xFFFFFFFF))
    assert info.schemes == [] and any("ZIP64" in w for w in info.warnings)
    info = signing.read_signatures(patch(apk, eocd + 16, "<I", len(apk) + 100))
    assert info.schemes == [] and any("does not end where" in w for w in info.warnings)
    shifted = b"prefix" + apk                                              # offsets no longer match
    info = signing.read_signatures(shifted)
    assert info.schemes == [] and any("does not end where" in w for w in info.warnings)
    info = signing.read_signatures(tmp_path / "missing.apk")
    assert any("cannot read" in w for w in info.warnings)


# ------------------------------------------------------------------ the real lab APKs

def read_apk(name):
    with zipfile.ZipFile(APK_DIR / name) as archive:
        return {n: archive.read(n) for n in archive.namelist()
                if n == "resources.arsc" or (n.startswith("classes") and n.endswith(".dex"))}


def apk_dexes(name):
    return {n: dex.parse_dex(data, n) for n, data in read_apk(name).items() if n.endswith(".dex")}


@real_apks
def test_real_resource_tables():
    release = arsc.parse_arsc(read_apk("release.apk")["resources.arsc"])
    assert release.warnings == []
    assert release.file_paths()["res/Zn.xml"] == "drawable/launch_background"
    assert len(release.file_paths()) == 6 and release.strings() == {"androidx_startup": "androidx.startup"}
    assert Counter(e.type for e in release.entries()) == {"drawable": 1, "id": 93, "mipmap": 1, "string": 1,
                                                          "style": 2}
    icon = release.lookup(0x7F0A0000)
    assert release.name_of(0x7F0A0000) == "@mipmap/ic_launcher"
    assert [(v.config, v.text) for v in icon.values] == [
        ("mdpi", "res/9w.png"), ("hdpi", "res/yn.png"), ("xhdpi", "res/FS.png"), ("xxhdpi", "res/RJ.png"),
        ("xxxhdpi", "res/o-.png")]
    debug = arsc.parse_arsc(read_apk("debug.apk")["resources.arsc"])
    assert debug.warnings == [] and len(debug.file_paths()) == 85 and len(debug.strings()) == 9
    assert Counter(e.type for e in debug.entries()) == {
        "anim": 1, "animator": 6, "attr": 38, "color": 6, "dimen": 22, "drawable": 20, "id": 93, "integer": 1,
        "layout": 9, "mipmap": 1, "string": 9, "style": 9}
    answer = debug.lookup(0x7F0B0001)
    assert answer.default().text == "Answer" and len(answer.values) > 80
    assert {"ar", "b+sr+Latn", "fr-rCA"} <= {v.config for v in answer.values}


@real_apks
def test_real_dex_files():
    release = list(apk_dexes("release.apk").values())
    assert len(release) == 1 and release[0].version == "037" and release[0].warnings == []
    assert len(release[0].strings()) == 4612 and len(release[0].class_defs()) == 588
    main = [c for c in release[0].class_defs() if c[0] == "Lcom/example/vuln_probe/MainActivity;"]
    assert main == [("Lcom/example/vuln_probe/MainActivity;", "Le0/f;", 0x11)]
    markers = dex.flutter_markers(release)
    assert markers["flutter_jni"] and markers["plugin_registrant"] and not markers["flutter_activity"]
    debug = apk_dexes("debug.apk")
    assert sorted(debug) == ["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex", "classes5.dex"]
    assert len(debug["classes.dex"].strings()) == 50064 and all(d.warnings == [] for d in debug.values())
    assert debug["classes3.dex"].class_defs() == [("Lcom/example/vuln_probe/MainActivity;",
                                                    "Lio/flutter/embedding/android/FlutterActivity;", 0x11)]
    assert dex.flutter_markers(debug.values())["flutter_activity"]
    assert dex.plugin_classes(debug.values()) == []


@real_apks
@pytest.mark.parametrize("name", APKS)
def test_real_signatures(name):
    info = signing.read_signatures(APK_DIR / name)
    assert info.schemes == ["v2"] and info.has_block and info.warnings == []
    assert signing.V2_BLOCK_ID in info.block_ids and signing.VERITY_PADDING_ID in info.block_ids
    assert (signing.DEPENDENCY_INFO_ID in info.block_ids) == (name != "debug.apk")
    cert, = info.signers
    assert cert.subject == cert.issuer == "C=US, O=Android, CN=Android Debug" and cert.is_debug
    assert (cert.sha256, cert.key, cert.serial) == (DEBUG_SHA256, "RSA 2048", "1")
    assert (cert.valid_from, cert.valid_to) == ("2026-03-10", "2056-03-02")
    assert cert.signature_algorithm == "sha256WithRSAEncryption" and cert.schemes == ["v2"]
