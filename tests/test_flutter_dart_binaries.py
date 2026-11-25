"""Tests for the readers of compiled Dart code in a Flutter app: kernel_blob.bin source
recovery (sca/flutter/kernel.py) and libapp.so / libflutter.so analysis
(sca/flutter/snapshot.py). Inputs are built with the modules' own builders; the checks on
real APKs run only when SCA_FLUTTER_APK_DIR points to a folder with debug.apk, release.apk
and release_obf.apk."""
import os
import random
import struct
import time
import zipfile
from pathlib import Path

import pytest

from sca.flutter import kernel, snapshot
from sca.flutter.kernel import KernelSource, app_sources, build_kernel, parse_kernel
from sca.flutter.snapshot import (ElfError, analyze_libapp, analyze_libflutter, ascii_strings,
                                  build_elf, build_snapshot_data, dart_snapshot_strings,
                                  parse_elf, read_snapshot_header)

HASH = "ace654289f5abc240509fc941453ebc5"
RELEASE_FEATURES = ["product", "no-code_comments", "no-dwarf_stack_traces_mode",
                    "dedup_instructions", "no-asan", "no-msan", "no-tsan", "no-shared_data",
                    "arm64", "android", "compressed-pointers"]
SECRET = "sk_" + "live_" + "51Hx9EXAMPLEKEYabcdef0123456789"   # joined: no key in one piece
URL = "http://insecure-api.example.com/v1/login"
SQL = "SELECT * FROM users WHERE name = '"
ENGINE = "0cd610717bde95fd88343c64f81c11ba4e5c0010"
SKIA = "e9ed4fc9f1544c58d8a9347c1fc9471d8dd7c465"
VERSION = '3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "android_arm64"'

PROJECT = "file:///C:/Users/dev/work/my%20app"
CACHE = "file:///C:/Users/dev/AppData/Local/Pub/Cache"
FLUTTER = "file:///C:/flutter"
MAIN_TEXT = "import 'package:flutter/material.dart';\n\nvoid main() {\n  runApp(App());\n}\n"


def app_project_sources():
    return [
        (CACHE + "/hosted/pub.dev/collection-1.19.1/lib/collection.dart",
         "package:collection/collection.dart", "library collection;\n"),
        (CACHE + "/git/mylib-0123456789abcdef0123456789abcdef01234567/lib/mylib.dart",
         "package:mylib/mylib.dart", "int answer() => 42;\n"),
        (FLUTTER + "/packages/flutter/lib/material.dart",
         "package:flutter/material.dart", "export 'src/material/app.dart';\n"),
        (PROJECT + "/lib/main.dart", "package:my_app/main.dart", MAIN_TEXT),
        (PROJECT + "/lib/src/api.dart", "package:my_app/src/api.dart",
         "const loginUrl = '%s';\n// no newline at the end" % URL),
    ]


def offsets_increase(values):
    return all(a < b for a, b in zip(values, values[1:]))


def damage_source_table_offset(blob):
    """The last library offset (where the source table starts) pointed into the header, so
    the component's sources have to be carved."""
    damaged = bytearray(blob)
    struct.pack_into(">I", damaged, len(damaged) - 12, 3)
    return bytes(damaged)


# ------------------------------------------------------------------ kernel


def test_kernel_round_trip():
    blob = build_kernel(app_project_sources(), main="package:my_app/main.dart")
    info = parse_kernel(blob)
    assert info.warnings == []
    assert len(info.components) == 1
    component = info.components[0]
    assert (component.format_version, component.sdk_hash, component.library_count,
            component.source_count) == (130, "0000000000", 5, 5)
    assert [(s.uri, s.import_uri, s.text) for s in info.sources] == app_project_sources()
    assert [s.line_count for s in info.sources] == [1, 1, 1, 5, 2]
    assert info.main_package == "my_app"
    assert info.packages == {"collection": "1.19.1", "mylib": None}
    assert info.build_paths == ["file:///C:/Users/dev/work/my app",
                                "file:///C:/Users/dev/AppData/Local/Pub/Cache",
                                "file:///C:/flutter"]
    app = app_sources(info)
    assert [s.path for s in app] == ["main.dart", "src/api.dart"]
    assert app[0].text == MAIN_TEXT and app[0].package == "my_app"


@pytest.mark.parametrize("components", [2, 3, 7])
def test_kernel_several_components(components):
    sources = app_project_sources()
    info = parse_kernel(build_kernel(sources, components=components,
                                     main="package:my_app/main.dart"))
    assert info.warnings == []
    assert len(info.components) == components
    assert sum(c.source_count for c in info.components) == len(sources)
    assert offsets_increase([c.offset for c in info.components])
    assert [s.text for s in info.sources] == [text for _, _, text in sources]
    assert info.main_package == "my_app"


def test_kernel_older_format_with_compilation_mode_field():
    info = parse_kernel(build_kernel(app_project_sources(), format_version=122,
                                     main="package:my_app/main.dart"))
    assert info.warnings == []
    assert info.components[0].format_version == 122
    assert info.main_package == "my_app"


def test_kernel_main_package_without_main_reference():
    info = parse_kernel(build_kernel(app_project_sources()))
    assert info.main_package == "my_app"            # the local package with a main.dart
    assert [s.path for s in app_sources(info)] == ["main.dart", "src/api.dart"]


def test_kernel_keeps_non_ascii_text_exactly():
    text = "// تطبيق تجريبي\nconst greeting = 'مرحبا 👋';\n"
    sources = [(PROJECT + "/lib/main.dart", "package:my_app/main.dart", text)]
    info = parse_kernel(build_kernel(sources, main="package:my_app/main.dart"))
    assert info.sources[0].text == text
    carved = parse_kernel(damage_source_table_offset(build_kernel(sources)))
    assert any("recovered by carving" in w for w in carved.warnings)
    assert [s.text for s in carved.sources] == [text]


def test_kernel_source_without_embedded_text():
    sources = [("org-dartlang-sdk:///sdk/lib/core/map.dart", "dart:core/map.dart", ""),
               (PROJECT + "/lib/main.dart", "package:my_app/main.dart", MAIN_TEXT)]
    info = parse_kernel(build_kernel(sources))
    assert [(s.import_uri, s.text, s.line_count) for s in info.sources] == [
        ("dart:core/map.dart", "", 0), ("package:my_app/main.dart", MAIN_TEXT, 5)]


def test_kernel_carves_a_component_whose_index_is_damaged():
    sources = app_project_sources()
    info = parse_kernel(damage_source_table_offset(build_kernel(sources,
                                                                main="package:my_app/main.dart")))
    assert any("carved instead" in w for w in info.warnings)
    assert any("recovered by carving" in w for w in info.warnings)
    assert sorted(s.text for s in info.sources) == sorted(text for _, _, text in sources)
    assert info.main_package == "my_app"


def test_kernel_finds_components_after_leading_garbage():
    sources = app_project_sources()
    blob = b"\x00garbage\xff" * 7 + build_kernel(sources, components=2)
    info = parse_kernel(blob)
    assert len(info.components) == 2
    assert any("not a component" in w for w in info.warnings)
    assert [s.text for s in info.sources] == [text for _, _, text in sources]


def test_kernel_component_with_bad_trailer_in_the_middle():
    sources = app_project_sources()
    parts = [build_kernel(sources[:2]), build_kernel(sources[2:4]), build_kernel(sources[4:])]
    middle = bytearray(parts[1])
    struct.pack_into(">I", middle, len(middle) - 4, 7)  # component size no longer fits
    info = parse_kernel(parts[0] + bytes(middle) + parts[2])
    assert len(info.components) == 2
    assert sorted(s.text for s in info.sources) == sorted(text for _, _, text in sources)


def test_kernel_never_raises_on_damaged_input():
    blob = build_kernel(app_project_sources(), components=2, main="package:my_app/main.dart")
    rng = random.Random(7)
    for size in list(range(0, 200, 7)) + [len(blob) // 2, len(blob) - 1]:
        parse_kernel(blob[:size])
    for _ in range(200):
        damaged = bytearray(blob)
        for _ in range(rng.randint(1, 8)):
            damaged[rng.randrange(len(damaged))] = rng.randrange(256)
        info = parse_kernel(bytes(damaged))
        assert len(info.sources) <= len(app_project_sources()) * 2
    noise = bytes(rng.randrange(256) for _ in range(20000))
    info = parse_kernel(noise + b"package:" + noise)
    assert info.sources == [] and info.warnings


def test_kernel_hostile_counts_are_refused():
    blob = bytearray(build_kernel(app_project_sources()))
    table = struct.unpack_from(">I", blob, len(blob) - 12)[0]
    struct.pack_into(">I", blob, table, 0xFFFFFFF0)    # absurd number of sources
    info = parse_kernel(bytes(blob))
    assert any("declares" in w for w in info.warnings)
    blob = bytearray(build_kernel(app_project_sources()))
    struct.pack_into(">I", blob, len(blob) - 8, 0x7FFFFFFF)   # absurd library count
    info = parse_kernel(bytes(blob))
    assert any("library count" in w for w in info.warnings)


def test_kernel_caps(monkeypatch):
    sources = app_project_sources()
    monkeypatch.setattr(kernel, "MAX_SOURCE_BYTES", 30)
    info = parse_kernel(build_kernel(sources))
    assert info.sources[3].text == "" and info.sources[0].text == "library collection;\n"
    assert any("left out" in w for w in info.warnings)
    monkeypatch.setattr(kernel, "MAX_SOURCES", 2)
    info = parse_kernel(build_kernel(sources))
    assert len(info.sources) == 2
    assert any("more than 2 sources" in w for w in info.warnings)
    monkeypatch.setattr(kernel, "MAX_BLOB", 100)
    info = parse_kernel(build_kernel(sources))
    assert info.sources == [] and "limit" in info.warnings[0]


def kernel_with_gaps(gap, gaps):
    """`gaps` copies of `gap` with an empty component between them, so the carver searches
    several gaps."""
    component = build_kernel([]) + kernel._MAGIC + bytes(12)
    return component.join([gap] * gaps)


def test_kernel_carving_charges_the_uri_bytes():
    # each match claims a 4095-byte URI that has no source after it
    blob = kernel_with_gaps(b"\x8f\xffpackage:" * 20000, 3)
    started = time.perf_counter()
    info = parse_kernel(blob)
    assert time.perf_counter() - started < 2
    assert info.sources == [] and any("carving stopped" in w for w in info.warnings)


def test_kernel_carving_tries_are_counted_over_every_gap(monkeypatch):
    monkeypatch.setattr(kernel, "_MAX_CARVE_TRIES", 1500)
    info = parse_kernel(kernel_with_gaps(b"\x00package:" * 1000, 3))
    assert any("carving stopped" in w for w in info.warnings)


def test_kernel_main_library_is_looked_up_once(monkeypatch):
    # every component names a main(); only the last one (the entry component) is resolved
    calls = []
    string_table = kernel._string_table
    monkeypatch.setattr(kernel, "_string_table", lambda *a: calls.append(a) or string_table(*a))
    sources = app_project_sources()
    blob = b"".join(build_kernel(sources[i:i + 1], main="package:my_app/main.dart")
                    for i in range(len(sources)))
    info = parse_kernel(blob)
    assert len(info.components) == len(sources) and info.main_package == "my_app"
    assert len(calls) == 1


def test_kernel_warnings_are_capped():
    info = kernel.KernelInfo()
    for i in range(kernel.MAX_WARNINGS + 10):
        info.warn("problem %d" % i)
    assert len(info.warnings) == kernel.MAX_WARNINGS + 1


def test_kernel_source_path_is_safe():
    source = KernelSource("file:///x", "package:app/../../etc/./pass\x00wd//x.dart", "", 0)
    assert source.package == "app"
    assert source.path == "etc/pass_wd/x.dart"
    assert KernelSource("file:///x", "dart:core/map.dart", "", 0).path == ""


# ------------------------------------------------------------------ ELF


@pytest.mark.parametrize("bits,little,arch", [(64, True, "aarch64"), (32, True, "arm"),
                                              (64, False, "aarch64"), (32, False, "arm"),
                                              (64, True, "x86_64")])
def test_parse_elf(bits, little, arch):
    data = build_elf({"_kDartVmSnapshotData": b"VMDATA", "other": b"OTHER!"},
                     sections=[".symtab", (".text", b"\x00" * 8)], bits=bits, little=little,
                     arch=arch, build_id=bytes(range(16)), vaddr_offset=0x4000)
    elf = parse_elf(data)
    assert (elf.bits, elf.little, elf.arch) == (bits, little, arch)
    assert elf.warnings == []
    assert elf.has_section(".rodata") and elf.has_section(".symtab")
    assert not elf.has_section(".debug_info")
    symbol = elf.symbol("_kDartVmSnapshotData")
    start, end = elf.symbol_range(symbol)
    assert data[start:end] == b"VMDATA"
    assert elf.vaddr_to_offset(symbol.value) == symbol.value - 0x4000 == start
    assert elf.offset_to_vaddr(start) == symbol.value
    assert elf.vaddr_to_offset(0x10) is None
    assert elf.build_id() == bytes(range(16)).hex()
    text = elf.section(".text")
    assert elf.code_ranges() == [(text.offset, text.offset + 8, text.addr)]


def test_parse_elf_rejects_other_data():
    for data in (b"", b"MZ\x90\x00" + bytes(60), b"\x7fELF\x03\x01" + bytes(60), b"\x7fELF"):
        with pytest.raises(ElfError):
            parse_elf(data)


def test_parse_elf_survives_truncation_and_damage():
    data = build_elf({"_kDartIsolateSnapshotData": b"x" * 100}, sections=[".symtab"],
                     build_id=b"\x01" * 16)
    for size in range(64, len(data), 5):
        elf = parse_elf(data[:size])
        assert len(elf.sections) <= 7
    elf = parse_elf(data[:len(data) - 40])
    assert any("entries readable" in w for w in elf.warnings)
    damaged = bytearray(data)
    struct.pack_into("<H", damaged, 0x3A, 3)            # e_shentsize smaller than an entry
    assert any("too small" in w for w in parse_elf(bytes(damaged)).warnings)
    damaged = bytearray(data)
    struct.pack_into("<H", damaged, 0x3E, 999)          # e_shstrndx out of range
    elf = parse_elf(bytes(damaged))
    assert any("out of range" in w for w in elf.warnings)
    assert {s.name for s in elf.sections} == {""}


def raw_elf(sections, blob=b"", shstrndx=0):
    """An ELF64 file: header, blob at offset 64, then the given section header rows (name,
    type, flags, addr, offset, size, link, entsize)."""
    shoff = 64 + len(blob) + (-(64 + len(blob)) % 8)
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 3, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections), shstrndx)
    rows = b"".join(struct.pack("<IIQQQQIIQQ", name, kind, flags, addr, offset, size, link, 0, 1,
                                entsize)
                    for name, kind, flags, addr, offset, size, link, entsize in sections)
    return header + blob + bytes(shoff - 64 - len(blob)) + rows


def test_elf_address_lookups_follow_the_first_matching_part():
    rng = random.Random(13)
    for _ in range(200):
        elf = snapshot.ElfFile(bytes(300), 64, True, 183, 3)
        elf.sections = [snapshot.ElfSection("", 1, 2, rng.randrange(0, 400), rng.randrange(0, 400),
                                            rng.randrange(0, 120), 0, 0) for _ in range(8)]
        parts = [(s.addr, s.offset, s.size) for s in elf.sections]
        for key in range(0, 520, 3):
            to_vaddr = next((v + key - o for v, o, n in parts if o <= key < o + n), None)
            to_offset = next((o + key - v for v, o, n in parts
                              if v <= key < v + n and o + key - v < 300), None)
            assert elf.offset_to_vaddr(key) == to_vaddr and elf.vaddr_to_offset(key) == to_offset


def test_libflutter_with_many_sections_and_revision_strings():
    # 3000 sections map the whole file and 5000 revision strings: each lookup is a binary
    # search and only the first 64 strings are read
    blob = b"\x00" + (ENGINE.encode() + b"\x00") * 5000
    whole = 64 + len(blob) + 64 * 3000 + 8
    data = raw_elf([(0, 1, 2, 0, 0, whole, 0, 0)] * 3000, blob)
    started = time.perf_counter()
    info = analyze_libflutter(data)
    assert time.perf_counter() - started < 2
    assert info.revision_candidates == [ENGINE]
    assert any("more than 64 revision strings" in w for w in info.warnings)


def test_elf_code_ranges_without_text_are_deduplicated_and_capped():
    same = [(0, 1, 6, 0x1000, 64, 32, 0, 0)] * 20                       # PROGBITS, ALLOC | EXEC
    other = [(0, 1, 6, 0x1000 + 8 * i, 64 + 8 * i, 32, 0, 0) for i in range(1, 40)]
    elf = parse_elf(raw_elf(same + other, bytes(512)))
    ranges = elf.code_ranges()
    assert len(ranges) == snapshot.MAX_CODE_RANGES and len(set(ranges)) == len(ranges)
    assert ranges[0] == (64, 96, 0x1000)


def test_elf_sections_past_the_end_of_the_file():
    names = b"\0.rodata\0"
    data = raw_elf([(0, 0, 0, 0, 0, 0, 0, 0), (1, 1, 2, 0, 1 << 63, 16, 0, 0),
                    (0, 3, 0, 0, 64, len(names), 0, 0)], names, shstrndx=2)
    data += b"\x00" + ENGINE.encode() + b"\x00"
    elf = parse_elf(data)
    assert elf.section_range(elf.section(".rodata")) == (len(data), len(data))
    info = analyze_libflutter(data)                         # this raised OverflowError
    assert info.revision_candidates == [] and any("no 40-character" in w for w in info.warnings)


def test_elf_symbol_names_are_shared_and_budgeted():
    # 3000 symbols at different offsets of a table without NUL (4096-byte names), two at the
    # same offset, and the snapshot symbol last
    strtab = b"A" * 8192 + b"_kDartIsolateSnapshotData\x00"
    offsets = [0, 0] + [2 * i for i in range(1, 3001)] + [8192]
    dynsym = bytes(24) + b"".join(struct.pack("<IBBHQQ", offset, 0x11, 0, 1, 0, 0)
                                  for offset in offsets)
    data = raw_elf([(0, 0, 0, 0, 0, 0, 0, 0), (0, 3, 2, 0, 64, len(strtab), 0, 0),
                    (0, 11, 2, 0, 64 + len(strtab), len(dynsym), 1, 24)], strtab + dynsym)
    elf = parse_elf(data)
    assert len(elf.symbols) == len(offsets) + 1                            # and the null symbol
    assert elf.symbols[1].name is elf.symbols[2].name
    distinct = {id(s.name): s.name for s in elf.symbols}.values()
    assert sum(map(len, distinct)) < 2 * len(strtab) + snapshot.MAX_NAME_BYTES + 4096
    assert elf.symbol("_kDartIsolateSnapshotData") is not None


# ------------------------------------------------------------------ snapshot strings


def names(count, template="name%d"):
    return [template % i for i in range(count)]


def app_strings():
    return names(150) + [SECRET, URL, SQL, "token=", "X-Api-Key", "'", "x" * 70, "y" * 200,
                         "تسجيل الدخول", "package:my_app/main.dart", "dart:core"]


def test_dart_snapshot_strings_reads_every_record():
    data = build_snapshot_data(RELEASE_FEATURES, app_strings(), HASH)
    header = read_snapshot_header(data)
    assert dart_snapshot_strings(data, header.body) == app_strings()


def test_dart_snapshot_strings_takes_short_records_before_a_run():
    # three short strings, a long one that starts the run, then the rest
    strings = ["ab", "cd", "ef", "L" * 80, "gh", "ij"]
    data = build_snapshot_data(RELEASE_FEATURES, strings, HASH)
    assert dart_snapshot_strings(data, read_snapshot_header(data).body) == strings


def test_dart_snapshot_strings_trims_noise_at_the_edges_of_a_run():
    strings = ["\xe9\xe8\xe0", "ok1", "ok2", "ok3", "ok4", "\xe9t\xe9", "caf\xe9", "end1"]
    data = build_snapshot_data(RELEASE_FEATURES, strings, HASH)
    found = dart_snapshot_strings(data, read_snapshot_header(data).body)
    assert found == ["ok1", "ok2", "ok3", "ok4", "\xe9t\xe9", "caf\xe9", "end1"]


def test_dart_snapshot_strings_needs_four_short_records_or_a_long_one():
    for strings, expected in ((["ab", "cd", "ef"], []), (["ab", "cd", "ef", "gh"], None),
                              (["L" * 64], None), (["L" * 63], [])):
        data = build_snapshot_data(RELEASE_FEATURES, strings, HASH)
        found = dart_snapshot_strings(data, read_snapshot_header(data).body)
        assert found == (strings if expected is None else expected)


def test_dart_snapshot_strings_on_noise_and_limits():
    rng = random.Random(3)
    noise = bytes(rng.randrange(256) for _ in range(200000))
    assert len(dart_snapshot_strings(noise)) < 20
    data = build_snapshot_data(RELEASE_FEATURES, names(500), HASH)
    assert dart_snapshot_strings(data, limit=10) == names(10)
    assert dart_snapshot_strings(data, 0, 0) == []


def test_dart_snapshot_strings_is_fast():
    rng = random.Random(5)
    chunks = []
    for i in range(200):
        chunks.append(bytes(rng.randrange(256) for _ in range(2000)))
        chunks.append(build_snapshot_data(RELEASE_FEATURES, names(100, "s%d_" + str(i)), HASH))
    data = b"".join(chunks)
    started = time.perf_counter()
    found = dart_snapshot_strings(data)
    assert time.perf_counter() - started < 3.0
    assert len(found) >= 20000


def test_dart_snapshot_strings_search_work_is_bounded(monkeypatch):
    # every other byte starts a candidate run that does not decode
    calls = []
    record = snapshot._string_record
    monkeypatch.setattr(snapshot, "_string_record", lambda *a: calls.append(1) or record(*a))
    data = b"\x84A" * (1 << 19)
    assert dart_snapshot_strings(data) == []
    assert len(calls) <= max(snapshot._MIN_WORK, len(data) >> snapshot._WORK_SHIFT) + 1


def test_ascii_strings():
    data = b"\x00abc\x01abcdef\x02tab\there!\xffsix666" + b"z" * 10
    assert ascii_strings(data) == ["abcdef", "tab\there!", "six666zzzzzzzzzz"]
    assert ascii_strings(data, min_len=3) == ["abc", "abcdef", "tab\there!",
                                              "six666zzzzzzzzzz"]
    assert ascii_strings(data, limit=1) == ["abcdef"]


# ------------------------------------------------------------------ snapshot header


def test_read_snapshot_header():
    data = build_snapshot_data(RELEASE_FEATURES, ["a"], HASH)
    header = read_snapshot_header(data, kinds=snapshot.KINDS_UP_TO_3_12)
    assert (header.kind, header.kind_name, header.version_hash) == (3, "kFullAOT", HASH)
    assert header.features == RELEASE_FEATURES and header.build_mode == "release"
    assert read_snapshot_header(data).kind_name == ""          # 3 differs between versions
    assert read_snapshot_header(b"\x00" + data) is None
    assert read_snapshot_header(data, 1) is None
    assert read_snapshot_header(data[:40]) is None


def test_read_snapshot_header_of_a_debug_build():
    core = build_snapshot_data(["release"], [], HASH, kind=1)  # isolate_snapshot_data
    header = read_snapshot_header(core)
    assert (header.kind_name, header.build_mode) == ("kFullCore", "debug")
    jit = build_snapshot_data(["release", "arm64", "android"], [], HASH, kind=1)
    assert read_snapshot_header(jit).kind_name == "kFullJIT"


@pytest.mark.parametrize("features,mode", [(["product", "arm64"], "release"),
                                           (["release", "arm64"], "profile"),
                                           (["debug", "arm64"], "unknown"), ([], "unknown")])
def test_build_mode(features, mode):
    assert snapshot.build_mode(features) == mode


# ------------------------------------------------------------------ libapp.so


def libapp(strings, *, features=RELEASE_FEATURES, symbols="3.12", kind=None, **elf_options):
    vm = build_snapshot_data(features, ["dart:core", "_vm@1", "Object", "String", "List"], HASH,
                             kind=kind or 3)
    isolate = build_snapshot_data(features, strings, HASH, kind=kind or 3)
    code = b"\x1f\x20\x03\xd5" * 16
    if symbols == "3.12":
        table = {"_kDartVmSnapshotInstructions": code, "_kDartIsolateSnapshotInstructions": code,
                 "_kDartVmSnapshotData": vm, "_kDartIsolateSnapshotData": isolate,
                 "_kDartSnapshotBuildId": b"\x00" * 32}
    else:
        table = {"_kDartSnapshotText": code, "_kDartSnapshotData": isolate,
                 "_kDartSnapshotBss": b"", "_kDartSnapshotBuildId": b"\x00" * 32}
    return build_elf(table, build_id=b"\xb7\x18\x85\x09" * 4, **elf_options)


def test_analyze_libapp_release_build():
    info = analyze_libapp(libapp(app_strings()))
    assert info.warnings == []
    assert (info.kind, info.kind_name, info.version_hash) == (3, "kFullAOT", HASH)
    assert info.features == RELEASE_FEATURES and info.build_mode == "release"
    assert (info.arch, info.build_id) == ("aarch64", "b7188509" * 4)
    assert info.symbols_present is False
    assert info.strings_source == "dart"
    for text in (SECRET, URL, SQL, "'", "y" * 200, "تسجيل الدخول", "dart:core", "_vm@1"):
        assert text in info.strings
    assert info.package_uris == ["package:my_app/main.dart"]


def test_analyze_libapp_dart_3_13_symbols_and_profile_build():
    features = ["release"] + RELEASE_FEATURES[1:]
    info = analyze_libapp(libapp(app_strings(), features=features, symbols="3.13", kind=2))
    assert info.warnings == []
    assert (info.kind, info.kind_name, info.build_mode) == (2, "kFullAOT", "profile")
    assert SECRET in info.strings


def test_analyze_libapp_debug_symbols():
    assert analyze_libapp(libapp(app_strings(), sections=[".symtab"])).symbols_present
    with_dwarf = libapp(app_strings(), sections=[(".debug_line", b"\x01\x02")])
    assert analyze_libapp(with_dwarf).symbols_present


def test_analyze_libapp_armeabi_v7a_uses_printable_runs():
    # without compressed pointers strings are image objects: header word, hash, Smi length,
    # characters, padding; the walker finds no records and printable runs are used instead
    features = RELEASE_FEATURES[:8] + ["arm", "android", "no-compressed-pointers"]
    blob = bytearray(build_snapshot_data(features, [], HASH))
    for text in names(40, "identifier_%d") + [SECRET, URL, SQL]:
        raw = text.encode("latin-1")
        blob += struct.pack("<III", 0x0000_5D02, 0, len(raw) << 1) + raw
        blob += bytes((-len(blob)) % 8)
    data = build_elf({"_kDartVmSnapshotData": build_snapshot_data(features, [], HASH),
                      "_kDartIsolateSnapshotData": bytes(blob)}, arch="arm", bits=32)
    info = analyze_libapp(data)
    assert info.arch == "arm" and info.kind_name == "kFullAOT"
    assert info.strings_source == "ascii"
    assert {SECRET, URL, "identifier_7"} <= set(info.strings)
    assert any(s.startswith(SQL) for s in info.strings)


def test_analyze_libapp_without_symbols_finds_the_snapshot_by_magic():
    isolate = build_snapshot_data(RELEASE_FEATURES, app_strings(), HASH)
    data = b"\x00" * 64 + build_snapshot_data(RELEASE_FEATURES, ["a"], HASH) + isolate
    info = analyze_libapp(data)
    assert any("not an ELF file" in w for w in info.warnings)
    assert any("by its magic" in w for w in info.warnings)
    assert (info.kind_name, info.version_hash, info.build_mode) == ("kFullAOT", HASH, "release")
    assert SECRET in info.strings


def test_analyze_libapp_caps_the_data_it_searches(monkeypatch):
    monkeypatch.setattr(snapshot, "MAX_WALK", 1000)
    info = analyze_libapp(libapp(app_strings()))
    assert any("over the 1000-byte limit" in w for w in info.warnings)
    assert info.strings_source == "dart"
    assert "name5" in info.strings and SECRET not in info.strings


def test_analyze_libapp_never_raises():
    data = libapp(app_strings())
    rng = random.Random(11)
    for size in range(0, len(data), 97):
        analyze_libapp(data[:size])
    for _ in range(100):
        damaged = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            damaged[rng.randrange(len(damaged))] = rng.randrange(256)
        analyze_libapp(bytes(damaged))
    info = analyze_libapp(b"garbage" * 100)
    assert "libapp.so: no Dart snapshot found" in info.warnings


def obfuscated_names(count):
    return ["_%s@%d" % (chr(65 + i % 26) + chr(97 + i // 26 % 26), 5048458 + i)
            for i in range(count)]


def test_obfuscation_verdicts():
    plain = names(100, "_LoginPageState%d@444214061") + ["package:my_app/main.dart"]
    info = analyze_libapp(libapp(plain + obfuscated_names(5)))
    assert info.obfuscation.obfuscated is False
    assert (info.obfuscation.private_names, info.obfuscation.short_private_names) == (106, 6)
    assert info.obfuscation.package_uri_count == 1
    info = analyze_libapp(libapp(obfuscated_names(300) + names(10, "_longName%d@1")))
    assert info.obfuscation.obfuscated is True
    assert info.obfuscation.short_private_names == 301
    info = analyze_libapp(libapp(names(150) + obfuscated_names(10)))
    assert info.obfuscation.obfuscated is None
    assert "too few" in info.obfuscation.note


# ------------------------------------------------------------------ libflutter.so


def rodata_strings():
    """Engine strings with NUL on both sides, as they sit in .rodata."""
    return (b"\x00" + VERSION.encode() + b"\x00flutter_engine\x00skia\x00" + ENGINE.encode()
            + b"\x00" + SKIA.encode() + b"\x00")


def libflutter(arch, assemble, size=256):
    """An engine library whose .text is assemble(addresses, text_address); built twice so
    the code can use the final addresses."""
    bits = 32 if arch == "arm" else 64

    def build(code):
        return build_elf({"strings": rodata_strings()}, sections=[(".text", code)], arch=arch,
                         bits=bits)

    elf = parse_elf(build(bytes(size)))
    base = elf.symbol("strings").value
    blob = rodata_strings()
    where = {"flutter_engine": base + blob.index(b"flutter_engine"),
             "skia": base + blob.index(b"skia\x00"),
             "engine": base + blob.index(ENGINE.encode()),
             "skia_revision": base + blob.index(SKIA.encode())}
    code = assemble(where, elf.section(".text").addr)
    assert len(code) <= size
    return build(code.ljust(size, b"\x00"))


def arm64_adrp(reg, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | reg


def arm64_add(reg, source, imm):
    return 0x91000000 | (imm << 10) | (source << 5) | reg


def arm64_bl(pc, target):
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def arm64_code(where, base, getters):
    """Load "flutter_engine", the engine revision, "skia", the Skia revision (each followed
    by a call), directly or through getter functions placed after the code."""
    words = []

    def load(reg, name):
        pc = base + 4 * len(words)
        words.extend([arm64_adrp(reg, pc, where[name]),
                      arm64_add(reg, reg, where[name] & 0xFFF)])

    def call(target):
        words.append(arm64_bl(base + 4 * len(words), target))

    getter_at = {"engine": base + 160, "skia_revision": base + 176}
    for name in ("flutter_engine", "engine", "skia", "skia_revision"):
        if getters and name in getter_at:
            call(getter_at[name])
            words.append(0xAA0003E1)                    # mov x1, x0
        else:
            load(1, name)
        call(base + 240)                                # std::string constructor
    words.append(0xD65F03C0)
    words.extend([0xD503201F] * (40 - len(words)))      # nop up to the getters
    for name in ("engine", "skia_revision"):
        pc = base + 4 * len(words)
        words.extend([arm64_adrp(0, pc, where[name]), arm64_add(0, 0, where[name] & 0xFFF),
                      0xD65F03C0, 0xD503201F])
    return struct.pack("<%dI" % len(words), *words)


def x64_code(where, base, getters):
    code = bytearray()

    def lea(reg_bits, name):
        disp = where[name] - (base + len(code) + 7)
        code.extend(bytes([0x48, 0x8D, reg_bits]) + struct.pack("<i", disp))

    def call(target):
        code.extend(b"\xe8" + struct.pack("<i", target - (base + len(code) + 5)))

    getter_at = {"engine": base + 160, "skia_revision": base + 176}
    for name in ("flutter_engine", "engine", "skia", "skia_revision"):
        code.extend(b"\x48\x8d\x7c\x24\x20")              # lea rdi, [rsp + 0x20]
        if getters and name in getter_at:
            call(getter_at[name])
            code.extend(b"\x48\x89\xc6")                  # mov rsi, rax
        else:
            lea(0x35, name)                               # lea rsi, [rip + disp]
        call(base + 240)
    code.extend(b"\xc3")
    code.extend(b"\x90" * (160 - len(code)))
    for name in ("engine", "skia_revision"):
        lea(0x05, name)                                   # lea rax, [rip + disp]
        code.extend(b"\xc3" + b"\x90" * 8)
    return bytes(code)


def thumb_code(where, base, getters):
    """ldr rN, [pc, #imm] / add rN, pc pairs with a literal pool, or BL to getters that do
    the same with r0 and return with bx lr."""
    halves = []
    pool = []                                           # (index of the ldr, add address, target)

    def load(reg, name):
        pool.append((len(halves), base + 2 * (len(halves) + 1), where[name], reg))
        halves.extend([0x4800 | (reg << 8), 0x4478 | reg])

    def call(target):
        pc = base + 2 * len(halves)
        offset = target - (pc + 4)
        sign = (offset >> 24) & 1
        j1 = (~((offset >> 23) & 1) ^ sign) & 1
        j2 = (~((offset >> 22) & 1) ^ sign) & 1
        halves.extend([0xF000 | (sign << 10) | ((offset >> 12) & 0x3FF),
                       0xD000 | (j1 << 13) | (j2 << 11) | ((offset >> 1) & 0x7FF)])

    getter_at = {"engine": base + 96, "skia_revision": base + 112}
    for name in ("flutter_engine", "engine", "skia", "skia_revision"):
        if getters and name in getter_at:
            call(getter_at[name])
            halves.append(0x4601)                         # mov r1, r0
        else:
            load(1, name)
        call(base + 200)
    halves.append(0x4770)
    halves.extend([0xBF00] * (48 - len(halves)))          # nop up to the getters
    for name in ("engine", "skia_revision"):
        load(0, name)
        halves.extend([0x4770, 0xBF00, 0xBF00, 0xBF00, 0xBF00, 0xBF00])
    halves.extend([0xBF00] * (64 - len(halves)))
    literals = []
    for index, add_at, target, reg in pool:
        literal_at = base + 2 * len(halves) + 4 * len(literals)
        ldr_pc = (base + 2 * index + 4) & ~3
        halves[index] = 0x4800 | (reg << 8) | ((literal_at - ldr_pc) // 4)
        literals.append((target - (add_at + 4)) & 0xFFFFFFFF)
    return struct.pack("<%dH" % len(halves), *halves) + struct.pack("<%dI" % len(literals),
                                                                    *literals)


@pytest.mark.parametrize("arch,assembler", [("aarch64", arm64_code), ("x86_64", x64_code),
                                            ("arm", thumb_code)])
@pytest.mark.parametrize("getters", [False, True])
def test_analyze_libflutter_engine_revision(arch, assembler, getters):
    data = libflutter(arch, lambda where, base: assembler(where, base, getters))
    info = analyze_libflutter(data)
    assert info.warnings == []
    assert (info.dart_version, info.channel) == ("3.12.2", "stable")
    assert info.version_string == VERSION
    assert (info.engine_revision, info.skia_revision) == (ENGINE, SKIA)
    assert info.revision_candidates == [ENGINE, SKIA]


def test_analyze_libflutter_does_not_guess():
    data = libflutter("aarch64", lambda where, base: b"\x1f\x20\x03\xd5" * 16)
    info = analyze_libflutter(data)
    assert info.dart_version == "3.12.2"
    assert info.engine_revision == ""
    assert info.revision_candidates == [ENGINE, SKIA]
    assert any("could not be told apart" in w and ENGINE in w for w in info.warnings)
    info = analyze_libflutter(libflutter("x86", lambda where, base: b"\x90" * 16))
    assert info.engine_revision == "" and info.dart_version == "3.12.2"


def test_analyze_libflutter_on_other_data():
    info = analyze_libflutter(b"garbage")
    assert info.dart_version == "" and info.engine_revision == ""
    assert "libflutter.so: not an ELF file" in info.warnings
    info = analyze_libflutter(b"\x00" + VERSION.encode() + b"\x00")
    assert info.dart_version == "3.12.2"
    data = libflutter("aarch64", lambda where, base: arm64_code(where, base, False))
    info = analyze_libflutter(data[:len(data) - 100])        # section table cut short
    assert info.engine_revision == ENGINE
    assert any("ELF: section table" in w for w in info.warnings)


def test_analyze_libflutter_reference_search_is_bounded(monkeypatch):
    # every instruction is an ADD of the marker's page offset, none has its ADRP: each needs
    # the search back, and the work budget stops it
    def assemble(where, base):
        return struct.pack("<I", arm64_add(1, 1, where["flutter_engine"] & 0xFFF)) * 4096

    data = libflutter("aarch64", assemble, size=4 * 4096)
    searches = []
    page = snapshot._Arm64._page
    monkeypatch.setattr(snapshot._Arm64, "_page", lambda *a: searches.append(1) or page(*a))
    monkeypatch.setattr(snapshot, "_MAX_REF_WORK", 1000)
    info = analyze_libflutter(data)
    assert info.engine_revision == "" and len(searches) <= 1000 // 17 + 1


# ------------------------------------------------------------------ real app packages

APK_DIR = os.environ.get("SCA_FLUTTER_APK_DIR", "")
real = pytest.mark.skipif(
    not (APK_DIR and all((Path(APK_DIR) / n).is_file()
                         for n in ("debug.apk", "release.apk", "release_obf.apk"))),
    reason="set SCA_FLUTTER_APK_DIR to a folder with debug.apk, release.apk, release_obf.apk")


def apk_entry(apk, name):
    with zipfile.ZipFile(Path(APK_DIR) / apk) as archive:
        return archive.read(name)


@real
def test_real_debug_kernel():
    info = parse_kernel(apk_entry("debug.apk", "assets/flutter_assets/kernel_blob.bin"))
    assert info.warnings == []
    assert len(info.components) == 8
    assert {(c.format_version, c.sdk_hash) for c in info.components} == {(130, "d684a576a6")}
    assert len(info.sources) == 777 and sum(1 for s in info.sources if s.text) == 775
    assert info.main_package == "vuln_probe"
    assert info.packages == {"characters": "1.4.1", "collection": "1.19.1",
                             "material_color_utilities": "0.13.0", "meta": "1.18.0",
                             "vector_math": "2.2.0"}
    assert info.build_paths[0].endswith("/vuln_probe")
    assert any(p.endswith("/Pub/Cache") for p in info.build_paths)
    main = [s for s in app_sources(info) if s.path == "main.dart"]
    assert len(main) == 1 and SECRET in main[0].text
    on_disk = Path(APK_DIR).parent / "vuln_probe" / "lib" / "main.dart"
    if on_disk.is_file():
        assert main[0].text.encode("utf-8") == on_disk.read_bytes()


@real
def test_real_debug_snapshot_headers():
    for name in ("isolate_snapshot_data", "vm_snapshot_data"):
        header = read_snapshot_header(apk_entry("debug.apk", "assets/flutter_assets/" + name))
        assert (header.kind, header.kind_name, header.version_hash) == (1, "kFullCore", HASH)
        assert header.features == ["release"] and header.build_mode == "debug"


@real
@pytest.mark.parametrize("apk,obfuscated", [("release.apk", False), ("release_obf.apk", True)])
def test_real_libapp(apk, obfuscated):
    data = apk_entry(apk, "lib/arm64-v8a/libapp.so")
    started = time.perf_counter()
    info = analyze_libapp(data)
    assert time.perf_counter() - started <= 3.0
    assert info.warnings == []
    assert (info.kind, info.kind_name, info.version_hash) == (3, "kFullAOT", HASH)
    assert info.build_mode == "release" and info.features[0] == "product"
    assert ("dwarf_stack_traces_mode" in info.features) is obfuscated
    assert info.symbols_present is False
    assert {SECRET, URL, SQL} <= set(info.strings)
    assert info.obfuscation.obfuscated is obfuscated
    assert ("package:vuln_probe/main.dart" in info.package_uris) is not obfuscated


@real
def test_real_split_debug_info_has_symbols():
    symbols = Path(APK_DIR) / "release_obf.app.android-arm64.symbols"
    if not symbols.is_file():
        pytest.skip("no .symbols file next to the APKs")
    assert analyze_libapp(symbols.read_bytes()).symbols_present


@real
@pytest.mark.parametrize("apk", ["debug.apk", "release.apk"])
def test_real_libflutter(apk):
    info = analyze_libflutter(apk_entry(apk, "lib/arm64-v8a/libflutter.so"))
    assert info.warnings == []
    assert (info.dart_version, info.channel) == ("3.12.2", "stable")
    assert (info.engine_revision, info.skia_revision) == (ENGINE, SKIA)
