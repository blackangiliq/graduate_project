"""Array, plural and style string members are source evidence, with bounded decoding."""
from io import BytesIO
from pathlib import Path
import struct
import zipfile

import pytest
import flutter_kit as kit

from sca.engines import secrets
from sca.flutter import apk, arsc, inventory
from test_flutter_resources import type_chunks


@pytest.mark.parametrize("options", [{}, {"utf8": False}, {"sparse": True}, {"offset16": True}])
def test_complex_resource_strings_and_configurations_keep_values(options):
    entries = [("array", "api_endpoints", {0x01000000: "https://api.bag.audit.example/v1"}),
               ("plurals", "links", {0x01000006: "https://api.bag.audit.example/{count}"}, "ar"),
               ("style", "ApiConfig", {0x01010001: "StyleLiteralCandidate123"})]
    table = arsc.parse_arsc(arsc.build_arsc("audit.example", entries, **options))
    assert table.warnings == []
    assert len(table.bags) == 3
    assert [(bag.config, bag.items[0].text) for bag in table.bags] == [
        ("", "https://api.bag.audit.example/v1"),
        ("ar", "https://api.bag.audit.example/{count}"), ("", "StyleLiteralCandidate123")]
    assert all(item.data_type == arsc.TYPE_STRING for bag in table.bags for item in bag.items)


def make_apk(tmp_path, table):
    source = BytesIO(kit.build_apk(mode="none"))
    out = BytesIO()
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(out, "w") as archive:
        for member in original.infolist():
            archive.writestr(member.filename, table if member.filename == "resources.arsc"
                             else original.read(member))
    path = tmp_path / "arrays.apk"
    path.write_bytes(out.getvalue())
    return path


def test_package_array_key_and_endpoint_are_full_and_point_to_decoded_item(tmp_path):
    key = "AIza" + "ComplexResourceFixture0123456789abcd"[:35]
    url = "https://api.bag.audit.example/v1/{item}"
    table = arsc.build_arsc("audit.example", [("array", "configuration", {0x01000000: key, 0x01000001: url})])
    ctx = apk.load_app(make_apk(tmp_path, table))
    sf = next(sf for sf in ctx.files if sf.rel == "res/values/complex_resources.xml")
    findings = secrets.scan_file(sf, rules=[])
    hit, = [hit for hit in sf.secret_hits if hit[2] == key]
    assert key in sf.lines[hit[0] - 1]
    out = inventory.build(ctx, ctx.files, findings, reveal_values=True)
    item, = [item for item in out["endpoints"] if item["url"] == url]
    location, = item["locations"]
    assert location["file"] == sf.rel and url in sf.lines[location["line"] - 1]
    assert ctx.facts["complex_resources"]["string_members"] == 2


def test_complex_resource_member_budget_is_shared_and_reported(monkeypatch):
    monkeypatch.setattr(arsc, "MAX_BAG_ITEMS", 2)
    data = arsc.build_arsc("audit.example", [("array", "a", {i: str(i) for i in range(4)}),
                                            ("array", "b", {0: "must-not-bypass-limit"})])
    table = arsc.parse_arsc(data)
    assert sum(len(bag.items) for bag in table.bags) == 2
    assert any("complex resource members" in warning for warning in table.warnings)


def test_corrupt_bag_count_does_not_read_the_next_entry_as_members():
    raw = bytearray(arsc.build_arsc("audit.example", [("array", "a", {0: "first"}),
                                                    ("array", "b", {1: "second"})]))
    offset, _, _, _ = type_chunks(raw)[0]
    entries_offset = struct.unpack_from("<I", raw, offset + 16)[0]
    struct.pack_into("<I", raw, offset + entries_offset + 12, 0xFFFFFFFF)
    table = arsc.parse_arsc(bytes(raw))
    assert [item.text for bag in table.bags for item in bag.items] == ["first", "second"]
    assert any("members run past" in warning for warning in table.warnings)
