"""Check the shipped runtime artifact, independently of a live Android device."""
import json
from pathlib import Path


AGENT = Path(__file__).resolve().parents[1] / "sca" / "dynamic" / "agent"


def test_shipped_frida_bundle_has_valid_byte_lengths_and_source_map():
    raw = (AGENT / "observer.bundle.js").read_bytes()
    signature = "📦\n".encode("utf-8")
    delimiter = "✄\n".encode("utf-8")
    assert raw.startswith(signature)
    header, body = raw[len(signature):].split(delimiter, 1)
    entries = [line.split(b" ", 1) for line in header.splitlines()]
    sections = body.split(b"\n" + delimiter)
    assert len(entries) == len(sections) == 2
    assert [name for _, name in entries] == [b"/observer.js", b"/observer.js.map"]
    # Frida uses byte offsets, not text character counts. Windows CRLF conversion
    # would make the supposedly ready-to-use capture fail.
    assert [int(size) for size, _ in entries] == [len(section) for section in sections]
    source_map = json.loads(sections[1])
    assert source_map["version"] == 3
    assert "observer.js" in source_map["sources"]
    assert all(not source.startswith(("/", "C:", "c:")) for source in source_map["sources"])


def test_bundled_bridge_keeps_pinned_dependency_and_license_material():
    package = json.loads((AGENT / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((AGENT / "package-lock.json").read_text(encoding="utf-8"))
    version = package["dependencies"]["frida-java-bridge"]
    bridge = lock["packages"]["node_modules/frida-java-bridge"]
    assert bridge["version"] == version
    assert bridge["resolved"].endswith(f"/frida-java-bridge-{version}.tgz")
    assert bridge["integrity"].startswith("sha512-")
    notice = (AGENT / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
    assert f"frida-java-bridge {version}" in notice
    assert "wxWindows Library Licence" in (AGENT / "COPYING").read_text(encoding="utf-8")
    assert "GNU LIBRARY GENERAL PUBLIC LICENSE" in (AGENT / "COPYING.LIB").read_text(encoding="utf-8")
