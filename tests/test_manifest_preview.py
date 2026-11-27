"""Package previews retain actual manifest settings at their recorded lines."""
from pathlib import Path

import pytest

from sca.decoded import build_previews
from sca.flutter.android import FILE_PROVIDER_PATHS, MAPS_KEY_METADATA
from sca.flutter.context import ORIGIN_DECODED
from sca.walker import SourceFile


@pytest.mark.parametrize("path", ["AndroidManifest.xml", "splits/feature.apk/AndroidManifest.xml"])
@pytest.mark.parametrize("name", [*MAPS_KEY_METADATA, FILE_PROVIDER_PATHS])
def test_manifest_keeps_exact_public_name_beside_its_value(path, name):
    lines = [
        "<manifest>",
        "  <meta-data",
        f'    android:name = "{name}"',
        '    android:value="fixture-private-setting" />',
        "</manifest>",
    ]
    source = SourceFile(Path(path), path, "config", "\n".join(lines), origin=ORIGIN_DECODED)
    preview = build_previews([source])[path]
    assert preview.lines == tuple(lines)


@pytest.mark.parametrize("path,attribute,value,origin", [
    ("AndroidManifest.xml", "android:value", MAPS_KEY_METADATA[0], ORIGIN_DECODED),
    ("AndroidManifest.xml", "android:name", MAPS_KEY_METADATA[0] + ".fixture", ORIGIN_DECODED),
    ("AndroidManifest.xml", "other-android:name", MAPS_KEY_METADATA[0], ORIGIN_DECODED),
    ("AndroidManifest.xml", "android:name", MAPS_KEY_METADATA[0], ""),
    ("assets/AndroidManifest.xml", "android:name", MAPS_KEY_METADATA[0], ORIGIN_DECODED),
])
def test_other_attributes_and_files_keep_exact_source_values(path, attribute, value, origin):
    xml = f"<manifest><meta-data {attribute}='{value}' /></manifest>"
    source = SourceFile(Path(path), path, "config", xml, origin=origin)
    assert build_previews([source])[path].lines == (xml,)
