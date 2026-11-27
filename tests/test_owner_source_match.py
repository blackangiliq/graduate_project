"""Offline matching of a separately supplied source file against a recorded manifest hit."""
from pathlib import Path

import pytest

from sca.decoded import CredentialEvidence, GOOGLE_KEY_RULE
from sca.engines.secrets import scan_file
from sca.walker import MAX_FILE_BYTES, SourceFile


MANIFEST = "AndroidManifest.xml"
KEY = "AIza" + "a" * 35
OTHER = "AIza" + "b" * 35


def evidence_for(attribute, *, path=MANIFEST, origin="decoded"):
    xml = '<meta-data\n    android:name="com.google.android.geo.API_KEY"\n    ' + attribute
    file = SourceFile(Path(path), path, "config", xml, origin=origin)
    scan_file(file, rules=[])
    return CredentialEvidence([file])


def test_match_from_separate_source_is_exact_and_scoped_to_recorded_location():
    evidence = evidence_for(f'android:value="{KEY}" />')
    data = f'// تعليقات\nval first = "{OTHER}"\nval key = "{KEY}"\n// {KEY}'.encode("utf-8")
    assert evidence.match_source_file(MANIFEST, 3, GOOGLE_KEY_RULE, data) == KEY
    assert evidence.match_source_file(MANIFEST, 2, GOOGLE_KEY_RULE, data) is None
    assert evidence.match_source_file("other.xml", 3, GOOGLE_KEY_RULE, data) is None
    assert evidence.match_source_file(MANIFEST, 3, "SECRET-HARDCODED-001", data) is None
    assert evidence.match_source_file(MANIFEST, 3, GOOGLE_KEY_RULE, OTHER.encode()) is None
    assert evidence.matches_manifest_value(MANIFEST, 3, GOOGLE_KEY_RULE, KEY)
    assert not evidence.matches_manifest_value(MANIFEST, 3, GOOGLE_KEY_RULE, OTHER)


def test_two_distinct_keys_recorded_on_one_line_have_no_unambiguous_source_match():
    evidence = evidence_for(f'android:value="{KEY}" other="{OTHER}" />')
    assert evidence.match_source_file(MANIFEST, 3, GOOGLE_KEY_RULE, KEY.encode()) is None
    assert not evidence.matches_manifest_value(MANIFEST, 3, GOOGLE_KEY_RULE, KEY)


@pytest.mark.parametrize("attribute", [
    f'android:value="some text {KEY}" />',
    f'android:name="{KEY}" />',
    f'android:value="{KEY}" android:other="extra" />',
])
def test_line_evidence_alone_does_not_authorize_attribute_replacement(attribute):
    evidence = evidence_for(attribute)
    assert evidence.match_source_file(MANIFEST, 3, GOOGLE_KEY_RULE, KEY.encode()) == KEY
    assert not evidence.matches_manifest_value(MANIFEST, 3, GOOGLE_KEY_RULE, KEY)


def test_manifest_attribute_proof_requires_decoded_manifest_and_current_scan_format():
    split = "splits/config.en.apk/AndroidManifest.xml"
    evidence = evidence_for(f'android:value="{KEY}"', path=split)
    assert evidence.matches_manifest_value(split, 3, GOOGLE_KEY_RULE, KEY)
    del evidence._manifest_values
    assert not evidence.matches_manifest_value(split, 3, GOOGLE_KEY_RULE, KEY)
    for path, origin in [(MANIFEST, "strings"), ("assets/AndroidManifest.xml", "decoded")]:
        evidence = evidence_for(f'android:value="{KEY}">', path=path, origin=origin)
        assert not evidence.matches_manifest_value(path, 3, GOOGLE_KEY_RULE, KEY)


def test_file_match_rejects_binary_invalid_utf8_and_oversized_sources():
    evidence = evidence_for(f'android:value="{KEY}" />')
    for prefix in [b"\0", b"\xff", b" " * MAX_FILE_BYTES]:
        assert evidence.match_source_file(MANIFEST, 3, GOOGLE_KEY_RULE, prefix + KEY.encode()) is None
