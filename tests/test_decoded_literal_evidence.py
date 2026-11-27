"""Derived values retain explicit provenance through history and source navigation."""
import base64
import hashlib
import json
from pathlib import Path
import zlib

import pytest

from sca.decoded import build_previews, validate_derivation
from sca.models import ScanResult
from sca.storage import Storage, _decode_evidence
from sca.walker import SourceFile


def sources():
    value = "FixtureOnlyCredential9x2P8q6A4b0Z"
    encoded = base64.b64encode(value.encode()).decode()
    detail = {"encoding": "base64", "depth": 1, "source_file": "classes.dex",
              "source_line": 2, "source_column": 3, "source_end_column": 3 + len(encoded),
              "encoded_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
              "decoded_sha256": hashlib.sha256(value.encode()).hexdigest()}
    original = SourceFile(Path("classes.dex"), "classes.dex", "config", "prefix\n  " + encoded,
                          origin="strings")
    derived = SourceFile(Path("literal.txt"), "_decoded_literals/base64/fixture.txt", "config", value,
                         origin="decoded_literal", derivation=detail)
    return original, derived


def test_derived_provenance_round_trips_without_changing_original_lines(tmp_path):
    original, derived = sources()
    result = ScanResult("fixture.apk", decoded_files=build_previews([original, derived]))
    assert result.decoded_files[derived.rel].derivation == derived.derivation
    assert result.decoded_files[derived.rel].derivation is not derived.derivation
    store = Storage(str(tmp_path / "history.sqlite"))
    restored = store.load_scan(store.save_scan(result))
    assert restored.decoded_files[derived.rel].derivation == derived.derivation
    assert restored.decoded_files[derived.rel].lines == (derived.text,)
    assert restored.decoded_files[original.rel].lines == tuple(original.lines)
    assert restored.decoded_files[derived.rel].original is None


@pytest.mark.parametrize("patch", [
    {"source_file": "../secret.txt"}, {"source_file": "C:/private/file"},
    {"source_file": "/etc/file"}, {"source_file": "a\\..\\file"},
    {"source_file": "a\x00b"}, {"source_file": "x" * 1025},
    {"source_line": True}, {"source_column": 0}, {"source_end_column": 2},
    {"source_line": 1 << 31}, {"depth": True}, {"depth": 3},
    {"encoded_sha256": "not a digest"}, {"untrusted_extra": {"huge": "payload"}},
])
def test_malformed_provenance_is_rejected_by_archive_decoder(patch):
    _, source = sources()
    detail = {**source.derivation, **patch}
    with pytest.raises(ValueError):
        validate_derivation(detail)
    data = {"version": 1, "visible_apis": {}, "decoded_files": {
        source.rel: {"language": "config", "origin": "decoded_literal",
                     "source_line_count": 1, "lines": [source.text], "derivation": detail}}}
    with pytest.raises(ValueError):
        _decode_evidence(zlib.compress(json.dumps(data).encode()))


def test_legacy_archives_without_provenance_remain_readable():
    data = {"version": 1, "visible_apis": {}, "decoded_files": {
        "classes.dex": {"language": "config", "origin": "strings",
                        "source_line_count": 1, "lines": ["legacy"]}}}
    files, _ = _decode_evidence(zlib.compress(json.dumps(data).encode()))
    assert files["classes.dex"].derivation == {}


PREVIEW_APP = '''
import streamlit as st
from sca.decoded import DecodedFile
from sca.ui.decoded_panel import render_location
detail = {"encoding": "base64", "depth": 1, "source_file": "classes.dex",
          "source_line": 9, "source_column": 7, "source_end_column": 51,
          "encoded_sha256": "a" * 64, "decoded_sha256": "b" * 64}
def opened(path, line):
    st.session_state["opened"] = (path, line)
render_location("_decoded_literals/base64/fixture.txt", 1,
                DecodedFile("config", "decoded_literal", 1, ("FixtureOnlyCredential",), derivation=detail),
                lambda text: text, on_open=opened, key="fixture")
'''


def test_side_preview_labels_derivation_and_opens_encoded_location():
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_string(PREVIEW_APP).run()
    assert not app.exception
    assert any("not original source lines" in item.value for item in app.info)
    assert any("classes.dex" in item.value and "line 9" in item.value for item in app.text)
    next(button for button in app.button if button.label == "Open encoded source").click().run()
    assert not app.exception
    assert app.session_state["opened"] == ("classes.dex", 9)
    assert app.session_state["decoded_files_pending_column"] == 7
    assert app.session_state["decoded_files_pending_focus"] == (7, 51, "")


BROWSER_APP = '''
import streamlit as st
from sca.ui.decoded_panel import FileInfo, render
detail = {"encoding": "base64", "depth": 2, "source_file": "classes.dex",
          "source_line": 2, "source_column": 3, "source_end_column": 9,
          "encoded_sha256": "a" * 64, "decoded_sha256": "b" * 64}
files = {"_decoded_literals/base64/fixture.txt": FileInfo("config", "decoded_literal", 1, derivation=detail),
         "classes.dex": FileInfo("config", "strings", 2)}
lines = {"_decoded_literals/base64/fixture.txt": ["FixtureOnly"], "classes.dex": ["prefix", "  encoded"]}
render(files, lambda path, first, last: lines[path][first - 1:last], lambda text: text,
       scan_key="fixture", wide={})
'''


def test_file_browser_opens_original_encoded_line():
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_string(BROWSER_APP).run()
    assert not app.exception
    next(button for button in app.button if button.label == "Open encoded source").click().run()
    assert not app.exception
    assert app.selectbox[0].value == "classes.dex"
    assert next(item for item in app.number_input if item.label == "Jump to line").value == 2
