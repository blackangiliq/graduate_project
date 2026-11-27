"""Packaged findings open their actual source values without a second upload."""
import json
import re
from html import unescape
from pathlib import Path

import pytest

from flutter_kit import MANIFEST, build_apk, build_apk_set
from sca.decoded import build_previews
from sca.flutter.checks import MAPS_CLIENT_NOTE
from sca.pipeline import ScanOptions, run_scan
from sca.walker import SourceFile

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402
from test_decoded_dashboard import _select_cell, _side_preview  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("split", [False, True], ids=["apk", "split-apks"])
def test_package_click_displays_complete_manifest_value_without_source_upload(tmp_path, monkeypatch, split):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    st.cache_resource.clear()
    maps_key = "AIza" + "Q" * 35
    nearby_key = "AIza" + "P" * 35
    original = MANIFEST.replace("</application>", (
        f'<meta-data android:name="com.google.android.geo.API_KEY" android:value="{maps_key}"/>\n'
        f'<meta-data android:name="fixture.other" android:value="{nearby_key}"/>\n'
        '</application>'))
    package = tmp_path / ("original.apkm" if split else "original.apk")
    if split:
        member_manifest = original.replace("<manifest", '<manifest split="feature"', 1)
        package.write_bytes(build_apk_set({
            "base": build_apk(mode="none"),
            "split_feature": build_apk(mode="none", manifest=member_manifest),
        }, layout="apkm"))
    else:
        package.write_bytes(build_apk(mode="none", manifest=original))
    options = ScanOptions(save=False, use_feedback=False, use_llm=False, use_ml=False,
                          use_gitleaks=False, use_semgrep=False, use_bandit=False, keep_decoded=True)
    result = run_scan(str(package), options)
    finding = next(f for f in result.findings if f.description == MAPS_CLIENT_NOTE)
    if split:
        assert finding.file.startswith("splits/") and finding.file.endswith("/AndroidManifest.xml")
    else:
        assert finding.file == "AndroidManifest.xml"
    assert result.credential_evidence.matches(finding.file, finding.line, finding.rule_id, maps_key)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.session_state["result"] = result
    app.run()

    def findings_tab():
        return next(tab for tab in app.tabs if tab.label == "Findings")

    grid = findings_tab().dataframe[0]
    row, = grid.value.index[(grid.value["File"] == finding.file) & (grid.value["Line"] == finding.line)]
    _select_cell(app, grid, int(row), "Title")

    assert not app.exception
    markup = _side_preview(findings_tab(), finding.line)
    marked = re.search(r'aria-current="location"[^>]*>([^<]*)</span>', markup)[1]
    assert f'android:value="{maps_key}"' in marked
    assert markup.count(maps_key) == 1
    assert nearby_key in markup
    raw_markup = next(e.proto.body for e in findings_tab().get("html")
                      if 'aria-current="location"' in e.proto.body)
    assert "&quot;" in raw_markup and "<meta-data" not in raw_markup
    assert any(f"{finding.file}:{finding.line}</code>" in e.proto.body
               for e in findings_tab().get("html"))
    assert all(w.label != "Find the matching key in your source file"
               for w in findings_tab().get("file_uploader"))
    assert all(w.label != "Known value from your project" for w in findings_tab().text_input)
    assert maps_key not in json.dumps(app.session_state["result"].to_dict())
    next(b for b in findings_tab().button if b.label == "Browse decoded files").click().run()
    assert not app.exception
    decoded_tab = next(tab for tab in app.tabs if tab.label == "Decoded files")
    assert next(p for p in decoded_tab.selectbox if p.label == "Decoded file").value == finding.file
    assert next(p for p in decoded_tab.number_input if p.label == "Jump to line").value == finding.line
    assert any(f'android:value="{maps_key}"' in c.value for c in decoded_tab.code)


@pytest.mark.parametrize("origin", ["decoded", "decompiled", "recovered", "strings"])
def test_packaged_selected_line_is_complete_and_html_escaped(origin):
    path = "splits/feature.apk/assets/config.xml"
    value = "fixture-secret-at-line-end"
    selected = 'setting = "' + "x" * 1250 + f'{value}<script>alert(0)</script> &"'
    source = SourceFile(Path(path), path, "config", "# first\n" + selected, origin=origin)
    app = AppTest.from_string('''
import streamlit as st
from sca.ui.decoded_panel import render_location
render_location("splits/feature.apk/assets/config.xml", 2, st.session_state["file"],
                lambda text: text, on_open=lambda path, line: None, key="open_file")
''')
    app.session_state["file"] = build_previews([source])[path]
    app.run()
    assert not app.exception
    markup = next(e.proto.body for e in app.get("html") if 'aria-current="location"' in e.proto.body)
    marked = re.search(r'aria-current="location"[^>]*>([^<]*)</span>', markup)[1]
    assert unescape(marked).endswith(selected)
    assert re.match(r"›\s*2\s", unescape(marked))
    assert value in markup
    assert "&lt;script&gt;" in markup and "<script>" not in markup
    assert any(f"{path}:2</code>" in e.proto.body for e in app.get("html"))
