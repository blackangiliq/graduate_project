"""Exercise APK preview navigation with invented values and a reserved domain."""
import json
import re
from html import unescape
from pathlib import Path

import pytest

from flutter_kit import MANIFEST, build_apk, build_apk_set
from sca import decoded
from sca.flutter.checks import MAPS_CLIENT_FIX, MAPS_CLIENT_NOTE
from sca.flutter.context import ORIGIN_DECODED, ORIGIN_DECOMPILED
from sca.storage import Storage
from sca.walker import SourceFile, mask_secret

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FAKE_KEY = "faux-" + "a91c4c74D8Q7" + "-retire-me"
FAKE_ENDPOINT = "https://api.decoded-test.example/v1/health"
UNRECOGNIZED = ("fixtureSegmentOne", "fixtureSegmentTwo")


@pytest.mark.parametrize("rel,language,origin,contents,marker", [
    ("jadx/Example.java", "java", ORIGIN_DECOMPILED,
     f'String known = "{FAKE_KEY}";\n'
     'String unknown = """\n' + "\n".join(UNRECOGNIZED) + '\n""";\n'
     "int lineAfter;\n",
     "int lineAfter;"),
    ("res/xml/example.xml", "config", ORIGIN_DECODED,
     f"<settings>\n  <known>{FAKE_KEY}</known>\n"
     "  <unknown>\n" + "\n".join(UNRECOGNIZED) + "\n  </unknown>\n</settings>\n",
     "</settings>"),
])
def test_decoded_preview_keeps_multiline_values_at_their_scanned_lines(rel, language, origin,
                                                              contents, marker):
    source = SourceFile(Path(rel), rel, language, contents, origin=origin,
                        secret_values=[FAKE_KEY])
    preview = decoded.build_previews([source])[rel]
    assert preview.lines == tuple(contents.splitlines())
    assert len(preview.lines) == len(source.lines)
    assert preview.lines[source.lines.index(marker)] == marker


@pytest.mark.parametrize("rel,language,origin,contents", [
    pytest.param("assets/example.html", "html", ORIGIN_DECODED,
                 f"<form>\n<input value={UNRECOGNIZED[0]}>\n</form>\n",
                 id="html-unquoted"),
    pytest.param("jadx/Example.java", "java", ORIGIN_DECOMPILED,
                 "long fixturePin = 9182736450123L;\nreturn fixturePin;\n",
                 id="java-number"),
    pytest.param("assets/example.cpp", "cpp", ORIGIN_DECODED,
                 'const char* demo = R"fixture(\n' + "\n".join(UNRECOGNIZED) + '\n)fixture";\n',
                 id="cpp-opaque"),
    pytest.param("lib/example.dart", "dart", "recovered",
                 "final demo = 'outer ${wrap('fixtureSegmentOne')}';\n",
                 id="dart-interpolation"),
    pytest.param("jadx/Example.java", "java", ORIGIN_DECOMPILED,
                 r"String demo = \u0022fixtureSegmentOne\u0022;",
                 id="java-escaped-delimiters"),
])
def test_preview_preserves_original_literal_syntax(rel, language, origin, contents):
    source = SourceFile(Path(rel), rel, language, contents, origin=origin)
    preview = decoded.build_previews([source])[rel]
    assert preview.lines == tuple(contents.splitlines())
    assert preview.source_line_count == len(contents.splitlines())


def test_preview_limit_preserves_source_lines_without_rewriting_values(monkeypatch):
    rel = "res/xml/truncated.xml"
    contents = ("<settings>\n"
                f'<item fixture="{UNRECOGNIZED[0]}\n'
                f"{UNRECOGNIZED[1]}\n"
                'more fixture text"/>\n'
                "</settings>\n")
    source = SourceFile(Path(rel), rel, "config", contents, origin=ORIGIN_DECODED)
    monkeypatch.setattr(decoded, "MAX_PREVIEW_LINES", 3)

    preview = decoded.build_previews([source])[rel]

    assert preview.lines == tuple(contents.splitlines()[:3])
    assert preview.source_line_count == 5


def test_preview_keeps_many_short_literals_within_character_budget(monkeypatch):
    rel = "jadx/Example.java"
    source = SourceFile(Path(rel), rel, "java", "'' " * 90, origin=ORIGIN_DECOMPILED)
    monkeypatch.setattr(decoded, "MAX_PREVIEW_CHARS", 300)
    preview = decoded.build_previews([source])[rel]
    assert preview.lines == (source.text,)


def _side_preview(tab, line: int) -> str:
    markup = next(
        element.proto.body
        for column in tab.columns
        for element in column.get("html")
        if 'aria-current="location"' in element.proto.body
    )
    marked_line = re.search(r'<span\b[^>]*aria-current="location"[^>]*>([^<]*)</span>', markup)
    assert marked_line is not None
    assert re.search(rf"›\s*{line}\b", unescape(marked_line[1]))
    return unescape(markup)


def _select_cell(app, grid, row: int, column: str) -> None:
    # AppTest has no public dataframe-selection gesture. Deliver the browser event.
    if hasattr(grid.proto, "SINGLE_CELL"):
        assert list(grid.proto.selection_mode) == [grid.proto.SINGLE_CELL]
        selection = {"cells": [[row, column]]}
    else:
        selection = {"rows": [row]}
    states = app._tree.get_widget_states()
    states.widgets.add(id=grid.proto.id, string_value=json.dumps({"selection": selection}))
    app._run(states)
    assert not app.exception


def test_dashboard_opens_actual_decoded_values_and_restores_archive(tmp_path, monkeypatch):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    # get_storage() must use this test's database even after another AppTest ran.
    st.cache_resource.clear()

    dummy_maps = "AIza" + "Z" * 35
    manifest = MANIFEST.replace("</application>", '<meta-data android:name="com.google.android.geo.API_KEY" '
                                f'android:value="{dummy_maps}"/></application>')
    apk = build_apk(mode="none", manifest=manifest, assets={
        ".env": "# Synthetic settings\n"
                f"PAYMENT_HMAC_SECRET={FAKE_KEY}\n"
                f"API_URL={FAKE_ENDPOINT}\n",
        "note.txt": f"Copied config marker: {FAKE_KEY}\n",
    })
    package = tmp_path / "preview-example.apks"
    package.write_bytes(build_apk_set({"base": apk}))

    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=180).run()
    app.text_input(key="target").set_value(str(package))
    next(button for button in app.button if button.label == "Run scan").click().run()
    assert not app.exception

    result = app.session_state["result"]
    inventory = result.visible_apis
    key = next(item for item in inventory["keys"] if item["value"] == FAKE_KEY)
    assert any(item["value"] == mask_secret(FAKE_KEY) for item in result.app["apis"]["keys"])
    endpoint = next(item for item in inventory["endpoints"] if item["url"] == FAKE_ENDPOINT)
    assert (key["locations"][0]["file"], key["locations"][0]["line"]) == ("assets/.env", 2)
    assert (endpoint["locations"][0]["file"], endpoint["locations"][0]["line"]) == ("assets/.env", 3)

    # Preview a key without leaving the dashboard.
    keys_tab = next(tab for tab in app.tabs if tab.label == f"Keys ({len(inventory['keys'])})")
    grid = keys_tab.dataframe[0]
    row = int(grid.value.index[grid.value["Value"] == key["value"]][0])
    _select_cell(app, grid, row, "Type")
    keys_tab = next(tab for tab in app.tabs if tab.label == f"Keys ({len(inventory['keys'])})")
    assert "PAYMENT_HMAC_SECRET=" in _side_preview(keys_tab, 2)
    location_picker = next(widget for widget in keys_tab.selectbox
                           if widget.label == "Key location in decoded files")
    app.session_state["main_tabs_en"] = "Dashboard"
    location_picker.set_value(("assets/.env", 2)).run()
    assert not app.exception
    assert app.session_state["main_tabs_en"] == "Dashboard"
    dashboard = next(tab for tab in app.tabs if tab.label == "Dashboard")
    markup = _side_preview(dashboard, 2)
    assert "PAYMENT_HMAC_SECRET=" in markup
    assert FAKE_KEY in markup and FAKE_ENDPOINT in markup
    assert any("Credential match · Hard-coded credential" in m.value for m in dashboard.markdown)

    assert all(w.label != "Known value from your project" for w in dashboard.text_input)

    # The dedicated file browser can still open the selected key.
    keys_tab = next(tab for tab in app.tabs if tab.label == f"Keys ({len(inventory['keys'])})")
    next(button for button in keys_tab.button
         if button.label == "Open decoded location").click().run()
    assert not app.exception
    decoded_tab = next(tab for tab in app.tabs if tab.label == "Decoded files")
    file_picker = next(widget for widget in decoded_tab.selectbox if widget.label == "Decoded file")
    assert file_picker.value == "assets/.env"
    line_picker = next(widget for widget in decoded_tab.number_input
                       if widget.label == "Jump to line")
    assert line_picker.value == 2
    preview = "\n".join(block.value for block in decoded_tab.code)
    assert "PAYMENT_HMAC_SECRET=" in preview and "API_URL=" in preview
    assert FAKE_KEY in preview and FAKE_ENDPOINT in preview

    file_filter = next(widget for widget in decoded_tab.text_input
                       if widget.label == "Filter decoded files")
    file_filter.set_value("note.txt").run()
    assert not app.exception
    decoded_tab = next(tab for tab in app.tabs if tab.label == "Decoded files")
    assert next(widget for widget in decoded_tab.selectbox
                if widget.label == "Decoded file").value == "assets/note.txt"
    preview = "\n".join(block.value for block in decoded_tab.code)
    assert FAKE_KEY in preview

    # Preview a separate finding at its manifest line without leaving Findings.
    index, finding = next((index, item) for index, item in enumerate(result.findings)
                          if item.rule_id == "ANDROID-MANIFEST-003")
    assert finding.file == "AndroidManifest.xml"
    app.session_state["main_tabs_en"] = "Findings"
    app.button(key=f"preview_finding_{index}").click().run()
    assert not app.exception
    assert app.session_state["main_tabs_en"] == "Findings"
    findings_tab = next(tab for tab in app.tabs if tab.label == "Findings")
    markup = _side_preview(findings_tab, finding.line)
    assert "allowBackup" in markup
    assert FAKE_KEY not in markup

    maps_index, maps = next((i, f) for i, f in enumerate(result.findings)
                            if f.description == MAPS_CLIENT_NOTE)
    app.button(key=f"preview_finding_{maps_index}").click().run()
    assert not app.exception
    findings_tab = next(tab for tab in app.tabs if tab.label == "Findings")
    markup = _side_preview(findings_tab, maps.line)
    assert f'android:value="{dummy_maps}"' in markup
    assert "**Credential match · Google Maps Android client key**" in {
        item.value for item in findings_tab.markdown}
    assert any(MAPS_CLIENT_FIX in m.value for m in findings_tab.markdown)
    assert any(f'AndroidManifest.xml:{maps.line}</code>' in e.proto.body
               for e in findings_tab.get("html"))

    # A filtered table row must open its underlying finding, not the unfiltered row.
    search = next(w for w in findings_tab.text_input if w.label.startswith("Search"))
    search.set_value(maps.title).run()
    findings_tab = next(tab for tab in app.tabs if tab.label == "Findings")
    grid = findings_tab.dataframe[0]
    rows = grid.value
    row = int(rows.index[(rows["File"] == maps.file) & (rows["Line"] == maps.line)][0])
    _select_cell(app, grid, row, "Title")
    assert app.session_state["finding_file_preview"] == (maps_index, "table")
    findings_tab = next(tab for tab in app.tabs if tab.label == "Findings")
    assert dummy_maps in _side_preview(findings_tab, maps.line)

    detail = next(e for e in findings_tab.expander if maps.title in e.label)
    if getattr(detail.proto, "id", ""):
        states = app._tree.get_widget_states()
        states.widgets.add(id=detail.proto.id, bool_value=True)
        app._run(states)
        assert not app.exception
        assert app.session_state["finding_file_preview"] == (maps_index, "detail")
        detail = next(e for e in app.expander if maps.title in e.label)
        assert dummy_maps in _side_preview(detail, maps.line)

    assert "decoded_files" not in result.to_dict()
    assert "visible_apis" not in result.to_dict()
    exported = json.dumps(result.to_dict())
    assert FAKE_KEY not in exported and dummy_maps not in exported
    assert result.scan_id is not None
    stored = Storage().load_scan(result.scan_id)
    assert stored is not None
    assert stored.decoded_files["assets/.env"].lines == result.decoded_files["assets/.env"].lines
    assert stored.visible_apis == result.visible_apis
    assert all(file.original is None for file in stored.decoded_files.values())
