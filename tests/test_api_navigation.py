"""Navigate API inventory evidence from a locally scanned debug APK."""
from dataclasses import replace
from pathlib import Path

import pytest

from flutter_kit import build_apk
from sca.pipeline import ScanOptions, run_scan
from sca.storage import Storage

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402
from test_decoded_dashboard import _select_cell, _side_preview  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "https://api.navigation-test.example/v1/status"
ROUTE = "/api/v2/count"
DART_FILE = "dart/lib/main.dart"
BINARY_URL = "https://binary.navigation-test.example/status"


def _tab(app, label):
    return next(tab for tab in app.tabs if tab.label.startswith(label + " ("))


def _click_inventory_value(app, label, column, value):
    grid = _tab(app, label).dataframe[0]
    row, = grid.value.index[grid.value[column] == value]
    _select_cell(app, grid, int(row), column)
    return _tab(app, label)


def _check_location(tab, file, line):
    assert any(f"{file}:{line}</code>" in element.proto.body for element in tab.get("html"))
    markup = _side_preview(tab, line)
    assert any(b.label == "Browse decoded files" for b in tab.button)
    return markup


def test_click_api_evidence_and_browse_the_selected_occurrence(tmp_path, monkeypatch):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    st.cache_resource.clear()
    package = tmp_path / "navigation.apk"
    source = ("const marker = 'side-preview-marker';\n"
              "void refresh(dio) async {\n"
              "  await dio.get(\n"
              f"    '{ADDRESS}');\n"
              f"  await dio.post('{ROUTE}');\n"
              "}\n")
    query_value = "fixture-query-value-only"
    package.write_bytes(build_apk(mode="debug", dart_sources={"main.dart": source},
                                  assets={".env": f"# local config\nSTATUS={ADDRESS}\n"},
                                  dex_strings=[f"{BINARY_URL}?access_token={query_value}"]))
    options = ScanOptions(save=False, use_feedback=False, use_llm=False, use_ml=False,
                          use_gitleaks=False, use_semgrep=False, use_bandit=False, keep_decoded=True)
    result = run_scan(str(package), options)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.session_state["result"] = result
    app.run()
    assert not app.exception

    addresses = _click_inventory_value(app, "Server addresses", "Address", ADDRESS)
    assert ADDRESS in [block.value for block in addresses.code]
    location = next(p for p in addresses.selectbox if p.label == "Recorded locations")
    places = {("assets/.env", 2), (DART_FILE, 4)}
    assert location.value in places
    assert ADDRESS in _check_location(addresses, *location.value)
    other, = places - {location.value}
    location.set_value(other).run()
    addresses = _tab(app, "Server addresses")
    assert ADDRESS in _check_location(addresses, *other)

    archived_binary = next(e for e in result.app["apis"]["endpoints"] if e["url"].startswith(BINARY_URL))
    assert query_value not in archived_binary["url"]
    binary = next(e for e in result.visible_apis["endpoints"] if e["url"].startswith(BINARY_URL))
    assert binary["url"] == f"{BINARY_URL}?access_token={query_value}"
    addresses = _click_inventory_value(app, "Server addresses", "Address", binary["url"])
    location, = binary["locations"]
    assert location["file"] == "classes.dex"
    markup = _check_location(addresses, location["file"], location["line"])
    assert f"{BINARY_URL}?access_token={query_value}" in markup
    assert any("index the extracted strings" in c.value for c in addresses.caption)
    assert binary["url"] in [c.value for c in addresses.code]

    calls = _click_inventory_value(app, "API calls", "Target", ADDRESS)
    assert ADDRESS in [block.value for block in calls.code]
    markup = _check_location(calls, DART_FILE, 3)
    assert "side-preview-marker" in markup and ADDRESS in markup
    location = next(p for p in calls.selectbox if p.label == "Recorded locations")
    location.set_value((DART_FILE, 4)).run()
    _check_location(_tab(app, "API calls"), DART_FILE, 4)

    paths = _click_inventory_value(app, "API paths", "Path", ROUTE)
    assert ROUTE in [block.value for block in paths.code]
    assert ROUTE in _check_location(paths, DART_FILE, 5)
    next(b for b in paths.button if b.label == "Browse decoded files").click().run()
    assert not app.exception
    decoded = next(tab for tab in app.tabs if tab.label == "Decoded files")
    assert next(p for p in decoded.selectbox if p.label == "Decoded file").value == DART_FILE
    assert next(p for p in decoded.number_input if p.label == "Jump to line").value == 5

    store = Storage(str(tmp_path / "archive.sqlite"))
    app.session_state["result"] = store.load_scan(store.save_scan(result))
    app.run()
    paths = _click_inventory_value(app, "API paths", "Path", ROUTE)
    assert ROUTE in _check_location(paths, DART_FILE, 5)
    addresses = _click_inventory_value(app, "Server addresses", "Address", binary["url"])
    assert query_value in _check_location(addresses, binary["locations"][0]["file"],
                                           binary["locations"][0]["line"])

    # Older JSON-only records cannot reconstruct source values and explicitly request a rescan.
    legacy = replace(result, decoded_files={}, visible_apis={}, credential_evidence=None)
    app.session_state["result"] = store.load_scan(store.save_scan(legacy))
    app.run()
    paths = _click_inventory_value(app, "API paths", "Path", ROUTE)
    assert f"{DART_FILE}:5" in [block.value for block in paths.code]
    assert any("Run the scan again" in message.value for message in paths.info)
    assert all('aria-current="location"' not in el.proto.body for el in paths.get("html"))
