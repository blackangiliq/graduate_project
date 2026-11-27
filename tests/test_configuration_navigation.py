"""Service identifiers and environment entries open their actual retained source."""
from pathlib import Path

import pytest

from flutter_kit import build_apk
from sca.pipeline import ScanOptions, run_scan
from sca.ui.app_panel import _endpoint_rows
from test_api_navigation import _click_inventory_value, _check_location

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest


def test_configuration_and_environment_values_navigate_to_exact_source(tmp_path, monkeypatch):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    st.cache_resource.clear()
    config_value = "test-project-navigation-only"
    secret_value = "V7cN9dP2sR4uX6zA8bE3hK5m"
    package = tmp_path / "configuration.apk"
    package.write_bytes(build_apk(strings={"project_id": config_value},
                                  assets={".env": "# fixture\nACCESS_TOKEN=" + secret_value + "\n"}))
    result = run_scan(str(package), ScanOptions(
        save=False, use_feedback=False, use_llm=False, use_ml=False,
        use_gitleaks=False, use_semgrep=False, use_bandit=False, keep_decoded=True))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=120)
    app.session_state["result"] = result
    app.run()
    assert not app.exception
    config = next(c for c in result.visible_apis["config"] if c["value"] == config_value)
    # Firebase's summary table is intentionally read-only; use the selectable source
    # inventory below it rather than confusing that summary with the evidence rows.
    from test_decoded_dashboard import _select_cell
    tab = next(t for t in app.tabs if t.label.startswith("Service IDs"))
    grid = next(g for g in tab.dataframe if list(g.proto.selection_mode))
    row = grid.value.index[grid.value["Value"] == config_value][0]
    _select_cell(app, grid, int(row), "Value")
    tab = next(t for t in app.tabs if t.label.startswith("Service IDs"))
    loc = config["locations"][0]
    assert config_value in _check_location(tab, loc["file"], loc["line"])
    tab = _click_inventory_value(app, ".env entries", "Value", secret_value)
    assert secret_value in _check_location(tab, "assets/.env", 2)
    assert secret_value in [block.value for block in tab.code]


def test_endpoint_table_distinguishes_runtime_templates_from_literals():
    rows = _endpoint_rows([{"url": "https://{region}.example.invalid/api",
                            "requires_runtime_resolution": True},
                           {"url": "https://api.example.invalid/v1"}], lambda value: value)
    assert rows[0]["Evidence"] == "URL template"
    assert rows[1]["Evidence"] == "URL literal"
