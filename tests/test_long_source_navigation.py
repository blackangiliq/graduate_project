"""Navigate a real-sized single source line without losing the selected evidence."""
from html import unescape
from pathlib import Path

import pytest

from sca.decoded import build_previews
from sca.models import Finding, ScanResult
from sca.presentation import finding_text
from sca.storage import Storage
from sca.walker import SourceFile

st = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402
from test_decoded_dashboard import _select_cell  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FILE = "assets/index.android.bundle"


def _result(value=None):
    # This fixture tests navigation and display only, not the secret detector. Repeating
    # the same value makes an incorrect jump to its first occurrence observable.
    value = value or "AIza" + "NavigationFixture9".ljust(35, "Q")
    line = ('const earlier_key="' + value + '";' + " " * 100_000
            + 'const selected_key="' + value + '";const tail="<script>literal</script> & end";')
    source = "// bundle source\n" + line
    column = line.index(value, 90_000) + 1
    finding = Finding("SECRET-GOOGLE-001", "Google API key", FILE, 2,
                      severity="high", cwe="CWE-798", engines=["secrets"],
                      language="javascript", column=column, end_column=column + len(value),
                      snippet="const selected_key=***;", context="const selected_key=***;")
    file = SourceFile(Path(FILE), FILE, "javascript", source, origin="decoded")
    result = ScanResult("fixture.apk", findings=[finding], files_scanned=1,
                        lines_scanned=2, languages={"javascript": 1},
                        app={"kind": "apk", "apk_file_members": {FILE: "base.apk"}},
                        decoded_files=build_previews([file]), visible_apis={
                            "values_visible": True,
                            "summary": {"keys": 1},
                            "keys": [{"value": value, "rule_id": finding.rule_id,
                                      "type": "Google API key", "cwe": "CWE-798",
                                      "locations": [{"file": FILE, "line": 2}]}],
                        })
    return result, source, value, column


def test_recorded_column_wins_over_another_key_on_the_same_source_line():
    result, source, value, _ = _result()
    another = "AIza" + "DifferentFixture7".ljust(35, "P")
    changed = source.replace(value, another, 1)
    file = SourceFile(Path(FILE), FILE, "javascript", changed, origin="decoded")
    result.decoded_files = build_previews([file])
    selected = result.visible_apis["keys"][0]
    result.visible_apis["keys"] = [{**selected, "value": another}, selected]
    shown = finding_text(result, result.findings[0], context=False)
    assert value in shown and "selected_key" in shown
    assert another not in shown and "earlier_key" not in shown


@pytest.mark.parametrize("archived,long_value", [(False, False), (True, False), (True, True)],
                         ids=["fresh", "reopened-history", "16k-value-from-history"])
def test_long_bundle_finding_opens_exact_column_and_downloads_full_source(tmp_path, monkeypatch,
                                                                       archived, long_value):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    st.cache_resource.clear()
    result, source, value, column = _result("LongFixture9" * 1365 if long_value else None)
    fingerprint = result.findings[0].fingerprint
    if archived:
        storage = Storage(str(tmp_path / "history.db"))
        result = storage.load_scan(storage.save_scan(result))
        assert result.findings[0].column == column
        assert result.findings[0].end_column == column + len(value)
        assert result.findings[0].fingerprint == fingerprint
        assert result.decoded_files[FILE].original is None

    downloads = []
    original_download = st.download_button

    def capture_file_download(label, data, *args, **kwargs):
        if label == "Download this file":
            downloads.append((kwargs.get("file_name"), data))
        return original_download(label, data, *args, **kwargs)

    monkeypatch.setattr(st, "download_button", capture_file_download)
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.session_state["result"] = result
    app.run()
    assert not app.exception

    def tab(label):
        return next(t for t in app.tabs if t.label == label)

    findings = tab("Findings")
    _select_cell(app, findings.dataframe[0], 0, "Title")
    findings = tab("Findings")
    markup = next(e.proto.body for e in findings.get("html")
                  if 'aria-current="location"' in e.proto.body)
    shown = unescape(markup)
    assert value in shown and "selected_key" in shown
    assert "earlier_key" not in shown
    assert "<script>" not in markup and "&lt;script&gt;" in markup
    assert len(markup) < max(12_000, len(value) + 2000)
    assert any("Showing columns" in c.value and str(len(source.splitlines()[1])) in c.value
               for c in findings.caption)

    next(b for b in findings.button if b.label == "Browse decoded files").click().run()
    assert not app.exception
    browser = tab("Decoded files")
    assert next(s for s in browser.selectbox if s.label == "Decoded file").value == FILE
    assert next(n for n in browser.number_input if n.label == "Jump to line").value == 2
    jump = next(n for n in browser.number_input if n.label == "Jump to column")
    assert jump.value == column
    assert any(value in code.value and "selected_key" in code.value for code in browser.code)
    assert downloads[-1] == ("index.android.bundle", source)

    jump.set_value(1).run()
    assert not app.exception
    browser = tab("Decoded files")
    assert any("earlier_key" in code.value for code in browser.code)
    assert all("selected_key" not in code.value for code in browser.code)
    assert downloads[-1][1] == source


def test_endpoint_row_focuses_its_original_column_in_a_large_archived_bundle(tmp_path, monkeypatch):
    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    st.cache_resource.clear()
    result, source, _, _ = _result()
    url = "https://long-navigation.example/api/v2/status?token=fixture-only-7&mode=full"
    source += f'const endpoint_url="{url}";'
    file = SourceFile(Path(FILE), FILE, "javascript", source, origin="decoded")
    result.decoded_files = build_previews([file])
    result.visible_apis["summary"]["endpoints"] = 1
    result.visible_apis["endpoints"] = [{"url": url, "count": 1,
                                        "locations": [{"file": FILE, "line": 2}]}]
    storage = Storage(str(tmp_path / "history.db"))
    restored = storage.load_scan(storage.save_scan(result))
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.session_state["result"] = restored
    app.run()
    assert not app.exception
    addresses = next(t for t in app.tabs if t.label == "Server addresses (1)")
    _select_cell(app, addresses.dataframe[0], 0, "Address")
    addresses = next(t for t in app.tabs if t.label == "Server addresses (1)")
    markup = next(e.proto.body for e in addresses.get("html")
                  if 'aria-current="location"' in e.proto.body)
    assert url in unescape(markup)
    assert "endpoint_url" in markup and "earlier_key" not in markup
    assert "&amp;mode=full" in markup
    next(b for b in addresses.button if b.label == "Browse decoded files").click().run()
    assert not app.exception
    browser = next(t for t in app.tabs if t.label == "Decoded files")
    expected_column = source.splitlines()[1].index(url) + 1
    assert next(n for n in browser.number_input if n.label == "Jump to column").value == expected_column
    assert any(url in c.value for c in browser.code)
