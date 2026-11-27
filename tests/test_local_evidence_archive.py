"""Offline evidence and stored locations on scanner-generated test data."""
import json
import re
import zipfile
from html import unescape
from pathlib import Path

import pytest

from flutter_kit import build_apk
from sca.decoded import CredentialEvidence, build_previews
from sca.models import ScanResult
from sca.pipeline import ScanOptions, run_scan
from sca.storage import Storage
from sca.walker import SourceFile


def _offline_scan(target, **overrides):
    return run_scan(str(target), ScanOptions(
        save=False, use_feedback=False, use_ml=False, use_llm=False, use_semgrep=False,
        use_gitleaks=False, use_bandit=False, keep_decoded=True, **overrides))


def test_local_comparison_is_scoped_to_one_file_line_and_rule(tmp_path):
    value = "faux-" + "a91c4c74D8Q7-retire-me"
    folder = tmp_path / "project"
    folder.mkdir()
    path = folder / "settings.py"
    source = f'# local configuration\nPAYMENT_HMAC_SECRET = "{value}"\n'
    path.write_text(source, encoding="utf-8")
    result = _offline_scan(folder)
    found = next(f for f in result.findings if f.rule_id == "SECRET-HARDCODED-001")
    assert found.file == "settings.py" and found.line == 2
    evidence = result.credential_evidence
    assert evidence.matches(found.file, 2, found.rule_id, value)
    assert not evidence.matches(found.file, 2, found.rule_id, value + " ")
    assert not evidence.at(found.file, 1, found.rule_id)
    assert not evidence.at(found.file, 2, "another-rule")
    assert "PAYMENT_HMAC_SECRET" in result.decoded_files[found.file].lines[1]
    assert result.decoded_files[found.file].lines == tuple(source.splitlines())
    saved = json.dumps(result.to_dict())
    assert value not in saved and "credential_evidence" not in saved
    original = result.decoded_files[found.file].original
    assert original.read_lines() == source.splitlines()
    path.write_text(source.replace("PAYMENT", "BILLING"), encoding="utf-8")
    assert original.read_lines() is None
    path.unlink()
    assert original.read_lines() is None


def test_archive_and_upload_previews_do_not_reopen_local_paths(tmp_path):
    contents = 'password = "archive-test-value"'
    path = tmp_path / "settings.py"
    path.write_text(contents, encoding="utf-8")
    archive = tmp_path / "project.zip"
    with zipfile.ZipFile(archive, "w") as packed:
        packed.writestr(path.name, contents)

    for result in (_offline_scan(archive), _offline_scan(path, target_label="uploaded source")):
        preview = result.decoded_files[path.name]
        assert preview.original is None
        assert preview.lines == (contents,)
    package = tmp_path / "example.apk"
    package.write_bytes(build_apk(mode="none"))
    previews = _offline_scan(package).decoded_files
    assert "AndroidManifest.xml" in previews
    assert all(preview.original is None for preview in previews.values())
    decoded = SourceFile(path, path.name, "python", contents, origin="decoded")
    assert build_previews([decoded], source_root=tmp_path)[path.name].original is None


def test_local_preview_checks_links_even_when_the_file_contents_match(tmp_path):
    source = tmp_path / "main.py"
    source.write_text("print(0)", encoding="utf-8")
    original = _offline_scan(source).decoded_files[source.name].original
    moved = source.rename(tmp_path / "other.py")
    try:
        source.symlink_to(moved)
    except OSError as exc:
        pytest.skip(f"File symlinks unavailable: {exc}")
    assert original.read_lines() is None


def test_finding_click_displays_the_original_local_line_and_checks_for_edits(tmp_path, monkeypatch):
    st = pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    monkeypatch.delenv("SCA_HOSTED", raising=False)
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    st.cache_resource.clear()
    path = tmp_path / "settings.py"
    value = "faux-" + "a91c4c74D8Q7-retire-me"
    line = f'PAYMENT_HMAC_SECRET = "{value}"  # <tag> &'
    long_line = "eval(input())  # " + " " * 1250 + "<end>"
    path.write_text(f"# first line\n{line}\n{long_line}\n", encoding="utf-8")
    result = _offline_scan(path)
    finding = next(f for f in result.findings if f.rule_id == "SECRET-HARDCODED-001")
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"), default_timeout=60)
    app.session_state["result"] = result
    app.run()
    assert not app.exception

    def selected_preview():
        current = next(tab for tab in app.tabs if tab.label == "Findings")
        return next(e.proto.body for e in current.get("html")
                    if 'aria-current="location"' in e.proto.body)

    tab = next(tab for tab in app.tabs if tab.label == "Findings")
    grid = tab.dataframe[0]
    row = next(i for i, title in enumerate(grid.value["Title"]) if title == finding.title)
    selection = {"cells": [[row, "Title"]]} if hasattr(grid.proto, "SINGLE_CELL") else {"rows": [row]}
    states = app._tree.get_widget_states()
    states.widgets.add(id=grid.proto.id, string_value=json.dumps({"selection": selection}))
    app._run(states)
    assert not app.exception
    markup = selected_preview()
    marked_line = re.search(r'aria-current="location"[^>]*>([^<]*)</span>', markup)
    assert marked_line and unescape(marked_line[1]).endswith(line)
    assert re.match(r"›\s*2\s", unescape(marked_line[1]))
    assert "&lt;tag&gt;" in markup and "<tag>" not in markup

    other_index = next(i for i, f in enumerate(result.findings) if f.line == 3)
    app.button(key=f"preview_finding_{other_index}").click().run()
    assert not app.exception
    markup = selected_preview()
    marked_line = re.search(r'aria-current="location"[^>]*>([^<]*)</span>', markup)
    assert marked_line and unescape(marked_line[1]).endswith(long_line)
    app.button(key=f"preview_finding_{result.findings.index(finding)}").click().run()
    current = next(tab for tab in app.tabs if tab.label == "Findings")
    next(b for b in current.button if b.label == "Browse source files").click().run()
    assert not app.exception
    file_tab = next(tab for tab in app.tabs if tab.label == "Source files")
    assert next(w for w in file_tab.selectbox if w.label == "Source file").value == path.name
    assert next(w for w in file_tab.number_input if w.label == "Jump to line").value == 2
    assert any(f"> 2  {line}" in code.value for code in file_tab.code)

    path.write_text("print('a different file')", encoding="utf-8")
    app.run()
    assert not app.exception
    assert any("original file changed" in warning.value.lower() for warning in app.warning)
    markup = selected_preview()
    assert value in markup and "a different file" not in markup


def test_two_detectors_on_one_line_and_python_multiline_literals():
    source = SourceFile(Path("sample.py"), "sample.py", "python",
                        'def load():\n    return """internal\nconfig words"""  # local note')
    source.secret_hits = [(2, "A", "first", "", "low"), (2, "B", "other", "", "medium")]
    evidence = CredentialEvidence([source])
    assert evidence.matches("sample.py", 2, "A", "first")
    assert not evidence.matches("sample.py", 2, "B", "first")
    lines = build_previews([source])["sample.py"].lines
    assert len(lines) == 3 and "def load()" in lines[0] and "return" in lines[1]
    assert lines == tuple(source.lines)


def test_archive_pages_search_literal_paths_and_reopen_snapshot(tmp_path):
    storage = Storage(str(tmp_path / "history.sqlite"))
    path = "D:/Release_10%/base.apk"
    for index in range(27):
        storage.save_scan(ScanResult(target=path, started_at=f"t{index}", score=index))
    storage.save_scan(ScanResult(target="D:/other", started_at="later", score=99))
    assert storage.count_scans() == 28 and storage.count_scans("_10%") == 27
    older = storage.list_scans(25, search="release_10%", offset=25)
    assert [s["id"] for s in older] == [2, 1]
    assert storage.load_scan(1).target == path
    assert storage.project_scores(path, 2) == [
        {"score": 25, "started_at": "t25"}, {"score": 26, "started_at": "t26"}]
