"""Derived text is real decoded evidence, never an invented original-source location."""
import base64
import hashlib
from pathlib import Path

import pytest

from sca import encoded
from sca.engines import secrets
from sca.flutter.context import AI_ORIGINS, KLOC_ORIGINS, RULES_ORIGINS
from sca.pipeline import ScanOptions, run_scan, scan_project
from sca.storage import Storage
from sca.walker import SourceFile

KEY = "AIza" + "M" * 35


def enc(text):
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize("depth", [1, 2])
def test_encoded_provider_value_and_its_actual_source_coordinates(depth):
    value = KEY
    for _ in range(depth):
        value = enc(value)
    sf = SourceFile(Path("classes.dex"), "classes.dex", "config", "before\n  " + value + "\nafter",
                    origin="strings")
    files, coverage = encoded.recover([sf])
    recovered, = files
    assert recovered.text == KEY and recovered.origin == "decoded_literal"
    assert recovered.origin not in RULES_ORIGINS + KLOC_ORIGINS + AI_ORIGINS
    ref = recovered.derivation
    assert ref["depth"] == depth and ref["source_file"] == sf.rel and ref["source_line"] == 2
    assert sf.lines[1][ref["source_column"] - 1:ref["source_end_column"] - 1] == value
    assert ref["encoded_sha256"] == hashlib.sha256(value.encode()).hexdigest()
    assert ref["decoded_sha256"] == hashlib.sha256(KEY.encode()).hexdigest()
    finding, = secrets.scan_file(recovered)
    assert finding.file == recovered.rel and finding.line == 1
    assert coverage["decoded_files"] == 1 and not coverage["limits_reached"]


def test_encoded_url_is_retained_but_ordinary_prose_and_binary_are_not():
    url = "https://api.example.invalid/v1/status"
    values = [enc(url), enc("Ordinary explanatory text without any credential"),
              base64.b64encode(bytes(range(256))).decode()]
    sf = SourceFile(Path("config.json"), "config.json", "config", "\n".join(values))
    files, _ = encoded.recover([sf])
    assert [f.text for f in files] == [url]


def test_no_fragment_is_decoded_from_an_oversized_base64_token():
    sf = SourceFile(Path("data.txt"), "data.txt", "config", "A" * (encoded.MAX_TOKEN + 10) + enc(KEY))
    assert encoded.recover([sf])[0] == []


def test_repeated_values_keep_both_encoded_source_occurrences():
    value = enc(KEY)
    sf = SourceFile(Path("a.json"), "a.json", "config", f'"{value}" "{value}"')
    files, _ = encoded.recover([sf])
    assert len(files) == 2 and files[0].rel != files[1].rel
    assert {f.derivation["source_column"] for f in files} == {2, len(value) + 5}


def test_budget_exhaustion_is_explicit_and_no_value_is_truncated(monkeypatch):
    monkeypatch.setattr(encoded, "MAX_DECODED_BYTES", 10)
    sf = SourceFile(Path("a.json"), "a.json", "config", enc(KEY))
    files, coverage = encoded.recover([sf])
    assert files == [] and coverage["limits_reached"] == ["derived_evidence_limit"]


def test_real_pipeline_and_archive_preserve_derived_value_and_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    project = tmp_path / "source"
    project.mkdir()
    (project / "config.json").write_text('{"encoded": "' + enc(KEY) + '"}', encoding="utf-8")
    result = run_scan(str(project), ScanOptions(
        save=False, use_ml=False, use_llm=False, use_feedback=False, keep_decoded=True,
        use_bandit=False, use_semgrep=False, use_gitleaks=False))
    item, = [k for k in result.visible_apis["keys"] if k["value"] == KEY]
    loc = item["locations"][0]
    file = result.decoded_files[loc["file"]]
    assert file.origin == "decoded_literal" and file.lines[loc["line"] - 1] == KEY
    assert file.derivation["source_file"] == "config.json"
    store = Storage(str(tmp_path / "archive.sqlite"))
    restored = store.load_scan(store.save_scan(result))
    assert restored.decoded_files[loc["file"]].derivation == file.derivation
    assert restored.visible_apis["keys"][0]["value"] == KEY


def test_encoded_credential_is_masked_for_analysis_but_retained_in_local_preview(tmp_path):
    value = enc(KEY)
    (tmp_path / "config.json").write_text('{"encoded": "' + value + '"}', encoding="utf-8")
    result, files = scan_project(str(tmp_path), ScanOptions(
        save=False, use_ml=False, use_llm=False, use_feedback=False, keep_decoded=True,
        use_bandit=False, use_semgrep=False, use_gitleaks=False))
    original = next(sf for sf in files if sf.rel == "config.json")
    assert value not in original.line_text(1)
    assert value in result.decoded_files["config.json"].lines[0]
