"""Original UI/export evidence must not change analysis, feedback or archive identities."""
import json
import re
import zlib
from html import escape

import pytest

from sca.decoded import DecodedFile
from sca.models import Finding, ScanResult
from sca.pipeline import Message, ScanOptions, run_scan
from sca.presentation import finding_text, view_result
from sca.report.html_report import api_tables, render_html
from sca.report.pdf_report import render_pdf
from sca.report.sarif import to_sarif
from sca.storage import Storage


def _pdf_text(pdf):
    streams = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
        try:
            streams.append(zlib.decompress(match.group(1)))
        except zlib.error:
            streams.append(match.group(1))
    return b"\n".join(streams).decode("latin-1")


@pytest.fixture
def scanned():
    value = "fixture-" + "ab3F9x7Q_" * 160 + "-complete-value-tail"
    line = '  API_TOKEN = "%s"; marker = "<script>alert(17)</script>"' % value
    finding = Finding("SECRET-HARDCODED-001", "Hard-coded credential", "settings.py", 2,
                      cwe="CWE-798", snippet='API_TOKEN = "fixt***tail"',
                      context='   2 | API_TOKEN = "fixt***tail"',
                      language="python", engines=["secrets"], risk_score=7.5)
    raw_apis = {"values_visible": True, "summary": {"keys": 1, "endpoints": 1},
                "keys": [{"type": "Fixture token", "value": value, "severity": "high",
                          "locations": [{"file": finding.file, "line": 2}]}],
                "endpoints": [{"url": "https://api.example.test/data?token=" + value}]}
    original = ScanResult("fixture.apk", findings=[finding],
                          ai={"llm": "switched off"}, engines_used=["secrets"],
                          app={"kind": "apk", "apis": {"keys": [{"value": "fixt***tail"}]}},
                          decoded_files={finding.file: DecodedFile(
                              "python", "decoded", 3, ("# settings", line, "enabled = True"))},
                          visible_apis=raw_apis)
    return original, value, line


def test_original_export_keeps_complete_value_identity_and_escaped_html(scanned):
    original, value, line = scanned
    saved_before = json.dumps(original.to_dict(), sort_keys=True)
    view = view_result(original)
    finding = view.findings[0]
    assert finding.snippet == line
    assert finding.context == "   1 | # settings\n   2 | %s\n   3 | enabled = True" % line
    assert finding.fingerprint == original.findings[0].fingerprint
    exported = view.to_dict()
    assert exported["findings"][0]["fingerprint"] == original.findings[0].fingerprint
    assert value in json.dumps(exported)
    assert not {"decoded_files", "visible_apis", "credential_evidence"} & exported.keys()
    assert "_source_fingerprint" not in exported["findings"][0]
    assert not view.decoded_files and not view.visible_apis and view.credential_evidence is None
    sarif = to_sarif(view)["runs"][0]["results"][0]
    assert sarif["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == line
    assert sarif["partialFingerprints"]["scaFingerprint/v1"] == original.findings[0].fingerprint
    html = render_html(view)
    assert escape(line) in html and value in html
    assert "<script>alert(17)</script>" not in html
    assert "Original values are shown" in html
    assert "Keys are masked" not in html and "passwords (masked)" not in html
    assert json.dumps(original.to_dict(), sort_keys=True) == saved_before


def test_presentation_copy_does_not_modify_model_inputs_or_saved_scan(scanned, tmp_path):
    original, value, _ = scanned
    before = original.to_dict()
    view = view_result(original)
    view.findings[0].engines.append("display-only")
    view.ai["llm"] = "display-only"
    view.app["apis"]["keys"][0]["value"] = "display-only"
    assert original.to_dict() == before
    assert original.visible_apis["keys"][0]["value"] == value
    storage = Storage(str(tmp_path / "history.sqlite"))
    restored = storage.load_scan(storage.save_scan(original))
    assert restored.findings[0].fingerprint == original.findings[0].fingerprint
    assert value not in json.dumps(restored.to_dict())
    assert restored.ai == {"llm": "switched off"}


def test_archived_or_out_of_snapshot_locations_keep_actual_stored_evidence(scanned):
    original, _, _ = scanned
    original.decoded_files.clear()
    original.visible_apis.clear()
    archived = view_result(original)
    assert finding_text(original, original.findings[0]) == original.findings[0].context
    assert archived.to_dict() == original.to_dict()
    original.decoded_files["settings.py"] = DecodedFile("python", "decoded", 3, ("# only",))
    assert finding_text(original, original.findings[0], context=False) == original.findings[0].snippet


def test_fresh_pipeline_scan_exports_progress_messages(tmp_path):
    path = tmp_path / "settings.py"
    value = "fixture-only-F7r39xQa1KqZm-retired"
    path.write_text('API_SECRET = "%s"\n' % value, encoding="utf-8")
    result = run_scan(str(path), ScanOptions(
        save=False, use_feedback=False, use_ml=False, use_llm=False, use_semgrep=False,
        use_gitleaks=False, use_bandit=False, keep_decoded=True))
    assert result.steps and isinstance(result.steps[0], Message)
    original_step = result.steps[0]
    view = view_result(result)
    assert view.steps == [str(step) for step in result.steps]
    assert all(type(step) is str for step in view.steps)
    assert result.steps[0] is original_step
    assert original_step.kind and original_step.template
    assert value in json.dumps(view.to_dict())
    assert "kind" not in view.app and view.app.get("apis")
    html = render_html(view)
    assert value in html and "APIs and keys" in html
    assert "App package" not in html and "Mobile project" not in html
    assert "OWASP Mobile" not in html and "MASVS groups" not in html
    assert value in json.dumps(to_sarif(view))
    pdf = render_pdf(view)
    assert pdf.startswith(b"%PDF-")
    pdf_content = _pdf_text(pdf)
    assert "APIs and keys" in pdf_content
    assert "App facts" not in pdf_content and "OWASP Mobile" not in pdf_content


@pytest.mark.parametrize(("collection", "field", "title", "column"), [
    ("keys", "value", "Keys, tokens and passwords", 2),
    ("endpoints", "url", "Server addresses", 0),
    ("calls", "target", "API calls in the code", 1),
    ("paths", "path", "API paths", 0),
    ("config", "value", "Service identifiers", 1),
    ("env", "value", ".env entries", 3),
])
def test_original_inventory_table_keeps_entire_values(collection, field, title, column):
    value = "test-value-" + "u1Q4x9" * 150 + "-end"
    apis = {"values_visible": True, collection: [{field: value}]}
    rows = next(rows for name, _, rows in api_tables(apis) if name == title)
    assert rows[0][column] == value
    apis.pop("values_visible")
    masked_rows = api_tables(apis)[0][2]
    assert masked_rows[0][column] == value[:600] + "..."


def test_original_pdf_keeps_evidence_after_old_character_limits(scanned):
    original, _, _ = scanned
    pdf = render_pdf(view_result(original))
    content = _pdf_text(pdf)
    assert "complete-value-tail" in content
    assert "Original values are shown" in content
    assert "Keys are masked" not in content
