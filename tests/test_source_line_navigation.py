from pathlib import Path

from sca.decoded import build_previews
from sca.models import Finding, ScanResult
from sca.presentation import finding_text, view_result
from sca.report.sarif import to_sarif
from sca.sourceview import line_window
from sca.walker import SourceFile


def test_focus_at_end_of_large_bundle_remains_complete_and_exact():
    token = "AIza" + "Synthetic9x" * 7
    text = "x" * 1_000_000 + 'config.apiKey="' + token + '";'
    window = line_window(text, focus=token)
    assert token in window.text
    assert len(window.text) < 9000
    assert window.text == text[window.first - 1:window.last]
    assert not window.complete


def test_long_selected_value_is_never_cut_by_display_window():
    value = "LongToken9" * 1600
    text = "x" * 30_000 + value + "ending"
    window = line_window(text, focus=value)
    assert value in window.text
    assert len(window.text) > 8192


def test_large_source_export_uses_exact_columns_and_keeps_identity():
    value = "ExampleCredential7" * 4
    line = "x" * 90_000 + '="' + value + '";'
    start = line.index(value) + 1
    finding = Finding("TEST-CREDENTIAL", "Credential", "assets/index.android.bundle", 1,
                      column=start, end_column=start + len(value), snippet="masked")
    source = SourceFile(Path(finding.file), finding.file, "javascript", line, origin="decoded")
    result = ScanResult("sample", findings=[finding], decoded_files=build_previews([source]))
    snippet = finding_text(result, finding, context=False)
    assert value in snippet and len(snippet) < 10_000
    exported = view_result(result)
    assert exported.findings[0].fingerprint == finding.fingerprint
    region = to_sarif(exported)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startColumn"] == start
    assert region["endColumn"] == start + len(value)
    assert finding.snippet == "masked"
