"""A scanner error must never be shown as a successful zero-finding scan."""
import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from sca.engines import external


@pytest.mark.parametrize("code,report,expected", [
    (2, "", "failed"), (0, "", "failed"), (2, "[]", "failed"),
    (0, "[]", "ok"), (0, "{}", "failed"), (0, "null", "failed"),
])
def test_gitleaks_empty_or_failed_execution_is_not_clean(monkeypatch, tmp_path, code, report, expected):
    monkeypatch.setattr(external, "gitleaks_binary", lambda: "gitleaks")
    reports = []
    def run(args, **kwargs):
        path = Path(args[args.index("--report-path") + 1])
        reports.append(path)
        path.write_text(report, encoding="utf-8")
        return CompletedProcess(args, code, "", "FixtureOnlySensitiveStderr")
    monkeypatch.setattr(external.subprocess, "run", run)
    findings, note = external.run_gitleaks(tmp_path)
    assert not findings and note.startswith(expected)
    assert "FixtureOnlySensitiveStderr" not in note
    assert all(not path.exists() for path in reports)


@pytest.mark.parametrize("code,errors,has_finding,expected", [
    (0, [], False, "ok"), (2, [], False, "failed"),
    (0, [{"type": "ParseError"}], False, "failed"),
    (2, [{"type": "ParseError"}], True, "partial"),
    (0, [{"type": "ParseError"}], True, "partial"),
    (1, [], True, "ok"), (1, [], False, "failed"),
])
def test_semgrep_exit_and_reported_errors_are_visible(monkeypatch, tmp_path, code, errors, has_finding, expected):
    monkeypatch.setattr(external, "semgrep_binary", lambda: "opengrep")
    item = {"check_id": "fixture", "path": "a.java", "start": {"line": 1},
            "extra": {"message": "fixture", "metadata": {"cwe": "CWE-327"}}}
    data = {"results": [item] if has_finding else [], "errors": errors}
    monkeypatch.setattr(external.subprocess, "run", lambda args, **kwargs:
                        CompletedProcess(args, code, json.dumps(data), ""))
    findings, note = external.run_semgrep(tmp_path, "local.yaml")
    assert bool(findings) == has_finding and note.startswith(expected)


def test_bandit_file_errors_are_not_hidden(monkeypatch, tmp_path):
    monkeypatch.setattr(external, "bandit_available", lambda: True)
    data = {"results": [], "errors": [{"filename": "invalid.py", "reason": "syntax error"}]}
    monkeypatch.setattr(external.subprocess, "run", lambda args, **kwargs:
                        CompletedProcess(args, 0, json.dumps(data), ""))
    findings, note = external.run_bandit(tmp_path)
    assert not findings and note.startswith("failed") and "1 reported errors" in note
