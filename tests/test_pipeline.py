"""Tests for merging, scoring, the ML classifier, the LLM layer (against a fake Ollama
server), reports, storage and the whole pipeline on the sample apps."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sca import merge, scoring
from sca.ai import classifier as clf
from sca.ai import llm
from sca.cwe import canonical, info
from sca.models import Finding
from sca.pipeline import ScanOptions, run_scan
from sca.report import write_reports
from sca.report.sarif import to_sarif
from sca.storage import Storage
from sca.walker import SourceFile

ROOT = Path(__file__).resolve().parent.parent
VULN = ROOT / "samples" / "vulnerable_app"
SAFE = ROOT / "samples" / "safe_app"


def finding(**kw):
    base = dict(rule_id="R1", title="t", file="a.py", line=10, severity="high", cwe="CWE-89",
                confidence=0.6, engines=["rules"], snippet="cur.execute(q + x)")
    base.update(kw)
    return Finding(**base)


# ------------------------------------------------------------------ CWE knowledge base
def test_cwe_canonical_and_info():
    assert canonical("cwe-089: SQL Injection") == "CWE-89"
    assert canonical("CWE-94") == "CWE-95"          # folded together
    assert canonical("") == ""
    assert "Injection" in info("CWE-89")["owasp"]
    assert info("CWE-89", "ar")["description"] != info("CWE-89", "en")["description"]
    assert info("CWE-99999")["cwe"] == "CWE-99999"


# ------------------------------------------------------------------ merge
def test_merge_combines_engines_with_noisy_or():
    merged = merge.merge_findings([
        finding(engines=["ast"], confidence=0.8),
        finding(engines=["bandit"], confidence=0.6, line=11, severity="medium"),
    ])
    assert len(merged) == 1
    assert merged[0].engines == ["ast", "bandit"]
    assert merged[0].confidence == pytest.approx(1 - 0.2 * 0.4)
    assert merged[0].severity == "high"
    assert merged[0].owasp.startswith("A03")
    assert merged[0].description and merged[0].fix


def test_merge_keeps_different_weaknesses_and_distant_lines_apart():
    merged = merge.merge_findings([
        finding(), finding(cwe="CWE-78", engines=["ast"]),
        finding(line=40, engines=["bandit"]), finding(file="b.py"),
    ])
    assert len(merged) == 4


def test_merge_keeps_adjacent_findings_of_one_engine_apart():
    merged = merge.merge_findings([
        finding(cwe="CWE-798", engines=["secrets"], line=5, snippet="a"),
        finding(cwe="CWE-798", engines=["secrets"], line=6, snippet="b"),
    ])
    assert len(merged) == 2


def test_merge_respects_suppression_comment():
    assert merge.merge_findings([finding(snippet="cur.execute(q + x)  # nosec")]) == []


# ------------------------------------------------------------------ scoring
def test_score_is_100_without_findings_and_drops_with_severity():
    assert scoring.project_score([], 1000) == (100, "A")
    low = scoring.project_score([finding(severity="low")], 1000)[0]
    crit = scoring.project_score([finding(severity="critical")], 1000)[0]
    assert 100 > low > crit


def test_score_is_normalized_by_code_size():
    f = [finding(severity="high", confidence=0.9)]
    assert scoring.project_score(f, 50_000)[0] > scoring.project_score(f, 1_000)[0]


def test_llm_false_positive_is_relabelled_not_deleted():
    f = finding(ai_verdict="false_positive", ai_confidence=0.9)
    score, _ = scoring.score_all([f], 1000)
    assert f.status == "likely_false_positive" and score == 100
    weak = finding(ai_verdict="false_positive", ai_confidence=0.3)
    scoring.score_all([weak], 1000)
    assert weak.status == "open"


def test_llm_true_positive_raises_confidence():
    f = finding(confidence=0.4, ai_verdict="true_positive", ai_confidence=0.9)
    scoring.score_all([f], 1000)
    assert f.confidence > 0.9 and 0 < f.risk_score <= 10


# ------------------------------------------------------------------ ML classifier
@pytest.mark.skipif(not clf.SKLEARN_AVAILABLE, reason="scikit-learn not installed")
def test_classifier_separates_obvious_cases(tmp_path):
    model = clf.get_classifier()
    risky = model.score('cursor.execute("SELECT * FROM t WHERE id = " + uid)')
    safe = model.score('cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))')
    assert risky > 0.5 > safe
    assert model.top_features(5)["vulnerable"]

    path = tmp_path / "data.jsonl"
    rows = [{"func": "strcpy(a, b);", "target": 1}, {"func": "strncpy(a, b, n);", "target": 0}]
    path.write_text("\n".join(json.dumps(r) for r in rows * 15), encoding="utf-8")
    texts, labels = clf.load_dataset(str(path))
    assert len(texts) == 30 and sum(labels) == 15
    trained, metrics = clf.train_and_evaluate(texts, labels, "unit-test")
    assert metrics["f1"] == 1.0
    trained.save(str(tmp_path / "m.joblib"))
    assert clf.VulnerabilityClassifier.load(str(tmp_path / "m.joblib")).score("strcpy(x, y);") > 0.5


# ------------------------------------------------------------------ LLM (fake Ollama server)
class FakeOllama(BaseHTTPRequestHandler):
    """Imitates the two Ollama endpoints the analyzer uses."""
    requests_seen = []

    def log_message(self, *args):
        pass

    def _send(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send({"models": [{"name": "fake-coder:1b"}]})

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOllama.requests_seen.append(request)
        user = request["messages"][1]["content"]
        if "Already reported" in user:      # deep scan
            answer = {"findings": [
                {"line": 2, "cwe": "CWE-639", "title": "Missing ownership check",
                 "severity": "high", "explanation": "no access control", "fix": "check owner"},
                {"line": 9999, "cwe": "CWE-79", "title": "invented line", "severity": "high"},
                {"line": 1, "cwe": "not-a-cwe", "title": "bad cwe", "severity": "high"},
            ]}
        elif user.startswith("Finding: Standard pseudo-random"):  # Bandit's report on random.choice
            answer = {"verdict": "false_positive", "confidence": 0.9,
                      "explanation": "Not a security value.", "fix": "No change needed."}
        else:
            answer = {"verdict": "true_positive", "confidence": 0.85,
                      "explanation": "User input reaches the sink.", "fix": "Use parameters."}
        # real models sometimes wrap the JSON in extra text; the parser must cope
        self._send({"message": {"content": "Here is my answer:\n" + json.dumps(answer)}})


@pytest.fixture()
def ollama():
    FakeOllama.requests_seen = []
    server = HTTPServer(("127.0.0.1", 0), FakeOllama)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d" % server.server_port
    server.shutdown()


def test_parse_json_object_handles_messy_answers():
    assert llm.parse_json_object('{"a": 1}') == {"a": 1}
    assert llm.parse_json_object('text {"a": {"b": "}"}} more') == {"a": {"b": "}"}}
    assert llm.parse_json_object("no json here") == {}
    assert llm.parse_json_object("[1, 2]") == {}


def test_llm_client_and_triage(ollama):
    client = llm.OllamaClient(ollama, "fake-coder:1b")
    assert client.available() and client.models() == ["fake-coder:1b"]
    answer = llm.triage_finding(client, finding(), "cur.execute(q + x)", "ar")
    assert answer["verdict"] == "true_positive" and answer["confidence"] == 0.85
    system = FakeOllama.requests_seen[-1]["messages"][0]["content"]
    assert "Arabic" in system and "untrusted" in system
    assert FakeOllama.requests_seen[-1]["format"] == "json"


def test_llm_unavailable_is_reported_not_fatal():
    client = llm.OllamaClient("http://127.0.0.1:9", "x", timeout=2)
    assert not client.available() and client.models() == []
    result = run_scan(str(SAFE), ScanOptions(use_llm=True, llm_host="http://127.0.0.1:9",
                                             use_bandit=False, save=False))
    assert "unavailable" in result.ai["llm"]


def test_deep_scan_validates_model_output(ollama):
    client = llm.OllamaClient(ollama, "fake-coder:1b")
    sf = SourceFile(Path("v.py"), "v.py", "python", "def view(i):\n    return db.get(i)\n")
    found = llm.deep_scan_file(client, sf, [])
    assert [(f.cwe, f.line, f.engines) for f in found] == [("CWE-639", 2, ["llm"])]


def test_pipeline_with_llm_review(ollama, tmp_path):
    storage = Storage(str(tmp_path / "t.db"))
    options = ScanOptions(use_llm=True, llm_host=ollama, llm_model="fake-coder:1b",
                          llm_max_findings=500, llm_deep_scan=True, llm_deep_max_files=1)
    result = run_scan(str(VULN), options, storage=storage)
    assert "reviewed" in result.ai["llm"]
    fps = [f for f in result.findings if f.status == "likely_false_positive"]
    assert [(f.file, f.cwe) for f in fps] == [("app.py", "CWE-338")]
    assert any(f.engines == ["llm"] and f.cwe == "CWE-639" for f in result.findings)
    reviewed = [f for f in result.findings if f.ai_verdict]
    assert len(reviewed) >= 60 and all(f.ai_model == "fake-coder:1b" for f in reviewed)

    # the hard-coded secrets must never be sent to the model unmasked
    sent = json.dumps(FakeOllama.requests_seen)
    for secret in ("Pr0d-DB-pass!2024", "r00t-Adm1n-pw", "Tr1ckyPass99"):
        assert secret not in sent.split("Already reported")[0]

    # second run answers come from the cache
    calls = len(FakeOllama.requests_seen)
    options.llm_deep_scan = False
    again = run_scan(str(VULN), options, storage=storage)
    assert len(FakeOllama.requests_seen) == calls
    assert "from cache" in again.ai["llm"]


# ------------------------------------------------------------------ whole pipeline
def test_scan_vulnerable_sample():
    result = run_scan(str(VULN), ScanOptions(save=False))
    found = {(f.file, f.cwe) for f in result.open_findings}
    for expected in [("app.py", "CWE-89"), ("app.py", "CWE-78"), ("app.py", "CWE-502"),
                     ("server.js", "CWE-89"), ("server.js", "CWE-78"),
                     ("index.php", "CWE-79"), ("index.php", "CWE-98"),
                     ("LoginServlet.java", "CWE-89"), ("parser.c", "CWE-242"),
                     ("config/settings.yaml", "CWE-798")]:
        assert expected in found
    assert result.grade == "F" and result.score < 20
    assert result.files_scanned == 7 and result.lines_scanned > 300
    assert {"rules", "ast", "secrets"} <= set(result.engines_used)
    assert all(f.owasp and f.description and f.fix for f in result.findings)
    assert all(0 <= f.confidence <= 1 and 0 < f.risk_score <= 10 for f in result.findings)


def test_scan_safe_sample_scores_much_better():
    vulnerable = run_scan(str(VULN), ScanOptions(save=False))
    safe = run_scan(str(SAFE), ScanOptions(save=False))
    assert len(safe.open_findings) <= 6
    assert not [f for f in safe.open_findings if f.severity == "critical"]
    assert safe.score > vulnerable.score + 30


def test_scan_single_file_and_missing_path():
    result = run_scan(str(VULN / "parser.c"), ScanOptions(save=False))
    assert result.files_scanned == 1 and result.findings
    with pytest.raises(FileNotFoundError):
        run_scan(str(ROOT / "does-not-exist"), ScanOptions(save=False))


def test_arabic_explanations():
    result = run_scan(str(VULN / "parser.c"), ScanOptions(save=False, lang="ar"))
    assert any("؀" <= ch <= "ۿ" for ch in result.findings[0].description)


# ------------------------------------------------------------------ reports and storage
def test_reports_and_history(tmp_path):
    storage = Storage(str(tmp_path / "h.db"))
    result = run_scan(str(VULN), ScanOptions(), storage=storage)
    written = write_reports(result, str(tmp_path / "out"), ["html", "json", "sarif", "pdf"])
    assert set(written) == {"html", "json", "sarif", "pdf"}

    html = Path(written["html"]).read_text(encoding="utf-8")
    assert "Security score" in html and "CWE-89" in html
    assert "Pr0d-DB-pass!2024" not in html          # secrets stay masked
    assert Path(written["pdf"]).read_bytes().startswith(b"%PDF")

    data = json.loads(Path(written["json"]).read_text(encoding="utf-8"))
    assert data["score"] == result.score and len(data["findings"]) == len(result.findings)

    sarif = to_sarif(result)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and len(run["results"]) == len(result.findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
               for r in run["results"])

    rows = storage.list_scans()
    assert len(rows) == 1 and rows[0]["score"] == result.score
    loaded = storage.load_scan(rows[0]["id"])
    assert len(loaded.findings) == len(result.findings)
    assert loaded.findings[0].fingerprint == result.findings[0].fingerprint
    storage.delete_scan(rows[0]["id"])
    assert storage.list_scans() == []


def test_fingerprint_is_stable_when_lines_shift():
    a = finding(line=10)
    b = finding(line=42)
    assert a.fingerprint == b.fingerprint != finding(snippet="other").fingerprint
