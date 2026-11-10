"""Tests for the API providers, the rule-learning loop, reviewer feedback and strict mode.

No real AI service is contacted. The "models" here are small scripted servers that speak
the same HTTP formats (Ollama, OpenAI chat-completions, Anthropic messages) and return
answers written in this file, so the whole mechanism can be tested deterministically.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sca.__main__ import main as cli
from sca.ai import llm
from sca.ai.providers import (AnthropicClient, LLMConfig, OpenAICompatClient, load_config,
                              make_client, save_config)
from sca.engines import rules_engine
from sca.learn import feedback, loop, sandbox, store, validate
from sca.models import Finding
from sca.pipeline import ScanOptions, run_scan, scan_project
from sca.report import write_reports
from sca.storage import Storage

ROOT = Path(__file__).resolve().parent.parent
VULN = ROOT / "samples" / "vulnerable_app"


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """An isolated data folder, learned-rules folder and settings file."""
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    return Storage()


def serve(handler_class):
    server = HTTPServer(("127.0.0.1", 0), handler_class)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_port


class JsonHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        return json.loads(self.rfile.read(int(self.headers["Content-Length"])))


# ====================================================================== API providers
class FakeOpenAI(JsonHandler):
    """Imitates an OpenAI-compatible server, including the awkward behaviours."""
    seen = []
    rate_limit_once = False
    reject = set()          # request options this server answers with HTTP 400

    def authorized(self):
        if self.headers.get("Authorization") != "Bearer sk-test":
            self.reply(401, {"error": {"message": "Incorrect API key provided"}})
            return False
        return True

    def do_GET(self):
        if self.authorized():
            self.reply(200, {"data": [{"id": "model-b"}, {"id": "model-a"}]})

    def do_POST(self):
        if not self.authorized():
            return
        request = self.body()
        FakeOpenAI.seen.append(request)
        if FakeOpenAI.rate_limit_once:
            FakeOpenAI.rate_limit_once = False
            return self.reply(429, {"error": {"message": "slow down"}}, {"Retry-After": "0"})
        for option in FakeOpenAI.reject:
            if option in request:
                return self.reply(400, {"error": {"message": "Unsupported parameter: " + option}})
        answer = {"verdict": "true_positive", "confidence": 0.9, "explanation": "ok", "fix": "x"}
        self.reply(200, {"choices": [{"message": {"role": "assistant",
                                                  "content": json.dumps(answer)}}]})


class FakeAnthropic(JsonHandler):
    seen = []
    reject_system = False

    def do_GET(self):
        if self.headers.get("x-api-key") != "sk-ant-test":
            return self.reply(401, {"type": "error", "error": {"type": "authentication_error",
                                                               "message": "invalid x-api-key"}})
        self.reply(200, {"data": [{"id": "claude-test", "type": "model"}]})

    def do_POST(self):
        request = self.body()
        FakeAnthropic.seen.append(({k.lower(): v for k, v in self.headers.items()}, request))
        if not self.headers.get("anthropic-version") or self.path != "/v1/messages":
            return self.reply(400, {"type": "error", "error": {"message": "bad request"}})
        if any(k in request for k in ("temperature", "top_p", "top_k")):
            return self.reply(400, {"type": "error",
                                    "error": {"message": "temperature is not supported"}})
        if FakeAnthropic.reject_system and "system" in request:
            return self.reply(400, {"type": "error", "error": {"message": "system: unexpected"}})
        answer = {"verdict": "false_positive", "confidence": 0.8, "explanation": "safe", "fix": ""}
        self.reply(200, {"type": "message", "role": "assistant", "content": [
            {"type": "thinking", "thinking": "..."},
            {"type": "text", "text": "```json\n" + json.dumps(answer) + "\n```"}]})


@pytest.fixture()
def openai_server():
    FakeOpenAI.seen, FakeOpenAI.rate_limit_once, FakeOpenAI.reject = [], False, set()
    server, url = serve(FakeOpenAI)
    yield url
    server.shutdown()


@pytest.fixture()
def anthropic_server():
    FakeAnthropic.seen, FakeAnthropic.reject_system = [], False
    server, url = serve(FakeAnthropic)
    yield url
    server.shutdown()


def test_openai_compatible_client(openai_server):
    client = OpenAICompatClient(openai_server, "sk-test", "model-a", name="openai")
    client.backoff = 0.01
    assert client.check() == (True, "ready")
    assert client.models() == ["model-a", "model-b"]
    assert client.label == "openai/model-a"
    assert client.chat_json("system text", "user text")["verdict"] == "true_positive"
    sent = FakeOpenAI.seen[-1]
    assert sent["model"] == "model-a" and sent["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in sent["messages"]] == ["system", "user"]


def test_openai_client_retries_rate_limits_and_drops_unsupported_options(openai_server):
    client = OpenAICompatClient(openai_server, "sk-test", "model-a")
    client.backoff = 0.01
    FakeOpenAI.rate_limit_once = True
    assert client.chat_json("s", "u")["confidence"] == 0.9          # 429, then success
    FakeOpenAI.reject = {"response_format", "temperature"}
    assert client.chat_json("s", "u")["confidence"] == 0.9          # falls back twice
    assert "temperature" not in FakeOpenAI.seen[-1]
    assert "response_format" not in FakeOpenAI.seen[-1]


def test_openai_client_reports_bad_key_and_unreachable_server(openai_server):
    wrong = OpenAICompatClient(openai_server, "sk-wrong", "model-a")
    ready, message = wrong.check()
    assert not ready and "rejected" in message and "sk-wrong" not in message
    with pytest.raises(llm.LLMError) as error:
        wrong.chat_json("s", "u")
    assert "401" in str(error.value) and "sk-wrong" not in str(error.value)
    assert OpenAICompatClient("https://api.example.com/v1", "", "m").check() == \
        (False, "no API key is set")
    assert OpenAICompatClient(openai_server, "sk-test", "").check() == \
        (False, "no model is selected")
    assert not OpenAICompatClient("http://127.0.0.1:9/v1", "k", "m", timeout=2).check()[0]
    assert not OpenAICompatClient("https://api.example.com/v1", "k", "m").is_local
    assert OpenAICompatClient("http://localhost:1234/v1", "", "m").is_local


def test_anthropic_client(anthropic_server):
    client = AnthropicClient(anthropic_server, "sk-ant-test", "claude-test", name="anthropic")
    assert client.check() == (True, "ready")
    assert client.models() == ["claude-test"]
    answer = client.chat_json("system text", "user text")
    assert answer["verdict"] == "false_positive"          # fenced JSON, thinking block skipped
    headers, sent = FakeAnthropic.seen[-1]
    assert headers["x-api-key"] == "sk-ant-test" and headers["anthropic-version"]
    assert sent["system"] == "system text" and sent["max_tokens"] > 0
    assert sent["messages"] == [{"role": "user", "content": "user text"}]
    assert "temperature" not in sent

    FakeAnthropic.reject_system = True                     # a server without top-level system
    assert client.chat_json("system text", "user text")["verdict"] == "false_positive"
    assert "system" not in FakeAnthropic.seen[-1][1]
    assert FakeAnthropic.seen[-1][1]["messages"][0]["content"].startswith("system text")
    assert not AnthropicClient(anthropic_server, "sk-bad", "claude-test").check()[0]


def test_settings_file_round_trip(home):
    assert load_config().preset == "ollama"
    path = save_config(LLMConfig(preset="openai", api_key="sk-secret-value", model="model-a"))
    config = load_config()
    assert (config.preset, config.api_key, config.model) == ("openai", "sk-secret-value", "model-a")
    assert config.resolved_base_url() == "https://api.openai.com/v1"
    assert isinstance(make_client(config), OpenAICompatClient)
    assert isinstance(make_client(LLMConfig(preset="anthropic")), AnthropicClient)
    assert isinstance(make_client(LLMConfig(preset="ollama")), llm.OllamaClient)
    save_config(LLMConfig(preset="groq", model="m2"))       # switching provider drops the key
    assert "sk-secret-value" not in path.read_text()


def test_scan_through_an_api_provider_keeps_the_key_out_of_the_output(openai_server, home,
                                                                     tmp_path):
    options = ScanOptions(use_llm=True, llm_provider="custom", llm_base_url=openai_server,
                          llm_api_key="sk-test", llm_model="model-a", llm_max_findings=5)
    result = run_scan(str(VULN), options, storage=home)
    assert "custom/model-a reviewed 5 findings" in result.ai["llm"]
    assert sum(1 for f in result.findings if f.ai_verdict == "true_positive") == 5
    assert "privacy" not in result.ai                      # the fake server is on localhost
    written = write_reports(result, str(tmp_path / "out"), ["html", "json", "sarif"])
    for path in list(written.values()) + [home.path]:
        assert b"sk-test" not in Path(path).read_bytes()
    sent = json.dumps(FakeOpenAI.seen)
    for secret in ("Pr0d-DB-pass!2024", "r00t-Adm1n-pw", "Tr1ckyPass99"):
        assert secret not in sent                          # secrets are masked before sending

    bad = ScanOptions(use_llm=True, llm_provider="openai", llm_base_url=openai_server,
                      llm_api_key="", llm_model="model-a", save=False)
    note = run_scan(str(VULN), bad, storage=home).ai["llm"]
    assert note.startswith("unavailable") and "rejected" in note       # reported, not fatal


# ====================================================================== sandbox + validation
def candidate(**overrides):
    base = {"id": "LRN-C-120-test", "kind": "rule", "title": "memcpy with a variable length",
            "languages": ["c"], "cwe": "CWE-120", "severity": "high",
            "pattern": r"\bmemcpy\s*\([^,]+,[^,]+,\s*[A-Za-z_]\w*\s*\)", "exclude": "sizeof",
            "examples_vulnerable": ["memcpy(dst, src, n);", "memcpy(buf, input, length);",
                                    "memcpy(out, in, count);"],
            "examples_safe": ["memcpy(dst, src, sizeof(dst));", "memcpy(dst, src, 16);",
                              "memmove(dst, src, n);"],
            "evidence": {"file": "parser.c", "line": 36,
                         "snippet": "memcpy(packet, data, len); /* [C10] */"}}
    base.update(overrides)
    return base


def failed(report):
    return [c["name"] for c in report["checks"] if not c["passed"]]


def test_sandbox_runs_patterns_and_kills_slow_ones():
    assert sandbox.run_patterns(r"ab+c", "", False, ["xabbc", "ac", "ABC"]) == ([0], "")
    assert sandbox.run_patterns(r"ab+c", "x", True, ["xabbc", "ac", "ABC"]) == ([2], "")
    matches, error = sandbox.run_patterns(r"(unclosed", "", False, ["a"])
    assert matches is None and "invalid regular expression" in error
    matches, error = sandbox.run_patterns(r"(x|xx)+y", "", False, ["x" * 200], timeout=1.5)
    assert matches is None and "too slow" in error


def test_validation_accepts_a_good_rule(home):
    files = loop.load_files(str(VULN))
    report = validate.validate(candidate(), files, home)
    assert report["passed"], failed(report)
    assert report["match_count"] == 1 and report["project_matches"][0]["file"] == "parser.c"
    assert {c["name"] for c in report["checks"]} == {
        "schema", "compiles", "fast", "specific", "evidence", "examples", "clean corpus",
        "blast radius", "novelty"}


@pytest.mark.parametrize("change,check", [
    ({"pattern": r"memcpy\s*\((unclosed"}, "compiles"),
    ({"pattern": r"(a+)+memcpy"}, "schema"),                        # nested quantifier
    ({"pattern": r"memcpy" + "x?" * 200}, "schema"),                # too long
    ({"cwe": "buffer overflow"}, "schema"),
    ({"languages": ["klingon"]}, "schema"),
    ({"pattern": r"\w+\s*=\s*\w+"}, "specific"),                    # matches everyday code
    ({"pattern": r"\bmemmove\s*\("}, "evidence"),                   # misses the real line
    ({"examples_safe": ["memcpy(a, b, n);"]}, "examples"),          # matches its safe example
    ({"pattern": r"\bstrncpy\s*\(|\bmemcpy\s*\(\w+, \w+, \w+\)"}, "clean corpus"),
    ({"pattern": r"\bstrcpy\s*\(", "exclude": "", "evidence": {
        "snippet": "strcpy(buffer, input); /* [C03] */"},
      "examples_vulnerable": ["strcpy(a, b);", "strcpy(x, y);"]}, "novelty"),
])
def test_validation_rejects_bad_rules(home, change, check):
    files = loop.load_files(str(VULN))
    report = validate.validate(candidate(**change), files, home)
    assert not report["passed"] and check in failed(report)


def test_validation_rejects_slow_and_overbroad_rules(home, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "TIMEOUT_SECONDS", 2.0)
    slow = validate.validate(candidate(pattern=r"memcpy|(n|nn)+y", exclude=""), None, home)
    assert failed(slow) == ["fast"]

    project = tmp_path / "big"
    project.mkdir()
    (project / "a.c").write_text("\n".join("memcpy(a%d, b, n);" % i for i in range(300)))
    broad = validate.validate(candidate(), loop.load_files(str(project)), home)
    assert failed(broad) == ["blast radius"] and broad["match_count"] == 300


def test_validation_uses_reviewer_dismissals_as_clean_code(home):
    dismissed = Finding(rule_id="X", title="t", file="x.c", line=1, cwe="CWE-120",
                        snippet="memcpy(header, trusted_header, header_len);", language="c")
    home.set_feedback(dismissed, "fp")
    report = validate.validate(candidate(), None, home)
    assert failed(report) == ["clean corpus"]
    assert "dismissed by the reviewer" in report["checks"][-2]["detail"]


# ====================================================================== the learning loop
class Teacher(JsonHandler):
    """A scripted model that speaks the Ollama API. It 'knows' one weakness the static
    engines miss (memcpy with an unchecked length) and first writes a wrong rule for it."""
    log = []
    good_rule = {
        "title": "memcpy with a length that is not derived from the destination size",
        "cwe": "CWE-120", "severity": "high",
        "pattern": "\\bmemcpy\\s*\\([^,]+,[^,]+,\\s*[A-Za-z_]\\w*\\s*\\)", "exclude": "sizeof",
        "ignore_case": False,
        "message": "The length is not checked against the size of the destination buffer.",
        "fix": "Check the length against sizeof(destination) before copying.",
        "examples_vulnerable": ["memcpy(dst, src, n);", "memcpy(buf, input, length);",
                                "memcpy(out, in, count);"],
        "examples_safe": ["memcpy(dst, src, sizeof(dst));", "memcpy(dst, src, 16);",
                          "memmove(dst, src, n);"]}

    def do_GET(self):
        self.reply(200, {"models": [{"name": "teacher:1"}]})

    def do_POST(self):
        request = self.body()
        system, user = (m["content"] for m in request["messages"])
        if system.startswith("You write detection rules"):
            kind = "rule"
            if "Weakness: CWE-89" in user:                  # bootstrap request
                answer = {"title": "SQL built with string interpolation", "cwe": "CWE-89",
                          "severity": "high",
                          "pattern": "\\.(rawQuery|execSQL)\\s*\\(\\s*\"[^\"]*\\$",
                          "exclude": "", "message": "m", "fix": "f",
                          "examples_vulnerable": ["db.rawQuery(\"SELECT * FROM t WHERE id = $id\")",
                                                  "db.execSQL(\"DELETE FROM t WHERE n = '$name'\")"],
                          "examples_safe": ["db.rawQuery(\"SELECT * FROM t WHERE id = ?\", [id])",
                                            "db.execSQL(\"VACUUM\")"]}
            elif "Weakness: CWE-78" in user:                # bootstrap: the model writes junk
                answer = {"title": "anything", "cwe": "CWE-78", "severity": "high",
                          "pattern": ".*", "examples_vulnerable": ["a", "b"],
                          "examples_safe": ["c", "d"]}
            elif "previous answer was rejected" in user:
                answer = Teacher.good_rule
            else:                                           # first attempt: wrong function
                answer = dict(Teacher.good_rule, pattern="\\bmemmove\\s*\\(")
        elif system.startswith("A rule of a static code analysis tool reported a FALSE"):
            kind = "exclude"
            if "previous answer was rejected" in user:
                answer = {"exclude": "\\$\\w+\\s*=\\s*md5\\(\\$(output|content|body)\\)",
                          "reason": "MD5 of generated output is a cache key, not a secret."}
            else:                                           # first attempt: far too broad
                answer = {"exclude": "md5", "reason": "it is fine"}
        elif "Already reported" in user:
            kind = "deep"
            found = re.search(r"^(\d+): .*memcpy\(packet", user, re.M)
            answer = {"findings": [{"line": int(found.group(1)), "cwe": "CWE-120",
                                    "title": "memcpy with an unchecked length",
                                    "severity": "high", "explanation": "len is not checked",
                                    "fix": "check len"}] if found else []}
        else:
            kind = "triage"
            answer = {"verdict": "true_positive", "confidence": 0.9,
                      "explanation": "reachable", "fix": "fix it"}
        Teacher.log.append(kind)
        self.reply(200, {"message": {"content": json.dumps(answer)}})


@pytest.fixture()
def teacher():
    Teacher.log = []
    server, url = serve(Teacher)
    yield url
    server.shutdown()


def test_learning_loop_end_to_end(teacher, home):
    static = ScanOptions(save=False)
    c10 = lambda result: [f for f in result.findings                      # noqa: E731
                          if f.file == "parser.c" and "memcpy" in f.snippet]

    # 1. the static engines alone miss the unchecked memcpy
    assert c10(run_scan(str(VULN), static, storage=home)) == []

    # 2. the AI deep scan finds it, and its second pass confirms it
    options = ScanOptions(use_llm=True, llm_deep_scan=True, llm_host=teacher,
                          llm_model="teacher:1", llm_max_findings=0, save=False)
    result, files = scan_project(str(VULN), options, storage=home)
    found = c10(result)
    assert len(found) == 1 and found[0].engines == ["llm"]
    assert found[0].ai_verdict == "true_positive" and found[0].tier == "confirmed"
    assert "deep scan added 1 (1 verified)" in result.ai["llm"]

    # 3. learning: the first rule the model writes fails validation, the reasons are sent
    #    back, the corrected rule passes and waits for a human
    client = llm.OllamaClient(teacher, "teacher:1")
    created = loop.learn_from_scan(result, files, client, home)
    assert Teacher.log.count("rule") == 2
    assert [c["status"] for c in created] == ["pending"]
    pending = created[0]
    assert pending["kind"] == "rule" and pending["languages"] == ["c"]
    assert pending["source"] == "ollama/teacher:1" and pending["origin"] == "scan"
    assert pending["validation"]["passed"] and pending["validation"]["match_count"] == 1

    # 4. nothing changes until the rule is approved
    assert store.read_learned() == []
    assert c10(run_scan(str(VULN), static, storage=home)) == []
    assert loop.learn_from_scan(result, files, client, home) == []       # no duplicates

    # 5. approval activates the rule: the next scan finds the weakness statically,
    #    with no AI call at all
    store.approve(home, pending["id"])
    assert [r["id"] for r in store.read_learned()] == [pending["id"]]
    assert home.get_candidate(pending["id"])["status"] == "approved"
    calls = len(Teacher.log)
    after = run_scan(str(VULN), static, storage=home)
    learned = c10(after)
    assert len(learned) == 1 and learned[0].engines == ["learned"]
    assert learned[0].cwe == "CWE-120" and learned[0].rule_id == pending["id"]
    assert learned[0].confidence <= store.PROBATION_CONFIDENCE + 0.01    # on probation
    assert "1 from learned rules" in after.engine_notes["rules"]
    assert len(Teacher.log) == calls

    # 6. a learned rule can be removed again
    assert store.remove_learned_rule(pending["id"])
    assert c10(run_scan(str(VULN), static, storage=home)) == []


def test_unvalidated_candidates_cannot_be_approved(teacher, home):
    client = llm.OllamaClient(teacher, "teacher:1")
    created = loop.bootstrap(client, home, "dart", ["CWE-89", "CWE-78"])
    by_cwe = {c["cwe"]: c for c in created}
    assert by_cwe["CWE-89"]["status"] == "pending" and by_cwe["CWE-89"]["origin"] == "bootstrap"
    assert by_cwe["CWE-78"]["status"] == "rejected_auto"                 # the ".*" rule
    with pytest.raises(ValueError):
        store.approve(home, by_cwe["CWE-78"]["id"])
    with pytest.raises(KeyError):
        store.approve(home, "no-such-id")
    # bootstrap rules have no real evidence, so they are never approved automatically
    assert loop.auto_approve(home, created) == []
    assert "CWE-89" in loop.coverage_gaps("dart", ["CWE-89"])
    store.approve(home, by_cwe["CWE-89"]["id"])
    assert loop.coverage_gaps("dart", ["CWE-89"]) == []
    assert loop.coverage_matrix()["dart"] == {"CWE-89": 1}


def test_a_broken_learned_rule_file_never_stops_a_scan(home):
    folder = rules_engine.learned_dir()
    folder.mkdir(parents=True)
    (folder / "rules.yaml").write_text(
        "- id: BAD-1\n  title: t\n  languages: [c]\n  pattern: '(unclosed'\n"
        "- id: GOOD-1\n  title: custom\n  languages: [c]\n  cwe: CWE-120\n"
        "  pattern: 'alloca\\s*\\('\n", encoding="utf-8")
    (folder / "overrides.yaml").write_text("C-BOF-001: ['(broken']\n", encoding="utf-8")
    ids = {r.id: r for r in rules_engine.load_rules()}
    assert "GOOD-1" in ids and "BAD-1" not in ids and ids["GOOD-1"].origin == "learned"
    assert run_scan(str(VULN), ScanOptions(save=False), storage=home).findings


# ====================================================================== reviewer feedback
def md5_project(tmp_path, lines=4):
    project = tmp_path / "site"
    project.mkdir()
    names = ["output", "content", "body", "page"]
    (project / "cache.php").write_text("<?php\n" + "\n".join(
        "$etag%d = md5($%s);" % (i, names[i]) for i in range(lines)) + "\n")
    return str(project)


def test_feedback_dismisses_confirms_and_adjusts_rule_confidence(home, tmp_path):
    project = md5_project(tmp_path)
    options = ScanOptions(use_ml=False, save=False)
    first = run_scan(project, options, storage=home)
    assert [f.rule_id for f in first.findings] == ["PHP-CRYPTO-002"] * 4
    assert all(f.confidence == pytest.approx(0.4) and f.status == "open" for f in first.findings)

    home.set_feedback(first.findings[0], "fp")
    home.set_feedback(first.findings[1], "tp")
    second = run_scan(project, options, storage=home)
    by_fp = {f.fingerprint: f for f in second.findings}
    dismissed, confirmed = by_fp[first.findings[0].fingerprint], by_fp[first.findings[1].fingerprint]
    assert dismissed.status == "dismissed" and dismissed.user_verdict == "false_positive"
    assert confirmed.status == "open" and confirmed.tier == "confirmed"
    assert confirmed.confidence >= 0.97 and "confirmed by the reviewer" in confirmed.evidence
    # one tp and one fp: (1 + 4*0.4) / (1 + 1 + 4) = 0.433 for the unreviewed findings
    others = [f for f in second.findings if not f.user_verdict]
    assert all(f.confidence == pytest.approx(2.6 / 6, abs=1e-3) for f in others)
    assert len(second.open_findings) == 3 and second.status_count("dismissed") == 1
    assert "1 dismissed and 1 confirmed" in second.engine_notes["feedback"]

    # feedback can be switched off for a clean measurement, and cleared
    assert run_scan(project, ScanOptions(use_ml=False, save=False, use_feedback=False),
                    storage=home).status_count("dismissed") == 0
    home.clear_feedback(first.findings[0].fingerprint)
    assert run_scan(project, options, storage=home).status_count("dismissed") == 0


def test_rule_is_quarantined_after_repeated_false_positives(home, tmp_path):
    project = md5_project(tmp_path)
    options = ScanOptions(use_ml=False, save=False)
    first = run_scan(project, options, storage=home)
    for finding in first.findings[:3]:
        home.set_feedback(finding, "fp")
    assert home.rule_stats() == {"PHP-CRYPTO-002": {"tp": 0, "fp": 3}}
    assert feedback.adjusted_confidence(0.4, 0, 3) == pytest.approx(1.6 / 7)
    assert feedback.quarantined_rules(home.rule_stats(), {"PHP-CRYPTO-002": 0.4}) == \
        {"PHP-CRYPTO-002"}
    second = run_scan(project, options, storage=home)
    assert second.findings == []                       # the fourth md5 line is no longer reported
    assert "PHP-CRYPTO-002" in second.engine_notes["quarantine"]
    # a rule with a good record is not quarantined by three misses
    assert not feedback.is_quarantined(0.8, 10, 3)
    assert feedback.adjusted_confidence(0.6, 0, 0) == pytest.approx(0.6)
    assert feedback.adjusted_confidence(0.6, 6, 0) > 0.8


def test_classifier_learns_from_reviews(home):
    from sca.ai.classifier import SKLEARN_AVAILABLE, get_classifier
    if not SKLEARN_AVAILABLE:
        pytest.skip("scikit-learn not installed")
    line = "$etag = md5($output);"
    before = get_classifier().score(line)
    after_model = get_classifier(None, [(line, 0)] * 3)
    assert after_model.score(line) < before
    assert "reviewed findings" in after_model.source


def test_false_positive_becomes_a_validated_exclusion(teacher, home, tmp_path):
    project = md5_project(tmp_path, lines=3)
    options = ScanOptions(use_ml=False, save=False)
    first = run_scan(project, options, storage=home)
    home.set_feedback(first.findings[0], "fp")

    client = llm.OllamaClient(teacher, "teacher:1")
    created = loop.learn_from_feedback(client, home)
    assert Teacher.log == ["exclude", "exclude"]        # "md5" alone was rejected, then fixed
    assert [(c["kind"], c["status"], c["target_rule"]) for c in created] == \
        [("exclude", "pending", "PHP-CRYPTO-002")]
    assert loop.learn_from_feedback(client, home) == []          # not proposed twice

    store.approve(home, created[0]["id"])
    assert list(store.read_overrides()) == ["PHP-CRYPTO-002"]
    second = run_scan(project, ScanOptions(use_ml=False, save=False, use_feedback=False),
                      storage=home)
    assert [f.snippet for f in second.findings] == []            # all three etag lines are quiet
    # ... while the rule still reports a line the exclusion does not cover
    still = rules_engine.scan_file(
        __import__("tests.test_engines", fromlist=["make"]).make("$h = md5($username);\n", "a.php"))
    assert [f.rule_id for f in still] == ["PHP-CRYPTO-002"]


def test_exclusion_that_would_hide_real_vulnerabilities_is_rejected(home):
    bad = {"id": "EXC-1", "kind": "exclude", "target_rule": "PHP-SQLI-001", "exclude": r"\$_GET",
           "evidence": {"snippet": "$r = mysqli_query($c, \"SELECT 1 WHERE id=\" . $_GET['id']);"}}
    report = validate.validate(bad, None, home)
    assert not report["passed"] and "keeps true positives" in failed(report)
    missing = dict(bad, target_rule="NO-SUCH-RULE")
    assert failed(validate.validate(missing, None, home)) == ["schema"]


# ====================================================================== strict mode
def test_strict_mode_counts_only_confirmed_findings(home):
    normal = run_scan(str(VULN), ScanOptions(save=False), storage=home)
    strict = run_scan(str(VULN), ScanOptions(save=False, strict=True), storage=home)
    assert len(strict.findings) == len(normal.findings)            # nothing is deleted
    assert all(f.tier == "confirmed" and f.evidence for f in strict.open_findings)
    review = [f for f in strict.findings if f.status == "needs_review"]
    assert review and all(f.tier == "probable" for f in review)
    assert len(strict.open_findings) + len(review) == len(normal.open_findings)
    assert strict.score >= normal.score
    reasons = {reason for f in strict.open_findings for reason in f.evidence}
    assert "user input was traced to this line" in reasons
    assert any("independent engines agree" in r for r in reasons)

    safe = run_scan(str(ROOT / "samples" / "safe_app"),
                    ScanOptions(save=False, strict=True), storage=home)
    assert safe.open_findings == []                    # every false positive there is unconfirmed


def test_ai_review_confirms_or_clears_findings_in_strict_mode(teacher, home):
    options = ScanOptions(save=False, strict=True, use_llm=True, llm_host=teacher,
                          llm_model="teacher:1", llm_max_findings=500)
    result = run_scan(str(VULN), options, storage=home)
    assert result.status_count("needs_review") == 0     # the review confirmed all of them
    assert any("confirmed by the AI review" in f.evidence for f in result.open_findings)


# ====================================================================== command line
def test_cli_review_and_rule_commands(home, capsys, tmp_path):
    project = md5_project(tmp_path)
    assert cli(["scan", project, "--quiet", "--format", "", "--no-ml"]) == 0
    out = capsys.readouterr().out
    finding_id = re.search(r"id ([0-9a-f]{16})", out).group(1)
    assert "probable" in out

    assert cli(["feedback", "fp", finding_id[:10]]) == 0
    assert "false positive" in capsys.readouterr().out
    assert cli(["feedback", "list"]) == 0 and finding_id in capsys.readouterr().out
    assert cli(["scan", project, "--quiet", "--format", "", "--no-ml", "--strict"]) == 0
    out = capsys.readouterr().out
    assert "1 dismissed by earlier reviews" in out and "needs review" in out
    assert cli(["feedback", "tp", "ffffffffffffffff"]) == 1
    capsys.readouterr()

    assert cli(["rules", "stats"]) == 0 and "PHP-CRYPTO-002" in capsys.readouterr().out
    assert cli(["rules", "list", "--status", "all"]) == 0
    assert cli(["rules", "approve", "missing-id"]) == 1
    assert cli(["coverage"]) == 0
    out = capsys.readouterr().out
    assert "ruby" in out and "AST taint engine" in out
    assert cli(["config", "--show"]) == 0 and "ollama" in capsys.readouterr().out
    assert cli(["doctor"]) == 0 and "LLM provider" in capsys.readouterr().out
    # learning needs a working provider; without one the command explains what to do
    assert cli(["learn", project, "--quiet", "--llm-host", "http://127.0.0.1:9"]) == 2
    assert "python -m sca config" in capsys.readouterr().err


def test_cli_learn_and_approve(teacher, home, capsys):
    assert cli(["learn", str(VULN), "--quiet", "--llm-host", teacher, "--model", "teacher:1",
                "--llm-max", "0"]) == 0
    out = capsys.readouterr().out
    assert "1 passed validation" in out
    candidate_id = re.search(r"(LRN-C-120-[0-9a-f]{6})", out).group(1)
    assert cli(["rules", "show", candidate_id]) == 0 and "memcpy" in capsys.readouterr().out
    assert cli(["rules", "approve", "all"]) == 0
    assert "active from the next scan" in capsys.readouterr().out
    assert cli(["scan", str(VULN), "--quiet", "--format", "", "--top", "200"]) == 0
    assert "+learned" in capsys.readouterr().out or store.read_learned()
    assert cli(["rules", "remove", candidate_id]) == 0


# ====================================================================== confirmation rules
def test_engine_agreement_does_not_confirm_injection_findings(home, tmp_path):
    from sca.engines import external
    project = tmp_path / "lib"
    (project / "tests").mkdir(parents=True)
    (project / "cache.py").write_text(
        "import hashlib\nimport pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n\n\n"
        "def digest(data):\n    return hashlib.md5(data).hexdigest()\n")
    (project / "tests" / "test_cache.py").write_text(
        "import hashlib\n\n\ndef test_digest():\n    assert hashlib.md5(b'x').hexdigest()\n")
    result = run_scan(str(project), ScanOptions(save=False), storage=home)
    by = {(f.file, f.cwe): f for f in result.findings}
    unpickle, weak_hash = by[("cache.py", "CWE-502")], by[("cache.py", "CWE-327")]
    in_test = by[("tests/test_cache.py", "CWE-327")]

    # two engines noticing pickle.loads() is not evidence that attacker data reaches it
    assert unpickle.tier == "probable" and unpickle.evidence == []
    if external.bandit_available():
        assert set(unpickle.engines) == {"ast", "bandit"}
        # a weak algorithm is a property of the line: agreement is enough
        assert weak_hash.tier == "confirmed"
        assert "2 independent engines agree" in weak_hash.evidence
    # the same weakness in test code: kept, weaker, never confirmed automatically
    assert in_test.test_code and not weak_hash.test_code
    assert in_test.tier == "probable" and in_test.confidence < weak_hash.confidence
    assert "test code" in result.engine_notes

    skipped = run_scan(str(project), ScanOptions(save=False, include_tests=False), storage=home)
    assert {f.file for f in skipped.findings} == {"cache.py"}
    assert "skipped 1 test files" in skipped.engine_notes["test code"]


def test_test_path_detection():
    from sca.walker import is_test_path
    for path in ("tests/test_x.py", "pkg/tests/io/helpers.py", "src/app.test.js", "a/b.spec.ts",
                 "handlers_test.go", "conftest.py", "spec/models/user_spec.rb", "__tests__/a.js"):
        assert is_test_path(path), path
    for path in ("src/app.js", "contest.py", "latest/build.py", "testimonials/view.php",
                 "attest.go", "protest_handler.py"):
        assert not is_test_path(path), path


# ====================================================================== configuration command
def test_cli_config_stores_provider_and_key(openai_server, home, capsys, monkeypatch):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "sk-test")
    assert cli(["config", "--provider", "custom", "--base-url", openai_server,
                "--model", "model-a"]) == 0
    out = capsys.readouterr().out
    assert "Connection: ready" in out and "sk-test" not in out
    config = load_config()
    assert (config.preset, config.api_key, config.model) == ("custom", "sk-test", "model-a")
    assert cli(["config", "--show"]) == 0
    out = capsys.readouterr().out
    assert "API key  : set" in out and "sk-test" not in out

    # the saved provider is used by scan without repeating the settings
    assert cli(["scan", str(VULN), "--quiet", "--format", "", "--llm", "--llm-max", "3"]) == 0
    out = capsys.readouterr().out
    assert "custom/model-a reviewed 3 findings" in out and "sk-test" not in out
    assert cli(["doctor"]) == 0 and "[ok] LLM provider" in capsys.readouterr().out
    assert cli(["config", "--provider", "nonsense"]) == 2

    monkeypatch.setattr("getpass.getpass", lambda prompt="": "sk-wrong")
    assert cli(["config", "--set-key"]) == 1                # saved, but reported as not ready
    assert "NOT ready" in capsys.readouterr().out


def test_evaluation_script_with_an_ai_provider(teacher, home, tmp_path):
    import os
    import subprocess
    import sys
    save_config(LLMConfig(preset="ollama", base_url=teacher, model="teacher:1"))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "evaluation" / "evaluate.py"), "--deep",
         "--out", str(tmp_path / "results")],
        capture_output=True, text=True, timeout=300, env=dict(os.environ))
    assert proc.returncode == 0, proc.stderr[-2000:]
    rows = json.loads((tmp_path / "results.json").read_text())
    names = [r["name"] for r in rows]
    assert names[-2:] == ["All static + AI review", "All static + AI review, strict mode"]
    static = next(r for r in rows if r["name"] == "All static engines")
    with_ai, with_ai_strict = rows[-2], rows[-1]
    # the scripted model finds the unchecked memcpy that no rule reports ...
    assert with_ai["tp"] == static["tp"] + 1
    # ... and its review confirms the findings strict mode had set aside
    assert with_ai_strict["tp"] == with_ai["tp"]
    assert "deep scan added" in with_ai["ai"]["llm"]
