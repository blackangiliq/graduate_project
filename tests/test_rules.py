"""The rule set: imported rules, the rule book (edit, disable, create, export) and the CLI."""
from __future__ import annotations

import re
import warnings

import pytest
import yaml

from sca import rulebook
from sca.__main__ import main as cli
from sca.engines import rules_engine, secrets
from sca.models import SEVERITY_RANK
from sca.pipeline import ScanOptions, run_scan

IMPORTED = sorted(rules_engine.IMPORTED_DIR.glob("*.yaml"))


@pytest.fixture(autouse=True)
def own_rule_folder(tmp_path_factory, monkeypatch):
    """Each test gets an empty folder for learned and custom rules, edits and exclusions."""
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path_factory.mktemp("learned")))


def scan_text(tmp_path, name: str, text: str):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return run_scan(str(tmp_path), ScanOptions(use_bandit=False, use_ml=False, save=False))


# ------------------------------------------------------------------ imported rules
def test_imported_files_name_their_source_and_licence():
    assert {p.name for p in IMPORTED} == {"devskim.yaml", "gitleaks.yaml"}
    for path in IMPORTED:
        source = yaml.safe_load(path.read_text(encoding="utf-8"))["source"]
        assert source["license"] == "MIT" and source["url"].startswith("https://github.com/")
        assert source["copyright"] and source["commit"]


def test_every_imported_rule_is_valid():
    rules = [r for r in rules_engine.all_rules(include_user=False) if r.origin == "imported"]
    assert len(rules) > 250
    for rule in rules:
        assert rule.severity in SEVERITY_RANK and re.fullmatch(r"CWE-\d+", rule.cwe)
        assert rule.source and rule.license == "MIT" and rule.title
        assert rule.enabled or rule.note, "%s is disabled without a reason" % rule.id
        with warnings.catch_warnings():          # no construct Python plans to reinterpret
            warnings.simplefilter("error")
            re.compile(rule.pattern.pattern)


def test_imported_pattern_rules_pass_their_own_examples():
    checked = 0
    for rule in rules_engine.all_rules(include_user=False):
        if rule.origin != "imported" or rule.kind != "pattern":
            continue
        for sample in rule.examples_vulnerable:
            assert any(rule.matches(line) for line in sample.splitlines()), (rule.id, sample)
            checked += 1
        for sample in rule.examples_safe:
            assert not any(rule.matches(line) for line in sample.splitlines()), (rule.id, sample)
    assert checked > 150


def test_imported_secret_rules_match_a_string_built_from_their_expression():
    exrex = pytest.importorskip("exrex")
    import random
    matched = 0
    rules = [r for r in rules_engine.all_rules(include_user=False) if r.kind == "secret"]
    for rule in rules:
        random.seed(rule.id)
        source = re.sub(r"\\b|\(\?<?[!=][^)]*\)", "", rule.pattern.pattern)
        for _ in range(60):
            candidate = exrex.getone(source, limit=12).split("\n")[0]
            if len(candidate) <= 900 and any(True for _ in
                                             secrets.match_secret_rule(rule, candidate)):
                matched += 1
                break
    assert matched >= 0.9 * len(rules)        # generation is random; the import proved all


def test_imported_rules_find_what_builtin_rules_did_not(tmp_path):
    result = scan_text(tmp_path, "Crypto.cs", "var f = new BinaryFormatter();\n"
                                              "var des = new DESCryptoServiceProvider();\n")
    ids = {rule_id for f in result.findings for rule_id in f.rule_ids}
    assert "DEVSKIM-DS425070" in ids and any(i.startswith("DEVSKIM-DS1068") for i in ids)


def test_imported_secret_format_is_found_and_masked(tmp_path):
    token = "glpat-" + "Ab3dE6gH9jK2mN5pQ8sT"           # the GitLab format, not a real token
    result = scan_text(tmp_path, "deploy.sh", 'curl -H "PRIVATE-TOKEN: %s" https://x\n' % token)
    finding = next(f for f in result.findings if "GITLEAKS-gitlab-pat" in f.rule_ids)
    assert finding.cwe == "CWE-798" and finding.engines == ["secrets"]
    assert token not in finding.snippet and token not in finding.context


def test_secret_rule_respects_keywords_entropy_and_placeholders():
    rule = rules_engine.get_rule("GITLEAKS-gitlab-pat")
    # made-up strings in the GitLab format, assembled here so that no token-shaped literal
    # sits in the repository (secret scanners would flag it)
    prefix = "glpat-"
    assert list(secrets.match_secret_rule(rule, "x = '%s'" % (prefix + "Ab3dE6gH9jK2mN5pQ8sT")))
    assert not list(secrets.match_secret_rule(rule, "x = '%s'" % (prefix + "a" * 20)))  # entropy
    assert not list(secrets.match_secret_rule(rule, "nothing to see"))                  # keyword


def test_disabled_imported_rule_does_not_fire_until_enabled(tmp_path):
    rule = next(r for r in rules_engine.all_rules() if r.origin == "imported"
                and r.kind == "pattern" and not r.enabled and r.examples_vulnerable
                and "\n" not in r.examples_vulnerable[0] and r.languages == ["python"])
    name = "sample.py"
    before = scan_text(tmp_path, name, rule.examples_vulnerable[0] + "\n")
    assert rule.id not in {i for f in before.findings for i in f.rule_ids}
    rulebook.set_enabled(rule.id, True)
    after = scan_text(tmp_path, name, rule.examples_vulnerable[0] + "\n")
    assert rule.id in {i for f in after.findings for i in f.rule_ids}
    rulebook.set_enabled(rule.id, False)                 # back to the shipped state:
    assert rule.id not in rules_engine.load_edits()      # nothing is left in edits.yaml


# ------------------------------------------------------------------ rule book
RULE = {
    "id": "MY-EXEC-001", "title": "exec built from a template string",
    "languages": ["javascript"], "cwe": "78", "severity": "High", "confidence": 0.6,
    "pattern": r"\bexec(Sync)?\(\s*`[^`]*\$\{",
    "examples_vulnerable": ["exec(`ping ${host}`)"],
    "examples_safe": ['execFile("ping", [host])'],
}


def test_create_custom_rule_and_use_it_in_a_scan(tmp_path):
    result = rulebook.create(RULE)
    assert result["passed"] and not result["errors"]
    rule = rulebook.get("MY-EXEC-001")
    assert rule.origin == "custom" and rule.cwe == "CWE-78" and rule.severity == "high"
    assert rule.file == "learned/custom.yaml"
    found = scan_text(tmp_path, "a.js", "exec(`ping ${req.query.host}`);\n")
    assert "MY-EXEC-001" in {i for f in found.findings for i in f.rule_ids}


@pytest.mark.parametrize("change, message", [
    ({"id": "x"}, "id:"),
    ({"id": "JS-SQLI-001"}, "already exists"),
    ({"title": ""}, "title"),
    ({"languages": ["klingon"]}, "languages"),
    ({"cwe": "injection"}, "cwe"),
    ({"severity": "terrible"}, "severity"),
    ({"confidence": 3}, "confidence"),
    ({"pattern": "exec(("}, "pattern"),
    ({"pattern": r"(a+)+$"}, "slow"),
    ({"examples_vulnerable": ["nothing dangerous"]}, "misses its own"),
    ({"examples_safe": ["exec(`ping ${host}`)"]}, "matches its own safe"),
])
def test_invalid_rule_is_refused_with_a_reason(change, message):
    with pytest.raises(rulebook.RuleError) as error:
        rulebook.create({**RULE, **change})
    assert message in str(error.value)
    assert rules_engine.load_custom() == []


def test_check_warns_about_a_broad_rule_but_allows_it():
    result = rulebook.check({**RULE, "id": "BROAD-1", "pattern": r"=", "examples_vulnerable": [],
                             "examples_safe": []})
    assert result["passed"] and len(result["warnings"]) >= 3
    assert any("everyday code" in w for w in result["warnings"])


def test_edit_a_builtin_rule_is_stored_separately_and_can_be_reset():
    original = rulebook.get("JS-SQLI-001")
    shipped_file = (rules_engine.RULES_DIR / "javascript.yaml").read_text(encoding="utf-8")
    rulebook.update("JS-SQLI-001", {"severity": "low", "confidence": 0.3})
    edited = rulebook.get("JS-SQLI-001")
    assert (edited.severity, edited.confidence, edited.edited) == ("low", 0.3, True)
    assert edited.pattern.pattern == original.pattern.pattern
    assert rules_engine.load_edits() == {"JS-SQLI-001": {"severity": "low", "confidence": 0.3}}
    assert (rules_engine.RULES_DIR / "javascript.yaml").read_text(encoding="utf-8") == shipped_file
    assert rulebook.reset("JS-SQLI-001") and not rulebook.reset("JS-SQLI-001")
    restored = rulebook.get("JS-SQLI-001")
    assert (restored.severity, restored.edited) == (original.severity, False)


def test_an_edit_equal_to_the_original_leaves_no_trace():
    original = rulebook.get("JS-SQLI-001")
    rulebook.update("JS-SQLI-001", {"severity": "low"})
    rulebook.update("JS-SQLI-001", {"severity": original.severity})
    assert rules_engine.load_edits() == {} and not rulebook.get("JS-SQLI-001").edited


def test_a_broken_edit_is_refused_and_a_corrupt_edits_file_cannot_stop_a_scan(tmp_path):
    with pytest.raises(rulebook.RuleError):
        rulebook.update("JS-SQLI-001", {"pattern": "db.query(("})
    (rules_engine.learned_dir()).mkdir(parents=True, exist_ok=True)
    (rules_engine.learned_dir() / "edits.yaml").write_text(
        "JS-SQLI-001: {pattern: 'db.query(('}\n", encoding="utf-8")
    rule = rulebook.get("JS-SQLI-001")                    # the original stays in force
    assert not rule.edited and rule.matches('db.query("SELECT * FROM t WHERE id=" + id)')


def test_disable_and_enable_a_builtin_rule(tmp_path):
    code = 'db.query("SELECT * FROM t WHERE id=" + req.query.id);\n'
    assert "JS-SQLI-001" in {i for f in scan_text(tmp_path, "a.js", code).findings
                             for i in f.rule_ids}
    rulebook.set_enabled("JS-SQLI-001", False)
    assert not rulebook.get("JS-SQLI-001").enabled
    assert "JS-SQLI-001" not in {i for f in scan_text(tmp_path, "a.js", code).findings
                                 for i in f.rule_ids}
    assert "JS-SQLI-001" not in {r.id for r in rules_engine.load_rules()}
    rulebook.set_enabled("JS-SQLI-001", True)
    assert rulebook.get("JS-SQLI-001").enabled and rules_engine.load_edits() == {}


def test_custom_rule_edit_disable_delete():
    rulebook.create(RULE)
    rulebook.update("MY-EXEC-001", {"title": "new title", "exclude": r"execFile"})
    rule = rulebook.get("MY-EXEC-001")
    assert rule.title == "new title" and rule.exclude.pattern == "execFile"
    rulebook.set_enabled("MY-EXEC-001", False)
    assert not rulebook.get("MY-EXEC-001").enabled
    with pytest.raises(rulebook.RuleError):
        rulebook.reset("MY-EXEC-001")                     # reset is for shipped rules
    rulebook.delete("MY-EXEC-001")
    assert rules_engine.get_rule("MY-EXEC-001") is None
    with pytest.raises(rulebook.RuleError):
        rulebook.delete("JS-SQLI-001")                    # shipped rules cannot be deleted


def test_list_filters_and_summary():
    counts = rulebook.summary()
    assert counts["by_origin"]["builtin"]["total"] == 98
    assert counts["by_origin"]["imported"]["total"] == counts["total"] - 98
    assert counts["enabled"] < counts["total"] and counts["secret"] > 150
    php = rulebook.list_rules(language="php", origin="builtin")
    assert php and all("php" in r.languages for r in php)
    assert all(r.cwe == "CWE-89" for r in rulebook.list_rules(cwe="cwe-89"))
    assert all(not r.enabled for r in rulebook.list_rules(enabled=False))
    assert [r.id for r in rulebook.list_rules(text="JS-SQLI-001")] == ["JS-SQLI-001"]
    assert "typescript" not in rulebook.get("JS-SQLI-001").languages
    assert "JS-SQLI-001" in {r.id for r in rulebook.list_rules(language="typescript")}


def test_try_rule_reports_lines_and_survives_a_runaway_expression():
    lines, error = rulebook.try_rule(r"eval\(", "", False, "x = 1\neval(data)\nprint(x)")
    assert lines == [2] and not error
    lines, error = rulebook.try_rule(r"eval\((", "", False, "eval(x)")
    assert lines is None and error


def test_export_and_import_round_trip():
    rulebook.create(RULE)
    text = rulebook.export_yaml(origin="custom")
    assert "MY-EXEC-001" in text and "origin" not in text
    rulebook.delete("MY-EXEC-001")
    added, problems = rulebook.import_yaml(text)
    assert added == ["MY-EXEC-001"] and not problems
    added, problems = rulebook.import_yaml(text)          # a second time: the id is taken
    assert not added and "already exists" in problems[0]
    assert rulebook.import_yaml("not: [valid")[1] and rulebook.import_yaml("just text")[1]
    template = yaml.safe_load(rulebook.TEMPLATE)
    assert rulebook.check(template[0])["passed"]          # the template itself is a valid rule


def test_remove_an_approved_exclusion():
    from sca.learn import store
    store.add_override("JS-SQLI-001", r"knex\.raw")
    assert [e.pattern for e in rulebook.get("JS-SQLI-001").extra_excludes] == [r"knex\.raw"]
    assert rulebook.remove_exclusion("JS-SQLI-001", r"knex\.raw")
    assert not rulebook.get("JS-SQLI-001").extra_excludes
    assert not rulebook.remove_exclusion("JS-SQLI-001", r"knex\.raw")


# ------------------------------------------------------------------ command line
def test_cli_rule_management(tmp_path, capsys):
    assert cli(["rules", "catalog", "--lang", "php", "--origin", "builtin"]) == 0
    out = capsys.readouterr().out
    assert "PHP-SQLI-001" in out and "JS-SQLI-001" not in out and "In total" in out

    assert cli(["rules", "show", "DEVSKIM-DS425070"]) == 0
    out = capsys.readouterr().out
    assert "DevSkim DS425070" in out and "MIT" in out and "BinaryFormatter" in out

    assert cli(["rules", "disable", "PHP-SQLI-001"]) == 0
    assert cli(["rules", "catalog", "--disabled", "--origin", "builtin"]) == 0
    assert "PHP-SQLI-001" in capsys.readouterr().out
    assert cli(["rules", "enable", "PHP-SQLI-001"]) == 0

    assert cli(["rules", "edit", "PHP-SQLI-001", "--set", "severity=low",
                "--set", "confidence=0.4"]) == 0
    assert rulebook.get("PHP-SQLI-001").confidence == 0.4
    assert cli(["rules", "edit", "PHP-SQLI-001", "--set", "pattern=(("]) == 1
    assert cli(["rules", "edit", "PHP-SQLI-001"]) == 2
    assert cli(["rules", "reset", "PHP-SQLI-001"]) == 0
    assert not rulebook.get("PHP-SQLI-001").edited

    capsys.readouterr()
    assert cli(["rules", "template"]) == 0
    rule_file = tmp_path / "my-rule.yaml"
    rule_file.write_text(capsys.readouterr().out, encoding="utf-8")
    assert cli(["rules", "new", str(rule_file)]) == 0
    assert rulebook.get("MY-RULE-001").origin == "custom"
    assert cli(["rules", "new", str(rule_file)]) == 1     # the id is taken now

    code = tmp_path / "code"
    code.mkdir()
    (code / "a.js").write_text('db.query("SELECT * FROM t WHERE id=" + id)\nlet x = 1;\n',
                               encoding="utf-8")
    capsys.readouterr()
    assert cli(["rules", "test", "MY-RULE-001", str(code)]) == 0
    assert "1 line(s) matched" in capsys.readouterr().out

    exported = tmp_path / "out.yaml"
    assert cli(["rules", "export", "--origin", "custom", "-o", str(exported)]) == 0
    assert "MY-RULE-001" in exported.read_text(encoding="utf-8")
    assert cli(["rules", "delete", "MY-RULE-001"]) == 0
    assert cli(["rules", "import", str(exported)]) == 0
    assert cli(["rules", "delete", "MY-RULE-001", "JS-SQLI-001"]) == 1
    assert cli(["rules", "show", "NO-SUCH-RULE"]) == 1
    assert cli(["doctor"]) == 0
    assert "imported" in capsys.readouterr().out
