"""Actual decompiled Android logging/path false positives and retained unsafe flows."""
from pathlib import Path

import pytest

from sca.engines import rules_engine
from sca.walker import SourceFile


def scan(code, rule_id):
    sf = SourceFile(Path("Review.java"), "Review.java", "java", code, origin="decompiled")
    rule = next(rule for rule in rules_engine.load_builtin() if rule.id == rule_id)
    return rules_engine.scan_file(sf, rules=[rule])


@pytest.mark.parametrize("code", [
    'GriverLogger.d("GriverSelectActivity", "select image result, size=" + list.size());',
    'log.debug("update image size=" + image.size());',
    'String label = "SELECT a photo" + hint;',
])
def test_java_sql_assembly_ignores_logging_labels_without_sql_grammar(code):
    assert scan(code, "JAVA-SQLI-002") == []


@pytest.mark.parametrize("fragment", [
    "SELECT * FROM users WHERE id=", "select name from users where id=",
    "INSERT INTO users(name) VALUES (", "UPDATE users SET name=", "DELETE FROM users WHERE id=",
])
def test_java_sql_assembly_keeps_query_candidates_but_does_not_claim_a_sink(fragment):
    finding, = scan('String query = "' + fragment + '" + value;', "JAVA-SQLI-002")
    assert finding.severity == "medium" and finding.confidence <= .55
    assert "does not establish query execution or untrusted input" in finding.description
    assert not finding.tainted


@pytest.mark.parametrize("code", [
    'File f = new File(directory, strO1 + "(" + i10 + ")." + strH1);',
    'File f = new File(outputDir + RemoteSettings.FORWARD_SLASH_STRING + "frame_info.json");',
    'String name = "fixed";\nFile f = new File(directory, name + ".json");',
])
def test_java_path_concatenation_without_traced_input_is_not_a_traversal_finding(code):
    assert scan(code, "JAVA-PATH-001") == []


@pytest.mark.parametrize("code,line", [
    ('File f = new File("/reports/" + request.getParameter("name"));', 1),
    ('String name = request.getParameter("name");\n'
     'File f = new File(directory, name + ".json");', 2),
    ('String name = request.getParameter("name");\nString other = name;\n'
     'File f = new File("/reports/" + other);', 3),
])
def test_java_path_construction_preserves_direct_and_propagated_request_flows(code, line):
    finding, = scan(code, "JAVA-PATH-001")
    assert finding.line == line and finding.tainted
    assert "determine whether directory traversal is possible" in finding.description


@pytest.mark.parametrize("algorithm", [
    "RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
    "rsa/ecb/OAEPWithSHA-1AndMGF1Padding",
])
def test_rsa_transformation_notation_is_not_symmetric_ecb(algorithm):
    assert scan('Cipher cipher = Cipher.getInstance("' + algorithm + '");', "JAVA-CRYPTO-002") == []


@pytest.mark.parametrize("algorithm", ["AES/ECB/PKCS5Padding", "AES", "DES/CBC/PKCS5Padding",
                                         "DESede/ECB/PKCS5Padding", "RC4", "ARCFOUR"])
def test_weak_symmetric_ciphers_and_ecb_are_still_detected(algorithm):
    assert scan('Cipher cipher = Cipher.getInstance("' + algorithm + '");', "JAVA-CRYPTO-002")


def test_rsa_on_same_line_does_not_hide_a_separate_aes_ecb_call():
    code = 'Cipher.getInstance("RSA/ECB/PKCS1Padding"); Cipher.getInstance("AES/ECB/NoPadding");'
    assert scan(code, "JAVA-CRYPTO-002")
