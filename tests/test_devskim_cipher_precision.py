"""A user-enabled imported cipher rule must distinguish symmetric ECB from RSA names."""
from dataclasses import replace
import json
from pathlib import Path

import pytest
import yaml

from sca.engines import rules_engine
from sca.walker import SourceFile
from tools.import_rules import DEVSKIM_ADAPTATIONS, import_devskim

RULE_ID = "DEVSKIM-DS187371"


def rule():
    shipped = next(r for r in rules_engine.load_builtin() if r.id == RULE_ID)
    return replace(shipped, enabled=True)


@pytest.mark.parametrize("text", [
    'Cipher.getInstance("RSA/ECB/PKCS1Padding");',
    'Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");',
    'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");',
    'Cipher.getInstance("AES/GCM/NoPadding");',
    'int EAX = 1; String label = "AEAD"; String name = "ECB";',
    'const modes = ["EAX", "OCB", "GCM", "OFB", "XTS", "PMAC"];',
])
def test_rsa_and_unrelated_mode_names_do_not_match(text):
    sf = SourceFile(Path("Source.java"), "Source.java", "java", text)
    assert not rules_engine.scan_file(sf, rules=[rule()])


@pytest.mark.parametrize("text", [
    'tdes.Mode = CipherMode.ECB;',
    'Cipher.getInstance("AES/ECB/PKCS5Padding");',
    'Cipher.getInstance("DES/ECB/NoPadding");',
    'Cipher.getInstance("DESede/ECB/PKCS5Padding");',
    'Cipher.getInstance("Blowfish/ECB/NoPadding");',
    'Cipher.getInstance("RC2/ECB/PKCS5Padding");',
])
def test_explicit_symmetric_ecb_settings_keep_their_line(text):
    sf = SourceFile(Path("Source.java"), "Source.java", "java", "// heading\n" + text)
    finding, = rules_engine.scan_file(sf, rules=[rule()])
    assert finding.rule_id == RULE_ID and finding.line == 2


@pytest.mark.parametrize("order", [0, 1])
def test_rsa_on_same_line_does_not_suppress_a_real_aes_match(order):
    parts = ['Cipher.getInstance("RSA/ECB/PKCS1Padding");', 'Cipher.getInstance("AES/ECB/NoPadding");']
    text = " ".join(parts if order == 0 else reversed(parts))
    assert [m.group() for m in rule().pattern.finditer(text)] == ['"AES/ECB/NoPadding"']
    sf = SourceFile(Path("Source.java"), "Source.java", "java", text)
    assert len(rules_engine.scan_file(sf, rules=[rule()])) == 1


def test_user_enable_override_uses_refined_rule_without_changing_default(tmp_path, monkeypatch):
    learned = tmp_path / "learned"
    learned.mkdir()
    edit = {RULE_ID: {"enabled": True}}
    (learned / "edits.yaml").write_text(yaml.safe_dump(edit), encoding="utf-8")
    monkeypatch.setenv("SCA_LEARNED_DIR", str(learned))
    rules_engine.invalidate()
    active = rules_engine.get_rule(RULE_ID)
    assert active.enabled and active.edited and not active.default_enabled
    source = SourceFile(Path("Cipher.java"), "Cipher.java", "java",
                        'Cipher.getInstance("RSA/ECB/PKCS1Padding");\n'
                        'Cipher.getInstance("AES/ECB/NoPadding");')
    findings = rules_engine.scan_file(source, rules=rules_engine.load_rules())
    assert [f.line for f in findings if f.rule_id == RULE_ID] == [2]
    assert yaml.safe_load((learned / "edits.yaml").read_text()) == edit


def test_reimport_preserves_precision_adaptation_and_disabled_state(tmp_path):
    path = tmp_path / "rules/default/crypto.json"
    path.parent.mkdir(parents=True)
    upstream = {"id": "DS187371", "name": "Legacy weak mode check", "tags": ["Cryptography.Symmetric"],
                "patterns": [{"pattern": "ECB|RSA|AEAD", "type": "regexword"}],
                "must-match": ["tdes.Mode = CipherMode.ECB;"], "severity": "important"}
    path.write_text(json.dumps([upstream]), encoding="utf-8")
    imported, report = import_devskim(tmp_path, None, [], 0.5)
    assert len(imported) == 1 and imported[0]["enabled"] is False
    assert report[0]["status"] == "disabled"
    assert "6997e759" in imported[0]["note"]
    for key, value in DEVSKIM_ADAPTATIONS["DS187371"].items():
        assert imported[0][key] == value
    assert imported[0]["pattern"] == rule().pattern.pattern
