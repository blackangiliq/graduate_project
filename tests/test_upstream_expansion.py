"""Independent literal/call fixtures for the 2026-11-27 rule expansion.

Tokens are generated locally and are not valid credentials. Production captures never
use these fixtures. The assertions exercise full values, context, negative cases and
source coordinates through the actual engines, not regex-only self checks.
"""
import hashlib
import json
import random
import string
from pathlib import Path

import pytest
import yaml

from sca.engines import rules_engine, secrets
from sca.walker import SourceFile
from tools.import_contextual_secrets import REVIEWED, convert

ROOT = Path(__file__).resolve().parent.parent


def payload(length, alphabet=string.ascii_letters + string.digits):
    rng = random.Random(719 + length)
    return "".join(rng.choice(alphabet) for _ in range(length))


HEX = "0123456789abcdef"
UUID = "-".join(payload(n, HEX) for n in (8, 4, 4, 4, 12))
CASES = [
    ("asaas-api-token", "value", "$aact_prod_" + payload(36)),
    ("azure-app-configuration-connection-string", "azure", "Endpoint=https://sample.azconfig.io;Id=identity;Secret=" + payload(52)),
    ("azure-servicebus-connection-string", "azure", "Endpoint=sb://sample.servicebus.windows.net/;SharedAccessKeyName=owner;SharedAccessKey=" + payload(44)),
    ("canadian-digital-service-notify-api-key", "value", "ApiKey-v1 gcntfy-client-" + UUID + "-" + UUID),
    ("clickup-personal-api-token", "clickup", "pk_12345678_" + payload(32, string.ascii_lowercase + string.digits)),
    ("crates-io-api-key", "crates", "cio" + payload(32)),
    ("databento-api-key", "databento", "db-" + payload(29)),
    ("deepseek-api-key", "deepseek", "sk-" + payload(32, HEX)),
    ("elevenlabs-api-key", "elevenlabs", "sk_" + payload(48, HEX)),
    ("fal-api-key.1", "fal_api", UUID + ":" + payload(32, HEX)),
    ("figma-personal-access-header-token", "x-figma-token", "1A2B-" + UUID.upper()),
    ("gitlab-pat-routable-versioned", "value", "glpat-" + payload(50) + ".ab." + payload(9, string.ascii_lowercase + string.digits)),
    ("kagi-api-key", "kagi", payload(11) + "." + payload(43)),
    ("kimi-api-key", "moonshot", "sk-" + payload(48)),
    ("mem0-api-key.1", "mem0", "m0-" + payload(32)),
    ("ngrok-api-key.1", "ngrok_authtoken", "2" + payload(26) + "_7" + payload(20)),
    ("ollama-api-key", "ollama", payload(32, HEX) + "." + payload(24)),
    ("retell-api-key.1", "retell", "key_" + payload(28, HEX)),
    ("zhipu-api-key", "zhipu", payload(32, HEX) + "." + payload(17)),
    ("zoho-oauth-token.1", "zoho", "1000." + payload(32, HEX) + "." + payload(32, HEX)),
    ("zoho-zapi-key.1", "zoho", "1003." + payload(48, HEX)),
]


@pytest.mark.parametrize("language,origin", [
    ("java", ""), ("kotlin", ""), ("dart", ""), ("config", "decoded"),
    ("config", "strings"), ("javascript", ""),
])
@pytest.mark.parametrize("provider,context,value", CASES, ids=[r[0] for r in CASES])
def test_new_formats_preserve_full_values_and_exact_line(language, origin, provider, context, value):
    rule = rules_engine.get_rule("BETTERLEAKS-" + provider)
    sf = SourceFile(Path("app/input"), "app/input", language,
                    "unrelated\n" + f'{context} = "{value}"' + "\nend", origin=origin)
    found = secrets.scan_file(sf, rules=[rule])
    assert any(f.rule_id == rule.id and f.line == 2 for f in found)
    # Azure's appconfig detector intentionally captures Secret only, not public Id/Endpoint.
    expected = value.split("Secret=", 1)[1] if provider.startswith("azure-app-") else value
    assert [(hit[0], hit[2]) for hit in sf.secret_hits if hit[1] == rule.id] == [(2, expected)]


@pytest.mark.parametrize("provider,context,value", CASES, ids=[r[0] for r in CASES])
def test_context_placeholders_and_short_values(provider, context, value):
    rule = rules_engine.get_rule("BETTERLEAKS-" + provider)
    for placeholder in ("<TOKEN>", "${SERVICE_KEY}", value[:8]):
        assert not list(secrets.match_secret_rule(rule, f'{context} = "{placeholder}"'))
    if context not in ("value", "azure"):
        assert not list(secrets.match_secret_rule(rule, f'unrelated = "{value}"'))


def test_every_contextual_rule_is_covered_and_filters_are_not_erased():
    assert {r[0] for r in CASES} == REVIEWED
    base = {"id": "asaas-api-token", "regex": r"(foo[a-z]{32})", "confidence": "high"}
    assert convert({**base, "filter": "arbitraryCode()"})[0] is None
    assert convert({**base, "components": [{"id": "host"}]})[0] is None
    assert convert({**base, "path": r".*\.json"})[0] is None
    assert convert({**base, "valueGroup": 5})[0] is None
    raw, reason = convert({**base, "filter": 'entropy(finding["secret"]) <= 3.5'})
    assert not reason and raw["entropy"] > 3.5
    assert not {"validate", "revoke", "analyze", "components"} & raw.keys()


def test_import_manifest_matches_pack_and_all_decisions_are_explicit():
    pack = yaml.safe_load((ROOT / "sca/rules/imported/betterleaks_contextual.yaml").read_text())
    report = json.loads((ROOT / "evaluation/contextual_secrets_import_report.json").read_text())
    assert pack["source"] == report["source"]
    assert len(pack["rules"]) == report["counts"]["enabled"] == len(REVIEWED)
    assert len(report["rules"]) == report["upstream_rules"] == 486
    assert all(row["reason"] for row in report["rules"])
    assert not any({"validate", "revoke", "analyze", "components"} & row.keys() for row in pack["rules"])


LIBRARY_RULES = yaml.safe_load((ROOT / "sca/rules/library_security.yaml").read_text())


@pytest.mark.parametrize("raw", LIBRARY_RULES, ids=[r["id"] for r in LIBRARY_RULES])
@pytest.mark.parametrize("origin", ["", "decompiled"])
def test_library_settings_have_real_code_locations_and_ignore_documentation(raw, origin):
    rule = rules_engine.get_rule(raw["id"])
    language = raw["languages"][0]
    comment = "# " if language == "python" else "// "
    vulnerable = raw["examples_vulnerable"][0]
    lines = [*raw["examples_safe"], comment + vulnerable, 'doc = "' + vulnerable + '"', vulnerable]
    sf = SourceFile(Path("app/Source"), "app/Source", language, "\n".join(lines), origin=origin)
    results = rules_engine.scan_file(sf, rules=[rule])
    assert [(f.file, f.line) for f in results] == [(sf.rel, len(lines))]
    assert results[0].snippet == vulnerable
    for safe in raw["examples_safe"]:
        sf = SourceFile(Path("app/Safe"), "app/Safe", language, safe)
        assert not rules_engine.scan_file(sf, rules=[rule])


def test_nearby_library_context_is_required_and_bounded():
    cases = [
        ("JVM-JJWT-UNSECURED", "java", "var builder = Jwts.parser();", "builder.unsecured();"),
        ("JVM-FASTJSON-AUTOTYPE", "java", "ParserConfig config = new ParserConfig();", "config.setAutoTypeSupport(true);"),
        ("DART-INAPPWEBVIEW-SAFE-BROWSING", "dart", "InAppWebViewSettings(", "safeBrowsingEnabled: false,"),
    ]
    for rule_id, language, context, call in cases:
        rule = rules_engine.get_rule(rule_id)
        def scan(text):
            return rules_engine.scan_file(SourceFile(Path("app/source"), "app/source", language, text), rules=[rule])
        assert scan(context + "\n" + call)
        assert not scan(call)
        assert not scan(context + "\n" * 8 + call)


def test_new_rules_do_not_run_api_patterns_on_binary_string_dumps():
    rule = rules_engine.get_rule("JVM-NETTY-INSECURE-TRUST")
    sf = SourceFile(Path("classes.dex"), "classes.dex", "java",
                    rule.examples_vulnerable[0], origin="strings")
    assert not rules_engine.scan_file(sf, rules=[rule])


def test_rule_guide_is_generated_from_defaults_not_local_overrides():
    from tools.build_docs import rules_md
    shipped = rules_engine.all_rules(include_user=False)
    generated = rules_md()
    assert f"**{len(shipped)} rules, {sum(r.enabled for r in shipped)} of them active**" in generated
    assert "Historical DevSkim/Gitleaks import baseline" in generated
    assert "UPSTREAM_RULES_2026_11_27.md" in generated
    assert "betterleaks_contextual.yaml | 21 | 21" in generated
    assert (ROOT / "docs/RULES.md").read_text(encoding="utf-8") == generated


def test_pinned_source_verifier_rejects_changed_content(tmp_path, monkeypatch):
    from tools import verify_rule_sources
    data = b"reviewed source content\n"
    sha = hashlib.sha256(data).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"sources": [{"repository": "example/reference",
        "commit": "a" * 40, "path": "src/example.py", "sha256": sha}]}))
    monkeypatch.setattr(verify_rule_sources, "MANIFEST", manifest)
    cache = tmp_path / "cache"
    cache.mkdir()
    source = cache / (sha + ".source")
    source.write_bytes(data)
    assert verify_rule_sources.verify(cache)[0]["verified"]
    source.write_bytes(data + b"changed")
    with pytest.raises(ValueError, match="changed"):
        verify_rule_sources.verify(cache)


def test_reference_manifest_contains_pinned_artifacts_not_floating_branches():
    import re
    manifest = json.loads((ROOT / "evaluation/upstream_sources_2026_11_27.json").read_text())
    assert len(manifest["sources"]) == 22
    assert len({(r["repository"], r["path"]) for r in manifest["sources"]}) == 22
    for source in manifest["sources"]:
        assert re.fullmatch("[a-f0-9]{40}", source["commit"])
        assert re.fullmatch("[a-f0-9]{64}", source["sha256"])
        assert source["commit"] in source["url"] and source["use"]
