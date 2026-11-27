"""Independent format fixtures and safe/unsafe API cases for the pinned rule additions."""
import json
import string
from pathlib import Path

import pytest
import yaml

from sca.engines import rules_engine, secrets
from sca.walker import SourceFile
from tools.import_betterleaks import COMMIT, SOURCE_SHA256, convert

ROOT = Path(__file__).resolve().parents[1]


def payload(size, alphabet=string.ascii_letters + string.digits):
    # Nonfunctional test material; does not derive from the rule's regular expression.
    return "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(size))


FORMATS = [
    ("aikido-ci-token", "AIK_CI_" + payload(32)),
    ("anthropic-oauth-access-token", "sk-ant-oat01-" + payload(80)),
    ("anthropic-oauth-refresh-token", "sk-ant-ort01-" + payload(80)),
    ("apify-api-token", "apify_api_" + payload(36)),
    ("brave-search-api-key", "BSA" + payload(30)),
    ("buildkite-user-access-token", "bkua_" + payload(40, string.ascii_lowercase + string.digits)),
    ("cal-api-key", "cal_live_" + payload(32, "0123456789abcdef")),
    ("cerebras-api-key", "csk-" + payload(48)),
    ("daytona-api-key", "dtn_" + payload(64, "0123456789abcdef")),
    ("dockerhub-organization-access-token", "dckr_oat_" + payload(32)),
    ("dockerhub-personal-access-token", "dckr_pat_" + payload(27)),
    ("figma-personal-access-token", "figd_" + payload(40)),
    ("gcp-gemini-api", "AQ.Ab8RN6" + payload(44)),
    ("groq-api-key", "gsk_" + payload(52)),
    ("jina-ai-api-key", "jina_" + payload(60)),
    ("neon-api-key", "napi_" + payload(64)),
    ("nvidia-api-key", "nvapi-" + payload(64)),
    ("openrouter-api-key", "sk-or-v1-" + payload(64, "0123456789abcdef")),
    ("polar-personal-access-token", "polar_pat_" + payload(40)),
    ("replicate-api-token", "r8_" + payload(37)),
    ("supabase-project-api-key", "sb_secret_" + payload(31)),
    ("tavily-api-key", "tvly-" + payload(32)),
    ("upcloud-api-token", "ucat_" + payload(30)),
    ("xai-api-key", "xai-" + payload(80)),
]


@pytest.mark.parametrize("language,origin", [
    ("java", ""), ("kotlin", ""), ("dart", ""), ("config", "decoded"),
    ("config", "strings"), ("javascript", ""),
])
@pytest.mark.parametrize("provider,value", FORMATS, ids=[r[0] for r in FORMATS])
def test_provider_format_keeps_full_value_and_line(language, origin, provider, value):
    rule_id = "BETTERLEAKS-" + provider
    rule = rules_engine.get_rule(rule_id)
    source = SourceFile(Path("app/input"), "app/input", language,
                        "unrelated\n" + f'value = "{value}"' + "\nend", origin=origin)
    findings = secrets.scan_file(source, rules=[rule])
    assert [(f.rule_id, f.line) for f in findings] == [(rule_id, 2)]
    assert [(hit[0], hit[1], hit[2]) for hit in source.secret_hits] == [(2, rule_id, value)]


@pytest.mark.parametrize("provider,value", FORMATS, ids=[r[0] for r in FORMATS])
def test_format_docs_placeholders_and_truncated_tokens_do_not_match(provider, value):
    rule = rules_engine.get_rule("BETTERLEAKS-" + provider)
    assert not list(secrets.match_secret_rule(rule, 'value = "<YOUR_API_KEY>"'))
    assert not list(secrets.match_secret_rule(rule, 'value = "' + value[:8] + '"'))
    assert not list(secrets.match_secret_rule(rule, 'value = "${SERVICE_API_KEY}"'))


def test_contextual_provider_keywords_remain_required():
    for provider, brand, value in [
        ("ionic-personal-access-token", "ionic", "ion_" + payload(42)),
        ("miro-access-token", "miro", "eyJtaXJv" + payload(20) + "_" + payload(30)),
        ("resend-api-key.1", "resend", "re_" + payload(8, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
         + "_" + payload(24, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")),
    ]:
        rule = rules_engine.get_rule("BETTERLEAKS-" + provider)
        assert not list(secrets.match_secret_rule(rule, value))
        assert [value] == [v for _, v in secrets.match_secret_rule(rule, brand + ' = "' + value + '"')]


def test_previously_skipped_gitleaks_formats_and_php_scope():
    airtable = "pat" + payload(14) + "." + payload(64, "0123456789abcdef")
    facebook = "123456789012345" + "|" + payload(32, string.ascii_lowercase + string.digits)
    cases = [("GITLEAKS-airtable-personnal-access-token", "airtable", airtable),
             ("GITLEAKS-facebook-access-token", "facebook", facebook)]
    for rule_id, brand, value in cases:
        rule = rules_engine.get_rule(rule_id)
        assert [value] == [v for _, v in secrets.match_secret_rule(rule, f'{brand} = "{value}"')]
        assert not list(secrets.match_secret_rule(rule, f'{brand} = "<TOKEN>"'))
    freemius = rules_engine.get_rule("GITLEAKS-freemius-secret-key")
    value = "sk_" + payload(29)
    text = "'secret_key' => '" + value + "'"
    php = SourceFile(Path("app/settings.php"), "app/settings.php", "php", text)
    config = SourceFile(Path("app/settings.json"), "app/settings.json", "config", text)
    assert any(f.rule_id == freemius.id for f in secrets.scan_file(php, rules=[freemius]))
    # The generic hard-coded-secret detector can still report this assignment;
    # the provider-specific Freemius classification must keep the PHP scope.
    assert not any(f.rule_id == freemius.id for f in secrets.scan_file(config, rules=[freemius]))


CODE_RULES = yaml.safe_load((ROOT / "sca/rules/imported/codeql_android_extended.yaml").read_text())["rules"]


@pytest.mark.parametrize("raw", CODE_RULES, ids=[r["id"] for r in CODE_RULES])
def test_narrow_codeql_adaptations_have_safe_counterexamples(raw):
    rule = rules_engine.get_rule(raw["id"])
    for text in raw["examples_vulnerable"]:
        language = "kotlin" if "fun " in text or "->" in text and "{" in text else "java"
        sf = SourceFile(Path("app/Source.kt"), "app/Source.kt", language, text)
        assert rules_engine.scan_file(sf, rules=[rule]), (rule.id, text)
        comment = SourceFile(sf.path, sf.rel, language, "// " + text)
        assert not rules_engine.scan_file(comment, rules=[rule])
    for text in raw["examples_safe"]:
        sf = SourceFile(Path("app/Safe.java"), "app/Safe.java", "java", text)
        assert not rules_engine.scan_file(sf, rules=[rule]), (rule.id, text)


def test_conversion_never_silently_drops_filter_or_association_conditions():
    base = {"id": "unknown-provider", "regex": r"\b(new_[A-Za-z0-9]{32})\b",
            "confidence": "high", "keywords": ["new_"]}
    assert convert({**base, "filter": 'tokenRatio(finding["secret"]) > 2'}, set())[0] is None
    assert convert({**base, "components": [{"id": "account-name"}]}, set())[0] is None
    assert convert({**base, "skipReport": True}, set())[0] is None
    assert convert({**base, "path": r".*\.json"}, set())[0] is None
    assert convert({**base, "regex": "["}, set())[0] is None
    assert convert(base, {"unknown-provider"})[0] is None
    raw, _ = convert({**base, "filter": 'entropy(finding["secret"]) <= 3.5'}, set())
    assert raw["entropy"] > 3.5
    assert not {"validate", "revoke", "analyze", "components"} & raw.keys()


def test_pinned_pack_has_explicit_decisions_and_no_network_expressions():
    pack = yaml.safe_load((ROOT / "sca/rules/imported/betterleaks.yaml").read_text())
    report = json.loads((ROOT / "evaluation/betterleaks_import_report.json").read_text())
    assert pack["source"]["commit"] == COMMIT
    assert pack["source"]["sha256"] == SOURCE_SHA256
    assert len(pack["rules"]) == report["counts"]["enabled"] == 80
    assert len(report["rules"]) == report["upstream_rules"] == 486
    assert all(r["reason"] for r in report["rules"])
    assert all(not {"validate", "revoke", "analyze", "components"} & r.keys() for r in pack["rules"])
    assert len({r.id for r in rules_engine.load_builtin()}) == len(rules_engine.load_builtin())
