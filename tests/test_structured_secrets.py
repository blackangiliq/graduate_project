"""Exact literal coordinates and conservative negative cases for config credentials."""
from pathlib import Path

import pytest

from sca.engines import secrets
from sca.flutter import inventory
from sca.walker import SourceFile

VALUE = "V7cN9dP2sR4uX6zA8bE3hK5m"


def scan(text, rel="src/Client.kt"):
    sf = SourceFile(Path(rel), rel, "kotlin" if rel.endswith(".kt") else "config", text)
    return sf, secrets.scan_file(sf, rules=[])


@pytest.mark.parametrize("text,rel", [
    ('val apiKey: String = "' + VALUE + '"', "src/Client.kt"),
    ('val apiKey: String? =\n    "' + VALUE + '"', "src/Client.kt"),
    ('private static final String CLIENT_SECRET =\n    "' + VALUE + '";', "src/Client.java"),
    ('const apiKey =\n  "' + VALUE + '";', "lib/client.dart"),
    ('{\n  "client_secret":\n    "' + VALUE + '"\n}', "assets/config.json"),
    ('api.key=' + VALUE, "assets/client.properties"),
    ('access_token: ' + VALUE + ' # deploy credential', "config.yml"),
    ('[service]\napi_key = ' + VALUE, "settings.ini"),
])
def test_structured_credential_has_complete_value_and_exact_value_line(text, rel):
    sf, findings = scan(text, rel)
    finding, = findings
    assert sf.secret_hits[0][2] == VALUE
    assert sf.lines[finding.line - 1][finding.column - 1:finding.end_column - 1] == VALUE
    assert VALUE not in finding.snippet and VALUE not in finding.context
    listed = inventory.build(None, [sf], findings, reveal_values=True)
    assert listed["keys"][0]["value"] == VALUE
    assert listed["keys"][0]["locations"][0]["line"] == finding.line


def test_long_generic_literal_is_retained_in_full_not_a_200_character_fragment():
    value = VALUE * 120
    sf, findings = scan('val privateToken: String = "' + value + '"')
    finding, = findings
    assert sf.secret_hits[0][2] == value
    assert finding.end_column - finding.column == len(value)
    assert len(inventory.build(None, [sf], findings, reveal_values=True)["keys"][0]["value"]) == len(value)


@pytest.mark.parametrize("text,rel", [
    ('val apiKey: String = "your-api-key-here"', "Client.kt"),
    ('val apiKey: String = "${runtimeSecret}"', "Client.kt"),
    ('val apiKey: String = "' + VALUE + '" + suffix', "Client.kt"),
    ('api_key=' + VALUE + '-${SECRET}', "config.yml"),
    ('api_key: https://api.example.invalid/v1', "config.yml"),
    ('token_name: auth_session', "settings.ini"),
    ('api_key_file: credentials.json', "settings.ini"),
    ('password_label: Enter your password', "config.yml"),
    ('client_secret: secret', "config.yml"),
    ('api_key: pk_live_' + VALUE, "config.yml"),
    ('api_key: cache_products_v2', "config.yml"),
    ('api_key: ' + VALUE, "translations/en.yml"),
    ('return x("firebaseRegistrationToken=", this.firebaseRegistrationToken, ")");', "Client.kt"),
    ("console.log('TOKEN:',e);var t=(0,l.default)(e,'token');", "client.js"),
])
def test_templates_labels_public_identifiers_and_computed_fragments_are_not_credentials(text, rel):
    assert scan(text, rel)[1] == []


def test_known_provider_key_is_not_duplicated_as_a_generic_key():
    value = "AIza" + "M" * 35
    sf, findings = scan('val apiKey: String =\n"' + value + '"')
    assert [f.rule_id for f in findings] == ["SECRET-GOOGLE-001"]
    assert sf.secret_hits[0][2] == value


def test_distinct_same_line_values_are_not_deduplicated_by_substring():
    longer = "X" + VALUE + "Y"
    sf, findings = scan('val token="' + VALUE + '"; val otherToken: String="' + longer + '"')
    assert len(findings) == 2 and {hit[2] for hit in sf.secret_hits} == {VALUE, longer}
    assert all(sf.lines[f.line - 1][f.column - 1:f.end_column - 1] in {VALUE, longer} for f in findings)


def test_config_suppression_survives_a_marker_inside_the_masked_literal():
    assert scan('storePassword=' + VALUE + ' // nosec', 'key.properties')[1] == []


def test_minified_log_prose_does_not_turn_intervening_javascript_into_a_token():
    text = ("console.log('Error while retrieving token: ',l),(0,f.default)(t)?"
            "V._unregisterForPushNotifications(u):Promise.resolve(),"
            "console.log('Discarding update registration: ');")
    assert scan(text, 'assets/index.android.bundle')[1] == []


@pytest.mark.parametrize("text,rel,expected", [
    ("api_key=" + VALUE + "#tail", "client.properties", VALUE + "#tail"),
    ("password=" + VALUE + ";tail", "client.properties", VALUE + ";tail"),
    ("password=" + VALUE + " #literal suffix", "client.properties", VALUE + " #literal suffix"),
    ("api_key=" + VALUE + "  ", "client.properties", VALUE + "  "),
    ("api_key: " + VALUE + "#tail", "client.yaml", VALUE + "#tail"),
    ("api_key: " + VALUE + ";tail", "client.yml", VALUE + ";tail"),
    ("api_key: " + VALUE + " # comment", "client.yml", VALUE),
    ("api_key: " + VALUE + "\r\n", "client.yml", VALUE),
    ("api_key=" + VALUE + "\r\n", "client.properties", VALUE),
    ("password=" + VALUE + ";tail\r\n", "client.ini", VALUE + ";tail"),
])
def test_config_comment_syntax_does_not_truncate_complete_literals(text, rel, expected):
    sf, findings = scan(text, rel)
    finding, = findings
    assert sf.secret_hits[0][2] == expected
    assert sf.lines[finding.line - 1][finding.column - 1:finding.end_column - 1] == expected


@pytest.mark.parametrize("text,rel", [
    ("api_key=" + VALUE + " ; ambiguous inline comment", "client.ini"),
    ("api_key=" + VALUE + " # ambiguous inline comment", "client.cfg"),
    ("api_key: *" + VALUE, "client.yml"),
    ("api_key: &anchor " + VALUE, "client.yml"),
    ("api_key: !!str " + VALUE, "client.yml"),
    ("api_key: # " + VALUE, "client.yml"),
    ("api_key: child: " + VALUE, "client.yml"),
    ("api_key=" + VALUE + "\\\ncontinued", "client.properties"),
    ("api_key=" + VALUE, "client.toml"),
])
def test_unsupported_config_expressions_are_not_reported_as_full_literals(text, rel):
    assert scan(text, rel)[1] == []
