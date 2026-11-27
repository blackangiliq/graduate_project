"""Show unknown configuration values without manufacturing vulnerability verdicts."""
from pathlib import Path

import pytest

from sca.flutter import inventory
from sca.walker import SourceFile


def inspect(text, reveal=True):
    sf = SourceFile(Path("res/values/strings.xml"), "res/values/strings.xml", "config",
                    text, origin="decoded")
    return inventory.build(None, [sf], [], reveal_values=reveal)


@pytest.mark.parametrize("name", ["idp_device_sdk_api_token", "idp_public_api_token",
                                  "custom_client_secret", "customApiKey", "password"])
def test_named_candidate_is_full_visible_with_exact_place_without_finding(name):
    value = "CandidateValue18BytesForReview"
    result = inspect(f'<resources>\n<string translatable="false" name=\'{name}\'>{value}</string>\n</resources>')
    item, = result["config"]
    assert item["value"] == value and item["name"] == name
    assert item["classification"] == "credential_candidate"
    assert item["requires_review"] and item["secret"]
    assert item["vulnerability_confirmed"] is False
    assert item["locations"] == [{"file": "res/values/strings.xml", "line": 2}]
    assert result["keys"] == [] and result["alerts"] == []


@pytest.mark.parametrize("name,service", [
    ("passenger_appmetrica_production_token", "AppMetrica"),
    ("appmetrica_api_key", "AppMetrica"),
    ("passenger_webengage_staging_token", "WebEngage"),
])
def test_recognized_client_identifier_is_not_a_private_secret_claim(name, service):
    item, = inspect(f'<string name="{name}">Client123Identifier</string>')["config"]
    assert item["service"] == service and item["classification"] == "sdk_client_identifier"
    assert item["secret"] is False and item["vulnerability_confirmed"] is False


@pytest.mark.parametrize("name", ["appmetrica_post_api_key", "webengage_rest_api_key",
                                  "webengage_server_token", "appmetrica_private_key"])
def test_sdk_name_does_not_exempt_server_credentials(name):
    item, = inspect(f'<string name="{name}">ServerCandidate012345</string>')["config"]
    assert item["classification"] == "credential_candidate" and item["secret"]


@pytest.mark.parametrize("name,value", [
    ("title_activity_password", "PasswordActivity"),
    ("password_toggle_content_description", "ShowPassword"),
    ("ERROR_INVALID_SECRET_KEY", "InvalidSecretKey"),
    ("hint_enter_password", "Password123"),
    ("auth_token", "@string/configured_token"),
    ("auth_token", "${TOKEN_FROM_RUNTIME}"),
    ("auth_token", "https://config.audit.example/"),
    ("auth_token", "true"), ("auth_token", "false"),
    ("token", "Please enter your access token"),
    ("token", "your_token_here"), ("token", "token"),
])
def test_ui_labels_refs_flags_and_placeholders_are_not_configuration_secrets(name, value):
    assert inspect(f'<string name="{name}">{value}</string>')["config"] == []


def test_long_configuration_value_is_never_cut_to_old_300_character_limit():
    value = "Candidate123" * 70
    text = '<string name="custom_api_token">' + value + '</string>'
    visible, = inspect(text)["config"]
    assert visible["value"] == value
    legacy, = inspect(text, reveal=False)["config"]
    assert value not in legacy["value"]


@pytest.mark.parametrize("assignment,expected", [
    ('PASSWORD="FixtureValue123 #literal"', 'FixtureValue123 #literal'),
    ("PASSWORD='FixtureValue123 #literal' # outside", 'FixtureValue123 #literal'),
    ('PASSWORD="FixtureValue123 #literal"#outside', 'FixtureValue123 #literal'),
    ('PASSWORD=FixtureValue123 # outside', 'FixtureValue123'),
    ('PASSWORD=FixtureValue123#inside', 'FixtureValue123#inside'),
    ('PASSWORD="FixtureValue123 \\" #literal" #outside', 'FixtureValue123 \\" #literal'),
    ('PASSWORD="Unterminated123 #literal', '"Unterminated123 #literal'),
])
def test_env_comments_are_removed_only_outside_the_value(assignment, expected):
    sf = SourceFile(Path("assets/.env"), "assets/.env", "config", assignment, origin="decoded")
    result = inventory.build(None, [sf], [], reveal_values=True)
    item, = result["env"]
    assert item["value"] == expected
    assert item["file"] == sf.rel and item["line"] == 1
    assert expected in sf.lines[0]


def test_quoted_configuration_keeps_escaped_quotes_and_does_not_parse_log_labels():
    value = 'Fixture123\\"Value456'
    sf = SourceFile(Path("assets/config.js"), "assets/config.js", "javascript",
                    'const custom_api_key = "' + value + '";\n'
                    "console.log('TOKEN:',e);var t=(0,l.default)(e,'token');", origin="decoded")
    item, = inventory.build(None, [sf], [], reveal_values=True)["config"]
    assert item["value"] == value and item["name"] == "custom_api_key"
    assert item["locations"] == [{"file": sf.rel, "line": 1}]
