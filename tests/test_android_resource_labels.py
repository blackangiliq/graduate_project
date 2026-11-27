from pathlib import Path

import pytest

from sca.engines import secrets
from sca.walker import SourceFile


@pytest.mark.parametrize("name", ["title_activity_password", "hint_enter_password",
                                  "label_private_key", "error_invalid_access_token"])
def test_android_ui_labels_are_not_classified_as_credentials(name):
    content = f'<string name="{name}">PasswordActivity</string>'
    source = SourceFile(Path("res/values/strings.xml"), "res/values/strings.xml", "config", content)
    assert "ANDROID-SECRET-RESOURCE" not in {f.rule_id for f in secrets.scan_file(source)}


def test_backend_resource_secret_still_detected():
    content = '<string name="service_client_secret">q8DmY6xW7FuV3kPa</string>'
    source = SourceFile(Path("res/values/strings.xml"), "res/values/strings.xml", "config", content)
    assert "ANDROID-SECRET-RESOURCE" in {f.rule_id for f in secrets.scan_file(source)}


def test_braze_sdk_identifier_does_not_exempt_rest_credentials():
    sdk = '<string name="com_braze_api_key">e6b93127-83cc-412b-a06b-d18f88d170ac</string>'
    rest = '<string name="braze_rest_api_key">q8DmY6xW7FuV3kPa</string>'
    source = SourceFile(Path("res/values/strings.xml"), "res/values/strings.xml", "config", sdk + "\n" + rest)
    assert [(f.rule_id, f.line) for f in secrets.scan_file(source)] == [("ANDROID-SECRET-RESOURCE", 2)]
