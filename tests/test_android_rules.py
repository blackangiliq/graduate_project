"""Android code, Gradle and resource rules through the normal scanning engines."""
from pathlib import Path

import flutter_kit as kit
import pytest

from sca.engines import rules_engine, secrets
from sca.pipeline import ScanOptions, run_scan
from sca.walker import SourceFile, detect_language, mask_secret

TEST_VALUE = "q8DmY6xW" + "7FuV3kPa"


def make_file(path, text, origin=""):
    return SourceFile(Path(path), path, detect_language(Path(path)), text, origin=origin)


@pytest.mark.parametrize(("rule_id", "path", "line"), [
    ("CODEQL-ANDROID-WEBVIEW-FILE-ACCESS", "app/src/main/java/ui/Page.java",
     "settings.setAllowFileAccessFromFileURLs(true);"),
    ("CODEQL-ANDROID-WEBVIEW-FILE-ACCESS", "android/app/src/main/kotlin/ui/Browser.kt",
     "webView.settings.allowFileAccessFromFileURLs = true"),
    ("ANDROID-WEBVIEW-MIXED-CONTENT", "app/src/main/kotlin/ui/Browser.kt",
     "settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW"),
    ("ANDROID-INTENT-IMPLICIT-MUTABLE", "app/src/main/kotlin/ui/Notify.kt",
     "PendingIntent.getBroadcast(this, 0, Intent(), PendingIntent.FLAG_MUTABLE)"),
    ("ANDROID-LOG-SENSITIVE", "app/src/main/java/ui/Login.java",
     'Log.d(TAG, "Session " + response.accessToken);'),
])
def test_android_source_rules_match_java_and_kotlin(rule_id, path, line):
    findings = rules_engine.scan_file(make_file(path, line))
    assert rule_id in {finding.rule_id for finding in findings}


def test_certificate_rule_requires_webview_context():
    path = "app/src/main/kotlin/ui/Browser.kt"
    rule = rules_engine.get_rule("CODEQL-ANDROID-WEBVIEW-CERTIFICATE")
    start = "override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {\n"
    assert rules_engine.scan_file(make_file(path, start + "    handler.proceed()\n}"), rules=[rule])
    assert not rules_engine.scan_file(make_file(path, "val handler = worker()\nhandler.proceed()"),
                                      rules=[rule])
    assert not rules_engine.scan_file(make_file(path, start + "    handler.cancel()\n}"), rules=[rule])


@pytest.mark.parametrize(("rule_id", "path", "line"), [
    ("ANDROID-SECRET-RESOURCE", "app/src/main/res/values/strings.xml",
     '<string name="service_client_secret">%s</string>'),
    ("ANDROID-SECRET-RESOURCE", "app/src/main/res/values-es/service.xml",
     '<string name="service_client_secret">%s</string>'),
    ("ANDROID-SECRET-BUILD-CONFIG", "app/build.gradle",
     """buildConfigField 'String', 'SERVICE_CLIENT_SECRET', '"%s"'"""),
    ("ANDROID-SECRET-BUILD-CONFIG", "app/build.gradle.kts",
     r'buildConfigField("String", "SERVICE_CLIENT_SECRET", "\"%s\"")'),
    ("ANDROID-SECRET-BUILD-CONFIG", "android/app/build.gradle.kts",
     'resValue("string", "service_client_secret", "%s")'),
    ("ANDROID-SECRET-CRYPTO-LITERAL", "app/src/main/java/Storage.java",
     'SecretKeySpec key = new SecretKeySpec("%s".getBytes(), "AES");'),
    ("ANDROID-SECRET-CRYPTO-LITERAL", "app/src/main/kotlin/Storage.kt",
     'val key = SecretKeySpec("%s".toByteArray(), "AES")'),
    ("ANDROID-SECRET-HTTP-BASIC", "app/src/main/kotlin/Api.kt",
     'val credential = Credentials.basic("account", "%s")'),
])
def test_mobile_secret_rules_mask_value_and_explain_remediation(rule_id, path, line):
    file = make_file(path, line % TEST_VALUE)
    finding = next(f for f in secrets.scan_file(file) if f.rule_id == rule_id)
    assert TEST_VALUE not in finding.snippet and TEST_VALUE not in finding.context
    assert finding.description and finding.fix


def test_secret_rules_respect_scope_and_leave_placeholders_alone():
    settings = '<string name="private_api_key">%s</string>' % TEST_VALUE
    assert not secrets.scan_file(make_file("docs/sample.xml", settings))
    assert not secrets.scan_file(make_file("lib/guide.dart", settings))
    assert not secrets.scan_file(make_file("app/res/values/strings.xml",
                                           settings.replace(TEST_VALUE, "your_api_key_here")))
    assert not secrets.scan_file(make_file("app/res/values/strings.xml",
                                           settings.replace("private_api_key", "google_api_key")))
    dynamic = 'resValue("string", "service_client_secret", props["SERVICE_CLIENT_SECRET"])'
    assert not secrets.scan_file(make_file("app/build.gradle.kts", dynamic))


def test_apk_report_masks_android_resource_credential_and_compiled_supabase_key(tmp_path):
    supabase = "sb_" + "secret_" + TEST_VALUE
    path = tmp_path / "android.apk"
    path.write_bytes(kit.build_apk(mode="none", strings={"service_client_secret": TEST_VALUE},
                                   dex_strings=[supabase]))
    result = run_scan(str(path), ScanOptions(use_bandit=False, use_ml=False, save=False))
    ids = {rule_id: finding for finding in result.findings for rule_id in finding.rule_ids}
    assert ids["ANDROID-SECRET-RESOURCE"].file == "res/values/strings.xml"
    assert ids["DART-SECRET-003"].file == "classes.dex"
    values = {key["value"] for key in result.app["apis"]["keys"]}
    assert {mask_secret(TEST_VALUE), mask_secret(supabase)} <= values
    serialized = str(result.to_dict())
    assert TEST_VALUE not in serialized and supabase not in serialized


@pytest.mark.parametrize("separator", ["\n", r"\n"])
def test_private_key_payload_is_masked_in_context(separator):
    import base64
    # Structurally valid EncryptedPrivateKeyInfo: AlgorithmIdentifier + encrypted octets.
    der = bytes.fromhex("3028300406022a030420") + bytes(range(32))
    payload = base64.b64encode(der).decode()
    pem = separator.join(["-----BEGIN ENCRYPTED PRIVATE KEY-----", payload,
                          "-----END ENCRYPTED PRIVATE KEY-----"])
    file = make_file("app/key.pem", pem)
    finding = next(f for f in secrets.scan_file(file) if f.rule_id == "SECRET-KEY-001")
    assert payload not in finding.context and payload not in finding.snippet
    assert "*" in finding.context
