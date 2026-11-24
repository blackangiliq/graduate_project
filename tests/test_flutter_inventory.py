"""Tests for the API and key inventory (sca/flutter/inventory.py): what it lists for a Flutter
project and for an app package, the alerts, the masking of every secret, and its use in the
pipeline, the reports, the command line and the dashboard.

The keys below are invented. Those in formats that GitHub's push protection knows are joined
from parts, so that the repository holds no such key in one piece. The scans of real packages
run only when SCA_FLUTTER_API_DIR holds release.apk, release_obf.apk and debug.apk built from
samples/flutter_api_probe (python tools/build_flutter_apks.py --app flutter_api_probe
--modes release,obfuscated,debug --out DIR).
"""
import json
import os
import re
import zlib
from pathlib import Path

import pytest

import flutter_kit as kit
from sca.__main__ import main as cli
from sca.flutter import inventory
from sca.flutter.inventory import jwt_claims, mask_url, service_of
from sca.models import Finding
from sca.pipeline import ScanOptions, inspect_mobile, run_scan
from sca.report import write_reports

ROOT = Path(__file__).resolve().parent.parent
API_DIR = Path(os.environ.get("SCA_FLUTTER_API_DIR", "") or "missing")
API_PACKAGES = ("release.apk", "release_obf.apk", "debug.apk")
real_api_probe = pytest.mark.skipif(
    not all((API_DIR / n).is_file() for n in API_PACKAGES),
    reason="SCA_FLUTTER_API_DIR does not hold the packages of samples/flutter_api_probe")
QUIET = dict(save=False, use_ml=False, use_feedback=False, use_semgrep=False,
             use_gitleaks=False)
FAST = ["--no-save", "--quiet", "--no-ml", "--no-semgrep", "--no-gitleaks", "--no-bandit"]

STRIPE = "sk_" + "live_" + "51InvTestKey0123456789abcdefXYZ"
GOOGLE = "AIza" + "SyInv3ntoryTestKey0123456789abcdefg"
SLACK_TOKEN = "abcdefghijklmnop" + "12345678"
SLACK = "https://hooks.slack.com/services/" + "T0INV0000/B0INV0000/" + SLACK_TOKEN
BOT_TOKEN = "123456789:" + "AAHinventory-test-token-0123456789"
TELEGRAM = "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage"
URL_PASSWORD = "Pa55w0rdInv"
HMAC = "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
SECRETS = (STRIPE, GOOGLE, SLACK_TOKEN, BOT_TOKEN, URL_PASSWORD, HMAC)
FIREBASE_STRINGS = {"app_name": "Kit App",
                    "google_app_id": "1:123456789012:android:0a1b2c3d4e5f6a7b",
                    "project_id": "kit-demo",
                    "firebase_database_url": "https://kit-demo-default-rtdb.firebaseio.com",
                    "google_storage_bucket": "kit-demo.appspot.com"}

API_DART = """import 'dart:io';

import 'package:http/http.dart' as http;

class Api {
  static const baseUrl = 'https://api.shop.example/v1';
  static const staging = 'https://staging.shop.example/v1';
  static const lan = 'http://192.168.0.10:8080/api';
  static const stripeKey = '%(stripe)s';
  static const hook = '%(slack)s';
  final _dio = Dio(BaseOptions(baseUrl: baseUrl));

  Future<void> login(String user) async {
    await http.post(
      Uri.parse('https://api.shop.example/v1/auth/login'),
      body: {'user': user},
    );
    await _dio.get<Map<String, dynamic>>('/api/v1/orders');
    await HttpClient().getUrl(Uri.https('api.shop.example', '/v1/profile'));
    final channel = WebSocketChannel.connect(Uri.parse('wss://live.shop.example/ws'));
    final saved = await prefs.get('token');
    final receipt = '$baseUrl/receipt.pdf?access_token=$saved';
  }
}
""" % {"stripe": STRIPE, "slack": SLACK}
PROJECT_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="shop">
        <activity android:name=".MainActivity" android:exported="true" />
        <meta-data
            android:name="com.google.android.geo.API_KEY"
            android:value="%s" />
        <meta-data
            android:name="com.google.android.gms.ads.APPLICATION_ID"
            android:value="ca-app-pub-3940256099942544~3347511713" />
    </application>
</manifest>
""" % GOOGLE
STRINGS_XML = "<resources>\n%s</resources>\n" % "".join(
    '    <string name="%s">%s</string>\n' % item for item in FIREBASE_STRINGS.items())


def shop_project(folder: Path) -> Path:
    files = {
        "pubspec.yaml": "name: shop\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n"
                        "  flutter:\n    sdk: flutter\nflutter:\n  assets:\n    - assets/.env\n",
        "lib/api.dart": API_DART,
        "android/app/src/main/AndroidManifest.xml": PROJECT_MANIFEST,
        "android/app/src/main/res/values/strings.xml": STRINGS_XML,
        "assets/.env": "API_URL=https://api.shop.example/v1\nPAYMENT_HMAC_SECRET=%s\n" % HMAC,
        "test/api_test.dart": "const fake = 'https://never-listed.example/api';\n",
    }
    for rel, text in files.items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_text(text, encoding="utf-8")
    return folder


def line_of(text: str, needle: str) -> int:
    return next(n for n, line in enumerate(text.splitlines(), 1) if needle in line)


def endpoint(apis, url):
    return next(e for e in apis["endpoints"] if e["url"] == url)


def codes(apis):
    return [a["code"] for a in apis["alerts"]]


def pdf_text(data):
    parts = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        try:
            parts.append(zlib.decompress(match.group(1)))
        except zlib.error:
            parts.append(match.group(1))
    return b"\n".join(parts).decode("latin-1")


def kit_apk() -> bytes:
    """A release APK with the keys and addresses in the snapshot, the resources, the
    manifest and the assets."""
    manifest = kit.MANIFEST.replace("    </application>", (
        '        <meta-data android:name="com.google.android.geo.API_KEY"\n'
        '            android:value="%s" />\n    </application>') % GOOGLE)
    return kit.build_apk(
        manifest=manifest, strings=FIREBASE_STRINGS,
        assets={"flutter_assets/assets/.env": "PAYMENT_HMAC_SECRET=%s\n" % HMAC,
                "flutter_assets/assets/config.json":
                    '{"collector": "http://collect.kit-shop.example/v1/events"}\n'},
        extra_strings=[STRIPE, SLACK, TELEGRAM, "https://api.kit-shop.example/v2",
                       "https://dev-api.kit-shop.example/v2", "/api/v2/cart/items/",
                       "/receipt.pdf?access_token=", "api.kit-shop.example",
                       "com.example.kitapp.service", "https://3f2a-81-12-4-9.ngrok-free.app/hook",
                       "https://admin:%s@back.kit-shop.example/admin" % URL_PASSWORD,
                       "https://developer.android.com/guide", "/data/data/com.example/files"])


# ------------------------------------------------------------------ helpers
def test_mask_url_hides_the_secrets_that_addresses_carry():
    assert URL_PASSWORD not in mask_url("https://admin:%s@h.example/a" % URL_PASSWORD)
    masked = mask_url("https://h.example/geo?api_key=%s&q=x&token=" % HMAC)
    assert HMAC not in masked and masked.endswith("&q=x&token=")    # empty values stay
    assert SLACK_TOKEN not in mask_url(SLACK) and "T0INV0000/B0INV0000/" in mask_url(SLACK)
    masked = SLACK.replace(SLACK_TOKEN, "abcd****78")               # masked once already
    assert mask_url(masked) == masked
    assert BOT_TOKEN not in mask_url(TELEGRAM) and mask_url(TELEGRAM).endswith("/sendMessage")
    hook = "https://discord.com/api/webhooks/123456789/" + "A" * 30
    assert "A" * 30 not in mask_url(hook)
    assert mask_url("https://h.example/v1/?key=$apiKey") == "https://h.example/v1/?key=$apiKey"


def test_jwt_claims_and_services():
    token = ("eyJhbGciOiJIUzI1NiJ9." + "eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUi"
             "LCJleHAiOjIwMDAwMDAwMDB9" + ".c2ln")
    assert jwt_claims(token) == {"iss": "supabase", "role": "service_role", "exp": "2033-05-18"}
    assert jwt_claims("a.b.c") == {} and jwt_claims("eyJ.eyJ!!!.x") == {}
    assert service_of("abc-default-rtdb.firebaseio.com") == ("Firebase Realtime Database",
                                                             "backend")
    assert service_of("mybucket.s3.eu-west-1.amazonaws.com") == ("Amazon S3", "backend")
    assert service_of("discord.com", "/api/webhooks/1/x") == ("Discord webhook", "webhook")
    assert service_of("x.ngrok-free.app")[1] == "tunnel"
    assert service_of("api.shop.example") == ("", "app")
    assert service_of("10.1.2.3") == ("IP address", "app")
    assert inventory._dev_host("api-dev.shop.example") and inventory._dev_host("qa2.a.example")
    assert not inventory._dev_host("shop-demo-default-rtdb.firebaseio.com")
    assert not inventory._dev_host("devices.example")              # the domain itself


def test_secrets_engine_finds_webhooks_bot_tokens_and_env_values():
    from sca.engines import secrets
    from sca.walker import SourceFile

    def scan(rel, text):
        sf = SourceFile(path=Path(rel), rel=rel, language="config", text=text)
        return sf, secrets.scan_file(sf)

    sf, found = scan("lib/a.dart", "const a = '%s';\nconst b = '%s';\n" % (SLACK, TELEGRAM))
    assert [f.rule_id for f in found] == ["SECRET-SLACK-002", "SECRET-TELEGRAM-001"]
    assert set(sf.secret_values) == {SLACK_TOKEN, BOT_TOKEN}       # only the token is masked
    assert "hooks.slack.com/services/T0INV0000" in sf.line_text(1)
    sf, found = scan("assets/.env", "API_URL=https://a.example\nPAYMENT_HMAC_SECRET=%s\n"
                                    "DB_PASSWORD=changeme\nTOKEN_URL=https://t.example\n"
                                    "STRIPE_KEY=\"%s\"\n" % (HMAC, STRIPE))
    assert [(f.line, f.rule_id) for f in found] == [(2, "SECRET-HARDCODED-001"),
                                                    (5, "SECRET-STRIPE-001")]
    assert HMAC not in sf.line_text(2)
    _sf, found = scan(".env.production", "MAPS_KEY=%s\nKEY_ID=%s\nKEYBOARD=%s\n" % (
        HMAC, HMAC, HMAC))                                         # *_KEY, not KEY_ID
    assert [f.line for f in found] == [1]
    _sf, found = scan("lib/b.dart", "final s = 'PAYMENT_HMAC_SECRET=%s';\nPAYMENT_HMAC_SECRET=%s\n"
                      % (HMAC, HMAC))                            # NAME=value only in .env files
    assert not any(f.rule_id == "SECRET-HARDCODED-001" for f in found)
    _sf, found = scan("docs/notes.txt", "version 12345678:AAnot-a-token\n")
    assert found == []


# ------------------------------------------------------------------ a Flutter project
def test_inventory_of_a_flutter_project(tmp_path):
    project = shop_project(tmp_path / "shop")
    result = run_scan(str(project), ScanOptions(**QUIET))
    apis = result.app["apis"]
    assert "ok (" in result.engine_notes["api inventory"]
    dumped = json.dumps(result.app)
    assert [s for s in SECRETS if s in dumped] == []               # every secret is masked

    base = endpoint(apis, "https://api.shop.example/v1")
    assert {"file": "lib/api.dart", "line": line_of(API_DART, "baseUrl = ")} in base["locations"]
    assert {"file": "assets/.env", "line": 1} in base["locations"] and base["count"] == 2
    assert endpoint(apis, "https://staging.shop.example/v1")["alerts"] == ["dev_host"]
    assert endpoint(apis, "http://192.168.0.10:8080/api")["alerts"] == ["cleartext",
                                                                        "private_ip"]
    hook = next(e for e in apis["endpoints"] if e["host"] == "hooks.slack.com")
    assert hook["category"] == "webhook" and "webhook" in hook["alerts"]
    assert "never-listed" not in dumped                            # test code is left out

    calls = {(c["method"], c["target"]) for c in apis["calls"]}
    assert ("POST", "https://api.shop.example/v1/auth/login") in calls     # two lines down
    assert ("GET", "/api/v1/orders") in calls                       # dio with a generic type
    assert ("GET", "https://api.shop.example/v1/profile") in calls  # built with Uri.https
    assert ("BASE", "baseUrl") in calls
    assert any(method == "WS" and "live.shop.example" in target for method, target in calls)
    assert not any("token" in target for _, target in calls)        # prefs.get is no request
    paths = {p["path"]: p for p in apis["paths"]}
    assert "/api/v1/orders" in paths
    assert paths["/receipt.pdf?access_token=$saved"]["alerts"] == ["secret_in_url"]

    keys = {k["advice"]: k for k in apis["keys"]}
    stripe = keys["stripe"]
    assert stripe["value"].startswith("sk_l") and "*" in stripe["value"]
    assert stripe["locations"] == [{"file": "lib/api.dart",
                                    "line": line_of(API_DART, "stripeKey")}]
    google = keys["google"]
    assert google["locations"][0]["file"] == "android/app/src/main/AndroidManifest.xml"
    assert "com.google.android.geo.API_KEY" in google["used_by"]
    config = {(c["label"], c["value"]) for c in apis["config"]}
    assert ("Firebase project ID", "kit-demo") in config
    assert ("AdMob app ID", "ca-app-pub-3940256099942544~3347511713") in config
    assert apis["firebase"]["project_id"] == "kit-demo"
    assert apis["firebase"]["database_urls"] == ["https://kit-demo-default-rtdb.firebaseio.com"]
    env = {e["name"]: e for e in apis["env"]}
    assert env["API_URL"]["value"] == "https://api.shop.example/v1" and not env["API_URL"]["secret"]
    assert env["PAYMENT_HMAC_SECRET"]["secret"] and HMAC[:4] in env["PAYMENT_HMAC_SECRET"]["value"]

    found = codes(apis)
    for code in ("keys_in_source", "cleartext", "dev_host", "private_ip", "webhook",
                 "secret_in_url", "env_asset", "firebase_db", "storage_bucket"):
        assert code in found, code
    levels = [inventory.LEVEL_RANK[a["level"]] for a in apis["alerts"]]
    assert levels == sorted(levels)                                 # the most serious first
    summary = apis["summary"]
    assert summary["keys"] == len(apis["keys"]) and summary["endpoints"] == len(apis["endpoints"])
    assert any("API inventory: " in str(step) for step in result.steps)


def test_inventory_without_mobile_context_and_limits(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.py").write_text("URL = 'https://api.plain.example/v1'\n", encoding="utf-8")
    result = run_scan(str(plain), ScanOptions(**QUIET))
    assert "apis" not in result.app and "api inventory" not in result.engine_notes

    from sca.walker import SourceFile
    lines = ["'https://h%d.example/api'" % (n % 400) for n in range(1200)]
    sf = SourceFile(path=Path("lib/many.dart"), rel="lib/many.dart", language="dart",
                    text="\n".join(lines))
    apis = inventory.build(None, [sf], [])
    assert len(apis["endpoints"]) == inventory.MAX_ITEMS
    assert apis["truncated"]["endpoints"] == 400 - inventory.MAX_ITEMS
    first = endpoint(apis, "https://h0.example/api")
    assert first["count"] == 3 and len(first["locations"]) == 3
    many = SourceFile(path=Path("lib/one.dart"), rel="lib/one.dart", language="dart",
                      text="\n".join(["'https://one.example/api'"] * 50))
    one = inventory.build(None, [many], [])["endpoints"][0]
    assert one["count"] == 50 and len(one["locations"]) == inventory.MAX_LOCATIONS


def test_keys_come_from_the_findings_and_are_grouped_by_value(tmp_path):
    from sca.walker import SourceFile
    text = "const a = '%s';\nconst b = '%s';\n" % (STRIPE, STRIPE)
    sf = SourceFile(path=Path("lib/k.dart"), rel="lib/k.dart", language="dart", text=text)
    from sca.engines import secrets
    found = secrets.scan_file(sf)
    apis = inventory.build(None, [sf], found)
    assert len(apis["keys"]) == 1
    key = apis["keys"][0]
    assert key["count"] == 2 and [loc["line"] for loc in key["locations"]] == [1, 2]
    dismissed = [Finding(**{**f.__dict__, "status": "dismissed"}) for f in found]
    assert inventory.build(None, [sf], dismissed)["keys"] == []
    # a rule finding without the secrets engine: the value of the line, not a variable name
    rule = Finding(rule_id="DART-X", title="Hard-coded encryption key", file="lib/k.dart",
                   line=1, severity="high", cwe="CWE-321")
    names = SourceFile(path=Path("lib/e.dart"), rel="lib/e.dart", language="dart",
                       text="final k = dotenv.env['PAYMENT_SECRET_KEY'];\n")
    other = Finding(rule_id="DART-Y", title="Secret from .env", file="lib/e.dart", line=1,
                    severity="medium", cwe="CWE-798")
    items = {k["rule_id"]: k for k in inventory.build(None, [sf, names], [rule, other])["keys"]}
    assert items["DART-X"]["advice"] == "crypto" and items["DART-X"]["value"].startswith("sk_l")
    assert items["DART-Y"]["value"] == ""


# ------------------------------------------------------------------ an app package
def test_inventory_of_a_release_apk(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(kit_apk())
    result = run_scan(str(path), ScanOptions(**QUIET))
    apis = result.app["apis"]
    dumped = json.dumps(result.app)
    assert [s for s in SECRETS if s in dumped] == []
    urls = {e["url"]: e for e in apis["endpoints"]}
    assert "api.kit-shop.example" in urls and urls["api.kit-shop.example"]["host_only"]
    assert "com.example.kitapp.service" not in urls                 # a package name
    assert not any("developer.android.com" in url for url in urls)  # documentation
    assert urls["https://dev-api.kit-shop.example/v2"]["alerts"] == ["dev_host"]
    assert urls["http://collect.kit-shop.example/v1/events"]["cleartext"]
    telegram = next(e for e in apis["endpoints"] if e["host"] == "api.telegram.org")
    assert "telegram" in telegram["alerts"] and telegram["url"].endswith("/sendMessage")
    assert {p["path"] for p in apis["paths"]} == {"/api/v2/cart/items/",
                                                  "/receipt.pdf?access_token="}
    keys = {k["advice"]: k for k in apis["keys"]}
    assert keys["stripe"]["locations"][0]["file"] == "lib/arm64-v8a/libapp.so"
    assert keys["stripe"]["severity"] == "critical"
    assert "geo.API_KEY" in keys["google"]["used_by"]
    assert apis["firebase"]["storage_buckets"] == ["kit-demo.appspot.com"]
    found = codes(apis)
    for code in ("keys_in_app", "key", "cleartext", "tunnel", "webhook", "telegram",
                 "password_in_url", "dev_host", "secret_in_url", "env_file", "firebase_db",
                 "strings_visible", "services"):
        assert code in found, code
    assert apis["calls"] == []                                      # no code text in release
    env = next(a for a in apis["alerts"] if a["code"] == "env_file")
    assert env["level"] == "danger" and env["file"].endswith("assets/.env")


def test_reports_command_line_and_inspect_show_the_inventory(tmp_path, capsys):
    path = tmp_path / "app.apk"
    path.write_bytes(kit_apk())
    result = run_scan(str(path), ScanOptions(**QUIET))
    written = write_reports(result, str(tmp_path / "out"), ["html", "json", "sarif", "pdf"])
    html = Path(written["html"]).read_text(encoding="utf-8")
    sarif = Path(written["sarif"]).read_text(encoding="utf-8")
    pdf = pdf_text(Path(written["pdf"]).read_bytes())
    for text in (html, sarif, pdf, Path(written["json"]).read_text(encoding="utf-8")):
        assert [s for s in SECRETS if s in text] == []
    for text in ("<h2>APIs and keys</h2>", "Keys, tokens and passwords (masked)",
                 "Server addresses", "API paths", "Firebase project", "Service identifiers",
                 "ngrok tunnel", "kit-demo.appspot.com"):
        assert text in html, text
    assert "<h3>Endpoints" not in html                              # replaced by the inventory
    assert "APIs and keys" in pdf
    inventory_props = json.loads(sarif)["runs"][0]["properties"]["apiInventory"]
    assert inventory_props["summary"]["keys"] == result.app["apis"]["summary"]["keys"]
    assert any("Stripe" in a["text"] for a in inventory_props["alerts"])

    ctx, _files, _findings, note = inspect_mobile(str(path))
    assert ctx.facts["apis"]["summary"]["keys"] >= 3 and "API inventory failed" not in note
    # `flutter apis` also takes the keys that only a rule finds (an AES key in Dart code)
    project = shop_project(tmp_path / "shop")
    (project / "lib" / "crypto.dart").write_text(
        "final key = Key.fromUtf8('shop-wallet-key-2023-v1-32bytes!');\n", encoding="utf-8")
    plain = inspect_mobile(str(project))[0].facts["apis"]["keys"]
    full = inspect_mobile(str(project), key_rules=True)[0].facts["apis"]["keys"]
    assert not any(k["advice"] == "crypto" for k in plain)
    assert any(k["advice"] == "crypto" and k["locations"][0]["file"] == "lib/crypto.dart"
               for k in full)

    capsys.readouterr()
    assert cli(["flutter", "apis", str(path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("APIs and keys: ") and "DANGER  The app package holds" in out
    assert "Server addresses (" in out and "lib/arm64-v8a/libapp.so:" in out
    assert [s for s in SECRETS if s in out] == []
    assert cli(["flutter", "apis", "--json", str(path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) >= {"summary", "alerts", "keys", "endpoints", "hosts", "calls", "paths",
                         "config", "env", "firebase"}
    assert cli(["flutter", "info", str(path)]) == 0
    assert "APIs and keys: " in capsys.readouterr().out
    assert cli(["scan", str(path), "--format", "", *FAST]) == 0
    out = capsys.readouterr().out
    assert "APIs   : " in out and "  ! The app package holds" in out


def test_inventory_of_the_samples():
    """The samples: the vulnerable app lists its keys and servers, the safe one has no key
    and no unencrypted address."""
    vulnerable = run_scan(str(ROOT / "samples" / "flutter_vulnerable_app"),
                          ScanOptions(**QUIET)).app["apis"]
    assert {"aws", "service_role", "signing", "crypto"} <= {k["advice"]
                                                            for k in vulnerable["keys"]}
    assert "service_role" in codes(vulnerable)
    assert any(c["target"] == "https://api.paygate.example/v1/charges"
               for c in vulnerable["calls"])
    safe = run_scan(str(ROOT / "samples" / "flutter_safe_app"), ScanOptions(**QUIET)).app["apis"]
    assert safe["summary"]["cleartext"] == 0
    assert [k for k in safe["keys"] if not k["public"]] == []
    api = run_scan(str(ROOT / "samples" / "flutter_api_probe"), ScanOptions(**QUIET)).app["apis"]
    assert api["summary"]["calls"] >= 12 and "tunnel" in codes(api)
    assert {"Firebase app ID", "AdMob app ID", "Google OAuth client ID", "Sentry DSN",
            "Stripe publishable key", "Mapbox public token"} <= {c["label"] for c in api["config"]}


# ------------------------------------------------------------------ review findings
def source(rel, text, language="dart"):
    from sca.walker import SourceFile
    return SourceFile(path=Path(rel), rel=rel, language=language, text=text)


def test_regexes_stay_fast_on_crafted_text():
    """Texts of an app package are untrusted: a line that never closes its quote, or long
    runs of separators, must not make a regex backtrack for seconds (ReDoS)."""
    import time
    lines = ["fetch('" + "\\n" * 300, "final r = await http.get('" + "\\t" * 300,
             "final key = Key.fromUtf8('" + "\\'" * 300, "a." * 2000, "/a" * 2000,
             "x = '" + "$a." * 1000, "<" * 3000, "(" * 3000, "@GET('" + "a/" * 1000]
    files = [source("lib/a.dart", "\n".join(lines)),
             source("web/a.js", "\n".join(lines), "javascript"),
             source("lib/arm64-v8a/libapp.so", "\n".join(lines), "config")]
    files[2].origin = "strings"
    began = time.time()
    inventory.build(None, files, [])
    for line in lines:
        inventory.rule_key_value(line)
        inventory._first_literal(line)
    assert time.time() - began < 3


def test_every_key_of_a_line_is_listed_with_its_own_type():
    aws, github = "AKIAIOSFODNN7EXAMPLE", "gh" + "p_" + "A" * 36
    text = ("const keys = {'aws': '%s', 'stripe': '%s', 'gh': '%s'};\n"
            "const awsKeys = ['%s', '%s'];\n" % (aws, STRIPE, github, aws, "AKIA" + "Z" * 16))
    project = Path(__import__("tempfile").mkdtemp()) / "keys"
    (project / "lib").mkdir(parents=True)
    (project / "lib" / "keys.dart").write_text(text, encoding="utf-8")
    (project / "pubspec.yaml").write_text("name: k\ndependencies:\n  flutter:\n    sdk: flutter\n",
                                          encoding="utf-8")
    keys = run_scan(str(project), ScanOptions(**QUIET)).app["apis"]["keys"]
    by_value = {k["value"]: k for k in keys}
    assert by_value["AKIA************LE"]["type"] == "AWS access key ID"
    assert by_value["AKIA************LE"]["count"] == 2   # the same AWS key on lines 1 and 2
    assert by_value["AKIA************ZZ"]["count"] == 1   # the second AWS key of line 2
    assert {k["type"] for k in keys} == {"AWS access key ID", "Stripe live key", "GitHub token"}
    assert all(k["count"] == len(k["locations"]) for k in keys)


def test_keys_of_adjacent_lines_merged_by_the_scan_stay_apart(tmp_path):
    project = shop_project(tmp_path / "shop")
    (project / "lib" / "k.dart").write_text(
        "// keys\n\nconst jwtSecret = 'my-super-secret-jwt-signing-key-2024';\n"
        "final key = Key.fromUtf8('shop-wallet-key-2023-v1-32bytes!');\n", encoding="utf-8")
    result = run_scan(str(project), ScanOptions(**QUIET))
    keys = [k for k in result.app["apis"]["keys"]
            if any(loc["file"] == "lib/k.dart" for loc in k["locations"])]
    assert sorted(loc["line"] for k in keys for loc in k["locations"]) == [3, 4]
    assert {k["advice"] for k in keys} >= {"crypto"}
    for secret in ("my-super-secret-jwt-signing-key-2024", "shop-wallet-key-2023-v1-32bytes!"):
        assert secret not in json.dumps(result.to_dict())   # snippets mask rule keys too


def test_secrets_are_masked_in_every_file_and_in_config_values(tmp_path):
    """A key found in strings.xml is masked where libapp.so quotes it, config values and the
    Firebase summary go through the URL masking, and *_PASS .env values are secrets."""
    token = "Q8vT3mZp0LkW9xYb2cRn"
    dsn_password = "Dsn5ecretP4ss"
    strings = dict(FIREBASE_STRINGS, firebase_database_url=(
        "https://kit-demo.firebaseio.com/.json?auth=%s" % token),
        sentry_dsn="https://abc:%s@o1.ingest.sentry.io/2" % dsn_password)
    manifest = kit.MANIFEST.replace("    </application>", (
        '        <meta-data android:name="io.sentry.dsn" android:value="@string/sentry_dsn" />\n'
        "    </application>"))
    path = tmp_path / "app.apk"
    path.write_bytes(kit.build_apk(
        manifest=manifest, strings=strings,
        assets={"flutter_assets/assets/.env": "SMTP_PASS=Hunter2Hunter2\n"
                                              "ADMIN_PASSPHRASE=correct-horse-battery\n"
                                              "SECRET=q7Rz2Lp9Xv4Kd8Wm3Nt6\nHMAC=%s\n" % HMAC},
        extra_strings=["https://cdn.kit-shop.example/a?x=%s" % GOOGLE, "Bearer " + GOOGLE]))
    result = run_scan(str(path), ScanOptions(**QUIET))
    written = write_reports(result, str(tmp_path / "out"), ["html", "json"])
    texts = [json.dumps(result.app)] + [Path(p).read_text(encoding="utf-8")
                                        for p in written.values()]
    for secret in (token, dsn_password, "Hunter2Hunter2", "correct-horse-battery",
                   "q7Rz2Lp9Xv4Kd8Wm3Nt6", HMAC, GOOGLE):
        assert not any(secret in text for text in texts), secret
    env = {e["name"]: e for e in result.app["apis"]["env"]}
    assert all(env[name]["secret"] for name in ("SMTP_PASS", "ADMIN_PASSPHRASE", "SECRET", "HMAC"))


def test_env_rule_skips_settings_that_are_not_secrets():
    from sca.engines import secrets
    sf = source("assets/.env", "CACHE_KEY=homepage_products_v2\nSTORAGE_KEY=flutter_secure_storage\n"
                               "SORT_KEY=created_at_descending\nAPI_KEY_URL=https://a.example/v1\n"
                               "CERT_KEY=certs/server.pem\nMAPS_KEY=%s\n" % HMAC, "config")
    assert [f.line for f in secrets.scan_file(sf)] == [6]
    template = source(".env.example", "PAYMENT_HMAC_SECRET=%s\n" % HMAC, "config")
    assert secrets.scan_file(template) == []               # a template holds made-up values


def test_webhooks_mask_only_their_token():
    from sca.engines import secrets
    workflow_token = "Wq3Er5Ty7Ui9Op1As2Df4Gh6"
    sf = source("lib/h.dart", "const workflowHook = 'https://hooks.slack.com/workflows/T01ABCDE23/"
                              "A04FGHIJ56/489327650193827465/%s';\n"
                              "static const discordToken = 'https://discord.com/api/webhooks/"
                              "123456789/%s';\n" % (workflow_token, "Zq8X" * 9))
    found = secrets.scan_file(sf)
    assert [f.rule_id for f in found] == ["SECRET-SLACK-002", "SECRET-DISCORD-001"]
    assert sf.secret_values == ["Zq8X" * 9, workflow_token]
    assert "489327650193827465" in sf.line_text(1) and workflow_token not in sf.line_text(1)
    assert "discord.com/api/webhooks/123456789/" in sf.line_text(2)


def test_calls_hosts_and_services_avoid_look_alikes():
    code = source("lib/c.dart", "await restaurantBox.put(r.id, r);\ninterestsBox.get('k');\n"
                                "_audioCache.fetch('beep.mp3');\nobserver.send(event);\n"
                                "if (baseUrl == null) return;\nawait _api.get('/v1/users');\n"
                                "final r = await ApiService().post('/v1/orders', body);\n")
    js = source("web/a.js", "fetch(url, {headers: {'X': 'y'}});\n", "javascript")
    calls = {(c["method"], c["target"]) for c in inventory.build(None, [code, js], [])["calls"]}
    assert calls == {("GET", "/v1/users"), ("POST", "/v1/orders"), ("-", "url")}
    assert inventory.client_like("_dio") and inventory.client_like("HttpClient")
    assert not inventory.client_like("audioCache") and not inventory.client_like("observer")
    dump = source("lib/arm64-v8a/libapp.so", "\n".join([
        "user.id", "settings.info", "home.page", "pending.in", "sa.gov.absher.app",
        "id.co.bankmandiri.app", "com.example.kitapp", "api.kit-shop.example", "backend.example.com",
        "myshop.io", "shopapi.dev", "ws.myshop.com", "eu.posthog.com"]), "config")
    dump.origin = "strings"
    hosts = {e["host"] for e in inventory.build(None, [dump], [])["endpoints"]}
    assert hosts == {"api.kit-shop.example", "backend.example.com", "myshop.io", "shopapi.dev",
                     "ws.myshop.com", "eu.posthog.com"}
    assert service_of("s3k2j4h5g6.execute-api.us-east-1.amazonaws.com") == ("AWS API Gateway",
                                                                          "backend")
    assert service_of("s3.eu-west-1.amazonaws.com")[0] == "Amazon S3"
    advice = {}
    for name in ("AWS_SECRET_ACCESS_KEY", "JWT_SECRET", "AES_KEY"):
        finding = Finding(rule_id="SECRET-HARDCODED-001", title="Hard-coded secret in '%s'" % name,
                          file="x", line=1, cwe="CWE-798")
        advice[name] = inventory._Inventory(None, [], [])._key_item(
            finding, finding.rule_id, finding.title, "high", "x7Kq9Lm2Np4Rs6Tv")["advice"]
    assert advice == {"AWS_SECRET_ACCESS_KEY": "aws", "JWT_SECRET": "jwt", "AES_KEY": "crypto"}
    assert inventory.rule_key_value("final s = dotenv.env['stripe_secret_key'];") == ""
    assert inventory.rule_key_value("String.fromEnvironment('openaiApiKey')") == ""
    assert inventory.rule_key_value("Key.fromBase64('q83vEjRWeJA/EjRWeJCrzQ==')") == \
        "q83vEjRWeJA/EjRWeJCrzQ=="
    for line, value in (("final k = Key.fromUtf8('my_secret_aes_key_0123456789abcd');",
                         "my_secret_aes_key_0123456789abcd"),
                        ("final k = Key.fromUtf8('mySecretAesKey0123456789');",
                         "mySecretAesKey0123456789"),
                        ("keyPassword=myKeyPass2024", "myKeyPass2024"),
                        ("    storePassword 'my_store_pass_2024'", "my_store_pass_2024")):
        assert inventory.rule_key_value(line) == value, line
    assert inventory.rule_key_value("x = 'sk_live_abc', defaultValue: 'zz'", "DART-SECRET-002") == ""
    code = source("lib/b.dart", "static String get baseUrl => 'https://api.example.com/v1';\n")
    assert [(c["method"], c["target"]) for c in inventory.build(None, [code], [])["calls"]] == \
        [("BASE", "https://api.example.com/v1")]


def test_truncation_counts_every_left_out_item():
    lines = ["'https://h%d.example/api'" % n for n in range(1000)]
    lines += ["'/api/v1/item%d'" % n for n in range(1000)]
    apis = inventory.build(None, [source("lib/m.dart", "\n".join(lines))], [])
    assert apis["summary"]["endpoints"] == 1000 and apis["summary"]["paths"] == 1000
    assert apis["truncated"]["endpoints"] == 1000 - inventory.MAX_ITEMS
    assert apis["truncated"]["paths"] == 1000 - inventory.MAX_ITEMS


def test_bundled_env_finding_is_no_key_and_dismissed_keys_leave(tmp_path):
    path = tmp_path / "app.apk"
    path.write_bytes(kit_apk())
    result = run_scan(str(path), ScanOptions(**QUIET))
    apis = result.app["apis"]
    assert not any(k["rule_id"] == "FLUTTER-APP-006" for k in apis["keys"])
    secret_before = apis["summary"]["secret_keys"]
    stripe = next(f for f in result.findings if f.rule_id == "SECRET-STRIPE-001")
    stripe.status = "dismissed"
    inventory.refresh_keys(apis, result.findings)
    assert apis["summary"]["secret_keys"] == secret_before - 1
    assert not any("Stripe live key" in a["text"] for a in apis["alerts"])
    html = Path(write_reports(result, str(tmp_path / "o"), ["html"])["html"]).read_text("utf-8")
    section = html[html.index("<h2>APIs and keys</h2>"):html.index("<h2>", html.index(
        "<h2>APIs and keys</h2>") + 5)]
    assert "Stripe live key" not in section and "AWS access key ID" in section
    stripe.status = "open"
    inventory.refresh_keys(apis, result.findings)
    assert apis["summary"]["secret_keys"] == secret_before
    assert any("Stripe live key" in a["text"] for a in apis["alerts"])


def test_second_review_round(tmp_path):
    """Regressions found by the second review: merged lines, rule severities, the Firebase
    order, short values, query and webhook tokens, .env comments and names, refresh counts."""
    from sca.engines import secrets
    project = shop_project(tmp_path / "shop")
    teams = ("https://contoso.webhook.office.com/webhookb2/" + "1a2b3c4d-1111-2222-3333-444455556666@"
             "9f8e7d6c-1111-2222-3333-444455556666/IncomingWebhook/" + "a1" * 16 +
             "/0a1b2c3d-1111-2222-3333-444455556666")
    query_token = "Zt5Kp8Wm2Lq9Xr4Vn7Bc3"
    files = {
        "lib/cfg.dart": "const openAi = String.fromEnvironment('OPENAI_API_KEY');\n"
                        "const stripeKey = '%s';\n" % STRIPE,
        "lib/maps.dart": "final u = Uri.parse('https://maps.googleapis.com/m?key=%s');\n" % GOOGLE,
        "lib/firebase_options.dart": "const apiKey = '%s';\nconst projectId = 'kit-demo';\n"
                                     "const databaseURL = 'https://kit-demo.firebaseio.com';\n"
                                     % GOOGLE,
        "lib/net.dart": "http.get(Uri.parse('https://api.shop.example/v1/q?token=%s'));\n"
                        "final hook = '%s';\n" % (query_token, teams),
        "android/key.properties": "storePassword=android\nkeyPassword=android\n",
        "lib/host.dart": "const android = 'https://android.myshop.example/api';\n",
        "assets/.env": "JWT_SECRET=q7Rz2Lp9Xv4Kd8Wm3Nt6Yb5 # rotate yearly\n"
                       "API_KEY_HEADER_NAME=X-Shop-Api-Key\nREDIS_URL=redis://:Rp9Lk2Mz7Qx4@cache.example\n",
    }
    for rel, text in files.items():
        (project / rel).parent.mkdir(parents=True, exist_ok=True)
        (project / rel).write_text(text, encoding="utf-8")
    result, scanned = __import__("sca.pipeline", fromlist=["scan_project"]).scan_project(
        str(project), ScanOptions(**QUIET))
    apis = result.app["apis"]
    dumped = json.dumps(result.to_dict(), ensure_ascii=False)
    for secret in (query_token, "Rp9Lk2Mz7Qx4", "q7Rz2Lp9Xv4Kd8Wm3Nt6Yb5", teams[-36:], STRIPE):
        assert secret not in dumped, secret
    assert "android.myshop.example" in dumped           # 'android' masks only its own file
    keys = apis["keys"]
    dart_define = [k for k in keys if k["rule_id"] == "DART-SECRET-002"]
    assert dart_define and dart_define[0]["locations"][0] == {"file": "lib/cfg.dart", "line": 1}
    assert dart_define[0]["severity"] == "medium"        # the rule's, not the merged finding's
    google = next(k for k in keys if k["value"].startswith("AIza"))
    assert not google["public"] and google["advice"] == "google"   # also outside Firebase
    assert {c["target"] for c in apis["calls"]} >= {
        "https://api.shop.example/v1/q?token=" + inventory.mask_secret(query_token)}
    env = {e["name"]: e for e in apis["env"]}
    assert env["JWT_SECRET"]["secret"] and "#" not in env["JWT_SECRET"]["value"]
    found = secrets.scan_file(source("assets/.env", files["assets/.env"], "config"))
    assert [f.line for f in found] == [1, 3]             # the header name is no secret
    # every file of the scan masks every secret of the scan (AI prompts, learner, reports)
    other = next(sf for sf in scanned if sf.rel == "lib/host.dart")
    assert inventory.mask_secret(STRIPE) in other.mask(STRIPE)


def test_refresh_keeps_counts_of_cut_lists_and_matches_any_rule():
    lines = ["const s%d = '%s%02d';" % (n, STRIPE[:-2], n) for n in range(60)]
    lines += ["'https://staging%d.shop.example/api'" % n for n in range(60)]
    sf = source("lib/many.dart", "\n".join(lines))
    from sca.engines import secrets
    found = secrets.scan_file(sf)
    apis = inventory.build(None, [sf], found)
    before = dict(apis["summary"]["alerts"])
    assert len(apis["alerts"]) == inventory.MAX_ALERTS and apis["truncated"]["alerts"] > 0
    inventory.refresh_keys(apis, found)
    assert apis["summary"]["alerts"] == before            # nothing changed, nothing recounted
    found[0].status = "dismissed"
    inventory.refresh_keys(apis, found)
    assert apis["summary"]["alerts"]["danger"] == before["danger"] - 1
    assert apis["summary"]["secret_keys"] == 59
    # one key found by two rules in two files: dismissed when both findings are
    token = "Zx9Qw8Er7Ty6Ui5Op4As"
    a = source("lib/a.dart", "const password = '%s';\n" % token)
    b = source("lib/b.dart", "final db = 'postgres://app:%s@db.example/x';\n" % token)
    found = secrets.scan_file(a) + secrets.scan_file(b)
    apis = inventory.build(None, [a, b], found)
    assert len(apis["keys"]) == 1 and apis["keys"][0]["count"] == 2
    for finding in found:
        finding.status = "dismissed"
    inventory.refresh_keys(apis, found)
    assert apis["keys"][0]["dismissed"] and apis["summary"]["secret_keys"] == 0


def test_flutter_apis_masks_rule_keys_like_a_scan(tmp_path, capsys):
    project = shop_project(tmp_path / "shop")
    key = "Wq9Xk2Lm7Np4Rt6Vz8Yb3Cd5Fg7Hj1Q"
    (project / "lib" / "crypto.dart").write_text("final k = Key.fromUtf8('%s');\n" % key,
                                                 encoding="utf-8")
    (project / "assets" / "config.json").write_text(            # the key in an address path
        '{"backup": "https://b.example/restore/%s/latest"}\n' % key, encoding="utf-8")
    capsys.readouterr()
    assert cli(["flutter", "apis", "--json", str(project)]) == 0
    assert key not in capsys.readouterr().out
    assert cli(["flutter", "info", "--json", str(project)]) == 0
    assert key not in capsys.readouterr().out


def test_third_review_round(tmp_path, capsys):
    """Weak values stay in their file, .env addresses are no secrets, values come from the
    rule's own match, quoted and public .env values, Teams and base64 JWT masking, and a
    suppressed check line is no key for `flutter apis` either."""
    from sca.engines import secrets
    project = shop_project(tmp_path / "shop")
    files = {
        "tool/dev_db.dart": "const db = 'postgres://admin:admin@localhost:5432/shop';\n",
        "lib/users.dart": "final u = Uri.parse('http://admin.myshop.example/api/v1/users');\n",
        "assets/auth.env": "AUTH_URL=http://auth.myshop.example/v1\nAUTH0_DOMAIN=shop.eu.auth0.com\n"
                           "STRIPE_PUBLISHABLE_KEY=pk_test_51Abc0123456789abcdefXYZ\n"
                           "JWT_KEY=\"Jk3Lm5Np7Qr9St1Uv3Wx\"\n",
        "lib/weather.dart": "const weatherKey = String.fromEnvironment('WEATHER_API_KEY', "
                            "defaultValue: 'Zq8Rt2Lm5Np7Vx1Bc3Hk9Wd4');\n",
        "lib/jwt.dart": "final token = JWT({'id': id}).sign(SecretKey('Yq8Rt2Lm5Np7Vx1Bc3Hk'));\n",
        "android/app/build.gradle": "android { signingConfigs { release { keyAlias 'upload'; "
                                    "keyPassword 'Secr3tKeyPass77'; storePassword "
                                    "'Secr3tKeyPass77' } } }\n",
    }
    for rel, text in files.items():
        (project / rel).parent.mkdir(parents=True, exist_ok=True)
        (project / rel).write_text(text, encoding="utf-8")
    result = run_scan(str(project), ScanOptions(**QUIET))
    dumped = json.dumps(result.to_dict(), ensure_ascii=False)
    assert "admin.myshop.example" in dumped and "auth.myshop.example" in dumped
    for secret in ("Zq8Rt2Lm5Np7Vx1Bc3Hk9Wd4", "Yq8Rt2Lm5Np7Vx1Bc3Hk", "Secr3tKeyPass77",
                   "Jk3Lm5Np7Qr9St1Uv3Wx"):
        assert secret not in dumped, secret
    values = {k["value"] for k in result.app["apis"]["keys"]}
    assert inventory.mask_secret("Zq8Rt2Lm5Np7Vx1Bc3Hk9Wd4") in values       # defaultValue
    assert inventory.mask_secret("Yq8Rt2Lm5Np7Vx1Bc3Hk") in values           # SecretKey(...)
    assert inventory.mask_secret("Secr3tKeyPass77") in values and "u*****" not in values
    env = source("assets/auth.env", files["assets/auth.env"], "config")
    assert [f.line for f in secrets.scan_file(env)] == [4]   # quoted key; no URL, host, pk_
    teams = ("https://contoso.webhook.office.com/webhookb2/1a2b3c4d-1111-2222-3333-"
             "444455556666@9f8e7d6c-1111-2222-3333-444455556666/IncomingWebhook/" + "a1" * 16
             + "/0a1b2c3d-1111-2222-3333-444455556666")
    sf = source("lib/t.dart", "final hook = '%s';\nfinal blob = 'ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0"
                              "NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrcHZ"
                              "hRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeWZR';\n" % teams)
    secrets.scan_file(sf)
    assert "contoso.webhook.office.com/webhookb2/" in sf.line_text(1)
    assert "IncomingWebhook" not in sf.line_text(1)          # the token is masked as one
    assert "lpYVzRnUkc5bEl" not in sf.line_text(2)           # the whole base64 token
    (project / "android" / "key.properties").write_text(
        "storePassword=Kp9Xw2Zq7Lm4Rt // nosec\n", encoding="utf-8")
    capsys.readouterr()
    assert cli(["flutter", "apis", "--json", str(project)]) == 0
    keys = json.loads(capsys.readouterr().out)["keys"]
    assert not any(loc["file"] == "android/key.properties" for k in keys for loc in k["locations"])


def test_intro_counts_the_built_in_key_formats():
    from sca.engines import rules_engine, secrets
    from sca.ui import intro
    secret_rules = sum(1 for r in rules_engine.all_rules() if r.enabled and r.kind == "secret")
    assert intro.facts()["secrets"] == secret_rules + len(secrets.KNOWN_FORMATS) == \
        secret_rules + 11


# ------------------------------------------------------------------ the dashboard
def test_dashboard_shows_the_inventory_in_both_languages(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    import streamlit as st
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path / "learned"))
    monkeypatch.setenv("SCA_ENV_FILE", str(tmp_path / "env"))
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    st.cache_resource.clear()
    st.cache_data.clear()
    path = tmp_path / "app.apk"
    path.write_bytes(kit_apk())
    result = run_scan(str(path), ScanOptions(**QUIET))
    result.app["apis"]["alerts"].append({"level": "warning", "code": "dev_host",
                                         "args": ["[x](http://evil.example)"],
                                         "text": "Development server: [x](http://evil.example)"})
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.session_state["result"] = result
    app.run()
    assert not app.exception
    label = next(e.label for e in app.expander if e.label.startswith("APIs and keys: "))
    assert re.match(r"APIs and keys: \d+ server addresses, \d+ keys, \d+ serious alerts", label)
    errors = [e.value for e in app.error]
    assert any(e.startswith("The app package holds") for e in errors)
    assert any("Stripe live key" in e for e in errors)
    warnings = [w.value for w in app.warning]
    assert any("\\[x\\](http:⁠//evil.example)" in w for w in warnings)   # text, no link
    keys = next(d.value for d in app.dataframe if "Value (masked)" in d.value.columns)
    assert all("*" in v or v == "-" for v in keys["Value (masked)"])
    assert [s for s in SECRETS if any(s in str(v) for v in keys.values.ravel())] == []
    hosts = next(d.value for d in app.dataframe if "Host" in d.value.columns)
    assert "hooks.slack.com" in list(hosts["Host"])
    app.radio[0].set_value("العربية").run()
    assert not app.exception
    assert any(e.label.startswith("واجهات API والمفاتيح: ") for e in app.expander)
    assert any(e.value.startswith("حزمة التطبيق تحوي") for e in app.error)
    assert any("القيمة (مخفيّة جزئياً)" in d.value.columns for d in app.dataframe)


# ------------------------------------------------------------------ real packages
@real_api_probe
@pytest.mark.parametrize("name", ["release.apk", "release_obf.apk"])
def test_real_release_apks_of_the_api_probe(name):
    """What the compiled app gives away: the keys that the source only holds in parts, the
    servers, the webhook and bot tokens, and the Firebase project."""
    result = run_scan(str(API_DIR / name), ScanOptions(**QUIET))
    apis = result.app["apis"]
    keys = {k["advice"]: k for k in apis["keys"]}
    assert keys["stripe"]["severity"] == "critical"                 # joined by the compiler
    assert keys["stripe"]["locations"][0]["file"].endswith("libapp.so")
    assert keys["aws"]["value"] == "AKIA************LE"
    assert "geo.API_KEY" in keys["google"]["used_by"]
    assert keys["public"]["claims"]["role"] == "anon"
    hosts = {e["host"]: e for e in apis["endpoints"]}
    for host in ("api.shop-probe.example", "staging-api.shop-probe.example",
                 "graph.shop-probe.example", "realtime.shop-probe.example", "192.168.1.20",
                 "3f2a-81-12-4-9.ngrok-free.app", "hooks.slack.com", "api.telegram.org",
                 "abcdefghijklmnopqrst.supabase.co", "shop-probe-demo-default-rtdb.firebaseio.com"):
        assert host in hosts, host
    found = codes(apis)
    for code in ("keys_in_app", "cleartext", "tunnel", "webhook", "telegram", "password_in_url",
                 "private_ip", "dev_host", "secret_in_url", "env_file", "supabase",
                 "firebase_db", "storage_bucket", "strings_visible"):
        assert code in found, code
    assert {"/api/v2/cart/items/", "/receipt.pdf?access_token=", "/v2/orders"} <= {
        p["path"] for p in apis["paths"]}
    assert apis["firebase"]["project_id"] == "shop-probe-demo"


@real_api_probe
def test_real_debug_apk_of_the_api_probe_lists_the_calls():
    apis = run_scan(str(API_DIR / "debug.apk"), ScanOptions(**QUIET)).app["apis"]
    calls = {(c["method"], c["target"]) for c in apis["calls"]}
    assert ("POST", "https://api.shop-probe.example/v2/orders") in calls
    assert ("WS", "ApiConfig.socketUrl") in calls
    assert all(c["file"] == "dart/lib/main.dart" for c in apis["calls"])
    assert "debug_build" in codes(apis)
