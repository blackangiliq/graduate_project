"""The Dart and Flutter rules (sca/rules/dart.yaml, sca/rules/flutter.yaml), the `files`
field of a rule, and the walker and taint-lite support for Flutter projects."""
from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
import yaml

from sca import rulebook
from sca.engines import rules_engine, secrets, taint_lite
from sca.learn import loop, store
from sca.models import SEVERITY_RANK
from sca.pipeline import ScanOptions, run_scan
from sca.walker import (CODE_LANGUAGES, SourceFile, detect_language, is_test_path,
                        walk_project)

ROOT = Path(__file__).resolve().parent.parent
LABS = ROOT / "infected_project"
# the CWE ids of the Flutter module (design 2.3) and the ids that fold into them
MODULE_CWES = {22, 78, 79, 89, 94, 200, 284, 287, 295, 311, 312, 319, 321, 327, 328, 338,
               347, 470, 489, 532, 601, 693, 732, 749, 780, 798, 829, 862, 916, 922, 939, 1204}


@pytest.fixture()
def own_rule_folder(tmp_path_factory, monkeypatch):
    """An empty folder for learned and custom rules, edits and exclusions, for a test that
    changes rules (the others share the session's empty folder and its cached rule set)."""
    monkeypatch.setenv("SCA_LEARNED_DIR", str(tmp_path_factory.mktemp("learned")))


def make(code: str, name: str, origin: str = "") -> SourceFile:
    return SourceFile(Path(name), name, detect_language(Path(name)), code, origin=origin)


def found(code: str, name: str = "lib/a.dart") -> set:
    return {f.rule_id for f in rules_engine.scan_file(make(code, name))}


def module_rules():
    return [r for r in rules_engine.all_rules(include_user=False)
            if r.file in ("dart.yaml", "flutter.yaml")]


def hits(rule, line: str) -> bool:
    if rule.kind == "secret":
        return any(True for _ in secrets.match_secret_rule(rule, line))
    return rule.matches(line)


# ------------------------------------------------------------------ the rule files
def test_rule_files_hold_every_dart_rule_and_only_the_flutter_file_rules():
    rules = module_rules()
    dart = {r.id for r in rules if r.file == "dart.yaml"}
    flutter = {r.id for r in rules if r.file == "flutter.yaml"}
    assert len(dart) == 49 and all(i.startswith("DART-") for i in dart)
    assert {"DART-CMD-003", "DART-CODE-002", "DART-CRYPTO-010", "DART-STORAGE-006"} <= dart
    assert flutter == {"FLUTTER-BUILD-001", "FLUTTER-BUILD-002", "FLUTTER-FIREBASE-001",
                       "FLUTTER-FIREBASE-002", "FLUTTER-WEB-001"}
    for rule in rules:
        assert rule.severity in SEVERITY_RANK and rule.title and rule.message and rule.fix
        assert re.fullmatch(r"CWE-\d+", rule.cwe) and int(rule.cwe[4:]) in MODULE_CWES, rule.id
        assert all(language in rulebook.LANGUAGES for language in rule.languages), rule.id
        assert 0 < rule.confidence < 1 and rule.enabled
        assert (rule.file == "flutter.yaml") == bool(rule.files), rule.id
        if rule.file == "dart.yaml":
            assert rule.languages == (["any"] if rule.id == "DART-SECRET-003" else ["dart"])


def test_every_module_rule_passes_at_least_two_examples_of_each_kind():
    for rule in module_rules():
        assert len(rule.examples_vulnerable) >= 2 and len(rule.examples_safe) >= 2, rule.id
        for line in rule.examples_vulnerable:
            assert hits(rule, line), (rule.id, line)
        for line in rule.examples_safe:
            assert not hits(rule, line), (rule.id, line)


def test_module_rules_are_fast_on_long_adversarial_lines():
    lines = ["'" + "${" * 299, "a" * 600, "x = '" + "$a " * 190 + "'", "(" * 300 + ")" * 300,
             "print(" + "token." * 99, "SELECT * FROM t WHERE a = '" + "$x" * 280,
             "'http://" + "a" * 590, "Random(" + "a" * 590, "prefs.setString(" + "'" * 580]
    for rule in module_rules():
        started = time.perf_counter()
        for line in lines:
            hits(rule, line)
            if rule.near:
                rule.near.search(line)
        assert time.perf_counter() - started < 0.5, rule.id


def test_credential_formats_are_found_and_masked_by_the_secrets_engine():
    key = "sb_" + "secret_" + "Qx7Rt2Zp9Lm4Vb8K"            # assembled: no key-shaped literal
    sf = make("const supabaseSecret = '%s';\nfinal ok = 'sb_publishable_x';\n" % key, "lib/k.dart")
    finding = next(f for f in secrets.scan_file(sf) if f.rule_id == "DART-SECRET-003")
    assert finding.line == 1 and finding.severity == "critical" and key not in finding.snippet
    basic = make("final auth = 'Basic ' + base64Encode(utf8.encode('admin:Winter2024'));\n",
                 "lib/api.dart")
    finding = next(f for f in secrets.scan_file(basic) if f.rule_id == "DART-SECRET-001")
    assert "admin:Winter2024" not in finding.snippet and finding.cwe == "CWE-798"


# ------------------------------------------------------------------ context and multi-line code
CONTEXT = [
    ("DART-TLS-002", [5], ["class DevHttpOverrides extends HttpOverrides {", "  @override",
                           "  HttpClient createHttpClient(SecurityContext? context) {",
                           "    final client = super.createHttpClient(context);",
                           "    client.badCertificateCallback = (X509Certificate cert, String host, int port) {",
                           "      return true;", "    };", "    return client;", "  }", "}"]),
    ("DART-TLS-002", [], ["    client.badCertificateCallback = (X509Certificate cert, String host, int port) {",
                          "      return sha256.convert(cert.der).toString() == kPinnedSha256;",
                          "    };"]),
    # pinning as the rule's own fix describes it: return true only inside the comparison
    ("DART-TLS-002", [], ["  client.badCertificateCallback = (X509Certificate cert, String host, int port) {",
                          "    if (sha256.convert(cert.der).toString() == pinnedFingerprint) {",
                          "      return true;", "    }", "    return false;", "  };"]),
    ("DART-TLS-002", [], ["  client.badCertificateCallback = (cert, host, port) {",
                          "    if (cert.pem == kPinnedPem) {", "      return true;", "    }",
                          "    return false;", "  };"]),
    ("DART-TLS-002", [2], ["    HttpClient(context: SecurityContext()).badCertificateCallback =",
                           "        (X509Certificate cert, String host, int port) {",
                           "      return true;", "    };"]),
    ("DART-TLS-001", [2], ["    client.badCertificateCallback =",
                           "        (X509Certificate cert, String host, int port) => true;"]),
    ("DART-TLS-003", [3], ["onSslAuthError: (SslAuthError error) async {",
                           "  debugPrint('ssl error');", "  await error.proceed();", "},"]),
    ("DART-TLS-003", [], ["final job = queue.next();", "await job.proceed();"]),
    ("DART-CRYPTO-007", [1], ["final random = Random();",
                              "final otp = List.generate(6, (_) => random.nextInt(10)).join();"]),
    ("DART-CRYPTO-007", [], ["final random = Random();",
                             "final color = colors[random.nextInt(colors.length)];"]),
    # dio's multipart boundary: a Uint8List next to Random() is no security value
    ("DART-CRYPTO-007", [], ["  static final _rand = Random();",
                             "  final boundary = _nextRandomId();",
                             "  final bytes = Uint8List(16);"]),
    ("DART-CRYPTO-010", [3], ["  /// Define a random number generator with an insecure seed value",
                              "  static const SEED = 12345;", "    final gen1 = Random(SEED);",
                              "    Uint8List insecureBytes = Uint8List(LENGTH);",
                              "      insecureBytes[i] = gen1.nextInt(256);"]),
    ("DART-CRYPTO-010", [], ["final _random = math.Random(0); // fixed seed for reproducibility",
                             "final colors = List.generate(8, (_) => _random.nextInt(255));"]),
    ("DART-CODE-002", [4], ["var instance = Reflectee();",
                            "var instanceMirror = myReflectable.reflect(instance);",
                            "// instanceMirror.invoke('reflecteeMethod', [10]);",
                            "instanceMirror.invoke(input, [10]);"]),
    ("DART-CODE-002", [], ["Actions.invoke(context, const ActivateIntent());"]),
    ("DART-CMD-003", [2], ["Future<void> executeCommand(String command) async {",
                           "  await Process.run(command, []);", "}"]),
    ("DART-CRYPTO-009", [3], ["final pbkdf2 = Pbkdf2(", "  macAlgorithm: Hmac.sha256(),",
                              "  iterations: 1000,", "  bits: 256,", ");"]),
    ("DART-CRYPTO-009", [], ["final anim = RepeatingAnimation(", "  iterations: 3,", ");"]),
    ("DART-CLIP-001", [1], ["await Clipboard.setData(", "  ClipboardData(text: account.password),",
                            ");"]),
    ("DART-CLIP-001", [], ["await Clipboard.setData(", "  ClipboardData(text: shareLink),", ");"]),
    ("DART-AUTH-001", [1], ["final claims = JwtDecoder.decode(token);",
                            "if (claims['role'] == 'admin') {", "  context.go('/admin');", "}"]),
    ("DART-AUTH-001", [], ["final claims = JwtDecoder.decode(token);",
                           "final name = claims['name'] as String;"]),
    ("DART-AUTH-002", [1], ["final ok = await auth.authenticate(",
                            "  localizedReason: 'Unlock your vault',", "  biometricOnly: true,",
                            ");", "if (ok) _showSecrets();"]),
    ("DART-AUTH-002", [], ["final session = await api.authenticate(username, password);"]),
    ("DART-SQLI-004", [2], ["final rows = await db.rawQuery(",
                            "    \"SELECT * FROM notes WHERE title LIKE '%$query%'\");"]),
    ("DART-TLS-001", [], ["// client.badCertificateCallback = (cert, host, port) => true;"]),
]


@pytest.mark.parametrize("rule_id, lines, code", CONTEXT)
def test_rules_with_context_report_exactly_the_expected_lines(rule_id, lines, code):
    rule = rules_engine.get_rule(rule_id)
    findings = rules_engine.scan_file(make("\n".join(code) + "\n", "lib/a.dart"), rules=[rule])
    assert [f.line for f in findings] == lines


@pytest.mark.parametrize("code", [
    "await db.rawQuery('SELECT * FROM $table ORDER BY $columnDate DESC');",
    "await db.execute('CREATE TABLE $tableTodo ($columnId INTEGER PRIMARY KEY, $columnTitle TEXT)');",
    "await db.execute('INSERT INTO $table (group) VALUES (1)');",
    "await db.rawInsert('INSERT INTO $table ($columnName, $columnAge) VALUES (?, ?)', [n, a]);",
    "return await db.delete(tableTodo, where: '$columnId = ?', whereArgs: [id]);",
    "final sql = 'UPDATE $table SET $columnName = ? WHERE $columnId = ?';",
    "print('Select an account from the list for $userName');",
])
def test_sql_rules_ignore_table_and_column_names(code):
    assert not {i for i in found(code + "\n") if i.startswith("DART-SQLI")}


@pytest.mark.parametrize("code", [
    "final rows = await db.rawQuery('SELECT * FROM $table WHERE name = \"$name\"');",
    "final sql = 'UPDATE $table SET name = \"$name\" WHERE id = 1';",
    "String q = \"INSERT INTO ${H.TABLE}(${H.NAME}) VALUES($input, 10)\";",
    "final rows = await db.query('items', orderBy: '$sortColumn $sortDirection');",
])
def test_sql_rules_find_values_next_to_table_names(code):
    assert {i for i in found(code + "\n") if i.startswith("DART-SQLI")}


@pytest.mark.parametrize("code, expected", [
    ("await db.rawQuery('SELECT * FROM \"$tableName\" WHERE id = ?', [id]);", set()),
    ("await db.rawQuery(\"SELECT * FROM '$table' WHERE id = ?\", [id]);", set()),
    ("await db.execute('CREATE TABLE IF NOT EXISTS \"$table\" (id INTEGER PRIMARY KEY)');", set()),
    ("final sql = 'SELECT * FROM `$table` JOIN \"$other\" ON a = b WHERE id = ?';", set()),
    ("await db.rawQuery(\"SELECT * FROM '$table' WHERE name = '$name'\");", {"DART-SQLI-001"}),
    ("await db.rawQuery(\"SELECT * FROM notes WHERE title LIKE '%$q%'\");", {"DART-SQLI-001"}),
])
def test_sql_rules_treat_quoted_table_names_like_bare_ones(code, expected):
    assert {i for i in found(code + "\n") if i.startswith("DART-SQLI")} == expected


def test_net_rule_skips_xml_namespaces_and_the_loopback_address():
    code = ("const gpx = '<gpx xmlns=\"http://www.topografix.com/GPX/1/1\" version=\"1.1\">';\n"
            "const svg = '<svg xmlns:xlink=\"http://www.w3.org/1999/xlink\"/>';\n"
            "final u = Uri.http(InternetAddress.loopbackIPv4.address + ':8080', '/');\n"
            "final v = Uri.http('${InternetAddress.loopbackIPv6.host}:$port', '/cb');\n"
            "final w = Uri.http('[::1]:8080', '/');\n")
    assert "DART-NET-001" not in found(code)
    assert "DART-NET-001" in found("final api = Uri.http('api.shop-backend.io', '/v1');\n")


def test_storage_log_and_hash_rules_skip_identifiers_and_flags():
    assert "DART-STORAGE-001" not in found("await prefs.setString('fcm_token', fcmToken);\n"
                                           "prefs.setString('pushToken', token);\n")
    assert "DART-STORAGE-001" in found("await prefs.setString('auth_token', token);\n")
    assert "DART-LOG-001" not in found("print('Token expired: $isTokenExpired');\n"
                                       "debugPrint('has token: ${auth.hasToken}');\n"
                                       "print(isTokenValid);\n")
    assert "DART-LOG-001" in found("print('Token: $token expired: $isTokenExpired');\n")
    assert "DART-CRYPTO-001" not in found(
        "final hash = sha1.convert([...namespaceBytes, ...nameBytes]).bytes; // UUID v5\n")
    assert "DART-CRYPTO-001" in found("final hash = sha1.convert(bytes).toString();\n")


def test_new_rules_from_the_lab_misses():
    ostorlab = LABS / "Ostorlab-Insecure-Flutter" / "ostorlab_insecure_flutter_app" / "lib" / "bugs"
    world = ("  int MODE_WORLD_READABLE = 1;\n"
             "    Context.getSharedPreferences(token, MODE_PRIVATE);\n"
             "    Context.getSharedPreferences(token, MODE_WORLD_READABLE);\n")
    assert [f.line for f in rules_engine.scan_file(make(world, "lib/a.dart"))
            if f.rule_id == "DART-STORAGE-006"] == [3]
    assert "DART-CMD-003" not in found(
        "final r = await Process.run(Platform.resolvedExecutable, []);\n"
        "final s = await Process.run(adbPath ?? 'adb', ['devices']);\n")
    if not ostorlab.is_dir():
        return
    expected = {"command_exec.dart": "DART-CMD-003", "insecure_commands.dart": "DART-CMD-003",
                "insecure_random.dart": "DART-CRYPTO-010",
                "insecure_shared_preferences.dart": "DART-STORAGE-006",
                "reflection_api.dart": "DART-CODE-002"}
    for name, rule_id in expected.items():
        text = (ostorlab / name).read_text(encoding="utf-8")
        assert rule_id in found(text, "lib/bugs/" + name), name


@pytest.mark.parametrize("name, text, expected", [
    # a command that goes on in the next line (backslash, or a folded block) is not complete
    (".github/workflows/a.yml", "      - run: |\n          flutter build appbundle --release \\\n"
     "            --obfuscate --split-debug-info=build/symbols\n", []),
    (".github/workflows/a.yml", "      - run: >\n          flutter build apk\n          --obfuscate\n"
     "          --split-debug-info=symbols\n", []),
    (".github/workflows/a.yml", "      - run: |\n          flutter pub get\n"
     "          flutter build apk --release\n      - uses: actions/upload-artifact@v4\n", [3]),
    (".github/workflows/a.yml", "    steps:\n      - run: flutter build ipa\n\n", [2]),
    ("scripts/release.sh", "set -e\nflutter build apk --release\n", [2]),
    ("scripts/release.sh", "rm -f out.apks\n\nflutter build appbundle\n\njava -jar bt.jar\n", [3]),
    ("scripts/release.sh", "flutter build apk \\\n  --obfuscate --split-debug-info=s\n", []),
    # Firebase rules: a condition that goes on, an `if` with true on the next line, test mode
    ("firestore.rules", "    allow read: if request.auth != null\n"
     "      && request.auth.uid == resource.data.owner;\n", []),
    ("firestore.rules", "    allow read, write: if\n        true;\n", [1]),
    ("firestore.rules", "    allow write: if\n        request.auth != null;\n", []),
    ("database.rules.json", '{\n  "rules": {\n    ".read": "now < 1735689600000",\n', [3]),
])
def test_multi_line_build_commands_and_firebase_rules(name, text, expected):
    found_lines = [f.line for f in rules_engine.scan_file(make(text, name))
                   if f.rule_id.startswith(("FLUTTER-BUILD-001", "FLUTTER-FIREBASE"))]
    assert found_lines == expected


def test_log_rule_needs_the_secret_itself_not_a_property_of_it():
    assert "DART-LOG-001" in found("debugPrint('password=${passwordController.text}');\n")
    assert "DART-LOG-001" in found("print(headers['Authorization']);\n")
    assert "DART-LOG-001" not in found("print(token.error);\nprint('Payload: ${jwt.payload}');\n")
    assert "DART-LOG-001" not in found("print('equal: ${plainText == decompressed}');\n")


def test_text_that_only_names_an_api_is_not_code():
    assert not found("  value: 'client.badCertificateCallback = (cert, host, port) => true;',\n")
    assert not found("      'Uses Random() instead of Random.secure() for session tokens.',\n")


# ------------------------------------------------------------------ sink rules (requires_taint)
@pytest.mark.parametrize("rule_id, traced, untraced", [
    ("DART-PATH-002",
     "final target = uri.pathSegments.last;\nfinal file = File('${dir.path}/$target');\n",
     "final name = 'avatar.png';\nfinal file = File('${dir.path}/$name');\n"),
    ("DART-CMD-002",
     "final cmd = stdin.readLineSync()!;\nawait Process.run(cmd, []);\n",
     "final cmd = 'git';\nawait Process.run(cmd, ['status']);\n"),
    ("DART-PATH-002",
     "final name = _nameController.text;\nawait File(p.join(base, name)).writeAsString(data);\n",
     "final id = int.tryParse(_idController.text) ?? 0;\nawait File('$base/$id.json').readAsString();\n"),
])
def test_dart_sink_rules_fire_only_when_input_reaches_them(rule_id, traced, untraced):
    finding = next(f for f in rules_engine.scan_file(make(traced, "lib/a.dart"))
                   if f.rule_id == rule_id)
    assert finding.tainted and finding.line == 2
    assert rule_id not in found(untraced)


# ------------------------------------------------------------------ the files field
def rule_with(files):
    return rules_engine.parse_rule({"id": "T-1", "title": "t", "languages": ["any"],
                                    "pattern": "x", "files": files})


def test_files_field_matches_path_or_name_and_ignores_case():
    web = rule_with(["**/web/index.html"])
    assert web.applies_to("web/index.html") and web.applies_to("app/web/INDEX.html")
    assert not web.applies_to("web/other.html") and not web.applies_to("public/index.html")
    gradle = rule_with(["*.gradle", "**/fastlane/Fastfile"])
    assert gradle.applies_to("android/app/build.gradle") and gradle.applies_to("Build.GRADLE")
    assert gradle.applies_to("ios\\fastlane\\Fastfile")
    assert not gradle.applies_to("android/app/build.gradle.kts")
    assert rule_with([]).applies_to("anything/at/all.txt")
    assert rule_with("*.yml, *.yaml,").files == ["*.yml", "*.yaml"]
    assert rule_with(None).files == [] and rule_with(["*.yml"]).as_dict()["files"] == ["*.yml"]


@pytest.mark.parametrize("name, text, rule_id, expected", [
    (".github/workflows/build.yml", "      - run: flutter build apk --release\n",
     "FLUTTER-BUILD-001", True),
    ("config/build.yml", "      - run: flutter build apk --release\n", "FLUTTER-BUILD-001", False),
    ("scripts/release.sh", "flutter build ipa --dart-define=STRIPE_SECRET=$STRIPE_SECRET\n",
     "FLUTTER-BUILD-002", True),
    ("firestore.rules", "      allow read, write: if true;\n", "FLUTTER-FIREBASE-001", True),
    ("firebase/storage.rules", "    allow read: if request.auth != null;\n",
     "FLUTTER-FIREBASE-002", True),
    ("database.rules.json", '    ".write": true,\n', "FLUTTER-FIREBASE-001", True),
    ("settings.json", '    ".write": true,\n', "FLUTTER-FIREBASE-001", False),
    ("web/index.html", '<script src="http://cdn.example-cdn.io/sdk.js"></script>\n',
     "FLUTTER-WEB-001", True),
    ("docs/index.html", '<script src="http://cdn.example-cdn.io/sdk.js"></script>\n',
     "FLUTTER-WEB-001", False),
])
def test_flutter_rules_read_only_their_own_files(name, text, rule_id, expected):
    assert (rule_id in found(text, name)) == expected


def test_rule_book_keeps_checks_and_edits_the_files_field(tmp_path, own_rule_folder):
    rule = {"id": "MY-GRADLE-001", "title": "debuggable release", "languages": ["config"],
            "files": "*.gradle, **/build.gradle.kts", "cwe": "CWE-489", "severity": "high",
            "pattern": r"debuggable\s*(=\s*)?true", "examples_vulnerable": ["debuggable true"],
            "examples_safe": ["debuggable false"]}
    assert rulebook.create(rule)["passed"]
    saved = rulebook.get("MY-GRADLE-001")
    assert saved.files == ["*.gradle", "**/build.gradle.kts"]
    stored = yaml.safe_load((rules_engine.learned_dir() / "custom.yaml").read_text("utf-8"))
    assert stored[0]["files"] == ["*.gradle", "**/build.gradle.kts"]
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "build.gradle").write_text("    debuggable true\n", encoding="utf-8")
    (tmp_path / "app" / "flags.properties").write_text("debuggable true\n", encoding="utf-8")
    result = run_scan(str(tmp_path), ScanOptions(use_bandit=False, use_ml=False, save=False))
    assert {f.file for f in result.findings if "MY-GRADLE-001" in f.rule_ids} \
        == {"app/build.gradle"}
    assert "files:" in "".join(rulebook.check({**rule, "id": "MY-GRADLE-002",
                                               "files": [1, ""]})["errors"])
    assert "files:" in rulebook.export_yaml(origin="custom")
    rulebook.update("FLUTTER-WEB-001", {"files": ["**/web/*.html"]})
    assert rulebook.get("FLUTTER-WEB-001").files == ["**/web/*.html"]
    assert rules_engine.load_edits() == {"FLUTTER-WEB-001": {"files": ["**/web/*.html"]}}
    rulebook.update("FLUTTER-WEB-001", {"files": "**/web/index.html"})    # back as text
    assert rules_engine.load_edits() == {}


def test_template_and_learned_rules_carry_the_files_field(own_rule_folder):
    template = yaml.safe_load(rulebook.TEMPLATE)[0]
    assert template["files"] == [] and rulebook.check(template)["passed"]
    added = store.add_learned_rule({"id": "LEARNED-1", "title": "t", "languages": ["dart"],
                                    "files": ["lib/**"], "cwe": "CWE-89", "severity": "high",
                                    "pattern": r"rawQuery\("})
    assert added["files"] == ["lib/**"] and rulebook.get("LEARNED-1").files == ["lib/**"]


# ------------------------------------------------------------------ walker
def test_walker_reads_flutter_project_files_and_skips_tool_folders(tmp_path):
    files = {"lib/main.dart": "void main() {}\n", "lib/user.g.dart": "x\n",
             "lib/state.freezed.dart": "x\n", "test/mocks.mocks.dart": "x\n",
             "lib/router.gr.dart": "x\n", "pubspec.lock": "packages:\n", "firestore.rules": "x\n",
             "storage.rules": "x\n", "android/app/build.gradle": "x\n",
             "ios/Runner/Info.plist": "<plist/>\n", ".dart_tool/package_config.dart": "x\n",
             "ios/Pods/Firebase/x.swift": "x\n", "ios/.symlinks/plugins/a/a.dart": "x\n",
             "android/.gradle/x.gradle": "x\n", "linux/flutter/ephemeral/x.dart": "x\n",
             ".fvm/flutter_sdk/x.dart": "x\n", ".pub-cache/hosted/x.dart": "x\n",
             "android/app/.cxx/x.c": "x\n", "build/app.dart": "x\n"}
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    walked = {sf.rel: sf.language for sf in walk_project(str(tmp_path))}
    assert walked == {"lib/main.dart": "dart", "pubspec.lock": "config",
                      "firestore.rules": "config", "storage.rules": "config",
                      "android/app/build.gradle": "config", "ios/Runner/Info.plist": "config"}


def test_flutter_test_folders_are_test_code_and_languages_are_unchanged():
    assert is_test_path("integration_test/flows/login.dart")
    assert is_test_path("test_driver/main.dart")
    assert not is_test_path("lib/integration_testing/data_loader.dart")
    assert len(CODE_LANGUAGES) == 22 and "dart" in CODE_LANGUAGES


def test_commented_xml_and_binary_stand_ins_are_not_scanned():
    rule = rules_engine.parse_rule({"id": "T-XML", "title": "t", "languages": ["config"],
                                    "pattern": r'debuggable="true"'})
    xml = make('<!-- android:debuggable="true" -->\n    android:debuggable="true"\n',
               "AndroidManifest.xml")
    assert [f.line for f in rules_engine.scan_file(xml, rules=[rule])] == [2]
    plain = SourceFile(Path("x.txt"), "x.txt", "config", 'debuggable="true"\n')
    assert plain.origin == "" and rules_engine.scan_file(plain, rules=[rule])
    for origin in ("strings", "placeholder"):
        dump = make('debuggable="true"\n', "lib/arm64-v8a/libapp.so", origin)
        dump.language = "config"
        assert rules_engine.scan_file(dump, rules=[rule]) == []


# ------------------------------------------------------------------ taint-lite for Dart
DART_FLOWS = [
    (True, "final q = _searchController.text;\nawait db.rawQuery('SELECT * FROM t WHERE n = \\'$q\\'');\n"),
    (True, "final q = _searchController.text;\nawait db.rawQuery(\"SELECT * FROM t WHERE n = '${q}'\");\n"),
    (True, "final q = _searchController.text;\nawait db.rawQuery('SELECT * FROM t WHERE n = ' + q);\n"),
    (True, "final String q = state.uri.queryParameters['q']!;\nlaunchUrl(Uri.parse('https://x/$q'));\n"),
    (True, "late final Map<String, String> params = Uri.base.queryParameters;\nloadHtml('<b>$params</b>');\n"),
    (True, "final args = ModalRoute.of(context)!.settings.arguments as Map;\ncontroller.loadRequest(Uri.parse(args['url']));\n"),
    (True, "FirebaseMessaging.onMessage.listen((RemoteMessage m) {\nfinal link = message.data['link'];\nlaunchUrl(Uri.parse(link));\n"),
    (True, "final name = stdin.readLineSync();\nawait Process.run('sh', ['-c', 'echo $name']);\n"),
    (True, "final m = {'k': ctrl.text};\nfinal sql = 'SELECT * FROM t WHERE n = ${m['k']}';\n"),
    (False, "final id = int.tryParse(_idController.text) ?? 0;\nawait db.rawQuery('SELECT * FROM t WHERE id = $id');\n"),
    (False, "final q = _searchController.text;\nawait db.rawQuery(r'SELECT * FROM t WHERE n = $q');\n"),
    (False, "final x = 'constant';\nawait db.rawQuery('SELECT * FROM t WHERE n = $x');\n"),
    (False, "final q = Uri.encodeComponent(ctrl.text);\nlaunchUrl(Uri.parse('https://x/?q=$q'));\n"),
    (False, "final name = 'world';\nawait Process.run('sh', ['-c', 'echo $name']);\n"),
    (False, "final label = widget.text;\nawait db.rawQuery('SELECT * FROM t WHERE n = $label');\n"),
]


@pytest.mark.parametrize("traced, code", DART_FLOWS)
def test_taint_lite_follows_dart_input(traced, code):
    assert taint_lite.is_traced(make(code, "lib/a.dart"), code.count("\n")) == traced


def test_dart_strings_keep_their_holes_and_lose_their_words():
    def words(text):
        return taint_lite._idents(text, "dart")
    assert words("q('name $user and ${order.id}')") == {"q", "user", "order", "id"}
    assert words("q(r'raw $user')") == {"q"}
    assert words("q('''multi $line''', \"esc \\$not\")") == {"q", "line"}
    assert words("late required dynamic value") == {"value"}
    for text in ("'" + "${" * 3000 + "'", "'${'" * 3000, "'$" * 3000):
        started = time.perf_counter()
        taint_lite.code_only(text, "dart")
        assert time.perf_counter() - started < 1.0


def test_other_languages_trace_exactly_as_before():
    assert taint_lite.code_only("$sql = 'SELECT $id';", "php") == "$sql =  ;"
    assert taint_lite.code_only('q = "a ${b} #{c} {$d}"') == "q =  b c $d "
    assert taint_lite.code_only("x = `t ${u}` + r'$v'", "javascript") == "x =  u  + r "
    js ='const required = req.query.x;\ndb.query("SELECT * FROM t WHERE a = " + required);\n'
    assert taint_lite.is_traced(make(js, "a.js"), 2)       # not a keyword outside Dart
    php = "$q = $_GET['q'];\n$r = mysqli_query($c, 'SELECT $q');\n"
    assert not taint_lite.is_traced(make(php, "a.php"), 2)  # PHP single quotes stay text


# ------------------------------------------------------------------ coverage and a full scan
def test_coverage_lists_the_dart_rules(capsys):
    from sca.__main__ import main as cli
    row = loop.coverage_matrix()["dart"]
    assert {"CWE-89", "CWE-295", "CWE-319", "CWE-327", "CWE-532", "CWE-798"} <= set(row)
    assert cli(["coverage"]) == 0
    dart = next(line for line in capsys.readouterr().out.splitlines()
                if line.startswith("dart "))
    assert "89(4)" in dart and "none yet" not in dart


def test_scan_of_a_flutter_project(tmp_path):
    files = {
        "lib/api.dart": "const base = 'http://api.shop-backend.io/v1';\n"
                        "final key = Key.fromUtf8('0123456789abcdef');\n"
                        "client.badCertificateCallback = (cert, host, port) => true;\n",
        "lib/api.g.dart": "client.badCertificateCallback = (cert, host, port) => true;\n",
        ".github/workflows/release.yml": "      - run: flutter build appbundle --release\n",
        "firestore.rules": "match /{document=**} {\n  allow read, write: if true;\n}\n",
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    result = run_scan(str(tmp_path), ScanOptions(use_bandit=False, use_ml=False, save=False))
    by_rule = {i: f for f in result.findings for i in f.rule_ids}
    assert {"DART-NET-001", "DART-CRYPTO-004", "DART-TLS-001", "FLUTTER-BUILD-001",
            "FLUTTER-FIREBASE-001"} <= set(by_rule)
    assert by_rule["DART-CRYPTO-004"].cwe == "CWE-798"            # CWE-321 folds into 798
    assert not any(f.file == "lib/api.g.dart" for f in result.findings)
    assert by_rule["FLUTTER-FIREBASE-001"].line == 2


def test_rules_tab_shows_the_file_patterns_of_a_rule(monkeypatch, own_rule_folder):
    st = pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("SCA_SKIP_INTRO", "1")
    st.cache_resource.clear()
    st.cache_data.clear()
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.session_state["rule_pick"] = "FLUTTER-WEB-001"
    app.run()
    assert not app.exception
    assert any(m.value.startswith("**Applies to:** `**/web/index.html`") for m in app.markdown)
    assert app.text_input(key="rule_files_FLUTTER-WEB-001").value == "**/web/index.html"
    app.text_input(key="rule_files_FLUTTER-WEB-001").set_value("**/web/*.html")
    next(b for b in app.button if b.label == "Save changes").click().run()
    assert not app.exception and rulebook.get("FLUTTER-WEB-001").files == ["**/web/*.html"]
