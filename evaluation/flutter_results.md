# Flutter / Android evaluation

Secure Code Analyzer 1.5.0, static engines only (no AI), 2026-11-24. Produced by `python evaluation/flutter_eval.py`.

## 1. Flutter samples

`samples/flutter_vulnerable_app` (60 labelled weaknesses, 2 of them marked hard, 5 safe decoy lines) and `samples/flutter_safe_app` (no weaknesses: every finding there is a false positive). A finding counts when it has the labelled CWE and is at most one line away. These samples were written together with the tool: the numbers show that the module works end to end; they are not an unbiased benchmark.

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Pattern rules + secrets (no Flutter checks) | 33 | 0 | 27 | 1.000 | 0.550 | 0.710 |
| All static engines | 59 | 0 | 1 | 1.000 | 0.983 | 0.992 |
| All static, strict mode (confirmed only) | 14 | 0 | 46 | 1.000 | 0.233 | 0.378 |

Recall by part of the sample (All static engines):

| Part | Labelled | Found | Recall |
|---|---:|---:|---:|
| Dart code (D) | 27 | 26 | 96.3% |
| Android, iOS, Firebase, web and build configuration (M) | 27 | 27 | 100.0% |
| Dependencies (pubspec.lock) (G) | 6 | 6 | 100.0% |

### Missed (All static engines)

- `lib/services/auth_service.dart:47` D30 CWE-598 (hard): no rule: access token in the query string of a URL opened in the browser, so it lands in server logs and history

### False positives (All static engines)

- none

## 2. DVMA: module-level recall

DVMA's registry (`config/registry/categories`) lists 218 modules with their CWEs; the code of each is in `lib/modules/<category>/<module>/`. A module counts as **found** when an open finding in its folder has one of its CWEs, and as **any finding** when its folder has an open finding of any kind. Scan: 658 files, 102,911 lines, 229 open findings, 10.2 s.

| Category | Kind | Modules | Found | Recall | Any finding |
|---|---|---:|---:|---:|---:|
| storage | code | 17 | 4 | 23.5% | 9 |
| crypto | code | 10 | 5 | 50.0% | 7 |
| auth | design | 27 | 2 | 7.4% | 8 |
| network | code | 5 | 2 | 40.0% | 4 |
| platform | design | 68 | 4 | 5.9% | 20 |
| code_quality | code | 5 | 0 | 0.0% | 1 |
| resilience | runtime | 10 | 0 | 0.0% | 0 |
| supply_chain | design | 8 | 1 | 12.5% | 3 |
| privacy | runtime | 9 | 0 | 0.0% | 0 |
| input_validation | code | 5 | 0 | 0.0% | 1 |
| ai_ml | runtime | 13 | 1 | 7.7% | 2 |
| agentic | runtime | 9 | 0 | 0.0% | 2 |
| ai_mobile | runtime | 5 | 1 | 20.0% | 2 |
| native_bridge | design | 15 | 6 | 40.0% | 13 |
| system_provider | design | 12 | 0 | 0.0% | 3 |
| **All** | | **218** | **26** | **11.9%** | **75** |

By kind of weakness (a judgement per category, written in `evaluation/flutter_truth/dvma.json`):

| Kind | What it means | Modules | Found | Recall |
|---|---|---:|---:|---:|
| code | property of code or configuration lines | 42 | 11 | 26.2% |
| design | authorization, IPC and trust decisions (needs the intended behaviour) | 130 | 13 | 10.0% |
| runtime | AI behaviour, consent and runtime defences (not visible in the source) | 46 | 2 | 4.3% |

The resilience, privacy, ai_ml, agentic, ai_mobile categories are AI, behaviour and runtime weaknesses (prompt injection, agent tool abuse, consent, missing root/tamper/debugger defences). They are not patterns in the source, so static analysis is not expected to find them; the *design* categories need the intended behaviour of the app (who may call what), which a pattern or structural check only sees where it leaves a mark in code or configuration.

Findings outside the module folders are not counted above, because they belong to the whole app rather than to one module: 81 open findings, by check: ANDROID-MANIFEST-005 18, ANDROID-MANIFEST-009 15, SECRET-HARDCODED-001 10, DEVSKIM-DS106863 7, FLUTTER-BUILD-001 5, C-BOF-002 4, DART-SECRET-002 2, DART-WEBVIEW-007 2, DART-STORAGE-003 2, ANDROID-NSC-001 1, ANDROID-MANIFEST-001 1, IOS-PLIST-001 1, C-MEM-UAF 1, ANDROID-MANIFEST-004 1, ANDROID-MANIFEST-003 1, ANDROID-NSC-003 1, ANDROID-GRADLE-001 1, BANDIT-B104 1, IOS-PLIST-005 1, DART-NET-001 1, ANDROID-MANIFEST-012 1, ANDROID-GRADLE-002 1, ANDROID-MANIFEST-006 1, ANDROID-MANIFEST-011 1, IOS-PLIST-004 1.

## 3. Ostorlab-Insecure-Flutter: recall per file

Truth: `evaluation/flutter_truth/ostorlab.json` (one item per file, with file and line). An item counts as found when an open finding with one of its CWEs is at most one line away from one of its locations. Scan: 72 files, 3,507 lines, 37 open findings (20 of them on a truth item), 0.4 s.

Recall: **15 of 16 files (93.8%)**; without the items marked hard: 15 of 16 (93.8%).

| Id | Weakness | CWE | Where | Found | By |
|---|---|---|---|---|---|
| O01 | Biometric authentication without a CryptoObject | CWE-287 | `biometric_none_cryptobject.dart:16` | yes | DART-AUTH-002 (line 16) |
| O02 | Cleartext HTTP traffic | CWE-319 | `clear_text_traffic.dart:17` | yes | DART-NET-001 (line 17) |
| O03 | Command execution (chmod 777 on shared storage) | CWE-78, CWE-732 | `command_exec.dart:18`, `command_exec.dart:29` | yes | DART-CMD-003 (line 29) |
| O04 | AES in ECB mode | CWE-327 | `ecb_cipher_mode.dart:22` | yes | DART-CRYPTO-005 (line 21); DART-CRYPTO-003 (line 22) |
| O05 | Hard-coded credentials in a URL | CWE-798 | `hardcoded_creds_in_url.dart:23` | yes | SECRET-URL-001 (line 23) |
| O06 | Hash without salt or iterations (SHA-1) | CWE-327 | `hash_call.dart:22` | yes | DART-CRYPTO-001 (line 22) |
| O07 | Command taken from input | CWE-78 | `insecure_commands.dart:22` | yes | DART-CMD-003 (line 22) |
| O08 | Insecure random number generator with a fixed seed | CWE-338 | `insecure_random.dart:25`, `insecure_random.dart:33` | yes | DART-CRYPTO-010 (line 25) |
| O09 | World-readable shared preferences | CWE-732, CWE-276 | `insecure_shared_preferences.dart:23`, `insecure_shared_preferences.dart:24`, `insecure_shared_preferences.dart:25` | yes | DART-STORAGE-006 (line 23); DART-STORAGE-006 (line 24); DART-STORAGE-006 (line 25) |
| O10 | Padding oracle: AES-CBC with PKCS7 and no MAC decrypts input | CWE-327 | `oracle_padding.dart:17`, `oracle_padding.dart:20` | no | - |
| O11 | Path traversal through the last path segment of a URI | CWE-22 | `path_traversal.dart:20` | yes | DART-PATH-002 (line 21) |
| O12 | Reflection invokes a method named by input | CWE-470 | `reflection_api.dart:23` | yes | DART-CODE-002 (line 23) |
| O13 | SQL built from input (sqflite rawInsert) | CWE-89 | `sqlite_database_call.dart:14` | yes | DART-SQLI-004 (line 14) |
| O14 | Static IV | CWE-327, CWE-329 | `static_iv.dart:22` | yes | DART-CRYPTO-005 (line 22) |
| O15 | TLS certificate validation switched off | CWE-295 | `tls_traffic.dart:22` | yes | DART-TLS-002 (line 23) |
| O16 | Insecure WebView settings | CWE-200, CWE-489 | `webview_insecure_settings.dart:13`, `webview_insecure_settings.dart:19`, `webview_insecure_settings.dart:20` | yes | DART-WEBVIEW-007 (line 13); DART-WEBVIEW-004 (line 19); DART-WEBVIEW-004 (line 20) |

## 4. DVFA: recall per challenge

Truth: `evaluation/flutter_truth/dvfa.json` (one item per challenge, with file and line). An item counts as found when an open finding with one of its CWEs is at most one line away from one of its locations. Scan: 35 files, 2,086 lines, 11 open findings (6 of them on a truth item), 0.7 s.

Recall: **5 of 10 challenges (50.0%)**; without the items marked hard: 5 of 7 (71.4%).

| Id | Weakness | CWE | Where | Found | By |
|---|---|---|---|---|---|
| C1 | Insecure authentication: 4-digit PIN without an attempt limit (hard) | CWE-307 | `login_screen.dart:42` | no | - |
| C2 | Insecure local storage: account ID and PIN in SharedPreferences | CWE-312, CWE-922 | `login_screen.dart:45`, `login_screen.dart:46` | yes | DART-STORAGE-001 (line 46) |
| C3 | Insecure communication: balance requested over HTTP | CWE-319 | `dashboard_screen.dart:29` | yes | DART-NET-001 (line 29) |
| C4 | Client-side SQL injection in the notes search | CWE-89 | `notes_screen.dart:76`, `notes_screen.dart:77` | yes | DART-SQLI-004 (line 77) |
| C5 | Deep link runs a fund transfer without confirmation | CWE-939 | `main.dart:38`, `main.dart:39`, `main.dart:46` | no | - |
| C6 | Hidden developer menu with a staging API key | CWE-798, CWE-489 | `dev_menu_screen.dart:35`, `dashboard_screen.dart:47` | no | - |
| C7 | Insufficient cryptography: hard-coded AES key and IV | CWE-798, CWE-327, CWE-329 | `dashboard_screen.dart:58`, `dashboard_screen.dart:59` | yes | DART-CRYPTO-004 (line 58); DART-CRYPTO-005 (line 59) |
| C8 | Inadequate privacy controls: PIN and transfers written to the log | CWE-532 | `login_screen.dart:36`, `transfer_screen.dart:40` | yes | DART-LOG-001 (line 36) |
| C9 | Insecure authorization: VIP access from a local flag (hard) | CWE-602 | `dashboard_screen.dart:81` | no | - |
| C10 | Data leakage: sensitive screen in the app-switcher snapshot (hard) | CWE-200 | - | no | - |

## 5. What survives compilation: the APK probe

`samples/flutter_apk_probe` holds 16 planted weaknesses (P rows); B rows are properties of a build mode. Each column is one scan with all static engines: the source folder, then the packages built from it with Flutter 3.44.8 (Dart 3.12.2). *found* = reported, **missed** = present but not reported, *-* = not expected in that scan, *unexpected* = reported where it should not be.

| Id | Weakness | CWE | source | debug | release | release_obf | aab |
|---|---|---|---|---|---|---|---|
| P01 | AWS access key in the Dart code | CWE-798 | found | found | found | found | found |
| P02 | Cleartext http:// endpoint in the Dart code | CWE-319 | found | found | found | found | found |
| P03 | SQL text built by string concatenation | CWE-89 | found | found | found | found | found |
| P04 | TLS certificate check switched off (badCertificateCallback) | CWE-295 | found | found | **missed** | **missed** | **missed** |
| P05 | Token written to the log | CWE-532 | found | found | **missed** | **missed** | **missed** |
| P06 | .env file bundled as a Flutter asset | CWE-798 | found | found | found | found | found |
| P07 | AWS access key in the bundled .env file | CWE-798 | found | found | found | found | found |
| P08 | Backup allowed (android:allowBackup="true") | CWE-530 | found | found | found | found | found |
| P09 | Cleartext traffic allowed (android:usesCleartextTraffic) | CWE-319 | found | found | found | found | found |
| P10 | Broadcast receiver exported without a permission | CWE-926 | found | found | found | found | found |
| P11 | Deep link with the custom scheme probe:// | CWE-939 | found | found | found | found | found |
| P12 | https link without android:autoVerify | CWE-939 | found | found | found | found | found |
| P13 | Network security config allows cleartext (base-config) | CWE-319 | found | found | found | found | found |
| P14 | Network security config trusts user CAs | CWE-295 | found | found | found | found | found |
| P15 | FileProvider shares the file system root (root-path) | CWE-552 | found | found | found | found | found |
| P16 | Release build signed with the debug key | CWE-1188 | found | found | found | found | found |
| B01 | App is debuggable (android:debuggable) | CWE-489 | - | found | - | - | - |
| B02 | Debug build: Dart source in kernel_blob.bin | CWE-489 | - | found | - | - | - |
| B04 | Release build without Dart obfuscation | CWE-693 | - | - | found | - | found |
| B05 | Paths of the build machine in the app | CWE-200 | - | found | - | - | - |
| | **Planted weaknesses found** | | **16 of 16** | **16 of 16** | **14 of 16** | **14 of 16** | **14 of 16** |

| Scan | Package size | Build mode found | Dart obfuscated | Files | Open findings | Other findings | Time |
|---|---:|---|---|---:|---:|---:|---:|
| samples/flutter_apk_probe | - | - | - | 8 | 17 | 1 | 0.1 s |
| debug.apk | 75.3 MB | debug | no | 14 | 18 | 0 | 3.0 s |
| release.apk | 16.4 MB | release | no | 10 | 14 | 0 | 0.9 s |
| release_obf.apk | 15.7 MB | release | yes | 10 | 13 | 0 | 0.6 s |
| release.aab | 16.5 MB | release | no | 10 | 14 | 0 | 0.9 s |

Other findings (not on a P or B row):

- samples/flutter_apk_probe: `pubspec.yaml:1` CWE-1357 FLUTTER-PUB-005

## 6. API and key inventory: the API probe

`samples/flutter_api_probe` is full of server addresses and keys (evaluation/flutter_truth/api_probe.json lists 25 items). Each column is one scan: the source folder, then the packages built from it. *found* = listed by the inventory (`facts['apis']`), **missed** = present but not listed, *-* = not expected in that scan (a key written in parts in the source, or calls in a release build that keeps no code text).

| Id | Item | source | debug | release | obfuscated |
|---|---|---|---|---|---|
| I01 | Stripe secret key (joined by the compiler) | - | - | found | found |
| I02 | AWS access key ID | found | found | found | found |
| I03 | Google Maps key of the manifest (joined by Gradle) | - | found | found | found |
| I04 | Firebase API key, public by design (joined by the compiler) | - | - | found | found |
| I05 | Supabase anon key (JWT, role anon) | found | found | found | found |
| I06 | Key in assets/config.json | found | found | found | found |
| I07 | Secret of the bundled .env file | found | found | found | found |
| I08 | User name and password in an address | found | found | found | found |
| I09 | Slack webhook address | found | found | found | found |
| I10 | Telegram bot token in an address (joined by the compiler) | - | - | found | found |
| I11 | ngrok tunnel | found | found | found | found |
| I12 | Private IP address over http:// | found | found | found | found |
| I13 | Staging server | found | found | found | found |
| I14 | Key in the query of an address (?api_key=) | found | found | found | found |
| I15 | Token in the query of an API path (?access_token=) | found | found | found | found |
| I16 | Cleartext analytics address in config.json | found | found | found | found |
| I17 | GraphQL server | found | found | found | found |
| I18 | WebSocket server | found | found | found | found |
| I19 | Supabase project | found | found | found | found |
| I20 | Firebase project ID, database and storage bucket | found | found | found | found |
| I21 | AdMob app ID | found | found | found | found |
| I22 | Google OAuth client ID | found | found | found | found |
| I23 | Sentry DSN | found | found | found | found |
| I24 | API paths of compiled code (/v2/orders, /api/v2/cart/items/) | found | found | found | found |
| I25 | HTTP, WebSocket and GraphQL calls with their targets (10 or more) | found | found | - | - |
| | **Listed** | **21 of 21** | **22 of 22** | **24 of 24** | **24 of 24** |

| Scan | Addresses | Hosts | Keys (secret) | Calls | API paths | Service IDs | .env entries | Alerts (danger / warning / info) | Time |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| samples/flutter_api_probe | 15 | 15 | 5 (4) | 12 | 5 | 12 | 3 | 9 / 5 / 4 | 0.2 s |
| debug.apk | 15 | 15 | 6 (5) | 12 | 5 | 13 | 3 | 12 / 4 / 4 | 3.1 s |
| release.apk | 18 | 16 | 10 (8) | 0 | 3 | 13 | 3 | 15 / 4 / 5 | 0.8 s |
| release_obf.apk | 18 | 16 | 10 (8) | 0 | 3 | 13 | 3 | 15 / 4 / 5 | 0.5 s |
