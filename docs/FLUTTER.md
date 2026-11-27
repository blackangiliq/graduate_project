# Flutter and Android apps

The analyzer reads Flutter and Android apps in two forms: the **source project** (a folder
with `pubspec.yaml`, `android/`, `ios/`) and the **built app package** (`.apk`, `.aab`,
`.apks`, `.xapk`, `.apkm`). Both are analysed statically: an app package is decoded and read
in Python, without installing or running it. The separate [Runtime analysis](DYNAMIC_ANALYSIS.md)
tab can install and record an application on a configured Android lab.

> Current evidence behavior (2026-11-27): dashboard previews, inventories, downloads and
> local evidence archives retain complete original values. References below to masked values
> describe the analysis/AI and CLI representations. Literal templates, source locations,
> SDK configuration candidates and native extraction limits are documented in the
> [current validation review](VALIDATION_2026_11_27.md).

Arabic version: [FLUTTER_AR.md](FLUTTER_AR.md). Measured results:
[evaluation/flutter_results.md](../evaluation/flutter_results.md).

```bash
python -m sca scan path/to/flutter_app                 # a source project
python -m sca scan app-release.apk --format html,json   # an app package
python -m sca flutter info app-release.apk              # what the package is
python -m sca flutter deps path/to/flutter_app          # Dart packages and their advisories
python -m sca flutter apis app-release.apk              # server addresses, API calls and keys
python -m sca flutter decode app-release.apk --out decoded   # write the decoded files
```

## 1. What is analysed

### 1.1 In a source project

| Part | Files | How |
|---|---|---|
| Dart code | `lib/**/*.dart` (generated `*.g.dart`, `*.freezed.dart`, `*.mocks.dart`, `*.gr.dart` are skipped) | 47 `DART-*` pattern rules; the secrets engine, with 2 Dart credential formats of `kind: secret` (DART-SECRET-001 and DART-SECRET-003); and input tracing (taint-lite) with Dart sources such as `TextEditingController.text`, deep-link parameters and `Uri.base` |
| Build, Firebase and web files | CI workflows and `*.sh`, `firestore.rules`, `storage.rules`, `database.rules.json`, `web/index.html` | 5 `FLUTTER-*` rules that name the files they apply to (`files:`) |
| Android configuration | `android/app/src/main/AndroidManifest.xml` and `src/release/` overlays, `res/xml/*.xml`, `build.gradle(.kts)`, `key.properties`, keystore files | structural checks (engine `flutter`): the XML is parsed, not matched line by line |
| iOS configuration | `ios/Runner/Info.plist`, `macos/Runner/Info.plist` | structural checks with `plistlib` |
| Dependencies | `pubspec.yaml`, `pubspec.lock` | audit against 25 curated advisories for 23 Pub packages and a list of 16 discontinued packages (`sca/flutter/data/`) |

Debug, profile and test manifests (`src/debug/`, `src/profile/`, and flavor variants such as
`src/prodDebug/`) are listed in the facts but are not treated as release manifests; every
other source set, including product flavors (`src/prod/`, `src/prodRelease/`), counts as
release. A project is recognised by a `pubspec.yaml` that depends on the Flutter SDK, or by
`src/main/AndroidManifest.xml` next to a Gradle module file, so plain Android (Java/Kotlin)
projects get the Android checks too. An Android library module (`com.android.library`) is
merged into an app later, so only its components, permissions, links and network security
config are checked, not its application attributes or SDK levels. The `android/` and `ios/`
folders of a Flutter plugin (`flutter: plugin:` in its `pubspec.yaml`) hold the plugin's
platform code and are not audited as an app.

### 1.2 In an app package

The package is turned into **virtual files**: text kept in memory, with a path and lines, so
that every engine and every finding works as for a source file. The `origin` of each file
tells the engines what it is.

| Virtual file | Comes from | Origin | Read by |
|---|---|---|---|
| `AndroidManifest.xml` | binary XML (APK) or protobuf XML (AAB), rendered one attribute per line | decoded | rules, secrets, checks |
| `res/xml/<name>.xml` | XML resources under their logical names, also when R8 shortened the file name (`res/8G.xml`) | decoded | rules, secrets, checks |
| `res/values/strings.xml` | string resources of `resources.arsc` (`resources.pb` in an AAB), one per line | decoded | rules, secrets |
| `assets/...` | text assets such as `.env` and JSON files | decoded | rules, secrets, checks |
| `dart/lib/<path>.dart` | Dart source recovered from `kernel_blob.bin` (debug builds only) | recovered | rules, secrets, taint-lite, AI |
| `lib/<abi>/libapp.so` | strings of the Dart AOT snapshot (release and profile builds) | strings | secrets, checks |
| `classes.dex`, `classes2.dex` ... | DEX strings (type descriptors and other compiler strings left out) | strings | secrets |
| `lib/<abi>/<other>.so` | printable strings of other native libraries | strings | secrets |
| `jadx/<package>/<Class>.java` | the app's own classes decompiled by jadx (optional) | decompiled | rules, secrets, AI |
| `_sca/signing.txt`, `_sca/build.txt`, `_sca/packages.txt` | facts written by the analyzer | summary | checks only |

Strings dumps are not given to the pattern rules (a library constant is not code) and do
not count as lines of code for the score. Only the secrets engine and the API and key
inventory read the DEX dumps and the dumps of other native libraries; of all the dumps, the structural checks read only that
of `libapp.so` (FLUTTER-APP-007 and FLUTTER-APP-008). Summary files are never read by the
secrets engine, so a certificate digest is not reported as a key. Everything in an app
package ships to its users, so no file of a package is treated as test code, whatever its
folder is called.

**The score of an app package** is computed from the decoded, recovered and decompiled lines
only (manifest, resources, text assets, Dart source of a debug build, jadx output). A release
build has no recovered source, so it has few such lines: the penalty is divided by the floor
of 0.5 thousand lines, and a handful of findings already gives a low score. Release APKs
therefore often score low; compare packages by their findings, not by their score.

## 2. How an app package is decoded

`sca/flutter/apk.py` (`load_app`) runs these steps. Each step is guarded: a broken or
hostile part becomes a warning in the facts and the other steps go on.

1. **Container.** A ZIP reader of its own (`zipread.py`) reads the central directory,
   inflates entries with a size cap and never writes an entry to disk under its own name.
   It reports tricks that defeat other tools (duplicate names, names that differ only by
   case, several end records, the encryption flag). An `.aab` is one archive with module
   folders (`base/manifest/`, `base/dex/` ...); an APK set holds a base APK and ABI splits.
2. **Resource table.** `resources.arsc` (`arsc.py`) gives the names of resource ids, the
   logical names of shortened resource files and the string resources.
3. **Manifest.** Binary XML (`axml.py`) is decoded with attribute names taken from resource
   ids, as Android does, so a renamed attribute string does not hide `android:debuggable`.
   An AAB holds protobuf XML (`aabproto.py`). The result is rendered one attribute per line,
   so a finding points at the exact attribute.
4. **XML resources** (network security config, FileProvider paths) and **string
   resources**.
5. **Assets.** Text assets (`.env`, JSON, YAML ...) up to 1 MiB each. `NOTICES.Z` gives
   package names when the snapshot names none.
6. **Flutter.** A debug build ships `assets/flutter_assets/kernel_blob.bin`; `kernel.py`
   recovers the Dart source of the app's own package from it, with the package versions
   and the build-machine paths. A release or profile build ships `lib/<abi>/libapp.so`;
   `snapshot.py` reads the ELF file, the snapshot header (version hash and features, which
   give the build mode: `product` means release), the Dart strings, the `package:` URIs
   (an obfuscated build keeps only a few: 4 in the obfuscated probe build) and whether debug
   symbols are present. Obfuscation is judged from the share of short private names
   (`_Xb@...`), not from the URIs. `lib/<abi>/libflutter.so` gives the Dart version and the
   engine revision.
7. **DEX.** `dex.py` reads the string, type and class tables: plugin classes, Flutter
   markers, and the strings dump.
8. **Signing.** `signing.py` reads the v1 (JAR), v2, v3 and v3.1 signatures and parses
   the certificates (subject, validity, key, signature algorithm, debug certificate); names
   are printed in the order apksigner and keytool use (`C=US, O=Android, CN=Android Debug`).
   It does not verify signatures cryptographically; apksigner does that when it is
   installed and `--apk-tools` is given.
9. **Other native libraries** of the preferred ABI (arm64-v8a, then armeabi-v7a, x86_64,
   x86): printable strings, at most 10 libraries.
10. **Summaries.** `_sca/build.txt`, `_sca/signing.txt` and `_sca/packages.txt` hold the
    facts as `Label: value` lines, so that a finding about the build or the signature has a
    file and a line.
11. **Optional tools** (`--apk-tools`): jadx decompiles the classes of the app's package and
    of its manifest components; apksigner verifies the signature.

Limits that keep a hostile package in check: 64 MiB of decoded text per app, 300 XML
resources, 20,000 strings, 2,000 text assets, 100 DEX files, 200,000 lines per DEX or
`libapp.so` strings dump and 100,000 per other native library, lines shorter than 600
characters without control characters. Each part is read only up to a size cap, and the
decoders work within budgets (bytes of string data decoded, names and URIs examined), so a
crafted package with overlapping or oversized tables cannot make them run for long. Unicode
bidirectional control characters that come from an app are removed from every output
(findings, facts, reports and the terminal), so they cannot reorder what a reader sees. In
the dashboard, app texts shown as Markdown (alerts, labels) get an invisible WORD JOINER, so
that an address or an e-mail in them does not become a link.

## 3. The structural checks

52 checks, all in `sca/flutter/checks.py` (engine `flutter`); none of them is duplicated as
a regular-expression rule. The dashboard's Guide tab shows the same table, generated from
the code.

| Check | What it reports | CWE | Severity / confidence | Area | Applies to |
|---|---|---|---|---|---|
| ANDROID-MANIFEST-001 | App is debuggable (android:debuggable) | CWE-489 | high / 0.95 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-002 | App is marked test-only (android:testOnly) | CWE-489 | medium / 0.90 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-003 | App data can be backed up (android:allowBackup) | CWE-530 | medium / 0.80 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-004 | Cleartext HTTP allowed (android:usesCleartextTraffic) | CWE-319 | medium / 0.85 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-005 | Exported component without a permission | CWE-926 | medium / 0.75 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-006 | Exported component guarded by a weak or undefined permission | CWE-732 | low / 0.60 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-007 | Deep link with a custom URL scheme | CWE-939 | low / 0.50 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-008 | Web link without App Links verification (android:autoVerify) | CWE-939 | medium / 0.60 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-009 | Dangerous or special access permission requested | CWE-250 | info / 0.90 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-010 | Legacy external storage (android:requestLegacyExternalStorage) | CWE-922 | low / 0.70 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-011 | Task hijacking exposure (taskAffinity, allowTaskReparenting) | CWE-1021 | low / 0.40 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-012 | WebView Safe Browsing switched off (EnableSafeBrowsing) | CWE-1188 | low / 0.80 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-013 | Application disables native heap pointer tagging | CWE-693 | low / 0.90 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-014 | Application default disables GWP-ASan | CWE-693 | low / 0.90 | Android manifest | Source project and app package |
| ANDROID-MANIFEST-015 | Application default disables hardware memory tagging (MTE) | CWE-693 | info / 0.90 | Android manifest | Source project and app package |
| ANDROID-SDK-001 | Runs on Android versions before 7.0 (minSdk below 24) | CWE-693 | low / 0.70 | Android manifest | Source project and app package |
| ANDROID-SDK-002 | Targets an Android version before 9 (targetSdk below 28) | CWE-693 | low / 0.70 | Android manifest | Source project and app package |
| ANDROID-FILEPROVIDER-001 | FileProvider shares a whole storage root | CWE-552 | high / 0.80 | Android manifest | Source project and app package |
| ANDROID-NSC-001 | Network security config allows cleartext HTTP for all domains | CWE-319 | high / 0.90 | Network security | Source project and app package |
| ANDROID-NSC-002 | Network security config allows cleartext HTTP for some domains | CWE-319 | medium / 0.70 | Network security | Source project and app package |
| ANDROID-NSC-003 | User-installed certificate authorities are trusted | CWE-295 | medium / 0.80 | Network security | Source project and app package |
| ANDROID-NSC-004 | Certificate pinning bypassed or expired | CWE-295 | low / 0.60 | Network security | Source project and app package |
| ANDROID-GRADLE-001 | Release build signed with the debug key | CWE-1188 | medium / 0.80 | Gradle build | Source project |
| ANDROID-GRADLE-002 | Release build without code shrinking (minifyEnabled false) | CWE-693 | low / 0.60 | Gradle build | Source project |
| ANDROID-GRADLE-003 | Release build is debuggable | CWE-489 | high / 0.85 | Gradle build | Source project |
| ANDROID-GRADLE-004 | Keystore password written in the Gradle build file | CWE-798 | high / 0.85 | Gradle build | Source project |
| ANDROID-SIGN-001 | App signed with the Android debug certificate | CWE-1188 | high / 0.95 | App signing | App package (APK / AAB) |
| ANDROID-SIGN-002 | APK signed only with the v1 (JAR) scheme | CWE-347 | high / 0.85 | App signing | App package (APK / AAB) |
| ANDROID-SIGN-003 | APK is not signed | CWE-347 | medium / 0.90 | App signing | App package (APK / AAB) |
| ANDROID-SIGN-004 | Weak signing certificate | CWE-327 | medium / 0.80 | App signing | App package (APK / AAB) |
| ANDROID-SIGN-010 | Keystore password in key.properties inside the project | CWE-798 | high / 0.70 | App signing | Source project |
| ANDROID-SIGN-011 | Keystore file inside the project | CWE-798 | medium / 0.60 | App signing | Source project |
| IOS-PLIST-001 | App Transport Security turned off (NSAllowsArbitraryLoads) | CWE-319 | high / 0.80 | iOS Info.plist | Source project |
| IOS-PLIST-002 | App Transport Security weakened for web content, media or a domain | CWE-319 | medium / 0.70 | iOS Info.plist | Source project |
| IOS-PLIST-003 | Exception domain accepts TLS 1.0 or 1.1 | CWE-326 | medium / 0.75 | iOS Info.plist | Source project |
| IOS-PLIST-004 | Custom URL scheme registered (CFBundleURLSchemes) | CWE-939 | info / 0.80 | iOS Info.plist | Source project |
| IOS-PLIST-005 | Documents folder shared with the user (UIFileSharingEnabled) | CWE-552 | medium / 0.60 | iOS Info.plist | Source project |
| FLUTTER-APP-001 | Debug build: the Dart source code ships in the app | CWE-489 | high / 0.95 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-002 | Flutter profile build | CWE-489 | medium / 0.85 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-003 | Release build without Dart obfuscation | CWE-693 | low / 0.70 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-004 | Debug symbols left in libapp.so | CWE-215 | low / 0.85 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-005 | Paths of the build machine disclosed | CWE-200 | low / 0.70 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-006 | Secrets file bundled as a Flutter asset | CWE-798 | medium / 0.75 | Flutter app build | Source project and app package |
| FLUTTER-APP-007 | Cleartext HTTP endpoint in the compiled app | CWE-319 | medium / 0.60 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-008 | SQL query built by joining strings in the compiled app | CWE-89 | low / 0.45 | Flutter app build | App package (APK / AAB) |
| FLUTTER-APP-009 | Malformed app package (anti-analysis tricks) | CWE-693 | low / 0.60 | Flutter app build | App package (APK / AAB) |
| FLUTTER-PUB-001 | Dependency with a known vulnerability | CWE-1395 | high / 0.90 | Dependencies | Source project and app package |
| FLUTTER-PUB-002 | Discontinued or unmaintained package | CWE-1104 | low / 0.80 | Dependencies | Source project and app package |
| FLUTTER-PUB-003 | Dependency fetched over git:// or http:// | CWE-494 | high / 0.85 | Dependencies | Source project |
| FLUTTER-PUB-004 | Dependency override or dependency without a version constraint | CWE-1357 | low / 0.70 | Dependencies | Source project |
| FLUTTER-PUB-005 | Flutter app without pubspec.lock | CWE-1357 | info / 0.60 | Dependencies | Source project |
| FLUTTER-PUB-006 | Git dependency not pinned to a commit | CWE-494 | low / 0.60 | Dependencies | Source project |

Notes on the values:

- FLUTTER-PUB-001 takes its severity from the advisory. Confidence is 0.9 for an exact
  version from `pubspec.lock`. In an app package the version is often unknown (a release
  snapshot names packages but not versions): the finding is then *info* with confidence
  0.3, or keeps the advisory's severity at 0.35 when every version is affected.
- Google API keys (`AIza...`) found in `google-services.json`, `GoogleService-Info.plist`,
  `firebase_options.dart`, the Firebase entries of `strings.xml`,
  `web/firebase-messaging-sw.js`, the `firebaseConfig` of `web/index.html`, or the strings
  dump of `libapp.so` when it also holds the other Firebase values (database URL, storage
  bucket, `messagingSenderId`) are lowered to low severity and confidence 0.4: they identify
  a Firebase project. The project owner can verify their restrictions in Google Cloud.
- When a packaged Android manifest declares a client key for the Google Maps SDK, the
  scanner marks the value's decoded line with low severity and confidence 0.6. The
  project owner can check the allowed Android app, signing certificate and APIs in Google
  Cloud. The scanner evaluates a copy used elsewhere in its own context.
- A structural finding points at the attribute or key that causes it (one attribute per
  line), at the start tag when the attribute is missing and the platform default applies,
  or at the matching line of a `_sca/*.txt` summary.

Where the platform limits or cancels a setting, the finding is lowered or left out:

- ANDROID-MANIFEST-003: without `android:allowBackup` the platform default (backup on) is
  reported low (0.6). An app that targets API 31 or higher and limits its backups only with
  `android:fullBackupContent` is reported low (0.6): on Android 12 and later that setting
  does not restrict device-to-device transfer, which follows `android:dataExtractionRules`.
- ANDROID-MANIFEST-004: `android:usesCleartextTraffic="true"` next to a network security
  config in an app whose minSdk is 24 or higher is reported low (0.6): there the config
  replaces the attribute, so the attribute has no effect (the config's own cleartext
  settings are checked by ANDROID-NSC-001 and -002).
- ANDROID-MANIFEST-005 and -006: the launcher activity, activities that only open links
  (their links are checked by -007 and -008), share targets (`SEND` / `SEND_MULTIPLE`) and
  home-screen widget receivers (`APPWIDGET_*`) are exported by design and are not reported.
- ANDROID-FILEPROVIDER-001: paths are resolved as androidx FileProvider resolves them (the
  canonical form of root + path), so a path that climbs out of its folder with `..` is
  caught; `<root-path>` on a narrow folder is reported low (0.5).
- ANDROID-SIGN-004 reports only a weak key (RSA below 2048 bits, DSA, EC below 224 bits),
  not the certificate's own signature algorithm: Android does not verify the signature of
  the signing certificate, only the signatures the key makes over the APK.
- ANDROID-SIGN-010 and -011: `key.properties` and keystores that a `.gitignore` of the
  project keeps out of version control are reported low; `debug.keystore` is not reported.
- IOS-PLIST-001: `NSAllowsArbitraryLoads` is not reported when
  `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsArbitraryLoadsForMedia` or
  `NSAllowsLocalNetworking` is present, because iOS 10 and later then ignore it. The legacy
  `NSThirdPartyException...` keys of an exception domain are read like the current ones.

The Dart rules (`sca/rules/dart.yaml`, 49 rules: 47 pattern rules and 2 credential
formats), by group: TLS (3 rules, CWE-295), cleartext network (1, CWE-319), WebView (7:
CWE-79, 200, 319, 489, 749), storage (6: CWE-311, 312, 732, 922), SQL (4, CWE-89),
cryptography (10: CWE-327, 338, 798), logging (1, CWE-532), clipboard (1, CWE-200), redirect
(1, CWE-601), deep links (1, CWE-939), commands (3, CWE-78), dynamic code (2: CWE-94, 470),
authentication (3: CWE-287, 347, 489), secrets (3, CWE-798: one pattern rule and the two
credential formats), web (1, CWE-79), paths (2, CWE-22). CWEs are given in their canonical
form (CWE-328, CWE-780, CWE-916 and CWE-1204 count as CWE-327, CWE-321 as CWE-798). The rules
added with the latest fixes: DART-CMD-003 (`Process.run` / `Process.start` with a program
name taken from a variable), DART-CRYPTO-010 (`Random` with a fixed or time-based seed used
for a security value), DART-STORAGE-006 (a file or preferences opened with
`MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`) and DART-CODE-002 (a method chosen at run
time by name through `reflectable` or `dart:mirrors`). Every rule, with its examples, is in
`sca/rules/dart.yaml` and in the Rules tab (`python -m sca rules show DART-CMD-003` prints
one); how rules work and how to change them is in [RULES.md](RULES.md).

## 4. Mobile taxonomy

For a mobile project or app, every finding also gets an OWASP Mobile Top 10 (2024) risk and
a MASVS group, derived from its canonical CWE (`sca/cwe.py`, `MOBILE_BY_CWE`, 51 CWEs). This
mapping is the project's own: OWASP publishes no official CWE list for the Mobile Top 10.
CWEs outside the table get no mobile class (for example CWE-470 of DART-CODE-002).

| Mobile Top 10 (2024) | MASVS group | CWEs |
|---|---|---|
| M1 Improper Credential Usage | MASVS-STORAGE | 798 |
| M2 Inadequate Supply Chain Security | MASVS-CODE | 494, 1104, 1357, 1395 |
| M3 Insecure Authentication/Authorization | MASVS-AUTH | 284, 287, 347, 639, 862 |
| M3 Insecure Authentication/Authorization | MASVS-PLATFORM | 939 |
| M4 Insufficient Input/Output Validation | MASVS-CODE | 22, 78, 89, 90, 94, 95, 98, 502, 601, 611, 643, 943, 1336 |
| M4 Insufficient Input/Output Validation | MASVS-PLATFORM | 79, 749 |
| M5 Insecure Communication | MASVS-NETWORK | 295, 319, 322, 829 |
| M6 Inadequate Privacy Controls | MASVS-PRIVACY | 200, 359 |
| M7 Insufficient Binary Protections | MASVS-RESILIENCE | 215, 489, 693 |
| M8 Security Misconfiguration | MASVS-PLATFORM | 250, 276, 614, 732, 926, 942, 1004, 1021, 1188 |
| M8 Security Misconfiguration | MASVS-STORAGE | 552 |
| M9 Insecure Data Storage | MASVS-STORAGE | 311, 312, 530, 532, 922 |
| M10 Insufficient Cryptography | MASVS-CRYPTO | 327, 338 |

Folded ids take the class of the id they fold into (for example CWE-326, CWE-328 and
CWE-1204 count as CWE-327). The HTML, PDF and SARIF reports and the dashboard show these
classes and count findings per risk.

## 5. Build modes: what each build shows and what it hides

| | debug | profile | release | release, `--obfuscate` | app bundle (.aab) |
|---|---|---|---|---|---|
| Dart code in the package | source in `kernel_blob.bin` | AOT snapshot in `libapp.so` | AOT snapshot | AOT snapshot | AOT snapshot per ABI |
| Dart source readable | yes, recovered as `dart/lib/...` | no | no | no | no |
| Class, function and package names | yes | yes | yes | renamed | as the build |
| String constants (URLs, keys, SQL text) | yes | yes | yes | yes | yes |
| `android:debuggable` | true | true (Flutter makes profile a copy of debug) | false | false | false |
| Signature scheme of the probe builds | v2 | (not built) | v2 | v2 | v1 (JAR); Google Play signs the APKs it serves |
| Gradle, key.properties, Info.plist | not in the package | not in the package | not in the package | not in the package | not in the package |

**What survives compilation** (measured on `samples/flutter_apk_probe`, built with Flutter
3.44.8 for arm64; full table in [flutter_results.md](../evaluation/flutter_results.md)):

| Planted weakness | source | debug | release | release, obfuscated | aab |
|---|---|---|---|---|---|
| AWS key, cleartext URL, SQL text in Dart | found | found | found | found | found |
| TLS check switched off (`badCertificateCallback`) | found | found | missed | missed | missed |
| Token written to the log | found | found | missed | missed | missed |
| Bundled `.env` asset and its key | found | found | found | found | found |
| Manifest, network security config, FileProvider (8 weaknesses) | found | found | found | found | found |
| Release signed with the debug key | found (Gradle) | found (certificate) | found | found | found |
| **Planted weaknesses found** | **16 of 16** | **16 of 16** | **14 of 16** | **14 of 16** | **14 of 16** |

What a release build hides: the structure of the Dart code. A callback that returns
`true`, the flow of a token into `print`, the arguments of a call: these exist only as
machine code in `libapp.so`, and the analyzer reads its strings, not its instructions. What
it does not hide: every string constant (keys, URLs, SQL text), the manifest, the
resources, the assets and the signature. Obfuscation renames classes and functions and
removes most `package:` URIs (4 were left in the obfuscated probe build); it does not hide
strings. In release builds the analyzer also reports what the build itself shows: no
obfuscation (FLUTTER-APP-003), and in debug builds the shipped source (FLUTTER-APP-001) and
the build machine's paths (FLUTTER-APP-005).

## 6. Optional tools

None is needed. `python -m sca doctor` and `python -m sca flutter tools` show what is
installed.

| Tool | Used for | Where it is looked for |
|---|---|---|
| jadx 1.4 or newer (needs Java 11+) | with `--apk-tools`: decompiles the classes of the app's package and of its manifest components (at most 2,000) into `jadx/...` Java files; the output is cached per app under the data folder | `SCA_JADX`, `JADX_HOME`, `PATH` |
| apksigner (Android SDK build-tools) | with `--apk-tools`: verifies the signature; the result goes into the facts and `_sca/signing.txt` | newest `build-tools/*` of `ANDROID_HOME`, `ANDROID_SDK_ROOT` or the default SDK folder, then `PATH` |
| aapt2, flutter, dart | only listed, not used by a scan (`flutter` builds the probe app) | SDK folders, `FLUTTER_ROOT`, `PATH` |

jadx and apksigner get only paths that the analyzer created, with time limits (300 s and
120 s); a process tree that runs over is killed.

## 7. API and key inventory

After the score, the scan lists the servers an app talks to and the keys it carries
(`sca/flutter/inventory.py`, pipeline step *API inventory*). It does this for app packages
and for Flutter and Android source projects. Everything is read from text the scan already
has: no address is contacted. Every secret is masked (`sca.walker.mask_secret`) in the
facts, the reports, the dashboard and the terminal. Masking is scan-wide: after the engines
ran, every file masks every secret of the scan, so a secret found in one file is masked in
the snippets and contexts of any finding, the facts, the inventory, the AI prompts and the
rule learner. The secrets masked this way are the values of the secrets engine (for a
`.env` file exactly the values it reports), the values of other credential findings, and
what addresses hold in plain sight: key and token query parameters, the password of
`user:password@` (also `redis://:pw@host`), and webhook and bot tokens. The value of another
credential finding is taken from the rule's own match (`SecretKey('...')` even when an
earlier literal is on the line), from a Gradle or `key.properties` signing setting
(`keyPassword`, `storePassword`; not `keyAlias`), and for a line that reads a value by its
name only from the value written next to it (`defaultValue: '...'` of
`String.fromEnvironment`, `--dart-define=NAME=value`). Every value is masked in its own file;
it is shared with every other file of the scan only when it is strong: 8 characters or more,
not a single plain word, not only digits and not very regular (Shannon entropy 2.5 or more).
So a short or plain value, such as the debug keystore password `android` or the URL
password `admin`, does not hide that word elsewhere. The result is `ScanResult.app["apis"]` (`facts["apis"]`).

| List | What it holds |
|---|---|
| `endpoints` | every server address (`http`, `https`, `ws`, `wss`) with its host, scheme, service, category and places (file and line; 20 kept, all counted) |
| `hosts` | the servers behind those addresses, with their number of addresses and their alerts |
| `calls` | HTTP, WebSocket and GraphQL calls in code, with method and target |
| `paths` | API paths kept as texts, such as `/api/v1/login` or `/receipt.pdf?access_token=` |
| `keys` | keys, tokens and passwords, one row per distinct value, masked |
| `config` | service identifiers, which are not secrets; `firebase` gathers the Firebase project in one place |
| `env` | the entries of `.env` files (flutter_dotenv), secret values masked |
| `alerts` | the warnings drawn from all of these, the most serious first |
| `summary`, `truncated` | the counts, and the lists that hit their limit (300 rows per list, 80 alerts) |

**Server addresses.** The service and category of a host come from a table of 106 known
host suffixes of 88 services (Firebase, Supabase, AWS with S3 and API Gateway, Azure,
Heroku, Vercel, Stripe, OpenAI, Slack, Telegram, ngrok ...). The categories are app server
(a host that matches no entry), cloud backend, third-party API, SDK/analytics/ads, webhook,
and tunnel or test service. In compiled code (the strings dumps of `libapp.so`, the DEX
files and other native libraries) a text that is only a host name is listed as an address without scheme:
`Uri.https('api.example.com', '/v1/login')` keeps the host and the path as two texts. Such
a text counts only when it looks like a host. The app's own package name is skipped, and so
are reversed package names: texts that start with `com.`, `org.`, `net.`, `io.`, `dev.`,
`app.`, `android.`, `java.`, `kotlin.`, `dart.`, `flutter.`, `google.`, `me.`, `co.`,
`edu.` or `gov.`, or with a two-letter country code followed by a registry word (`gov`,
`com`, `co`, `org`, `net`, `edu`, `ac`, `mil`), such as `sa.gov.absher.app` or
`id.co.bank.app`. A two-label text is skipped when its last label is an identifier-like word
(`id`, `info`, `page`, `store`, `shop`, `in`: `user.id`, `home.page`). So `ws.myshop.com`,
`eu.posthog.com`, `js.stripe.com`, `myshop.io` and `shopapi.dev` are listed. Links to
documentation and issue trackers, OAuth scope URLs, XML namespaces and loopback hosts are
left out.

**API calls and paths.** Calls are read from code text: `http`, dio, `HttpClient`,
`Uri.https`, `WebSocketChannel`, `HttpLink`, Retrofit and Chopper annotations, `baseUrl`
(a Dart getter `get baseUrl => '...'` is listed as the base address), and OkHttp and `URL`
in Java. A method call such as `.get(...)` counts only when its receiver is named like an
HTTP client by a whole word (`http`, `https`, `dio`, `client`, `api`, `rest`, `graphql`,
`gql`, `chopper`, `backend`, `server`, `network`, `service`, `session`, `request`,
`requests`, `retrofit`, `remote`), so `audioCache.get(...)` or `restaurantBox.get(...)` is
not listed. Only source projects, debug builds (recovered Dart source) and jadx output have
code text. A release build has none, so there the API paths matter: the full URL is often
put together at run time, but its path stays in `libapp.so` as a text.

**Keys.** The keys are taken from the findings of the scan that point to a credential
(CWE-798, CWE-321, CWE-259, CWE-260, CWE-547). The same value found in several places is one
row with all its places, and several keys on one line are separate rows. The file-level
finding FLUTTER-APP-006 (a `.env` file bundled in the app) is not a key: the values of the
file are listed as `.env` entries and as keys of their own. A key whose finding a reviewer
dismissed, now or in an earlier review, is left out of the key list, the counts and the
alerts; the dashboard refreshes the inventory after a review. Each row has the type, the
service, the masked value, the severity (that of the rule that found the key), whether the
key is public by design (a Firebase configuration API key, a Stripe `pk_` key, a Mapbox
`pk.` token, a Supabase anon key; a Firebase API key that also appears outside the Firebase
configuration counts as a secret key), the manifest entry that uses it (for example
`com.google.android.geo.API_KEY`) and what to do: restrict a Google key, roll a
Stripe secret key, deactivate an AWS key, rotate a Supabase `service_role` key, revoke a
webhook or bot token, move an encryption key to Android Keystore or iOS Keychain, keep
signing passwords out of the code. For a JSON Web Token the claims `iss`, `role`, `ref`,
`aud`, `iat` and `exp` are shown; the signature is not checked. `flutter info`,
`flutter apis` and `flutter decode` (`facts.json`) run the secrets engine, the structural
checks and the pattern rules that report credentials, drop the lines that contain a
suppression marker (`nosec`, `nosemgrep`, `sca:ignore`; the structural checks' keys
included) and mask as a scan does, so their key list matches that of a full
scan. Reviews stored in the dashboard (dismissed findings) apply only to scans, not to these
commands.

For the inventory the secrets engine got three more key formats: Slack webhook URL
(SECRET-SLACK-002), Discord webhook URL (SECRET-DISCORD-001) and Telegram bot token
(SECRET-TELEGRAM-001). Only the token part is masked, so the address stays readable, also
when the URL is assigned to a variable named like `slackToken`; for a Slack webhook the
token is the last path segment, also in a Slack Workflow URL. The engine now has 11 built-in
formats. A Microsoft Teams webhook URL is reported by the imported Gitleaks rule with only
its token part as the secret (service Microsoft Teams, webhook advice), and the imported
base64 JSON Web Token rule masks the whole token.

It also reads the `NAME=value` lines of `.env` files (`.env`, `.env.<name>` or
`<name>.env`; templates such as `.env.example`, `.sample`, `.template`, `.dist`,
`.defaults` and `.schema` are skipped); the value may be quoted, and an inline comment after
it (`NAME=value # note`) is allowed. A line counts when the name is or contains password,
passwd, pwd, passphrase, secret, token, credential, hmac, auth, salt, private or signature,
ends in `KEY` (`MAPS_KEY`, `MAPKEY`, `STRIPE_KEY`, `KEY`) or has a separate `PASS` segment
(`SMTP_PASS`, `PASS`). Names of settings are skipped: names ending in `_NAME`, `_HEADER`,
`_PREFIX`, `_ALIAS`, `_FIELD`, `_PARAM`, `_LABEL`, `_ID`, `_TTL`, `_EXPIRY`, `_EXPIRES`,
`_LENGTH`, `_SIZE`, `_URL`, `_URI`, `_PATH`, `_FILE`, `_DIR`, `_DOMAIN`, `_HOST`,
`_HOSTS`, `_SCOPE`, `_SCOPES`, `_AUDIENCE` or `_REGION` (`API_KEY_HEADER_NAME`,
`TOKEN_PREFIX`), and `KEY_ID` and `PUBLIC_KEY`. Placeholders, URLs without credentials, file
paths, values that are public by design (`pk_live_`, `pk_test_`, `pk.eyJ...`, `appl_`,
`goog_`) and plain host names (`shop.eu.auth0.com`) are skipped as values, and a value that a
known key format already reports (a quoted Stripe key) is reported once; for keys and tokens (not passwords) so are words joined by
`_`, `-`, `:` or `.` (`CACHE_KEY=homepage_products_v2`, `X-Shop-Api-Key`). A key needs 12
characters and entropy 3.0, a password 6 characters.

**Service identifiers.** Firebase app ID, sender ID, project ID, storage bucket, database URL
and auth domain; Google OAuth client ID; AdMob app and ad unit IDs; Facebook app ID and
client token (masked); Sentry DSN; Stripe publishable key; Mapbox public token; Supabase
project URL. They are read from `strings.xml`, `google-services.json`,
`GoogleService-Info.plist`, `firebase_options.dart`, the `<meta-data>` entries of the
manifest and the texts of compiled code. They are not secrets, but they name the projects
whose access rules and key restrictions should be checked.

**Alerts**, the most serious first:

| Level | Alerts |
|---|---|
| danger | secret keys in the app package (or in the source, which goes into every build); each high or critical key with its place; a Supabase `service_role` key; unencrypted `http://` or `ws://` addresses; tunnel and request-catcher addresses (ngrok, localtunnel, webhook.site ...); webhook addresses (Slack, Discord, Teams); a Telegram bot token in an address; a user name and password in an address; a `.env` file inside the app package; a debug build that holds the full Dart source |
| warning | a key or token in the query of an address or API path; development, test or sandbox servers (host labels such as `dev`, `staging`, `test`, `qa`, `uat`, `sandbox`); private IP addresses and servers addressed by IP; a `.env` file of a project (flutter_dotenv copies it into the app when it is listed under assets) |
| info | the texts of `libapp.so` are readable (obfuscation hides names, not texts); reminders to check the access rules of a Firebase Realtime Database, a storage bucket, a Supabase project (Row Level Security) or an S3 bucket; the list of services the app talks to |

A release build keeps the texts of the Dart code, so its addresses and keys stay readable.
The compiler also joins adjacent string literals, so a key written in parts in the source is
whole only in `libapp.so`: in the API probe the release build lists 10 keys, the source 5.
Obfuscation renames classes and functions, not texts, and does not change the inventory
(section 9).

## 8. Command line and dashboard

- `python -m sca scan PATH` takes a folder, a file or an app package. `--no-flutter` turns
  the structural checks off; for a source project it also leaves out the app facts and the
  API and key inventory, while an app package keeps both. `--apk-tools` adds jadx and
  apksigner. Bandit, Semgrep and Gitleaks are skipped for app packages (they read files on
  disk). For a mobile target the summary also prints an `APIs   :` line and the serious
  (danger) alerts of the inventory.
- `python -m sca flutter info|decode|deps|apis|tools [PATH] [--out DIR] [--json]
  [--apk-tools] [--exclude a,b]`: `info` prints the facts and a one-line summary of the
  inventory (or a `Note:` when the inventory failed), `deps` the Dart packages and their
  issues, `apis` the inventory (summary, alerts, then every list with its places; with
  `--json`, `facts["apis"]`), `decode` writes every virtual file plus `facts.json`, which
  holds the inventory too, into an empty folder (exit 0, or 1 when a file could
  not be written; 2 for a usage error), `tools` the optional tools. The options can come
  before or after the action and the path (`flutter decode app.apk --out decoded` and
  `flutter --out decoded decode app.apk` are the same). Package sizes are given in decimal
  units (1 MB = 1,000,000 bytes), as in the evaluation tables.
- The **Scan input** tab accepts a file, a local directory, or uploads. Select the directory
  containing the base APK and its companion APKs, or upload the files together. Selecting
  a local base APK shows the adjacent files and a checkbox to include them. **Flutter sample** in **Samples** selects
  `samples/flutter_vulnerable_app`. **Flutter / Android checks** and **Decompile and verify
  app files (jadx, apksigner)** are the two switches. After a scan the Dashboard tab shows
  an app panel (package, versions, build mode, SDK levels, signing, permissions,
  components, deep links, packages, decoder warnings) and charts by OWASP Mobile Top 10 and
  MASVS group. Under the app panel, **APIs and keys: N server addresses, N keys, N serious
  alerts** opens the inventory: the counts, the alerts as coloured boxes, the tabs Server
  addresses, Keys, Hosts, API calls, API paths, Service IDs (with the Firebase project) and
  .env entries, and a **Download the inventory (JSON)** button. It replaces the plain list
  of server addresses that the app panel showed before. The Guide tab has a **Flutter and
  APK** page with the checks and rules tables and a description of this panel.
- Click a server address, API path or API call to open its recorded file and line beside the
  table. For repeated addresses or paths, use **Recorded locations** to choose the occurrence.
  A call opens at the invocation. When its target was recorded on a different line, both
  locations are available. A line in a binary strings view refers to the extracted list.
- Reports: the HTML report has an *APIs and keys* section (summary line, alerts, tables,
  and a note when a list was cut), the PDF report the same as text, SARIF the summary, the
  alerts and the `truncated` counts in `run.properties.apiInventory`, and the JSON report
  the whole inventory in `app.apis`.

## 9. Evaluation

`python evaluation/flutter_eval.py` writes `evaluation/flutter_results.md` and `.json`.
Static engines only, no AI.

| Measurement | Result |
|---|---|
| Flutter samples (60 labelled weaknesses, 2 hard, 5 decoys; safe app), all static engines | precision 1.000, recall 0.983, F1 0.992 (59 TP, 0 FP, 1 FN) |
| Same, pattern rules and secrets only (no Flutter checks) | precision 1.000, recall 0.550 |
| Same, strict mode | precision 1.000, recall 0.233 |
| DVMA, 218 modules (module-level recall) | 26 found (11.9%); 75 modules have some finding in their folder |
| DVMA, *code* categories / *design* / *runtime, AI* | 26.2% / 10.0% / 4.3% |
| Ostorlab Insecure Flutter, 16 files | 15 found (93.8%) |
| DVFA, 10 challenges | 5 found (50%); 5 of the 7 not marked hard |
| APK probe, planted weaknesses found | source 16/16, debug 16/16, release 14/16, obfuscated 14/16, aab 14/16 |
| API probe, inventory items listed | source 21/21, debug 22/22, release 24/24, obfuscated 24/24 |

How to read it: the samples and the two probes were written with the tool, so they show that
the module works end to end, not how it does on unseen code. The labs were written by others;
their truth files (`evaluation/flutter_truth/`) were written for this evaluation from each
lab's own documentation, with the file and line of every item. DVMA is large and most of
its modules are authorization, IPC, AI-agent or runtime-defence weaknesses that a static
pattern or structural check cannot see (`evaluation/flutter_truth/dvma.json` classifies
each category); its app-level settings (exported components, cleartext, backup, debuggable
release manifest) are found but belong to no single module, so they are reported separately.
Ostorlab rose from 10 to 15 of 16 files with the four Dart rules added in the latest round of
fixes (DART-CMD-003 for O03 and O07, DART-CRYPTO-010 for O08, DART-STORAGE-006 for O09,
DART-CODE-002 for O12). These rules were written after those misses were known, so for
these five files Ostorlab is no longer an unseen test. The one file still missed (O10, a
padding oracle: AES-CBC with PKCS7 and no MAC) needs to know that decrypted input is never
authenticated, which no line rule sees.

The Flutter samples rose from recall 0.967 (58 TP, 0 FP, 2 FN) to 0.983 when the secrets
engine began to read unquoted `NAME=value` lines of `.env` files: M27 (a secret in a `.env`
file) is now found, and pattern rules and secrets alone went from 32 to 33 TP (recall 0.533
to 0.550). The one weakness still missed is D30 (CWE-598, an access token in the query of a
URL). No rule reports it; the inventory raises a "key or token in the address" alert for
it, but an alert is not a finding.

**API and key inventory.** `samples/flutter_api_probe` is a Flutter app full of server
addresses and keys; `evaluation/flutter_truth/api_probe.json` lists 25 items and the scans
in which each one is expected. An item is expected only where it can exist: a key written in
parts (`'sk_' 'live_' '...'`) is whole only in a release build, the Google Maps key that
Gradle joins (`manifestPlaceholders`) only in a built manifest, and the calls only where
there is code text. Full table: [flutter_results.md](../evaluation/flutter_results.md),
section 6.

| Scan | Items listed | Addresses | Hosts | Keys (secret) | Calls | API paths | Service IDs | .env entries | Alerts (danger / warning / info) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| source | 21 of 21 | 15 | 15 | 5 (4) | 12 | 5 | 12 | 3 | 9 / 5 / 4 |
| debug.apk | 22 of 22 | 15 | 15 | 6 (5) | 12 | 5 | 13 | 3 | 12 / 4 / 4 |
| release.apk | 24 of 24 | 18 | 16 | 10 (8) | 0 | 3 | 13 | 3 | 15 / 4 / 5 |
| release_obf.apk | 24 of 24 | 18 | 16 | 10 (8) | 0 | 3 | 13 | 3 | 15 / 4 / 5 |

A release build lists more keys than the source, because the compiler joins the keys
written in parts. Obfuscation changes nothing in the inventory. The release builds list no
calls, because they keep no code text.

Reproduce:

```bash
python evaluation/flutter_eval.py                         # samples and the labs
python infected_project/fetch_labs.py                     # downloads DVMA, DVFA, Ostorlab (and the other labs)
python tools/build_flutter_apks.py --out ../probe_apks --modes debug,release,obfuscated,aab
python evaluation/flutter_eval.py --apks ../probe_apks    # adds the "what survives compilation" table
python tools/build_flutter_apks.py --app flutter_api_probe --out ../api_apks --modes release,obfuscated,debug
python evaluation/flutter_eval.py --api-apks ../api_apks  # adds the packages to the inventory table
```

`tools/build_flutter_apks.py` copies `samples/flutter_apk_probe` (or, with
`--app flutter_api_probe`, the API probe) to a temporary folder, adds the template files
with `flutter create`, and builds offline when the Gradle and engine caches are present
(`--allow-downloads` otherwise). It never writes into the repository. Never install or run
the built packages. `tests/test_flutter_inventory.py` scans the API probe packages when
`SCA_FLUTTER_API_DIR` names the folder that holds `release.apk`, `release_obf.apk` and
`debug.apk`.

## 10. Limits

- A release build is read through its strings, not its machine code: weaknesses that are
  code structure (a TLS callback, data flow into a log or a query) are found only in the
  source or in a debug build. In the probe, the release, obfuscated and AAB builds lost the
  evidence of the TLS callback and of the token written to the log; only the strings
  survived.
- Dart code is checked line by line with heuristic input tracing in one file; there is no
  Dart data-flow engine and no call graph across Dart and Kotlin/Java (platform channels).
  DART-TLS-002 looks only at the line right after the callback opens: a log line before
  `return true` makes it miss the weakness.
- FLUTTER-BUILD-001 checks a `flutter build` command written on one line; a command
  continued over several lines with `\` is not checked.
- The score of an app package counts only decoded, recovered and decompiled lines (section
  1.2), so release APKs often get a low score from a few findings.
- Authorization logic, deep links that trigger actions, missing runtime defences (root,
  tamper and debugger detection, FLAG_SECURE) and AI behaviour are not found by static
  checks.
- Package versions in a release app are usually unknown, so vulnerable-dependency findings
  for apps have low confidence. The advisory list is curated and offline; it is not a live
  OSV query.
- iOS apps (`.ipa`) are not decoded; only `Info.plist` of a source project is checked.
- Signatures are parsed, not verified, unless apksigner is installed.
- The mobile classes (M1-M10, MASVS) are the project's own mapping from CWE ids.
- The API and key inventory (section 7) lists API calls only where code text exists:
  source projects, debug builds and jadx output. In a release build only the addresses and
  API paths kept as texts remain.
- The service of a host comes from a fixed table of 106 host suffixes (88 services); every
  other host counts as the app's own server.
- In compiled code a text that is only a host name is taken as an address by a heuristic
  (section 7: not the app's own package name, not a reversed package name such as
  `sa.gov.absher.app`, and for two labels not an identifier-like last label such as `id`
  or `info`). It can miss a host, for example a two-label host under `.info` or `.shop`, it
  can take a dotted name for a host, and an address put together from parts at run time is
  not seen whole.
- The claims of a JSON Web Token are decoded, not verified.
- Service identifiers are recognised only under well-known names and formats (Firebase,
  Google, AdMob, Facebook, Sentry, Stripe, Mapbox, Supabase and a few more).
- Each list keeps at most 300 rows and the alerts at most 80; the rest is counted in
  `truncated`. Each item keeps at most 20 places; all its places are counted in its
  `count`.
- Nothing is checked over the network: whether a Firebase database or a storage bucket is
  really public, or whether a key still works, is not tested. The alerts say what to check.
