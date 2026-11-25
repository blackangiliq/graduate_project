# flutter_apk_probe

A deliberately insecure Flutter app that is built into real app packages to test the
analyzer on APKs and app bundles. FOR TESTING THE ANALYZER ONLY: never install, run or publish
the packages.

The folder holds only the files that differ from the Flutter template, and the app uses only
the Flutter SDK and `dart:` libraries, so it builds from the local caches without downloads.
`tools/build_flutter_apks.py` copies it to a temporary folder outside the repository, adds the
template files with `flutter create` (the shipped files are never overwritten) and builds:

    python tools/build_flutter_apks.py --out <folder> --modes debug,profile,release,obfuscated,aab

| mode | file | what shows the build mode |
|---|---|---|
| debug | `debug.apk` | `assets/flutter_assets/kernel_blob.bin` (the Dart source), `android:debuggable="true"` |
| profile | `profile.apk` | `lib/<abi>/libapp.so`; the Flutter Gradle plugin makes the profile build type a copy of the debug one (`initWith(debug)`), so it is expected to be debuggable and debug-signed. Gradle downloads its engine libraries the first time, so the tool builds it only when they are cached or with `--allow-downloads`. |
| release | `release.apk` | `lib/<abi>/libapp.so`, names not obfuscated |
| obfuscated | `release_obf.apk` | `lib/<abi>/libapp.so` without class, method and package names; symbols in `release_obf.*.symbols` |
| aab | `release.aab` | app bundle: `base/manifest` (protobuf XML), `base/lib`, `base/dex`, JAR signature |

Every package is signed with the Android debug certificate: the release build type keeps the
template's debug signing.

## What the analyzer should find

Dart code (`lib/main.dart`):

| marker | debug (`kernel_blob.bin`) | release, aab (`libapp.so`) | obfuscated (`libapp.so`) |
|---|---|---|---|
| AWS documentation key `AKIAIOSFODNN7EXAMPLE` | source | string | string |
| cleartext `http://api.flutter-probe.example/v1/login` | source | string | string |
| SQL text built by concatenation | source | string `SELECT * FROM users WHERE name = '` | same string |
| token written to the log | source | string `token=` | same string |
| TLS bypass (`badCertificateCallback` returns true) | source | only the method name `createTrustAllClient` | nothing |
| class `ProbeVaultService`, `package:flutter_apk_probe/main.dart` | source | names | nothing |

Android configuration: `android:allowBackup="true"`, `android:usesCleartextTraffic="true"`,
the receiver exported without a permission, the custom scheme `probe://`, the https link
without `android:autoVerify`, a network security config that allows cleartext in
`base-config` and trusts user CAs, and a FileProvider `root-path`. Release builds rename the
resource files (for example `res/8G.xml` for the network security config); the arsc table maps
them back. The asset `assets/.env` holds the same example key.
