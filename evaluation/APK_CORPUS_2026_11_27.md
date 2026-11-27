# Android corpus evidence review — 2026-11-27

The 12 supplied app sets, containing 48 APK files, were inspected with an independent AAPT2/direct-byte/DEX-string reference and scanned again through the platform. Selected manifest, resource, native-string and bundled-source evidence was reviewed across the app sets, then full values and retained-file locations were checked automatically. This is a finite evidence comparison, not an exhaustive manual code review or a claim to detect every vulnerability.

All 48 input hashes match the preceding corpus audit. Every APK member has a recorded `read` status. The independent reference reported no entry-size read limit. The platform used real app data with ML, LLM and feedback adjustments disabled for reproducibility. The full local reports and archive retain original values; this published report contains counts and evidence descriptions only.

## Results

| Phase | Retained text files | Findings | Key/material values | Normalized addresses | Configuration values | API call sites | Relative API paths |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Static extraction | 1,276 | 317 | 26 | 3,451 | 106 | 36 | 905 |
| Static plus targeted Java views | 3,964 | 328 | 26 | 3,451 | 112 | 573 | 1,014 |

Counts sum each app's inventory, so a shared SDK address can be counted in more than one app. There are 3,452 address rows before comparison normalization. Findings include informational/review evidence and are not 328 proven exploitable vulnerabilities. Key/material counts include public SDK test key material and do not establish that a credential grants access.

| App set | APKs | Files | Findings | Keys/material | Addresses | Config | Local archive scan |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 01_AynIQ | 5 | 172 | 26 | 2 | 66 | 7 | 49 |
| 02_Careem | 3 | 1181 | 48 | 4 | 513 | 20 | 50 |
| 03_Baly | 3 | 205 | 33 | 3 | 253 | 13 | 61 |
| 05_oodi | 5 | 163 | 39 | 2 | 146 | 22 | 62 |
| 06_Qi_Services | 3 | 313 | 26 | 5 | 119 | 13 | 53 |
| 07_Qi_PhonePay | 4 | 72 | 13 | 1 | 1773 | 0 | 54 |
| 08_SuperQi | 3 | 514 | 47 | 2 | 278 | 9 | 63 |
| 09_SNTAT | 4 | 869 | 25 | 1 | 99 | 9 | 56 |
| 10_Ministry_of_Communications | 4 | 41 | 7 | 0 | 6 | 0 | 57 |
| 11_UrukTech | 5 | 76 | 15 | 2 | 18 | 3 | 58 |
| 13_Taqaudi | 4 | 281 | 13 | 2 | 52 | 10 | 59 |
| 14_alwatani | 5 | 77 | 36 | 2 | 128 | 6 | 60 |

## Independent checks

Both phases matched all 20 directly observed Google-format key candidates, all four complete PEM bodies, all 87 reference URL templates, and all nine selected SDK/token resource values. The external Gitleaks review also identified one Base64-encoded Google-format key in UrukTech. The platform now recovers it; an independent Base64 decode verified its full 39-character value, encoded source span, hashes and derived-file content.

Every retained occurrence of a key, secret hit, configuration value and displayed address was compared with its referenced file and line. There were zero value/location discrepancies and zero derived-source provenance discrepancies. XML entities and complete PEM bodies are compared by their equivalent decoded representation where necessary. Locations identify the exact retained decoded XML, Java view, binary-string dump or derived plaintext view; they are not a claim to recover original pre-compilation Java/Dart line numbers.

The broad independent address reference has 1,454 candidates, of which 1,262 match the inventory after normalization. The remaining 192 include filtered store/documentation links, XML namespaces, certificate/media metadata and concatenated raw-binary fragments. These broad candidates are not a verified endpoint truth set, and the ratio must not be reported as vulnerability recall or endpoint completeness. Inventory addresses also include navigation, media and metadata literals; a literal's presence does not prove a network request occurred.

## Changes demonstrated by the corpus

- Complex Android resource bags now retain literal string members from arrays, plurals and styles, with configuration-specific files and locations. Across the corpus, 2,259 string members are retained. Careem alone contributes 683 members from 152 resources; its selected signup address is visible in `res/values/complex_resources.xml:163`.
- Resolved resource aliases link to the actual value definition. Full Careem `idp_public_api_token` and `idp_device_sdk_api_token` values are available as configuration candidates at `res/values/strings.xml:4328` and `:4306`. Their credential permissions are not assumed.
- Baly's AppMetrica and WebEngage resource values are retained with their actual locations. Known SDK client identifiers are separated from unverified credential candidates; REST/server credential names are not automatically exempted.
- Runtime URL placeholders, variable ports, balanced brackets and private IPv6 addresses retain their complete literal spelling. Templates are explicitly marked as needing runtime resolution.
- Application native strings are collected across available ABIs under shared budgets. These app sets yielded 118 application libraries, with zero application-library omissions reported. Five Flutter engine libraries remain explicitly metadata-only. Universal-APK tests separately verify different values in multiple ABIs.
- UrukTech's Base64 key is shown in a derived plaintext file with a link to its encoded origin at `classes.dex:7045`. It is not falsely attributed as plaintext in the original DEX string view.
- A new oodi generic-token alert was manually found to contain JavaScript between two log messages. The lexer was corrected and the app rescanned: the false alert and false key inventory row are gone. This is recorded as an accuracy correction, not a new vulnerability.

## Coverage limits and reproducibility

The Java phase uses 2,688 previously cached, targeted JADX files for the base APK's package and declared components. It is a fresh platform scan of retained Java views, not a fresh exhaustive decompilation. The old cache does not preserve every original JADX error/limit detail, and the reports state that limitation. Long-line pattern coverage counters and parser budgets remain visible. Static analysis cannot establish values generated only during execution, server-side restrictions, arbitrary encryption or all obfuscated code behavior.

The Base64 candidate budget was raised from 200,000 to 1,000,000 after Baly and SuperQi reached the original bound. Both were rescanned in both phases; their final Java-inclusive counts are 205,878 and 393,425 candidates, respectively. No final app reports a Base64 budget limit. Oodi was also rescanned after the lexer correction. Other app results retain their actual earlier detector identity; they had no generic-assignment hits and did not reach the old Base64 bound. Per-scan identities, input hashes, limits, source-check counts and archive IDs are in [the machine-readable report](APK_CORPUS_2026_11_27.json).

Reproduce with the authorized APK directory and locally installed Android SDK/JADX tools:

```text
python tools/independent_apk_audit.py PATH_TO_APKS --aapt2 PATH_TO_AAPT2 --output data/audits/recheck/reference.json
python tools/audit_phone_apps.py --inputs PATH_TO_APKS --output data/audits/recheck/updated
python tools/audit_phone_apps.py --inputs PATH_TO_APKS --output data/audits/recheck/deep --tools --database data/sca.db
python tools/review_phone_corpus.py data/audits/recheck --output evaluation/recheck_summary.json
```

The verifier writes full-value comparison details only to the selected local audit directory. The public JSON contains no extracted credentials, local workstation paths or decompiled application code.

Reference formats: [Android AAPT2](https://developer.android.com/tools/aapt2), [DEX string tables](https://source.android.com/docs/core/runtime/dex-format), and [Android resource-map structures](https://github.com/aosp-mirror/platform_frameworks_base/blob/main/libs/androidfw/include/androidfw/ResourceTypes.h). SDK identifier context: [AppMetrica settings](https://appmetrica.yandex.com/docs/en/settings/general?lang=en) and [WebEngage Android integration](https://docs.webengage.com/docs/android-getting-started).
