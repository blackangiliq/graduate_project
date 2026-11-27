# Source review and rule expansion — 2026-11-27

This update adds **37 enabled detector definitions**: **21 contextual credential
formats** and **16 explicit library/API setting checks**. The shipped YAML catalog is
now **666 rules, 619 enabled by default** (previously 629/582). Local rule edits may
change the active count. These counts do not include structural Android checks, the
Python AST analyzer or runtime observers, and do not measure complete vulnerability
coverage.

## GitHub sources reviewed

The machine-readable [source manifest](../evaluation/upstream_sources_2026_11_27.json)
records **22 pinned source artifacts** with repository, exact commit, file path, use and
SHA-256. The downloaded artifacts were checked locally. A moving branch name is not
used as an import identity.

| Source | Reviewed revision | Result |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks/tree/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c) | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | 222 configuration entries; the configuration bytes match the previous reviewed configuration. Existing adaptations retained. |
| [Betterleaks](https://github.com/betterleaks/betterleaks/tree/702504ab4551b9a1c1837efdb6b340536aa4c761) | `702504ab4551b9a1c1837efdb6b340536aa4c761` | 486 entries; 21 additional, explicitly selected contextual formats now supported. Original 80-format subset retained. |
| [Microsoft DevSkim](https://github.com/microsoft/DevSkim/tree/7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51) | `7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51` | Android XPath checks reviewed. Equivalent manifest settings already use the platform's structural XML analysis; XPath is not silently replaced with a text search. |
| [GitHub CodeQL](https://github.com/github/codeql/tree/a2eb8773e16f5c1c76810ae3bdc9d5cfbd44b5c2) | `a2eb8773e16f5c1c76810ae3bdc9d5cfbd44b5c2` | Existing nine narrow Java/Kotlin/Android adaptations retained. This project does not run the CodeQL type/data-flow engine. |
| [MobSF/mobsfscan](https://github.com/MobSF/mobsfscan/tree/e48f780d04c4fdd38ec07c1de3d2210513f48ecd) | `e48f780d04c4fdd38ec07c1de3d2210513f48ecd` | Android rule categories reviewed as a coverage reference. No LGPL analyzer/rule source is copied into the MIT import pack. |
| [Minded Security Android rules](https://github.com/mindedsecurity/semgrep-rules-android-security/tree/8133aa8aff3b0aa897cd92a004af9ae7b854270b) | `8133aa8aff3b0aa897cd92a004af9ae7b854270b` | Coverage reference only; GPL rule files are not copied or represented as locally executed checks. |
| [Semgrep community rules](https://github.com/semgrep/semgrep-rules/tree/a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2) | `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` | Separate Semgrep Rules License and engine semantics reviewed. No blanket conversion or inclusion. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog/tree/23255461ddf3958c4d949d89925b03eaf263d838) | `23255461ddf3958c4d949d89925b03eaf263d838` | Detector/validation architecture reviewed. No AGPL detector code or active credential-validation requests are executed by these additions. |

Research references are distinct from imported code. All copied credential rules in
this addition come from the pinned MIT Betterleaks configuration. See
[third-party notices](../THIRD_PARTY_NOTICES.md). The other 14 manifest artifacts are
official API sources used to check the semantics of original local patterns.

## Credential coverage added

`sca/rules/imported/betterleaks_contextual.yaml` adds Asaas, Azure App Configuration,
Azure Service Bus, GC Notify, ClickUp, crates.io, Databento, DeepSeek, ElevenLabs, Fal,
Figma header tokens, routable/versioned GitLab PATs, Kagi, Kimi/Moonshot, Mem0, ngrok,
Ollama, Retell, Zhipu and two Zoho token formats.

These rules address provider context and structured formats excluded from the original
prefix-only importer. They retain the original capture group, keyword gating and
supported entropy comparison. For example, Azure App Configuration captures the
`Secret` value separately from its public endpoint and ID. The GitLab rule retains
the complete versioned token including its suffix.

Independent fixtures found a pre-existing false negative: Asaas credentials beginning
with `$aact_` could be mistaken for a `$variable`. The secrets engine now exempts only
the exact Asaas provider detector and complete provider format from that heuristic;
ordinary variable references remain excluded.

The new importer has a fixed reviewed ID allow-list and requires the exact source
SHA-256. It refuses unsupported association, path or filter semantics. The decision
for all 486 entries is retained in
[`evaluation/contextual_secrets_import_report.json`](../evaluation/contextual_secrets_import_report.json).
The 465 entries outside this importer are **not** all unsupported by the platform:
many are already handled by its earlier packs or built-in detectors.

No upstream `validate`, `analyze` or `revoke` expression is copied or executed.
Matches are unverified credential candidates; the format does not establish account
access, permissions or exploitability. Full matching values and exact source lines
remain available in the local evidence inventory and file preview.

## Library and Android checks added

The 16 original patterns are in `sca/rules/library_security.yaml`. Each has positive
and negative examples, ignores calls quoted in documentation/comments, and describes
the setting actually observed rather than claiming a reachable exploit.

| Area | Setting detected |
|---|---|
| Android Keystore | Explicitly disabling randomized-encryption enforcement; does not claim actual IV reuse |
| Netty | Installing `InsecureTrustManagerFactory.INSTANCE` on the SSL context builder |
| Tink | Writing a keyset using `CleartextKeysetHandle.write`; public-only keysets are distinguished in the advice |
| JJWT | Enabling unsigned parsing, or enabling unsigned payload decompression |
| Auth0 java-jwt | Creating a verifier with `JWT.require(Algorithm.none())` |
| XStream | Granting `AnyTypePermission.ANY` to a deserializer |
| Fastjson | Explicitly enabling auto-type support with nearby `ParserConfig` context |
| Jackson | Enabling default typing with `LaissezFaireSubTypeValidator.instance` |
| Retrofit 1 | Selecting full request/response logging |
| gRPC Java/Kotlin | Selecting plaintext transport in a visible channel-builder context |
| Dio | An additional certificate callback that unconditionally accepts; underlying HttpClient TLS verification remains separate |
| Flutter InAppWebView | Disabling Android Safe Browsing; separately, disabling same-origin security on the **Linux** backend |
| HTTPX | An explicit unverified client configuration in supported direct-call forms |
| .NET HttpClient | Installing `DangerousAcceptAnyServerCertificateValidator` |

The Java rules also run on Kotlin and readable JADX Java output. They are bounded
syntax checks: nearby context is not type resolution, call names may be user-defined,
and the rules do not reconstruct arbitrarily separated calls, reflection, native code
or Dart AOT source. A disabled protection can be limited to a test/debug branch; that
reachability must be reviewed separately. Native binary string dumps are not passed
off as executable Java/Dart code.

## Reproduce and verify

From the repository root on Windows:

```powershell
# Download only the exact pinned source artifacts and check their SHA-256 values.
.\.venv\Scripts\python.exe tools/verify_rule_sources.py --download

# Subsequent offline verification of those same files.
.\.venv\Scripts\python.exe tools/verify_rule_sources.py

# Obtain the pinned Betterleaks configuration from the manifest source URL, then:
.\.venv\Scripts\python.exe tools/import_contextual_secrets.py PATH\TO\betterleaks.toml

# Regenerate current counts and guides without relying on local rule overrides.
.\.venv\Scripts\python.exe tools/build_docs.py

.\.venv\Scripts\python.exe -m pytest tests/test_upstream_expansion.py tests/test_expanded_rule_pack.py tests/test_rules.py -q
```

The contextual importer ran compile, bounded stress, matching-example and known-safe
corpus checks for all 21 additions. The independent tests exercise complete values in
Java, Kotlin, Dart, JavaScript, decoded resources and binary strings; absent provider
context, placeholders, truncated values, source lines, comments, strings, safe settings
and required context distance are also checked. Generated test tokens are nonworking
fixtures used only by tests, never injected into production scan results.

`docs/RULES.md` now derives both catalog totals and per-pack counts from the shipped
files. Its original 2026-11-11 corpus tables are explicitly historical; they are not
presented as validation of later additions.

## العربية

أُضيفت **37 قاعدة مفعّلة**: 21 صيغة اعتماد مرتبطة بسياق مزود الخدمة، و16 فحصاً
لإعدادات مكتبات وواجهات برمجية. أصبح الكتالوج **666 قاعدة، منها 619 مفعلة افتراضياً**.
قد يختلف عدد القواعد النشطة بسبب التعديلات المحلية. هذا عدد كواشف وليس عدد ثغرات
ولا ضماناً لاكتشاف جميع الحالات.

مراجعة GitHub موثقة بملف يحفظ 22 مرجعاً مع الإصدار وبصمة SHA-256. احتُفظ بشروط
الاستيراد والسياق والتراخيص، ولم تُحوَّل قواعد تدفق البيانات إلى تعابير نمطية مع
ادعاء التكافؤ. قيم المفاتيح الكاملة ومواضعها تبقى في جرد الأدلة المحلي. وجود مفتاح
أو إعداد لا يثبت وحده أنه صالح أو قابل للاستغلال. ميزات بعض المكتبات تخص منصات
محددة، ولذلك يُذكر أن `disableWebSecurity` في المصدر المراجع يخص Linux، لا Android.

تقارير فحص التطبيقات الفعلية وبياناتها محفوظة محلياً في `data/audits`، ومستقلة عن
أمثلة الاختبارات. لا تُضاف القيم المستخرجة من التطبيقات إلى مستودع القواعد أو وثائقه.
