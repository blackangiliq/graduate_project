# Validation and evidence review — 2026-11-27

## What changed

This update builds on the local static and runtime Android audits. The platform retains
full original values and opens their recorded files in a side preview. Findings, literal
inventory, SDK configuration, URL templates, and runtime observations have distinct meanings.

- Source secrets: bounded extraction now covers Kotlin typed declarations, quoted values
  on following lines, long complete literals, and unquoted YAML/properties/INI values.
  Placeholders, UI labels, variable references and concatenated fragments are not presented
  as complete credentials. Coordinates point to the value, including when its declaration
  starts on a preceding line. Additional generic literals are bounded to 16,384 characters.
  This is literal analysis, not arbitrary expression evaluation.
- URL inventory: complete placeholder templates and IPv6 literals are retained. A template
  such as `https://{region}.example.invalid/v1` needs runtime substitution; it is not an
  observed request. Documentation, namespaces and media remain distinct from API candidates.
- Android resources: resolved configuration points to the literal resource definition.
  References are recorded separately. Unknown credential-like resource fields are review
  candidates, not automatically vulnerabilities. AppMetrica/WebEngage client SDK identifiers
  are distinguished from similarly named REST/server credentials.
- Configuration and `.env` tables now support source navigation and complete value previews.
- An independent Gitleaks comparison found a Base64-encoded Google-format key in UrukTech.
  The scanner now decodes relevant canonical Base64/base64url text up to two whole-string
  layers. A separate `decoded_literal` preview contains the actual decoded text, with the
  encoded file/line/column and both hashes preserved. **Open encoded source** navigates back
  to the original literal. Derived text is excluded from code/taint checks and the source
  line denominator. Limits are explicit: 16,384-character tokens, 1,000,000 candidates,
  2,000 derived files and 4 MiB of decoded text per scan. This does not decrypt encrypted data.
- Complex Android resources now retain direct string members in arrays, plurals and styles,
  including configuration variants. They appear in a derived resource XML view with
  resource/member IDs. Manual comparison recovered Careem's previously omitted signup link.
- Native extraction checks application libraries across packaged ABIs within documented
  budgets. Coverage metadata records exclusions rather than implying every native instruction
  was decompiled. Optimized Dart AOT still yields available strings and metadata, not original
  Dart source.

## Independent comparison method

The local corpus contains 12 applications and 48 APK files, including split installations.
The independent reference tool does not import `sca`: it uses Android SDK AAPT2 resources,
the DEX string table format, and direct byte searches. The platform is then run against
the same inputs. APK hashes, tool settings, original source snapshots and comparison
artifacts are kept under `data/audits/2026-11-27-expansion/`.

Manual inspection means targeted review of decoded manifests, resource fields, DEX/native
literals, and differences for each app. It does **not** mean every decompiled instruction
or application screen was reviewed. A match against the reference measures agreement with
that reference's formats and extraction scope, not total vulnerability recall.

The publication summary in `evaluation/` contains aggregate counts and input identities;
raw credentials, decompiled app code and APKs stay in the ignored local audit directory.
Tests use isolated fixtures to verify positive and negative cases. They are never substituted
for observations in the live platform.

### Measured corpus results

| Phase | Retained files | Findings | Key/material entries | Normalized addresses |
| --- | ---: | ---: | ---: | ---: |
| Static extraction | 1,276 | 317 | 26 | 3,451 |
| Static plus targeted Java views | 3,964 | 328 | 26 | 3,451 |

The Java-inclusive pass also retains 112 configuration values, 573 API call sites and
1,014 relative API paths. These counts sum each application's inventory; shared SDK
values can appear in multiple applications. Addresses include navigation, media and
metadata literals, and findings include review/informational evidence. They are not
counts of confirmed exploitable vulnerabilities or observed API requests.

Both phases matched 20/20 direct provider-format candidates, 4/4 complete PEM bodies,
87/87 reference URL templates and 9/9 selected SDK/token resource values. The additional
Base64 key passed independent decode and provenance checks. Retained value/location
checks and derived-source checks reported zero discrepancies. No final app reached the
Base64 extraction budget. An oodi log-message false positive was corrected and rescanned.

The Java phase reuses 2,688 cached, targeted JADX files for package/component classes.
It is a fresh platform scan of those views, not a fresh exhaustive decompilation; original
cache-generation errors and limits are not fully recoverable. Final archive IDs, per-app
results, remaining coverage limits and actual detector identities are recorded in the
[corpus review](../evaluation/APK_CORPUS_2026_11_27.md) and its
[machine-readable evidence](../evaluation/APK_CORPUS_2026_11_27.json).

### Validation record

The local full-suite run completed with 2,251 passes, 45 skips and one missing-Arabic-label
failure. The missing labels were added and the failed test passed on rerun. Subsequent
focused checks cover the final lexer, Base64 provenance and budget, source navigation,
archive persistence and external-engine error reporting. CI runs the committed version
of the full suite on Windows and Ubuntu with Python 3.10/3.12 and separately exercises
the hosted container; its run status is the authoritative final-commit result.

The shipped-default static evaluation records TP 68, FP 6 and FN 3 (precision 0.919,
recall 0.958, F1 0.938) on the labeled repository fixtures. These fixture metrics do not
measure completeness on the supplied real applications. A live browser check confirmed
that UrukTech's full decoded key is visible without redaction and that **Open encoded
source** reaches `classes.dex:7045`.

## Reproduction

Use Python 3.10+ with the project's dependencies. The static loaders work on Windows without
Docker. Configure `SCA_JADX` to the installed JADX launcher for the deeper decompiled pass.

```powershell
python tools/independent_apk_audit.py --help
python tools/audit_phone_apps.py --inputs PATH_TO_APK_FOLDERS --output data/audits/validation/static
python tools/audit_phone_apps.py --inputs PATH_TO_APK_FOLDERS --output data/audits/validation/deep --tools --database data/sca.db
python tools/compare_phone_audit.py --help
python tools/review_phone_corpus.py data/audits/validation --output evaluation/recheck_summary.json
python -m pytest tests -q
python evaluation/evaluate.py
```

The static corpus driver uses the same `scan_project` pipeline as the dashboard, with AI,
ML and review feedback disabled for deterministic comparison. Per-app artifacts list
engine errors, omitted data and input members. The static driver's resume check fingerprints
APK contents, detector code, rule packs and local rule overrides, so changed inputs or
detectors are rescanned.

## Runtime evidence retained from the preceding experiment

The 12-app startup experiment recorded 1,121 events and 175 derived observations: 64 URLs,
34 hosts, 34 socket destinations/attempts, 25 credential candidates and 18 cryptographic
key values. Seven recording windows completed; five had partial coverage. These are
per-application totals, not globally unique secrets or confirmed vulnerabilities.

AynIQ's retained compatibility session observes Java only. PhonePay also crashed in an
uninstrumented emulator baseline. Other partial runs record their startup/attach limitations.
These measurements cover the stated startup windows, not login flows or every screen.
See [runtime setup and limitations](DYNAMIC_ANALYSIS.md). This static expansion does not
relabel those older runtime sessions as newly recorded sessions.

## Interpretation and remaining limits

- An API-looking string can be a template, SDK configuration, dead code or a test value.
- An embedded client key can require server-side restriction review without being a leaked
  privileged credential. No extracted key is automatically sent to a service for validation.
- Exact literal source links are verified against retained files. Runtime-only values show
  their journal event and stack when no literal location can be established.
- Encrypted/dynamically loaded data, unexecuted paths, obfuscation, stripped native code,
  external services and decoder budgets constrain visibility. Zero findings means zero
  findings within that coverage, not proof of safety.
- Rules needing AST, taint, component association, live verification or incompatible
  licensing are not silently converted into weaker regex rules. See the
  [upstream source review](UPSTREAM_RULES_2026_11_27.md).

Primary interpretation references: [AppMetrica SDK and POST keys](https://appmetrica.yandex.com/docs/en/settings/general?lang=en),
[WebEngage Android initialization](https://docs.webengage.com/docs/android-getting-started),
[Android AAPT2](https://developer.android.com/tools/aapt2),
[Android DEX format](https://source.android.com/docs/core/runtime/dex-format).
