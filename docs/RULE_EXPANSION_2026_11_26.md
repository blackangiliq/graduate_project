# Reviewed rule expansion — 2026-11-26

This update adds **88 enabled rules**: 80 provider credential formats from Betterleaks,
three previously skipped Gitleaks formats, and five narrow Java/Kotlin syntax checks
adapted from CodeQL. The original packs and user rule edits are preserved. The shipped
YAML inventory now contains **629 rules, 582 enabled by default** (previously 541/494).
Local learned rules or edits can change a running installation's active count.

These numbers count detector definitions. They do not measure vulnerabilities found,
prove the validity of a credential, or imply complete language or application coverage.

## Provenance

| Source | Pinned revision | Scope and result |
|---|---|---|
| [Betterleaks configuration](https://github.com/betterleaks/betterleaks/blob/702504ab4551b9a1c1837efdb6b340536aa4c761/config/betterleaks.toml) | `702504ab4551b9a1c1837efdb6b340536aa4c761`, 2026-11-25 | 486 upstream entries reviewed by the importer; 80 imported, 406 explicitly skipped |
| [Gitleaks configuration](https://github.com/gitleaks/gitleaks/blob/09242ce9c8a60d9b051fc2d166f9e849b88c7ac0/config/gitleaks.toml) | `09242ce9c8a60d9b051fc2d166f9e849b88c7ac0`, 2025-11-20 (configuration revision) | Three compatibility recoveries; original 205 imported definitions preserved |
| [CodeQL Java security queries](https://github.com/github/codeql/tree/43fb30bb443c04731009218f39cba97cd93dd6fe/java/ql/src/Security/CWE) | `43fb30bb443c04731009218f39cba97cd93dd6fe`, 2026-11-26 | Five narrow syntax adaptations; original four WebView adaptations preserved |
| [DevSkim comparison](https://github.com/microsoft/DevSkim/compare/6997e759b48d9fed457b5399b4e89681e6a4dcd4...7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51) | Existing `6997e759b48d9fed457b5399b4e89681e6a4dcd4` compared with retrieved `7f8e5e24f62d9ba95f261e7f45b4b1c293a59a51` | Only a release-pipeline file changed; no new rules to import |

The original Gitleaks repository revision `5f6ec56` resolves to
`5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` (2026-10-23). Its configuration is identical
to the older configuration revision pinned above; that date difference is intentional.
All copied/adapted sources use MIT; copyright notices and the license are in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

Downloaded source checksums (SHA-256):

- Betterleaks TOML: `d0bcc9fc06fbbd14c97a49a3d50eb6ee62be64bef18ccab74b86eab3767f2355`
- Gitleaks TOML: `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`

## What changed

The new provider formats include Groq, OpenRouter, Replicate, Neon, Supabase secret keys,
Anthropic OAuth tokens, Apify, Brave, Cerebras, Daytona, Docker Hub, Figma, Gemini, Jina,
Nvidia, Polar, Tavily, UpCloud and xAI. All 80 IDs and expressions are available in
`sca/rules/imported/betterleaks.yaml`. A captured value remains the complete matching
credential, with its source line retained by the secrets engine. Format matching alone
does not establish whether a credential is active or grants privileged access.

The compatibility pack adds Airtable personal access tokens, Facebook app access tokens
and Freemius PHP configuration keys. It fixes incompatible character classes or missing
test context while retaining provider keyword and PHP file restrictions. The Airtable
upstream ID spells `personnal` with two `n` characters; the ID is deliberately preserved.

The CodeQL adaptations cover an unconditional hostname-verifier lambda, additional
no-op certificate-chain callbacks, an always-true fragment validator, a nested incoming
Intent passed directly to a launcher, and sensitive-named values written through an
ordinary SharedPreferences creation/edit chain. Each describes the visible evidence
and the conditions still needing review. They do **not** run CodeQL's type or dataflow
analysis. Names, direct call syntax and one-line bodies are their deliberate limits.
They apply to Java and Kotlin source or readable decompiled code; they do not recover
these structures from opaque native or Flutter AOT instructions.

## Selection and exclusions

`tools/import_betterleaks.py` accepts only the exact pinned input checksum. It imports
new, high-confidence, provider-prefixed formats with one explicit value capture and
compatible entropy filters. It checks Python compatibility, bounded stress completion,
a matching example, overlap with existing built-in formats, and known-safe samples.
The complete decision for every upstream entry is in
`evaluation/betterleaks_import_report.json`:

| Reason skipped | Count |
|---|---:|
| Already represented by Gitleaks | 200 |
| Outside the standalone prefixed-token subset | 78 |
| Association-only identifiers | 45 |
| Component association unsupported by this importer | 29 |
| Filter semantics unsupported by this importer | 18 |
| Outside the reviewed high-confidence subset | 30 |
| Path semantics unsupported by this importer | 4 |
| Public client SDK identifier | 1 |
| Broad provider-name expression | 1 |

Supabase's distinctive `sb_secret_` format has one explicit adaptation: the literal is
reported without requiring a project-URL association, as an unverified credential
candidate. No association with a particular project is inferred. This exception is
recorded in the rule note. Some upstream rules require a provider keyword on the same
line; those restrictions remain in effect.

No validation, analysis or revocation expressions are copied or executed. Global
upstream path exclusions are not imported; the platform applies its own placeholder
checks. Unsupported expression filters are never silently dropped. Repositories with
different licensing terms were not bulk copied into these MIT packs.

## Verification

`tests/test_expanded_rule_pack.py` passes 177 cases. Independently constructed, nonworking
credential fixtures cover 24 provider formats across six source/origin combinations:
Java, Kotlin, Dart, decoded configuration, extracted native strings and JavaScript.
They check the full captured value and exact line; additional cases cover contextual
keywords, placeholders, truncated values, Gitleaks PHP scope, safe/unsafe API variants,
comments, importer exclusions, provenance and unique IDs. The importer separately
checks all 80 imported patterns and 324 known-safe sample lines (zero matches).

These are regression fixtures, not fabricated application findings. The app-corpus
audit is separate; its observed counts must not be replaced with fixture results.
Static inspection cannot prove that every runtime-generated, encrypted, downloaded,
obfuscated or split value has been recovered. A source path or binary offset describes
the actual evidence location; service access remains unverified without a separate
authorized validation step.

## Follow-up precision correction — 2026-11-27

`DEVSKIM-DS187371` keeps its ID and default disabled state. The original expression
matched bare mode names, including authenticated modes and the `ECB` spelling in an
RSA transformation. The local adaptation now matches only `CipherMode.ECB` and quoted
AES/DES/DESede/Blowfish/RC2 ECB transformations. It excludes RSA within each match, so
an RSA call on the same line does not suppress an actual AES ECB setting. The title
and guidance now describe symmetric ECB and authenticated encryption accurately.

The adaptation preserves DevSkim revision
`6997e759b48d9fed457b5399b4e89681e6a4dcd4` as its upstream provenance and is retained
by `tools/import_rules.py` on a subsequent import. User edits, including an existing
enable override, are preserved. This correction adds no rules and does not change
the 629/582 shipped counts. `tests/test_devskim_cipher_precision.py` covers safe RSA
names, unrelated names, symmetric ECB, mixed RSA/AES lines, the user override path
and reimport behavior.

Reproduction after retrieving the pinned TOML, in the project's development environment
with `requirements-dev.txt` installed (the importer needs `exrex`):

```powershell
python tools/import_betterleaks.py path\to\betterleaks.toml
python -m pytest tests/test_expanded_rule_pack.py -q
```
