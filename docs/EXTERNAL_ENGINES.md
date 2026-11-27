# External engine validation on Windows

This project has optional subprocess adapters for Bandit, Gitleaks and
Opengrep/Semgrep. The Windows adapters were exercised with real release binaries
on 2026-11-27. Source scans can use these adapters when the tools are on the process
PATH. APK scans still use the built-in decoded-file pipeline; the comparison below
materialized retained decoded text explicitly for the independent tools. It does
not mean that these executables automatically scan APK archives inside the platform.

## Verified tools and inputs

| Tool/input | Pinned version | Verification |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) | 8.30.1, Windows x64 | Release ZIP SHA256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`, matched both GitHub asset metadata and the published checksums file |
| [Opengrep](https://github.com/opengrep/opengrep/releases/tag/v2.1.0) | 2.1.0, Windows x86 release asset | Release ZIP SHA256 `de250811f7209619e4fdafff55e5f13cb24a70c9cb0ea86435c2c92393ea04ab`, matched GitHub asset metadata |
| [Gitleaks configuration](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml) | v8.30.1 | Explicit local configuration, SHA256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf` |
| [Opengrep rules](https://github.com/opengrep/opengrep-rules/tree/f1d2b562b414783763fd02a6ed2736eaed622efa) | `f1d2b562b414783763fd02a6ed2736eaed622efa` | 37 Java/Kotlin crypto/security YAML files; individual SHA256 hashes retained with the local audit |

The Opengrep rule repository is archived. Its snapshot is licensed under LGPL-2.1
with the Commons Clause, distinct from the engine's license. It was downloaded for
local comparison and is not redistributed or relicensed as this project's MIT rules.
The engine binaries, downloaded rules, decoded application files and full credential
reports remain in git-ignored `data/`. No global PATH or machine settings were changed.

## Actual comparison

The same retained decoded snapshots from the twelve application audit were written
to separate input files, preserving logical line numbers. A local mapping connects
each generated filename to its original decoded file and SHA256. This exercises the
external detectors on what was retained; it is not independent proof that the APK
decoder recovered every byte or every execution path.

Gitleaks returned **21 candidate occurrences** across the twelve applications. Nine
matched the previous secret-hit values exactly. The twelve non-exact matches were
reviewed individually:

- Two contained complete public SDK test keys already reported by the platform,
  but Gitleaks included adjacent PEM marker strings in its match.
- Two were PEM formatting code or marker strings without a private-key body.
- Four generic matches were code/function/setting identifiers, not demonstrated keys.
- Two were hexadecimal literals next to unrelated token labels in string dumps;
  the string-table order did not establish an assignment or a live credential.
- One was a patterned value in a payment test activity; it is not evidence of a
  working production credential.
- One was a Google-format key encoded in Base64 in UrukTech. This was a concrete
  coverage gap in the earlier plain-text inventory. The new bounded literal decoder
  recovered the same complete value from `classes.dex:7045`; source-span hashes and
  the archive round trip were independently checked. The derived preview explicitly
  distinguishes decoded text from the encoded source and provides navigation to it.

Opengrep scanned the retained Java source of all twelve applications using the
37-file configuration subset. It produced **six audit alerts**: two RSA strings
containing `/ECB/`, and four `Random` calls used for notification/UI operations or
requiring further call-site context. These alerts do not establish symmetric ECB
use or a security-sensitive random value. Eight partial-parsing diagnostics across
three applications were retained; decompiled Java is not guaranteed to parse as
original Java source.

The existing safe Java sample produced two upstream audit alerts: AES/GCM use and
random banner selection. The vulnerable Java sample produced four expected crypto
alerts. The real platform adapters also ran on both sample directories: Gitleaks
returned zero/three findings for safe/vulnerable samples, and Opengrep returned
two/four. These samples are development controls, not an unbiased accuracy benchmark.

See [external_engine_validation.json](../evaluation/external_engine_validation.json)
for sanitized counts, pins and comparison scope. Full values and source context
remain in the local audit under `data/audits/2026-11-27-expansion/`.

## Repeating a local comparison

Download an official release, verify its checksum and keep the Opengrep executable
and its DLLs together. These commands use explicit local rule files and do not
require Docker or a cloud registry lookup:

```powershell
& .\data\tools\gitleaks-8.30.1\gitleaks.exe dir .\decoded-input `
  --config .\data\tools\gitleaks-8.30.1\gitleaks.toml `
  --report-format json --report-path .\data\gitleaks-report.json `
  --exit-code 0 --no-banner --no-color --timeout 120

& .\data\tools\opengrep-2.1.0\opengrep.exe scan .\decoded-input `
  --config .\local-reviewed-opengrep-rules --json --quiet --no-git-ignore `
  --timeout 5 --max-target-bytes 4000000 --max-memory 1500 --jobs 2
```

The optional adapter now distinguishes execution/report errors from a successful
scan with zero findings. It retains findings from partial runs and reports the
exit code and diagnostic count. An empty Gitleaks report is not accepted as proof
of a clean scan. Detection of a credential-shaped value remains separate from
credential validity, remote permissions and exploitability; no credential checks
against application services were performed.
