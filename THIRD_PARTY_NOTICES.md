# Third-party notices

The rule sources copied into the import packs below use the MIT License, reproduced here.
Research-only references and runtime components have their own separately identified licenses.
`tools/import_rules.py` converts the DevSkim and Gitleaks packs. It changes the format
and leaves some rules out or disabled. See `evaluation/import_report.json` and
`docs/RULES.md` for that conversion. `tools/import_betterleaks.py` imports a separately
reviewed static subset; see `evaluation/betterleaks_import_report.json` and
`docs/RULE_EXPANSION_2026_11_26.md`. The CodeQL adaptations are maintained separately.

## DevSkim

- Source: <https://github.com/microsoft/DevSkim> (`rules/default/`)
- File here: `sca/rules/imported/devskim.yaml`
- DS187371 has a local 2026-11-27 precision adaptation of revision `6997e759b48d9fed457b5399b4e89681e6a4dcd4`, restricting it to explicit symmetric ECB settings; its default disabled state is preserved.
- Copyright (c) Microsoft Corporation. All rights reserved.

## Gitleaks

- Source: <https://github.com/gitleaks/gitleaks> (`config/gitleaks.toml`)
- Files here: `sca/rules/imported/gitleaks.yaml`, `sca/rules/imported/gitleaks_compatibility.yaml`
- Compatibility adaptations pin configuration commit `09242ce9c8a60d9b051fc2d166f9e849b88c7ac0`.
- Copyright (c) 2019 Zachary Rice

## Betterleaks

- Source: <https://github.com/betterleaks/betterleaks/blob/702504ab4551b9a1c1837efdb6b340536aa4c761/config/betterleaks.toml>
- Files here: `sca/rules/imported/betterleaks.yaml`, `sca/rules/imported/betterleaks_contextual.yaml`
- Pinned commit: `702504ab4551b9a1c1837efdb6b340536aa4c761`
- Static format adaptations only; no upstream validation, analysis or revocation expressions are executed.
- Copyright (c) 2026 Zachary Rice

The contextual subset is reproduced by `tools/import_contextual_secrets.py`. Its
21 reviewed formats preserve the supported provider context, capture groups and entropy
filters. Every upstream entry has an explicit decision in
`evaluation/contextual_secrets_import_report.json`.

## Source review references

`evaluation/upstream_sources_2026_11_27.json` pins 22 source/configuration/license
references and their SHA-256 checksums. References to MobSF, Minded Security, Semgrep
and TruffleHog are research records; their detector code is not included in these packs.
`sca/rules/library_security.yaml` contains original, narrow API-setting patterns checked
against the referenced library APIs. It does not copy or run those projects' analyzers.

## GitHub CodeQL

- Source: <https://github.com/github/codeql> (Java and Kotlin security queries)
- Files here: `sca/rules/imported/codeql_android.yaml`, `sca/rules/imported/codeql_android_extended.yaml`
- Extended adaptations pin commit `43fb30bb443c04731009218f39cba97cd93dd6fe`.
- The adapted rules use this project's regular-expression engine and carry the original query IDs.
- Copyright (c) 2006-2025 GitHub, Inc.

## MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

## Tools used at run time

Installed through `requirements.txt`, not copied into this repository: Streamlit
(Apache-2.0), pandas (BSD-3-Clause), scikit-learn (BSD-3-Clause), PyYAML (MIT), fpdf2
(LGPL-3.0), Bandit (Apache-2.0). Optional, installed by the user: Opengrep (LGPL-2.1),
Semgrep (LGPL-2.1), Gitleaks (MIT), Ollama (MIT).

The hosted container includes the official JADX distribution with its upstream Apache-2.0
licence. [JADX project](https://github.com/skylot/jadx)

The optional dynamic observer bundles the Frida Java bridge and Frida compiler runtime
shims. Their original copyright and license notices are retained in
[`sca/dynamic/agent/THIRD_PARTY_NOTICES.txt`](sca/dynamic/agent/THIRD_PARTY_NOTICES.txt)
and [`sca/dynamic/agent/SHIM_LICENSES.txt`](sca/dynamic/agent/SHIM_LICENSES.txt).
