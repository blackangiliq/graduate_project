# Third-party notices

The rules in `sca/rules/imported/` were converted from the two projects below by
`tools/import_rules.py`. Both are distributed under the MIT License, reproduced here as the
licence requires. The conversion changed the format of the rules (regular-expression
dialect, field names, severity scale) and left some rules out or disabled; see
`evaluation/import_report.json` and `docs/RULES.md`.

## DevSkim

- Source: <https://github.com/microsoft/DevSkim> (`rules/default/`)
- File here: `sca/rules/imported/devskim.yaml`
- Copyright (c) Microsoft Corporation. All rights reserved.

## Gitleaks

- Source: <https://github.com/gitleaks/gitleaks> (`config/gitleaks.toml`)
- File here: `sca/rules/imported/gitleaks.yaml`
- Copyright (c) 2019 Zachary Rice

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
