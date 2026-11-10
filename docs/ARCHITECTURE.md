# Architecture

This document explains how the analyzer is built and why. It is written so that each
section can be reused in the design and implementation chapters of the thesis.

## 1. Design goals

| Goal | Consequence in the design |
|---|---|
| Local and private | No cloud service. The LLM is reached only at `localhost` through Ollama. The dashboard binds to `localhost`. |
| Works without optional parts | Every external tool (Bandit, Opengrep, Gitleaks, Ollama, scikit-learn) is detected at run time and skipped with a note if missing. |
| Explainable | Each finding carries its rule, CWE, engines, confidence and, when traced, the fact that user input reaches the line. The ML model is linear so its weights can be inspected. |
| AI assists, static decides | AI can re-label and re-rank findings. It never deletes one. |
| Easy to extend | Rules are YAML files. Engines share one interface: files in, findings out. |

## 2. Data model (`sca/models.py`)

`Finding` is the single unit that flows through the system: location (`file`, `line`),
classification (`rule_id`, `cwe`, `owasp`, `severity`), evidence (`snippet`, `context`,
`engines`, `tainted`), belief (`confidence`, `ml_score`, `ai_verdict`, `ai_confidence`),
explanation (`description`, `fix`, `ai_explanation`, `ai_fix`) and assessment (`risk_score`,
`status`).

`fingerprint` = SHA-256 of file + CWE + whitespace-normalized code line. It does not include
the line number, so a finding keeps its identity when code above it changes. It is used as
the LLM cache key and exported to SARIF.

`ScanResult` holds the findings plus scan metadata, the project score and grade.

## 3. Pipeline (`sca/pipeline.py`)

```
walk -> detect (engines) -> merge -> ML -> LLM -> assess -> store
```

Each engine runs inside a guard: an exception or a missing tool is written to
`engine_notes` and the scan continues. The secrets engine always runs first, even when its
findings are switched off, because the values it finds are masked in every snippet, report
and LLM prompt.

## 4. Static engines

### 4.1 Pattern rules (`sca/engines/rules_engine.py`, `sca/rules/*.yaml`)

A rule is a regular expression that marks a vulnerable line plus an optional `exclude`
expression that cancels the match (for example a sanitizer on the same line). Comment
lines and block comments are skipped. Lines longer than 600 characters are skipped as
minified code. TypeScript shares the JavaScript rules; C++ shares the C rules.

Strength: fast, language-independent, easy to write. Weakness: no understanding of data
flow, one line at a time.

### 4.2 Python AST taint engine (`sca/engines/python_ast.py`)

The code is parsed with Python's `ast` module, then analysed per function:

- **Sources**: `request.args/form/json/...`, `input()`, `sys.argv`, parameters of functions
  decorated as web routes.
- **Propagation**: assignments, augmented assignments, `for` targets, `with ... as`,
  f-strings, `+`, `%`, `.format()`, calls with tainted arguments, attribute and index access.
  Assignments are processed repeatedly until no new tainted name appears (at most 3 passes).
- **Sanitizers**: `int`, `float`, `shlex.quote`, `escape`, `secure_filename`,
  `os.path.basename`, `url_for` and similar.
- **Sinks**: SQL execution, shell commands, `eval`/`exec`, template rendering, file access,
  outgoing HTTP requests, redirects, HTML responses, deserialization.

Two kinds of sink exist. Sinks that are dangerous with any dynamic string (SQL, shell,
`eval`) are reported with confidence 0.85 when the data is traced to a source and about 0.5
when the string is dynamic but its origin is unknown. Sinks that are only dangerous with
user data (`open`, `requests.get`, `redirect`) are reported only when tainted.

Import aliases are resolved (`import subprocess as sp`, `from os import system`).

Limits, stated plainly: the analysis is intra-procedural (taint does not follow a call into
another function), flow-insensitive within a function, and it does not model containers or
object fields precisely. Sample `K25` in the ground truth is a miss caused by the first limit.

### 4.3 Secrets (`sca/engines/secrets.py`)

1. Known formats: AWS, GitHub, Google, Slack, Stripe keys, private key blocks, JWTs,
   passwords inside connection URLs.
2. Assignments: a sensitive variable name (`password`, `api_key`, `token`, ...) assigned a
   string literal. Placeholders (`changeme`, `${VAR}`, `<your key>`), natural-language labels
   and names such as `token_url` are ignored. For keys and tokens the value must be at least
   12 characters with Shannon entropy H >= 3.2 bits per character, where
   `H = -sum(p_i * log2(p_i))` over the character frequencies.

### 4.4 External adapters (`sca/engines/external.py`)

Bandit, Opengrep/Semgrep and Gitleaks are executed as subprocesses with JSON output. Each
has a pure `parse_*` function that converts the tool's JSON into `Finding` objects. A small
table aligns Bandit's CWE numbers with the internal ones so that duplicates merge.

## 5. Merge (`sca/merge.py`)

Two findings are the same issue when they are in the same file, have the same canonical CWE
and are at most one line apart, and they come from different engines (one engine reporting
two adjacent lines means two issues).

Confidence is combined with a noisy-OR over the engines:

```
c = 1 - (1 - c_1)(1 - c_2)...(1 - c_n)        capped at 0.97
```

Example: the AST engine reports 0.85 and Bandit 0.60, so `c = 1 - 0.15 * 0.40 = 0.94`.
The assumption is that engines err independently; this is only approximately true, which is
why the result is capped.

Lines containing `nosec`, `sca:ignore` or `nosemgrep` are suppressed.

## 6. AI layer

### 6.1 ML classifier (`sca/ai/classifier.py`)

Pipeline: code tokenizer (identifiers, numbers as `<num>`, every operator and punctuation
mark as its own token) -> TF-IDF over 1 to 3-grams -> logistic regression with balanced
class weights. Output: probability that a line is vulnerable. It contributes 25% of the
final confidence:

```
confidence = 0.75 * static_confidence + 0.25 * ml_score
```

Default training data is a synthetic corpus built from templates
(`sca/ai/seed_corpus.py`). It makes the feature work out of the box and must not be reported
as a research result. `python -m sca train --dataset file.jsonl` trains on a real dataset
(PrimeVul, DiverseVul, Devign and BigVul field names are accepted) and prints held-out
precision, recall, F1 and ROC-AUC.

### 6.2 LLM (`sca/ai/llm.py`)

Transport: Ollama's HTTP API (`/api/tags`, `/api/chat` with `format: json`,
`temperature: 0`). No third-party client library is needed.

- **Triage**: for each finding the model receives the title, CWE, whether taint was proven,
  and up to 28 lines of surrounding code. It must answer with a JSON object: verdict
  (`true_positive`, `false_positive`, `uncertain`), confidence, explanation, fix.
- **Deep scan**: the model receives a whole file with line numbers and the list of findings
  already known, and returns new ones.

Defences, because the scanned code is untrusted input to the model (prompt injection):

1. The system prompt states that the code is data and must not be obeyed.
2. Only strict JSON is accepted; every field is validated. Deep-scan findings whose line
   number is outside the file or whose CWE is malformed are dropped.
3. A `false_positive` verdict re-labels a finding as `likely_false_positive` only when the
   model's confidence is at least 0.6. The finding stays in every report.
4. Secrets are masked before any text is sent.

Answers are cached in SQLite by model + language + fingerprint, so repeating a scan does not
repeat the slow model calls.

## 7. Assessment (`sca/scoring.py`)

Per finding, on a 0-10 scale (the same range as CVSS, but not a CVSS score):

```
risk = base(severity) * (0.6 + 0.4 * confidence)
base: critical 9.5, high 8.0, medium 5.5, low 3.0, info 1.0
```

Per project:

```
penalty = sum over open findings of weight(severity) * confidence
weight: critical 10, high 5, medium 2, low 0.5
density = penalty / max(KLOC, 0.5)
score   = round(100 * exp(-density / 25))
grade:  A >= 90, B >= 75, C >= 60, D >= 40, F below
```

Dividing by size makes projects comparable. The exponential keeps the score within 0-100
and makes the first serious findings cost the most. The constants are design choices; a
sensitivity analysis of them is a reasonable thesis experiment.

## 8. Storage and reports

`sca/storage.py`: SQLite database `data/sca.db` with a `scans` table (summary columns plus
the full result as JSON) and an `llm_cache` table.

`sca/report/`: HTML (one self-contained file, light and dark themes, filter buttons,
print-friendly), PDF (fpdf2; Latin text only), JSON (full data), SARIF 2.1.0 (accepted by
GitHub code scanning and VS Code).

## 9. Security of the tool itself

- The dashboard listens on `localhost` only (`.streamlit/config.toml`).
- Scanned code is never executed. External scanners are started with argument lists, never
  through a shell.
- Secrets are masked in snippets, reports and prompts.
- A model file given to `--ml-model` is a pickle: load only models you trained yourself.

## 10. Extending

- **New rule**: add an entry to a file in `sca/rules/` and a test line in
  `tests/test_engines.py`.
- **New language**: add the extension to `LANG_BY_EXT` in `sca/walker.py` and a rules file.
- **New engine**: write `scan(files) -> List[Finding]` and add one `run_engine(...)` line in
  `sca/pipeline.py`.
- **Another LLM provider**: implement `available()`, `models()` and `chat_json()` like
  `OllamaClient`.
