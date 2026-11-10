# Architecture

How the analyzer is built and why. Each section can be reused in the design and
implementation chapters of the thesis.

## 1. Design goals

| Goal | Consequence in the design |
|---|---|
| Works without optional parts | Every external tool and the AI provider are detected at run time and skipped with a note if missing. |
| The user chooses where code goes | One client interface for a local model (Ollama) and for cloud APIs. The dashboard binds to `localhost`. A warning is shown before code is sent to a cloud provider. |
| AI is never trusted blindly | An AI verdict re-labels a finding, never deletes it. An AI discovery needs a second confirming request. An AI-written rule needs automatic validation and human approval. |
| Explainable | Each finding carries its rules, engines, confidence and the evidence that confirms it. The ML model is linear. Learned rules are readable YAML. |
| Learns from use | Reviews adjust rule confidence, retrain the classifier and tighten the validation of new rules. |

## 2. Data model (`sca/models.py`)

`Finding`: location (`file`, `line`), classification (`rule_id`, `rule_ids`, `cwe`, `owasp`,
`severity`), evidence (`snippet`, `context`, `engines`, `tainted`, `evidence`, `tier`),
belief (`confidence`, `ml_score`, `ai_verdict`, `ai_confidence`, `user_verdict`),
explanation (`description`, `fix`, `ai_explanation`, `ai_fix`), assessment (`risk_score`,
`status`).

`status` is one of `open` (counted), `needs_review` (strict mode, unconfirmed),
`likely_false_positive` (AI verdict), `dismissed` (reviewer verdict).

`fingerprint` = SHA-256 of file + CWE + whitespace-normalized code line. It has no line
number, so a finding keeps its identity when code above it changes. It keys reviewer
feedback, the LLM cache and SARIF export.

## 3. Pipeline (`sca/pipeline.py`)

```
walk -> detect -> refine -> merge -> ML -> LLM -> assess -> store
```

Each engine runs inside a guard: an exception or a missing tool is written to
`engine_notes` and the scan continues. The secrets engine always runs first, because the
values it finds are masked in every snippet, report and LLM prompt.

## 4. Static engines

### 4.1 Pattern rules (`sca/engines/rules_engine.py`)

Sources of rules: `sca/rules/*.yaml` (built-in), `learned/rules.yaml` (approved learned
rules), `learned/overrides.yaml` (approved extra exclusions per rule). A broken learned
entry is skipped so that a bad learned rule can never stop a scan. The loaded set is cached
and reloaded when any rule file changes.

A rule is a regular expression for a vulnerable line plus an optional `exclude`. Comment
lines, block comments and lines over 600 characters are skipped. `RULE_LANGUAGE` maps
TypeScript to the JavaScript rules, C++ to C, and Kotlin/Scala/Groovy to the Java API rules.

### 4.2 Python AST taint engine (`sca/engines/python_ast.py`)

Sources: request objects, `input()`, `sys.argv`, parameters of route handlers.
Propagation: assignments, loops, `with`, string building, calls with tainted arguments.
Sanitizers: `int`, `shlex.quote`, `escape`, `secure_filename`, `basename` and similar.
Sinks: SQL, shell, `eval`/`exec`, templates, files, HTTP requests, redirects, HTML output,
deserialization.

Three passes:

1. **Intra-procedural.** Each function is analysed on its own. Sinks that are dangerous
   with any dynamic string (SQL, shell, `eval`) are reported with confidence 0.85 when the
   data is traced to a source and about 0.5 otherwise. Sinks that are dangerous only with
   user data (`open`, `requests.get`, `redirect`) are reported only when traced.
2. **Function summaries.** For every non-route function and every parameter: assume the
   parameter is tainted and record which sinks it reaches.
3. **Call sites.** A call that passes tainted data to a summarized parameter (by position
   or keyword, as a plain call or `self.method(...)`) reports the sink in the callee as
   traced, or upgrades the existing untraced finding.

Limits: one call deep, one file, flow-insensitive inside a function, no precise modelling of
containers or object fields.

### 4.3 Taint-lite (`sca/engines/taint_lite.py`)

For injection-type findings of the pattern rules in languages without an AST engine. It
scans up to 60 lines above the finding, follows simple assignments (including JavaScript
destructuring and Go multi-assignment), and checks whether an identifier on the flagged
line was assigned from a known source without passing a known sanitizer. A table lookup
(`$pages[$_GET['page']]`) is treated as trusted. A traced finding gets `tainted = True` and
+0.15 confidence. Nothing is removed. It is a heuristic and is documented as one.

### 4.4 Secrets (`sca/engines/secrets.py`)

Known key formats, and sensitive variable names assigned a literal. Placeholders, labels in
natural language and names such as `token_url` are ignored. Keys and tokens need at least 12
characters and Shannon entropy `H = -sum(p_i * log2(p_i)) >= 3.2` bits per character.

### 4.5 External adapters (`sca/engines/external.py`)

Bandit, Opengrep/Semgrep and Gitleaks run as subprocesses with JSON output; pure `parse_*`
functions convert the output to findings.

## 5. Refinement and merge

**Rule track record** (`sca/learn/feedback.py`). With `tp` confirmed and `fp` dismissed
findings of a rule, its confidence becomes the mean of a Beta posterior whose prior is the
written confidence `c` with strength `K = 4`:

```
c' = (tp + K*c) / (tp + fp + K)
```

A rule with `fp >= 3` and `c' < 0.35` is quarantined: its findings are dropped and the fact
is reported in the scan notes.

**Merge** (`sca/merge.py`). Same file, same canonical CWE, at most one line apart, different
engines. Confidence is a noisy-OR over the engines, capped at 0.97:

```
c = 1 - (1 - c_1)(1 - c_2)...(1 - c_n)
```

Earlier reviewer verdicts are re-applied by fingerprint: `fp` sets `dismissed`, `tp` marks
the finding confirmed.

## 6. AI layer

### 6.1 Providers (`sca/ai/providers.py`, `sca/ai/llm.py`)

One interface: `check()`, `models()`, `chat_json(system, user)`, `label`, `is_local`.

| Client | Protocol | Notes |
|---|---|---|
| `OllamaClient` | Ollama `/api/chat`, `format: json` | local |
| `OpenAICompatClient` | `POST {base}/chat/completions`, bearer key | on HTTP 400 it retries without `response_format`, then without `temperature`, because servers differ |
| `AnthropicClient` | `POST /v1/messages`, `x-api-key`, `anthropic-version` | sends no sampling parameters; falls back to a request without the top-level `system` field on HTTP 400 |

HTTP 429 and 5xx are retried up to twice, honouring `Retry-After`. Only the standard
library is used. Settings come from the environment or the git-ignored `.env` file; the key
is never written to the database, reports or error messages. Answers are cached in SQLite
by provider, model, language and fingerprint.

### 6.2 Review and deep scan

- **Triage**: title, CWE, whether taint was proven, and up to 28 lines of context. Answer:
  verdict, confidence, explanation, fix.
- **Deep scan**: a whole file with line numbers plus the findings already known. Answer: new
  findings. Each one is then reviewed by a separate triage request (second pass). Without
  that confirmation it stays `probable`.

Defences against prompt injection from scanned code: the system prompt declares the code as
data; only JSON is accepted and each field is validated (line inside the file, well-formed
CWE); verdicts re-label and never delete; secrets are masked before sending.

### 6.3 ML classifier (`sca/ai/classifier.py`)

Code tokenizer, TF-IDF over 1-3-grams, logistic regression. It contributes 25% of the
confidence: `confidence = 0.75 * static + 0.25 * ml`. Reviewed code lines are added to the
training data with weight 3 and the model is retrained at the next scan. The default
training data is synthetic; `python -m sca train --dataset` trains on a real dataset.

## 7. Rule learning (`sca/learn/`)

```
LLM-only finding, confirmed by the second pass  ->  propose_rule
finding judged false by the LLM (>= 0.8) or the reviewer  ->  propose_exclude
no rule for (language, CWE)  ->  propose_bootstrap_rule
        |
validate  --fail-->  reasons sent back to the model, one retry
        |
pending  --human-->  approved  ->  learned/rules.yaml | learned/overrides.yaml
```

**Proposal** (`propose.py`). The model returns strict JSON: title, CWE, severity, pattern,
exclude, message, fix, three vulnerable and three safe examples. The answer is data: it is
never executed.

**Sandbox** (`sandbox.py`). Python cannot interrupt a running regular expression, so every
untrusted pattern is run in a child process (`python -I sandbox.py`) that is killed after 6
seconds.

**Validation** (`validate.py`), for a new rule:

| Check | Fails when |
|---|---|
| schema | missing field, malformed CWE, unknown language, pattern over 400 characters, nested quantifier |
| compiles | the regular expression is invalid |
| fast | the sandbox times out on the stress lines (long runs, repeated literals from the pattern) |
| specific | no literal word of 3+ letters, or it matches everyday lines such as `x = 1` |
| evidence | it does not match the line it was learned from |
| examples | it misses its vulnerable examples or matches a safe one |
| clean corpus | it matches known-safe code: the safe samples, the safe training lines, lines the reviewer dismissed |
| blast radius | more than 25 matches, or more than 2% of the lines of that language in the project |
| novelty | an active rule with the same CWE already matches the evidence, or the pattern is a duplicate |

For an exclusion: compiles, fast, specific, matches the false positive, and matches none of
the known-vulnerable lines that the target rule reports (so recall cannot silently drop).

**Approval** (`store.py`). Only a candidate whose validation passed can be approved.
`--auto-approve` exists for unattended use and applies only to rules learned from real code;
exclusions and bootstrap rules always wait for a person. A learned rule starts at
confidence 0.55 and is then moved by its track record.

## 8. Assessment (`sca/scoring.py`)

**Tier.** A finding is `confirmed` when at least one holds:

- the reviewer confirmed it;
- the AI review says real with confidence >= 0.7;
- user input was traced to the line, outside test code;
- only for weaknesses that are a property of the line itself (not in `FLOW_CWES`), outside
  test code: two or more independent static engine families reported it (built-in and
  learned pattern rules are one family), or a single engine has confidence >= 0.85.

`FLOW_CWES` (`sca/cwe.py`) is the injection family: SQL, command, XSS, eval, path, file
inclusion, redirect, SSRF, NoSQL, deserialization, template, format string, buffer copy,
upload, variable extraction. For these, engine agreement is deliberately not enough: two
engines that both notice a call to `pickle.loads()` have seen the same thing, and neither has
shown that attacker-controlled data reaches it. This rule was introduced after a run on the
pandas source, where the earlier rule confirmed 56 findings, mostly in tests.

An AI `false_positive` verdict blocks confirmation unless the reviewer confirmed. Otherwise
the finding is `probable`.

**Test code.** `walker.is_test_path` recognises `tests/`, `test_*.py`, `*_test.go`,
`*.spec.js`, `conftest.py` and similar. Findings there keep their place in the report, get
their confidence multiplied by 0.6, and are never confirmed automatically. `include_tests =
False` (`--skip-tests`) leaves those files out of the scan.

**Strict mode.** Unconfirmed open findings get the status `needs_review` and do not count.

**Risk and score.**

```
risk    = base(severity) * (0.6 + 0.4 * confidence)       base: 9.5, 8.0, 5.5, 3.0, 1.0
penalty = sum over open findings of weight(severity) * confidence     weight: 10, 5, 2, 0.5
score   = round(100 * exp(-(penalty / max(KLOC, 0.5)) / 25))
grade:  A >= 90, B >= 75, C >= 60, D >= 40, F below
```

The constants are design choices; a sensitivity analysis is a reasonable thesis experiment.

## 9. Storage and reports

`sca/storage.py`, SQLite `data/sca.db`: `scans`, `llm_cache`, `feedback`, `rule_candidates`.
`sca/report/`: HTML (self-contained, light and dark, filters by severity and status), PDF
(Latin text only), JSON, SARIF 2.1.0.

## 10. Security of the tool itself

- The dashboard listens on `localhost` only.
- Scanned code is never executed. External scanners are started with argument lists.
- LLM output is parsed as data. Proposed regular expressions run in a killable sandbox
  before they can ever run inside a scan.
- Secrets detected by the tool are masked in snippets, reports and prompts. Secrets it does
  not detect are not masked.
- The API key lives in `.env` (git-ignored, mode 600 where supported).
- A model file given to `--ml-model` is a pickle: load only models you trained yourself.

## 11. Extending

- **New rule**: an entry in `sca/rules/` plus test lines in `tests/test_engines.py`.
- **New language**: extension in `LANG_BY_EXT`, name in `CODE_LANGUAGES`, comment prefix in
  `COMMENT_PREFIXES` (`sca/walker.py`); sources in `taint_lite.SOURCES` if wanted.
- **New engine**: `scan(files) -> List[Finding]` and one `run_engine(...)` line.
- **New provider**: a preset in `PRESETS` if it is OpenAI-compatible; otherwise a client
  class with `check`, `models` and `chat_json`.
