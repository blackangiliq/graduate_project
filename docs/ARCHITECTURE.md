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

For a mobile target `Finding` also carries `owasp_mobile` (`"M5"`) and `masvs`
(`"MASVS-NETWORK"`), and `ScanResult.app` holds the app facts (package, versions, SDK
levels, build mode, signing, permissions, components, endpoints, packages, warnings, and
the API and key inventory in `apis`); it is JSON-safe and stored with the scan.

`SourceFile.origin` (`sca/walker.py`) says where a file's text comes from: `""` (a file on
disk), `decoded`, `recovered`, `decompiled`, `strings`, `summary` or `placeholder` (section
4.6). Each engine reads only the origins it understands. `SourceFile.secret_values` and
`SourceFile.secret_hits` hold what the secrets engine found in the file (section 4.4).

`fingerprint` = SHA-256 of file + CWE + whitespace-normalized code line. It has no line
number, so a finding keeps its identity when code above it changes. It keys reviewer
feedback, the LLM cache and SARIF export.

## 3. Pipeline (`sca/pipeline.py`)

```
walk -> detect -> refine -> merge -> ML -> LLM -> assess -> store
```

Each engine runs inside a guard: an exception or a missing tool is written to
`engine_notes` and the scan continues. The secrets engine always runs first, because the
values it finds are masked in every snippet, report and LLM prompt. When the target is an
app package, `walk` decodes it into virtual files instead of reading a folder (section 4.6).
For a mobile target (app package or Flutter/Android project), the step *API inventory*
runs after `assess` and adds the API and key inventory to the app facts (section 4.6).

## 4. Static engines

### 4.1 Pattern rules (`sca/engines/rules_engine.py`)

Rules have four origins: `sca/rules/*.yaml` (built in), `sca/rules/imported/*.yaml`
(converted from DevSkim and Gitleaks by `tools/import_rules.py`; each file names its source,
commit and licence), `learned/rules.yaml` (approved learned rules) and `learned/custom.yaml`
(written by the user). Two more files hold the user's changes: `learned/edits.yaml`
(`{rule id: {field: value}}` for shipped rules, including `enabled`) and
`learned/overrides.yaml` (approved extra exclusions). `all_rules()` returns every rule with
edits applied; `load_rules()` returns the enabled pattern rules; `secret_rules()` the enabled
rules of `kind: secret`, which the secrets engine runs. A broken user entry or edit is
skipped, so it can never stop a scan. The set is cached and reloaded when a rule file changes.

A rule may carry two optional conditions. `near` / `within`: the pattern counts only if
another expression matches a line at most `within` lines away (context rules, e.g.
`java.util.Random` near a token). `requires_taint: true`: a sink rule, reported only when
`taint_lite.is_traced` finds that a variable on the line was assigned from a request source
in the 60 lines above. For Python files, lines inside docstrings are not given to rules.

`sca/rulebook.py` is the management layer used by the Rules tab and by `python -m sca
rules`: list, check, create, update, enable/disable, reset, delete, export and import. A
shipped rule file is never rewritten. `check()` separates errors (invalid field, expression
that does not compile or is too slow in the sandbox, a failed own example) from warnings
(matches everyday or known-safe code, duplicate expression).

The import (`tools/import_rules.py`) converts .NET and Go expressions to Python `re`,
maps languages, severities and CWE ids, and keeps a rule only if it compiles, finishes on
stress lines, passes its own examples and is silent on the known-safe samples. Kept rules
are measured on a corpus of real projects; review-only or noisy rules ship with
`enabled: false` and a `note`. The result of every rule is in
`evaluation/import_report.json`.

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

The engine has 11 built-in formats (`KNOWN_FORMATS`): AWS access key, GitHub token, Google
API key, Slack token, Stripe live key, private key, JSON Web Token, credentials in a
connection URL, Slack webhook URL (SECRET-SLACK-002), Discord webhook URL
(SECRET-DISCORD-001) and Telegram bot token (SECRET-TELEGRAM-001). The rules of
`kind: secret` (2 Dart formats and the Gitleaks import) run on top of them. For a webhook
URL or a bot token, as for the password of a connection URL, only the token part is the
secret, so the masked address stays readable; this holds also when the URL is assigned to a
variable named like `slackToken` or `webhookSecret`. For a Slack webhook the token is the
last path segment, so a Slack Workflow URL with four segments is masked at the right place.
The imported Gitleaks rule for Microsoft Teams webhooks takes only the token part as the
secret (key service Microsoft Teams, webhook advice), and the imported base64 JSON Web
Token rule masks the whole token.

In `.env` files (`ENV_FILE`: `.env`, `.env.<name>` or `<name>.env`; templates such as
`.env.example`, `.sample`, `.template`, `.dist`, `.defaults` and `.schema` are skipped) the
engine also reads `NAME=value` lines (`ENV_ASSIGNMENT`); the value may be quoted, and an
inline comment after it (`NAME=value # note`) is allowed. It runs after the known formats, so
a value one of them reports (a quoted Stripe key) is reported once. A line counts when the name is or contains
password, passwd, pwd, passphrase, secret, token, credential, hmac, auth, salt, private or
signature, ends in `KEY` (`MAPS_KEY`, `MAPKEY`, `STRIPE_KEY`, `KEY`) or has a separate `PASS`
segment (`SMTP_PASS`, `PASS`). Names of settings are skipped: names ending in `_NAME`,
`_HEADER`, `_PREFIX`, `_ALIAS`, `_FIELD`, `_PARAM`, `_LABEL`, `_ID`, `_TTL`, `_EXPIRY`,
`_EXPIRES`, `_LENGTH`, `_SIZE`, `_URL`, `_URI`, `_PATH`, `_FILE`, `_DIR`, `_DOMAIN`,
`_HOST`, `_HOSTS`, `_SCOPE`, `_SCOPES`, `_AUDIENCE` or `_REGION` (`ENV_NOT_A_SECRET_NAME`:
`API_KEY_HEADER_NAME`, `TOKEN_PREFIX`), and `KEY_ID` and `PUBLIC_KEY`. Values that are
placeholders, URLs without credentials or file paths (`ENV_NOT_A_SECRET`), public by design
(`pk_live_`, `pk_test_`, `pk.eyJ...`, `appl_`, `goog_`) or only a host name
(`shop.eu.auth0.com`; `ENV_PUBLIC_VALUE`) are skipped; for keys and tokens (not
passwords) so are values made of words joined by `_`, `-`, `:` or `.`
(`CACHE_KEY=homepage_products_v2`, `X-Shop-Api-Key`). A key needs 12 characters and entropy
3.0, a password 6 characters.

`scan_file` keeps what it found on the `SourceFile`: `secret_values` and `secret_hits`, a
list of (line, rule id, secret, title, severity). Masking is scan-wide: after the engines
ran, every file of a scan masks every secret of the scan (one shared list), so snippets,
contexts, facts, the API and key inventory, the AI prompts (triage and deep scan) and the
rule learner mask a secret found in any file (`pipeline.share_secrets`). The values are
those of the secrets engine (for a `.env` file exactly the ones it reports), the values of
other credential findings, and the secrets that addresses hold in plain sight
(`inventory.text_secrets`): values of key and token query parameters, the password of
`user:password@` (also with an empty user, as in `redis://:pw@host`), and webhook and bot
tokens. The value of another credential finding (`inventory.rule_key_value`) is taken from
the rule's own match (`SecretKey('...')` even after an earlier literal), from a Gradle or
`key.properties` signing setting (`keyPassword`, `storePassword`; not `keyAlias`), and for a
line that reads a value by its name only from the value written next to it
(`defaultValue: '...'`, `--dart-define=NAME=value`). Every value is masked in its own file;
it is shared with the other files only when it is strong (`inventory.strong_value`): 8
characters or more, not a single plain word, not only digits, Shannon entropy 2.5 or more.
So a short or plain value, such as the debug keystore password `android` or the URL
password `admin`, does not hide that word elsewhere. The inventory (section 4.6) uses `secret_hits` to
group keys by value; it stores only the masked value.

### 4.5 External adapters (`sca/engines/external.py`)

Bandit, Opengrep/Semgrep and Gitleaks run as subprocesses with JSON output; pure `parse_*`
functions convert the output to findings. They read files on disk, so they are skipped
for app packages.

### 4.6 Flutter and Android apps (`sca/flutter/`)

The module analyses Flutter and Android apps as source projects and as built packages
(`.apk`, `.aab`, `.apks`, `.xapk`, `.apkm`). It is pure Python: no Android SDK, Flutter
SDK or Java is needed, and a package is never installed or run. The user-level description,
with the checks table and the measured results, is in [FLUTTER.md](FLUTTER.md).

**Contract.** Two loaders build a `MobileContext` (`context.py`) and one function reads it:

```
load_app(path, use_tools)        app package   -> MobileContext (virtual files + facts)
load_project(root, files)        project folder -> MobileContext or None
analyze(ctx, by_rel)             structural checks (engine "flutter") -> findings, note
refine(findings, by_rel, ctx)    context-dependent changes to other engines' findings
inventory.build(ctx, files, findings)   API and key inventory -> ctx.facts["apis"]
```

`MobileContext` holds the release manifests as parsed `XmlNode` trees, the XML resources
and their `@xml/name` references, Gradle files, `key.properties`, keystore placeholders,
`Info.plist` files, pubspec/lock pairs, the decoded binaries (signing, snapshot, engine,
kernel, DEX) and the facts that become `ScanResult.app`.

**Virtual files.** For an app package every file of the scan is a `SourceFile` built in
memory. Its `origin` decides which engines read it:

| origin | example | rules | secrets | KLOC | ML / LLM |
|---|---|---|---|---|---|
| `decoded` | `AndroidManifest.xml`, `res/xml/*.xml`, `res/values/strings.xml`, text assets | yes | yes | yes | yes |
| `recovered` | `dart/lib/main.dart` from `kernel_blob.bin` | yes | yes | yes | yes |
| `decompiled` | `jadx/com/example/MainActivity.java` | yes | yes | yes | yes |
| `strings` | `lib/arm64-v8a/libapp.so`, `classes.dex` | no | yes | no | no |
| `summary` | `_sca/build.txt`, `_sca/signing.txt`, `_sca/packages.txt` | no | no | no | no |
| `placeholder` | a keystore found in a project | no | no | no | no |

Paths are deterministic (never a temporary folder), lines are shorter than 600 characters
and free of control characters, and XML is rendered one attribute per line so that a
finding names the exact attribute. Strings dumps are capped at 200,000 lines for DEX and
`libapp.so` and 100,000 for other native libraries. Because the KLOC column counts only
`decoded`, `recovered` and `decompiled` lines, a release package (no recovered source) has
few lines, its penalty is divided by the 0.5 KLOC floor, and it often gets a low score.
No file of an app package is treated as test code: everything in it ships to users.

**Decoders** (each bounds-checks every read, caps sizes and counts, decodes string data
within a byte budget so that overlapping or oversized tables cannot make it run long, and
reports anomalies as warnings instead of raising):

| Module | Format |
|---|---|
| `zipread.py` | ZIP central directory and local headers, raw inflate with an output cap, APK sets, AAB module layout; flags duplicate names, case collisions, several end records, the encryption bit |
| `axml.py`, `aabproto.py` | Android binary XML (attribute names resolved by resource id) and the protobuf XML of app bundles, both rendered by `xmltree.py` |
| `arsc.py` | `resources.arsc`: names of resource ids, logical names of shortened files, string resources, sparse and 16-bit-offset type chunks |
| `dex.py` | DEX string, type, method and class tables (MUTF-8), plugin classes, Flutter markers |
| `signing.py` | APK Signing Block (v2, v3, v3.1), v1 PKCS#7, a DER parser for X.509 certificates; no cryptographic verification |
| `kernel.py` | Dart kernel (`kernel_blob.bin`): embedded source of each library, package versions and build paths from file URIs |
| `snapshot.py` | ELF, the Dart AOT snapshot header (version hash and features, hence the build mode), Dart string objects, obfuscation signs, symbols; the Dart version and engine revision from `libflutter.so` |
| `pubspec.py` | pubspec and lock parsing, pub version ordering, offline advisories (`data/advisories.json`) and discontinued packages (`data/discontinued.json`) |

`apk.py` runs these in order (resources, manifest, XML resources, strings, assets, Flutter,
DEX, signing, other native libraries, summaries); each step is guarded, so one broken part
only adds a warning. `project.py` finds the Flutter app module, its release manifests, the
`res/xml` files, the application Gradle files, `key.properties`, keystores (bounded walk),
`Info.plist` files and pubspec/lock pairs. Release manifests are those of `src/main` and of
every source set a release build merges (`src/release`, product flavors such as `src/prod`
or `src/prodRelease`); debug, profile and test source sets are only listed in the facts.
Manifests of Android library modules (`com.android.library`) are kept in
`ctx.library_manifests`: their components, permissions and links are checked, but their
`<application>` attributes and SDK levels are not the app's. The `android/` and `ios/`
folders of a Flutter plugin (`flutter: plugin:` in its `pubspec.yaml`) are not audited as
an app.

**Checks** (`checks.py`, `android.py`). `android.py` holds the platform semantics as pure
functions over `XmlNode`: effective export of a component (the default depends on intent
filters and targetSdk), guard strength of a permission, backup and cleartext policies with
their platform defaults, network security config with inherited domain settings, FileProvider
paths (resolved as androidx FileProvider resolves them, so `..` that climbs out of the root
folder is caught). `checks.py` holds the 49 checks (`CHECKS`, used by the dashboard's guide
and the docs), each with a CWE, a severity, a confidence, an area and a target; it also
fills the facts `permissions`, `components`, `flags`, `endpoints` and `dependency_issues`.
Each part of `analyze` is guarded, findings are capped at 50 per file and check, and the
note says what was capped or not checked. A finding is lowered where the platform limits
the setting (for example `usesCleartextTraffic` beside a network security config with
minSdk 24 or higher, or a keystore that a `.gitignore` keeps out of version control); the
list is in [FLUTTER.md](FLUTTER.md) section 3. `refine` lowers Google API keys found in
Firebase configuration (configuration files, the Firebase entries of `strings.xml`, the
`firebaseConfig` of `web/index.html`, and a `libapp.so` dump that also holds the other
Firebase values) to low severity (they are identifiers, not secrets).

**API and key inventory** (`inventory.py`). `build(ctx, files, findings)` lists the server
addresses, hosts, API calls, API paths, keys, service identifiers and `.env` entries of an
app or project, each with its places (file and line), and draws alerts from them (levels
`danger`, `warning`, `info`). It reads the files of the scan except `summary` and
`placeholder` files, and leaves out the test files of a project. It works on text only and
contacts nothing:

- Addresses are the URLs of any text (the filter of `checks._endpoint` drops namespaces,
  documentation, loopback and placeholder hosts). In `strings` dumps a text that is only a
  host name is listed as an address without scheme when it looks like one. The app's own
  package name is skipped, and so are reversed package names: texts that start with `com.`,
  `org.`, `net.`, `io.`, `dev.`, `app.`, `android.`, `java.`, `kotlin.`, `dart.`,
  `flutter.`, `google.`, `me.`, `co.`, `edu.` or `gov.`, or with a two-letter country code
  followed by a registry word (`gov`, `com`, `co`, `org`, `net`, `edu`, `ac`, `mil`; for
  example `sa.gov.absher.app`, `id.co.bank.app`). A two-label text is skipped when its last label is
  an identifier-like word (`id`, `info`, `page`, `store`, `shop`, `in`: `user.id`,
  `home.page`); `ws.myshop.com`, `eu.posthog.com`, `js.stripe.com` and `myshop.io` are
  listed. The service
  and category of a host come from `SERVICES` (106 host suffixes of 88 services, the first
  match wins; no match means the app's own server). Host labels such as `dev`, `staging` or
  `sandbox`, IP addresses, tunnels, webhooks and keys in the query give each address its
  alerts.
- Calls are read only from code text (files of a code language that are not strings
  dumps): Dart `http`, dio, `HttpClient`, `Uri.https`, WebSocket and GraphQL clients,
  Retrofit/Chopper annotations, `baseUrl` (also a Dart getter `get baseUrl => '...'`, listed
  as the base address), and OkHttp/`URL` in Java. A method call counts only when its
  receiver is named like an HTTP client by a whole word (`http`, `https`, `dio`, `client`,
  `api`, `rest`, `graphql`, `gql`, `chopper`, `backend`, `server`, `network`, `service`,
  `session`, `request`, `requests`, `retrofit`, `remote`), so `audioCache.get(...)` or
  `restaurantBox.get(...)` is not a call.
  API paths are string literals and dump lines that look like an API path.
- Keys are not searched again. They come from the findings with a credential CWE (798, 321,
  259, 260, 547), except the file-level finding FLUTTER-APP-006 (a bundled `.env` file),
  whose values are listed as `.env` entries and as keys of their own. The value is taken
  from `SourceFile.secret_hits`, or for a rule finding from the first literal of its line.
  Keys are grouped by value, one entry per distinct key even when several keys share a
  line, given the severity of the rule that found them, typed by service, marked public by
  design where they are (Firebase configuration API key, Stripe `pk_`, Mapbox `pk.`,
  Supabase anon JWT; a Firebase API key that also appears outside the Firebase
  configuration counts as a secret key), given advice (`ADVICE`) and, for a
  JWT, their claims `iss`, `role`, `ref`, `aud`, `iat` and `exp` (the signature is not
  checked). A manifest `<meta-data>` entry that uses a key is named. A key whose finding a
  reviewer dismissed (now or in an earlier review) is left out of the key list, the counts
  and the alerts; the dashboard refreshes the inventory after a review.
- Service identifiers come from named entries (`CONFIG_NAMES`: `strings.xml`,
  `google-services.json`, `GoogleService-Info.plist`, `firebase_options.dart`, manifest
  `<meta-data>`) and from identifier formats (`_ID_PATTERNS`); `firebase` gathers the
  Firebase project.

Only masked values are stored: keys through `mask_secret`, URLs through `mask_url`
(passwords, key and token parameters, bot and webhook tokens). Every list is capped (300
rows, 80 alerts) and `truncated` counts the rest; an item keeps at most 20 places and counts
all of them in its `count`. The alert texts are English; the dashboard translates them
(`sca/ui/i18n.py`).

**Pipeline integration.** For an app target the walk is replaced by `load_app`; for a
folder, `load_project` runs after the walk and adds placeholder files. The `flutter` engine
runs after the C memory checks; Bandit, Semgrep and Gitleaks are skipped for app packages.
After masking, `refine` runs; `merge_findings(..., mobile=True)` fills `owasp_mobile` and
`masvs` from `cwe.MOBILE_BY_CWE` (the project's own mapping of canonical CWEs to the OWASP
Mobile Top 10 2024 and MASVS groups). Titles, descriptions and the URLs in the facts are
masked like snippets, and Unicode bidirectional control characters are removed from every
finding text and every fact, so text from an app cannot reorder what a report shows. In
the dashboard, app texts shown as Markdown (alerts, labels) get an invisible WORD JOINER,
so that an address or an e-mail in them does not become a link. After
scoring, `add_inventory` (step *API inventory*, engine note `api inventory`) builds the
inventory from the files and the final findings and stores it in `ctx.facts["apis"]`; a
failure is written to the note and leaves the findings and the other facts as they are.
`inspect_mobile`, which serves `python -m sca flutter info|deps|apis|decode`, runs the
secrets engine, the structural checks and the pattern rules that report credentials
(CWE-798, 321, 259, 260, 547), drops the lines that contain a suppression marker (`nosec`,
`nosemgrep`, `sca:ignore`; the structural checks' keys included) and masks in the same order
as a scan, so its key list matches that of a full scan.
Reviews stored by the dashboard (dismissed findings) apply only to scans, not to these
commands. `flutter info` prints a note when the inventory failed. With `--no-flutter` (dashboard
switch *Flutter / Android checks* off) a source project gets no app facts and no inventory;
an app package keeps both.

**Optional tools** (`tools.py`). jadx and apksigner are found through `SCA_JADX`,
`JADX_HOME`, the Android SDK folders and `PATH`. They get argument lists with paths the
analyzer created, time limits (300 s, 120 s) and a kill of the whole process tree on
timeout. jadx output is cached per app (keyed by input digest, classes and options) under
the data folder.

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

**Repeating** (`loop.learn_until_stable`, `--rounds N`). A round is deep scan plus
learning. Rounds repeat while each one activates at least one new rule, so the model is
asked again only after its earlier discoveries are covered statically. `bootstrap_all`
(`--bootstrap all`) proposes a first rule for every (language, weakness) pair that has none.

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
(Latin text only), JSON, SARIF 2.1.0. For a mobile target the HTML and PDF reports add the
app facts and an *APIs and keys* section (summary line, alerts, tables; the helpers
`api_summary`, `api_alerts` and `api_tables` in `html_report.py` also serve the command
line), SARIF puts the inventory's summary, alerts and `truncated` counts in
`run.properties.apiInventory`, and the JSON report holds the whole inventory in `app.apis`.
The HTML and PDF reports say when a list was cut.

## 10. Security of the tool itself

- The dashboard listens on `localhost` only.
- Scanned code is never executed. External scanners are started with argument lists.
- LLM output is parsed as data. Proposed regular expressions run in a killable sandbox
  before they can ever run inside a scan.
- Secrets detected by the tool are masked in snippets, reports, prompts, the rule learner
  and the API and key inventory, scan-wide: a secret found in one file is masked in every
  file where it appears (a short or plain value only in its own file, section 4.4).
  Secrets it does not detect are not masked. The inventory never contacts the
  addresses it lists.
- The API key lives in `.env` (git-ignored, mode 600 where supported).
- A model file given to `--ml-model` is a pickle: load only models you trained yourself.

## 11. Extending

- **New rule**: for a user, the Rules tab or `python -m sca rules new FILE` (stored in
  `learned/custom.yaml`); for the project, an entry in `sca/rules/` plus test lines in
  `tests/test_engines.py`.
- **New imported rule set**: a converter in `tools/import_rules.py` that writes
  `sca/rules/imported/<name>.yaml` with a `source:` block.
- **New language**: extension in `LANG_BY_EXT`, name in `CODE_LANGUAGES`, comment prefix in
  `COMMENT_PREFIXES` (`sca/walker.py`); sources in `taint_lite.SOURCES` if wanted.
- **New engine**: `scan(files) -> List[Finding]` and one `run_engine(...)` line.
- **New Flutter/Android check**: a `Check` entry in `sca/flutter/checks.py` (`CHECKS`: id,
  English and Arabic title, CWE, severity, confidence, area, target), the code in one of the
  guarded parts of `analyze`, and a test in `tests/test_flutter_checks.py`. Give a new CWE a
  knowledge-base entry and, if it is mobile, a row in `cwe._MOBILE_ROWS`. Never add the same
  check as a regular-expression rule.
- **New service in the API and key inventory**: a (host suffix, service, category) entry
  in `SERVICES`, a named entry in `CONFIG_NAMES` or a pattern in `_ID_PATTERNS`
  (`sca/flutter/inventory.py`); a new label or alert text also needs its Arabic entry in
  `sca/ui/i18n.py`, and a test in `tests/test_flutter_inventory.py`.
- **New Pub advisory or discontinued package**: an entry in
  `sca/flutter/data/advisories.json` (OSV-style `affected` ranges) or `discontinued.json`.
- **New Dart rule**: an entry in `sca/rules/dart.yaml` with at least two vulnerable and two
  safe examples; a rule for named files (CI, Firebase, web) uses `files:` in
  `sca/rules/flutter.yaml`.
- **New app format or decoder**: a module in `sca/flutter/` that never raises on bad input
  (warnings instead), plus one guarded step in `apk.py` that adds virtual files with the
  right `origin`; builders for synthetic test input go next to it or in `tests/flutter_kit.py`.
- **New provider**: a preset in `PRESETS` if it is OpenAI-compatible; otherwise a client
  class with `check`, `models` and `chat_json`.
