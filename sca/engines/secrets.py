"""Secrets engine: finds hard-coded passwords, API keys and tokens in any text file.

Two techniques are combined:
  1. Known formats  - regular expressions for well-known key formats (AWS, GitHub, ...).
  2. Assignments    - a variable whose NAME looks sensitive (password, api_key, ...) assigned
                      a string literal. Shannon entropy separates random-looking keys from
                      ordinary words, and obvious placeholders are ignored.

Secrets are masked in the output so that reports do not leak them.
"""
from __future__ import annotations

import math
import re
from typing import Iterable, List, Optional

from ..models import Finding
from ..walker import SourceFile, mask_secret
from . import rules_engine

KNOWN_FORMATS = [
    ("SECRET-AWS-001", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high", 0.9),
    ("SECRET-GITHUB-001", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "critical", 0.95),
    ("SECRET-GOOGLE-001", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high", 0.9),
    ("SECRET-SLACK-001", "Slack token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "high", 0.9),
    ("SECRET-STRIPE-001", "Stripe live key", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b", "critical", 0.95),
    ("SECRET-KEY-001", "Private key embedded in source",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "critical", 0.95),
    ("SECRET-JWT-001", "Hard-coded JSON Web Token",
     r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium", 0.7),
    ("SECRET-URL-001", "Credentials embedded in a connection URL",
     r"\b[a-z][a-z0-9+.-]{2,}://[^/\s:@'\"]{0,64}:(?!\$|\{|<|%|\*)[^/\s:@'\"]{3,64}@[\w.\-]+",
     "high", 0.8),
    # webhook addresses and bot tokens: whoever has them can post in the name of the owner.
    # The secret is the token (group 1), so that the rest of the address stays readable.
    ("SECRET-SLACK-002", "Slack webhook URL",
     r"\bhooks\.slack\.com/(?:services|workflows|triggers)/(?:[A-Za-z0-9_-]{6,}/){2,3}"
     r"([A-Za-z0-9_-]{16,})(?![A-Za-z0-9_/-])", "high", 0.85),     # the last segment
    ("SECRET-DISCORD-001", "Discord webhook URL",
     r"\bdiscord(?:app)?\.com/api/webhooks/\d{5,30}/([A-Za-z0-9_-]{30,})", "high", 0.85),
    ("SECRET-TELEGRAM-001", "Telegram bot token",
     r"(?:(?<=/bot)|(?<![\w:]))(\d{6,12}:AA[A-Za-z0-9_-]{31,40})(?![\w-])", "high", 0.8),
]
_KNOWN = [(i, t, re.compile(p), s, c) for i, t, p, s, c in KNOWN_FORMATS]

ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<name>[\w.\-\[\]'"]*?
        (?:passw(?:or)?d|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?key|
           access[_-]?key|private[_-]?key|client[_-]?secret|credential)
        [\w\-\]'"]*)
    \s*(?::|=|=>|:=)\s*
    (?P<quote>["'`])(?P<value>[^"'`\n]{4,200})(?P=quote)
    """)

# NAME=value lines of .env files (flutter_dotenv, docker, CI): the value has no quotes.
# Templates (.env.example ...) hold made-up values and are left to the quoted-value rule.
ENV_FILE = re.compile(r"(?i)(?:^|/)(?:\.env(?:\.[\w.-]+)?|[\w.-]+\.env)$")
ENV_TEMPLATE = re.compile(r"(?i)\.(?:example|sample|template|dist|defaults?|schema)$")
ENV_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?(?P<name>(?:[A-Za-z_][A-Za-z0-9_.]*?)?"
    r"(?:passw(?:or)?d|passwd|pwd|passphrase|secret|token|credential|hmac|auth|salt|private"
    r"|signature|key(?![A-Za-z0-9])|(?:^|(?<=[_.]))pass(?![A-Za-z0-9]))[A-Za-z0-9_.]*)"
    r"\s*=\s*(?P<q>[\"']?)(?P<value>[^\s'\"#]{4,200})(?P=q)(?:\s+#.*)?\s*$", re.IGNORECASE)
# names of settings, not of secrets (API_KEY_HEADER_NAME, TOKEN_PREFIX)
ENV_NOT_A_SECRET_NAME = re.compile(r"(?i)[_.](?:name|header|prefix|alias|field|param|label|id"
                                   r"|ttl|expiry|expires|length|size|url|uri|path|file|dir"
                                   r"|domain|host|hosts|scope|scopes|audience|region)$")
# values that are public by design or are only a host name: publishable keys (pk_live_,
# pk.eyJ ...), Firebase or Auth0 domains
ENV_PUBLIC_VALUE = re.compile(r"(?i)^(?:pk_(?:live|test)_|pk\.eyJ|appl_|goog_)"
                              r"|^(?:[a-z0-9-]+\.)+[a-z]{2,24}$")
# values of .env lines that are not secrets: an address without credentials, a file path,
# or lowercase words joined by _ - : . (CACHE_KEY=homepage_products_v2)
ENV_NOT_A_SECRET = re.compile(
    r"(?i)^[a-z][a-z0-9+.-]*://[^@\s]*$|^\.{0,2}/|\.(?:json|pem|p12|pfx|jks|key|crt|cer|txt"
    r"|ya?ml|xml|plist|db|sqlite)$")
_WORDS_VALUE = re.compile(r"(?i)^[a-z]{1,12}(?:[_\-:.](?:[a-z]{1,12}|v?\d{1,4}))+$")

PLACEHOLDER = re.compile(
    r"""(?ix)^(
        x+ | \*+ | \.+ | -+ | changeme | change[_-]?me | change[_-]?this | your[_\- ].* |
        <.*> | \$\{.*\} | \{\{.*\}\} | %\(.*\)s | %s | \{\w*\} | example.* | sample.* |
        placeholder.* | null | none | nil | true | false | todo | tbd | n/a | empty |
        password | passwd | secret | token | test | testing | dummy | fake.* | foo | bar |
        redacted | hidden | undefined | default | enter.* | insert.* | put.* | my[_-]?.*here
    )$""")
NOT_A_SECRET_NAME = re.compile(
    r"(?i)(token_?(url|uri|type|name|field|header|endpoint|path|expir|ttl|length|size|prefix)"
    r"|(password|passwd|pwd)_?(field|input|label|hint|reset|policy|min|max|length|regex|pattern|url"
    r"|hash_?alg|placeholder|text|title|prompt|message|error|help|rule)"
    r"|secret_?(name|id|arn|path|ref)|key_?(name|id|path|file|size|length)"
    r"|(public|pub)[_-]?key|_(file|path|url|uri|label|message|msg|error|prompt|placeholder)$"
    # interface text: "INITIAL_TOKEN_TOOLTIP", "LABEL_PASSWORD" hold words shown to a user
    r"|[_.-](tooltip|label|placeholder|title|hint|text|msg|message|error|header|heading"
    r"|description|desc|info|button|btn|link|prompt|help|caption|note|warning|success)['\"]?$"
    r"|^['\"]?(label|title|hint|btn|button|msg|message|error|tooltip|placeholder|text"
    r"|header|heading|link|nav|menu|tab|desc|description)[_.-]"
    r"|^['\"]?[\[(#*])")                          # an Angular binding: [passwordComponent]=
# Translation files hold words for every language, not configuration values.
TRANSLATION_DIRS = re.compile(r"(^|/)(i18n|l10n|locales?|langs?|translations?)/", re.IGNORECASE)
DOTTED_NAME = re.compile(r"^[a-z_]+(\.[a-z_-]+)+$")     # "keyword.operator", a style name
LOOKS_LIKE_CODE = re.compile(
    r"(os\.environ|getenv|process\.env|config\[|settings\.|\bself\.|\$_ENV)"
    r"|^\{?\$[A-Za-z_]\w*\}?$|#\{|^\$\{"           # a variable: '$pass_new', "{$x}", "#{x}"
    r"|^\$2[aby]?\$\d\d\$"                         # a bcrypt hash, not a password
    r"|^[A-Za-z_/]+#[A-Za-z_]+$")                  # a Rails route target: "users#reset"
QUOTED = re.compile(r"""["'`]([^"'`\n]*)["'`]""")


def placeholder_line(text: str) -> bool:
    """True when the value assigned on the line is a placeholder, a label or no literal at
    all: SECRET_KEY = 'your-secret-key-here', {"secret": None}. Used to drop the hard-coded
    password findings of Bandit, which has no placeholder list of its own."""
    values = QUOTED.findall(text)
    if not values:
        return True
    value = values[-1].strip()
    return bool(not value or PLACEHOLDER.match(value) or _natural_language(value)
                or LOOKS_LIKE_CODE.search(value))


def shannon_entropy(text: str) -> float:
    """Bits of information per character; random keys score higher than words."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(text))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def mask(secret: str) -> str:
    return mask_secret(secret)


def _natural_language(value: str) -> bool:
    """'Enter your password' is a label, not a password ("This is a secret!\\n" too)."""
    words = re.sub(r"(\\[nrt])+$", "", value).split()
    return len(words) >= 2 and all(w.strip(".,:!?").isalpha() for w in words)


def match_secret_rule(rule: "rules_engine.Rule", line: str):
    """Yield (span, secret) for each credential a rule of kind "secret" finds in a line.
    The secret is the rule's capture group when it has one, otherwise the whole match."""
    if rule.keywords:
        lowered = line.lower()
        if not any(keyword in lowered for keyword in rule.keywords):
            return
    for m in rule.pattern.finditer(line):
        if rule.exclude and rule.exclude.search(line):
            return
        if any(extra.search(line) for extra in rule.extra_excludes):
            return
        group = rule.secret_group or (1 if m.re.groups else 0)
        secret = m.group(group) if group <= m.re.groups and m.group(group) else m.group(0)
        if PLACEHOLDER.match(secret) or LOOKS_LIKE_CODE.search(secret):
            continue
        if rule.entropy and shannon_entropy(secret) < rule.entropy:
            continue
        span = m.span(group) if group <= m.re.groups and m.group(group) else m.span()
        yield span, secret


def _env_hit(match: "re.Match", number: int, hits: list) -> list:
    """A NAME=value line of a .env file whose name says it holds a secret: the value, when it
    is not a placeholder, a variable or too regular to be a key. Returns its span."""
    name, value = match.group("name"), match.group("value")
    if PLACEHOLDER.match(value) or LOOKS_LIKE_CODE.search(value) or NOT_A_SECRET_NAME.search(name) \
            or ENV_NOT_A_SECRET_NAME.search(name) or ENV_NOT_A_SECRET.search(value) \
            or ENV_PUBLIC_VALUE.search(value):
        return []
    entropy = shannon_entropy(value)
    if re.search(r"(?i)pass|pwd", name):
        if len(value) < 6:
            return []
        confidence = 0.75 if entropy >= 2.5 else 0.6
    elif len(value) < 12 or entropy < 3.0 or _WORDS_VALUE.match(value):
        return []
    else:
        confidence = 0.8 if entropy >= 3.5 else 0.65
    hits.append((number, value, "SECRET-HARDCODED-001",
                 "Hard-coded secret in '%s'" % name[-40:], "high", confidence))
    return [match.span("value")]


def scan_file(sf: SourceFile, rules: Optional[List["rules_engine.Rule"]] = None) -> List[Finding]:
    hits = []  # (line number, secret, rule id, title, severity, confidence)
    rules = rules_engine.secret_rules() if rules is None else rules
    if rules:   # keep only the rules whose keyword occurs somewhere in this file
        lowered_file = sf.text.lower()
        rules = [r for r in rules
                 if not r.keywords or any(k in lowered_file for k in r.keywords)]
    translations = bool(TRANSLATION_DIRS.search("/" + sf.rel.replace("\\", "/")))
    rel = sf.rel.replace("\\", "/")
    env_file = bool(ENV_FILE.search(rel)) and not ENV_TEMPLATE.search(rel)
    for number, line in enumerate(sf.lines, start=1):
        if len(line) > 1000:
            continue
        hit_spans = []
        for rule_id, title, pattern, severity, confidence in _KNOWN:
            for m in pattern.finditer(line):
                secret = m.group(1) if pattern.groups else m.group(0)
                if rule_id == "SECRET-URL-001":
                    secret = secret.split("@")[0].rsplit(":", 1)[-1]  # only the password part
                    if PLACEHOLDER.match(secret):
                        continue
                hit_spans.append(m.span())
                hits.append((number, secret, rule_id, title, severity, confidence))
        env = ENV_ASSIGNMENT.match(line) if env_file else None
        if env and not any(s[0] < env.end("value") and env.start("value") < s[1]
                           for s in hit_spans):     # a known format reported it already
            hit_spans.extend(_env_hit(env, number, hits))
        for rule in rules:
            for span, secret in match_secret_rule(rule, line):
                if any(s[0] < span[1] and span[0] < s[1] for s in hit_spans):
                    continue  # the same credential was already reported
                hit_spans.append(span)
                hits.append((number, secret, rule.id, rule.title, rule.severity,
                             rule.confidence))
        for m in (() if translations else ASSIGNMENT.finditer(line)):
            name, value = m.group("name"), m.group("value").strip()
            if any(s[0] < m.end("value") and m.start("value") < s[1] for s in hit_spans):
                continue  # already reported by a known-format rule (a webhook URL, a key)
            if PLACEHOLDER.match(value) or NOT_A_SECRET_NAME.search(name) \
                    or DOTTED_NAME.match(value):
                continue
            if LOOKS_LIKE_CODE.search(value) or _natural_language(value):
                continue
            entropy = shannon_entropy(value)
            if re.search(r"(?i)pass|pwd", name):
                if len(value) < 6:
                    continue
                confidence = 0.75 if entropy >= 2.5 else 0.6
            else:
                # keys and tokens are random-looking: require length and entropy
                if len(value) < 12 or entropy < 3.2:
                    continue
                confidence = 0.8 if entropy >= 3.8 else 0.65
            hits.append((number, value, "SECRET-HARDCODED-001",
                         "Hard-coded secret in '%s'" % name.strip("'\"[]")[-40:],
                         "high", confidence))
    # remember the values first, so that every snippet and context of this file is masked
    sf.secret_values = sorted({h[1] for h in hits}, key=len, reverse=True)
    # and where each one is, for the API and key inventory of an app (sca/flutter/inventory.py)
    sf.secret_hits = [(number, rule_id, secret, title, severity)
                      for number, secret, rule_id, title, severity, _confidence in hits]
    return [Finding(rule_id=rule_id, title=title, file=sf.rel, line=number, severity=severity,
                    cwe="CWE-798", confidence=confidence, engines=["secrets"],
                    snippet=sf.line_text(number), context=sf.context(number, 1, 1),
                    language=sf.language)
            for number, _secret, rule_id, title, severity, confidence in hits]


def scan(files: Iterable[SourceFile]) -> List[Finding]:
    rules = rules_engine.secret_rules()
    out: List[Finding] = []
    for sf in files:
        out.extend(scan_file(sf, rules))
    return out
