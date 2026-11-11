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
     r"\b[a-z][a-z0-9+.-]{2,}://[^/\s:@'\"]{1,64}:(?!\$|\{|<|%|\*)[^/\s:@'\"]{3,64}@[\w.\-]+",
     "high", 0.8),
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
    r"|(public|pub)[_-]?key|_(file|path|url|uri|label|message|msg|error|prompt|placeholder)$)")
LOOKS_LIKE_CODE = re.compile(r"(os\.environ|getenv|process\.env|config\[|settings\.|\bself\.|\$_ENV)")


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
    """'Enter your password' is a label, not a password."""
    words = value.split()
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


def scan_file(sf: SourceFile, rules: Optional[List["rules_engine.Rule"]] = None) -> List[Finding]:
    hits = []  # (line number, secret, rule id, title, severity, confidence)
    rules = rules_engine.secret_rules() if rules is None else rules
    if rules:   # keep only the rules whose keyword occurs somewhere in this file
        lowered_file = sf.text.lower()
        rules = [r for r in rules
                 if not r.keywords or any(k in lowered_file for k in r.keywords)]
    for number, line in enumerate(sf.lines, start=1):
        if len(line) > 1000:
            continue
        hit_spans = []
        for rule_id, title, pattern, severity, confidence in _KNOWN:
            for m in pattern.finditer(line):
                secret = m.group(0)
                if rule_id == "SECRET-URL-001":
                    secret = secret.split("@")[0].rsplit(":", 1)[-1]  # only the password part
                    if PLACEHOLDER.match(secret):
                        continue
                hit_spans.append(m.span())
                hits.append((number, secret, rule_id, title, severity, confidence))
        for rule in rules:
            for span, secret in match_secret_rule(rule, line):
                if any(s[0] < span[1] and span[0] < s[1] for s in hit_spans):
                    continue  # the same credential was already reported
                hit_spans.append(span)
                hits.append((number, secret, rule.id, rule.title, rule.severity,
                             rule.confidence))
        for m in ASSIGNMENT.finditer(line):
            name, value = m.group("name"), m.group("value").strip()
            if any(s[0] <= m.start("value") < s[1] for s in hit_spans):
                continue  # already reported by a known-format rule
            if PLACEHOLDER.match(value) or NOT_A_SECRET_NAME.search(name):
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
