"""Reproduce the reviewed contextual Betterleaks subset, without network verification.

Usage: python tools/import_contextual_secrets.py PATH/TO/betterleaks.toml
The source hash, selected IDs, capture layout and supported filter are checked before
writing. This supplements the prefix-only importer; it never replaces its decisions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 development environment
    import tomli as tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.import_betterleaks import COMMIT, SOURCE_SHA256, SOURCE_URL, ENTROPY_FILTER
from tools.import_rules import clean_lines, fast, generate_example, gitleaks_title, python_ok
from sca.engines import rules_engine, secrets

# Only these formats were reviewed. New upstream rows cannot silently broaden the pack.
REVIEWED = {
    "asaas-api-token", "azure-app-configuration-connection-string",
    "azure-servicebus-connection-string", "canadian-digital-service-notify-api-key",
    "clickup-personal-api-token", "crates-io-api-key", "databento-api-key",
    "deepseek-api-key", "elevenlabs-api-key", "fal-api-key.1",
    "figma-personal-access-header-token", "gitlab-pat-routable-versioned",
    "kagi-api-key", "kimi-api-key", "mem0-api-key.1", "ngrok-api-key.1",
    "ollama-api-key", "retell-api-key.1", "zhipu-api-key",
    "zoho-oauth-token.1", "zoho-zapi-key.1",
}


def convert(rule: dict) -> tuple[dict | None, str]:
    if rule.get("id") not in REVIEWED:
        return None, "outside the separately reviewed contextual subset"
    if any(rule.get(k) for k in ("skipReport", "path", "components")):
        return None, "requires unsupported path or component-association semantics"
    if rule.get("confidence") != "high":
        return None, "upstream confidence differs from the reviewed version"
    expression = rule.get("filter", "").strip()
    match = ENTROPY_FILTER.fullmatch(expression)
    if expression and match is None:
        return None, "unsupported filter semantics; never silently dropped"
    pattern = rule.get("regex", "")
    error = python_ok(pattern)
    if error:
        return None, "Python-incompatible regex: " + error
    groups = re.compile(pattern).groups
    group = int(rule.get("valueGroup", 1 if groups else 0))
    if group < 0 or group > groups or (groups and group == 0):
        return None, "invalid or ambiguous secret capture group"
    raw = {
        "id": "BETTERLEAKS-" + rule["id"], "source": rule["id"],
        "title": gitleaks_title(re.sub(r"\.\d+$", "", rule["id"])) + " candidate",
        "kind": "secret", "languages": ["any"], "cwe": "CWE-798",
        "severity": "high", "confidence": 0.8,
        "pattern": pattern, "secret_group": group,
        "keywords": [str(k).lower() for k in rule.get("keywords", [])],
        "message": "A literal matches the provider's format and any context required by "
                   "this rule. Its validity, permissions and exploitability are unverified.",
        "fix": "Review the value and provider restrictions. Rotate exposed privileged "
               "credentials and move service secrets to a trusted backend.",
        "note": "Reviewed static adaptation of Betterleaks " + COMMIT + ". "
                "Provider context, full captured value and supported entropy filter are "
                "preserved. No validation, analysis, revocation or association code is executed.",
    }
    if match:
        threshold = float(match[2])
        raw["entropy"] = math.nextafter(threshold, math.inf) if match[1] == "<=" else threshold
    return raw, ""


def build(config: Path) -> tuple[dict, dict]:
    data = config.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("input differs from the reviewed pinned configuration")
    upstream = tomllib.loads(data.decode("utf-8"))["rules"]
    if not REVIEWED <= {r["id"] for r in upstream}:
        raise ValueError("reviewed rules are missing from the configuration")
    rows, decisions = [], []
    clean = clean_lines()
    for rule in upstream:
        raw, reason = convert(rule)
        if raw is not None:
            reason = fast(raw["pattern"])
            if not reason and not generate_example(raw):
                reason = "could not construct an example accepted by the complete detector"
            parsed = rules_engine.parse_rule(raw, "imported")
            if not reason and any(list(secrets.match_secret_rule(parsed, line)) for line in clean):
                reason = "matched the known-safe corpus"
            if reason:
                raise ValueError(rule["id"] + ": " + reason)
            rows.append(raw)
        decisions.append({"id": rule["id"], "status": "enabled" if not reason else "skipped",
                          "reason": reason or "reviewed context/capture/filter; compile, stress, example and clean-corpus checks passed"})
    source = {"name": "Betterleaks contextual subset", "url": SOURCE_URL,
              "commit": COMMIT, "sha256": SOURCE_SHA256, "license": "MIT",
              "copyright": "Copyright (c) 2026 Zachary Rice", "imported": "2026-11-27"}
    pack = {"source": source, "rules": rows}
    report = {"source": source, "upstream_rules": len(upstream),
              "counts": {"enabled": len(rows), "skipped": len(upstream) - len(rows)},
              "checks": {"known_safe_lines": len(clean), "known_safe_matches": 0,
                         "stress_checks_passed": len(rows), "matching_examples": len(rows),
                         "live_credentials_validated": 0}, "rules": decisions}
    return pack, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        pack, report = build(args.config)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    (ROOT / "sca/rules/imported/betterleaks_contextual.yaml").write_text(
        "# Generated by tools/import_contextual_secrets.py; unverified literal detections only.\n" +
        yaml.safe_dump(pack, sort_keys=False, allow_unicode=True, width=100), encoding="utf-8")
    (ROOT / "evaluation/contextual_secrets_import_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["counts"]))


if __name__ == "__main__":
    main()
