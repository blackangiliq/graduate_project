"""Import a reviewed static subset of Betterleaks without executing its expressions.

Usage: python tools/import_betterleaks.py PATH/TO/betterleaks.toml
The input must match the pinned source SHA-256 below. No network request is made.
Requires the development dependencies from requirements-dev.txt (including exrex).
Only new, prefixed, high-confidence formats with compatible entropy filters qualify.
Validation, analysis, revocation and component-association expressions are never copied.
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
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools.import_rules import clean_lines, fast, generate_example, gitleaks_title, python_ok
from sca.engines import rules_engine, secrets

COMMIT = "702504ab4551b9a1c1837efdb6b340536aa4c761"
SOURCE_URL = f"https://github.com/betterleaks/betterleaks/blob/{COMMIT}/config/betterleaks.toml"
SOURCE_SHA256 = "d0bcc9fc06fbbd14c97a49a3d50eb6ee62be64bef18ccab74b86eab3767f2355"
ENTROPY_FILTER = re.compile(r'entropy\(finding\["secret"\]\)\s*(<=?)\s*(\d+(?:\.\d+)?)')
MANUAL_EXCLUSIONS = {
    "configcat-sdk-key-extended": "client SDK identifier; not treated as a secret by this pack",
    "couchbase-capella-api-key": "broad nearby-name expression, outside prefixed-token subset",
}
STATIC_ONLY_COMPONENTS = {"supabase-project-api-key"}


def convert(rule: dict, existing: set[str]) -> tuple[dict | None, str]:
    """Return a compatible literal detector, or an explicit reason for not importing it."""
    rule_id = rule["id"]
    if rule_id in existing or re.sub(r"\.\d+$", "", rule_id) in existing:
        return None, "already represented by the Gitleaks pack"
    if rule_id in MANUAL_EXCLUSIONS:
        return None, MANUAL_EXCLUSIONS[rule_id]
    if rule.get("skipReport"):
        return None, "association-only identifier, not a stand-alone secret"
    if rule.get("components") and rule_id not in STATIC_ONLY_COMPONENTS:
        return None, "requires component association not implemented by the static importer"
    if rule.get("path"):
        return None, "requires path semantics not implemented by this importer"
    if rule.get("confidence") != "high":
        return None, "outside the reviewed high-confidence subset"
    pattern = rule.get("regex", "")
    if not pattern.startswith((r"\b(", r"(?i)\b(")):
        return None, "not a standalone provider-prefixed token"
    expression = rule.get("filter", "").strip()
    match = ENTROPY_FILTER.fullmatch(expression)
    if expression and match is None:
        return None, "requires unsupported filter semantics; not silently dropped"
    error = python_ok(pattern)
    if error:
        return None, "Python-incompatible expression: " + error
    parsed = re.compile(pattern)
    group = int(rule.get("valueGroup", 1))
    if group != 1 or parsed.groups != 1:
        return None, "requires a nonstandard capture layout"
    raw = {
        "id": "BETTERLEAKS-" + rule_id,
        "source": rule_id,
        "kind": "secret",
        "title": gitleaks_title(rule_id.removesuffix(".1").removesuffix(".2")),
        "languages": ["any"], "cwe": "CWE-798", "severity": "high", "confidence": 0.85,
        "pattern": pattern, "secret_group": 1,
        "keywords": [str(k).lower() for k in rule.get("keywords", [])],
        "message": "A literal matches this provider's credential format. Static detection does "
                   "not establish whether it is active, which permissions it has, or whether "
                   "the service accepts it.",
        "fix": "Review the credential and its provider restrictions. If it grants unintended "
               "access, rotate it and move privileged operations to a trusted backend.",
        "note": "Static format adaptation of Betterleaks " + COMMIT + ". "
                "No network verification, analysis, revocation, or global path exclusions. "
                "The scanner's own placeholder checks apply.",
    }
    if match:
        threshold = float(match[2])
        # The engine accepts entropy >= threshold; upstream <= rejects equality too.
        raw["entropy"] = math.nextafter(threshold, math.inf) if match[1] == "<=" else threshold
    if rule_id in STATIC_ONLY_COMPONENTS:
        raw["note"] += (" The provider-specific sb_secret_ format is reported as an unverified "
                        "literal even without a project URL. Upstream's URL association is used "
                        "for service validation and is not claimed by this adaptation.")
    return raw, ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        import exrex  # noqa: F401 -- used by the shared example generator
    except ImportError:
        parser.error("exrex is required; use the project development environment (requirements-dev.txt)")
    data = args.config.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        parser.error("input differs from the reviewed pinned configuration")
    upstream = tomllib.loads(data.decode("utf-8"))
    old = yaml.safe_load((ROOT / "sca/rules/imported/gitleaks.yaml").read_text(encoding="utf-8"))
    existing = {row["source"] for row in old["rules"]}
    clean = clean_lines()
    builtins = [re.compile(pattern) for _, _, pattern, *_ in secrets.KNOWN_FORMATS]
    rows, decisions = [], []
    for rule in upstream["rules"]:
        raw, reason = convert(rule, existing)
        if raw is not None:
            reason = fast(raw["pattern"])
            example = generate_example({**raw, "keywords": []}) if not reason else ""
            if example and raw["keywords"] and not any(k in example.lower() for k in raw["keywords"]):
                # Some upstream formats deliberately require the provider name on the line.
                example = raw["keywords"][0] + " = " + example
            if not reason and not example:
                reason = "could not construct a matching example for the converted rule"
            if not reason and any(p.search(example) for p in builtins):
                reason = "example already recognized by a built-in format"
            parsed = rules_engine.parse_rule(raw, "imported")
            if not reason and any(list(secrets.match_secret_rule(parsed, line)) for line in clean):
                reason = "matches a known-safe sample or decoy"
            if not reason:
                rows.append(raw)
        decisions.append({"id": rule["id"], "status": "skipped" if reason else "enabled",
                          "reason": reason or "compatible prefix, capture, entropy, stress and clean-sample checks passed"})
    metadata = {"name": "Betterleaks", "url": SOURCE_URL, "license": "MIT",
                "copyright": "Copyright (c) 2026 Zachary Rice", "commit": COMMIT,
                "sha256": SOURCE_SHA256, "imported": "2026-11-26"}
    out = ROOT / "sca/rules/imported/betterleaks.yaml"
    out.write_text("# Generated by tools/import_betterleaks.py; static subset only.\n" +
                   yaml.safe_dump({"source": metadata, "rules": rows}, sort_keys=False,
                                  allow_unicode=True, width=100), encoding="utf-8")
    report = {"source": metadata, "upstream_rules": len(upstream["rules"]),
              "counts": dict(Counter(row["status"] for row in decisions)),
              "checks": {"known_safe_lines": len(clean), "known_safe_matches": 0,
                         "python_compatible": len(rows), "stress_checks_passed": len(rows),
                         "matching_examples": len(rows), "live_credentials_validated": 0},
              "rules": decisions}
    (ROOT / "evaluation/betterleaks_import_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"imported": len(rows), "upstream": len(upstream["rules"]),
                      "skipped": len(decisions) - len(rows)}))


if __name__ == "__main__":
    main()
