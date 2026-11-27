"""Compare independent literal evidence with real pipeline scan artifacts.

Counts describe this finite reference set, never every possible endpoint or vulnerability.
Full values go to local JSON, not the console or summary Markdown.
"""
import argparse
import base64
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit


def url_key(value):
    value = html.unescape(value).strip().rstrip(".,;")
    try:
        parts = urlsplit(value)
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))
    except ValueError:
        return value


def pem_key(value):
    text = value.replace(r"\r\n", "\n").replace(r"\n", "\n")
    match = re.search(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----(.*?)-----END \1-----", text, re.S)
    if not match:
        return None
    try:
        body = base64.b64decode(re.sub(r"\s", "", match[2]), validate=True)
        return hashlib.sha256(body).hexdigest()
    except ValueError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--phases", nargs="+", default=["baseline", "updated"])
    args = parser.parse_args()
    reference = json.loads((args.root / "reference.json").read_text(encoding="utf-8"))
    comparison = {"method": "Exact candidate values; HTML entities normalized in URLs; PEM compared by decoded body hash. No network validity checks.",
                  "apps": []}
    for app in reference["apps"]:
        expected = [key for key in app["keys"] if key["status"] == "format_candidate_not_remotely_validated"]
        fixtures = [key for key in app["keys"] if key["status"] == "fixture_shaped_jwt_not_production_secret_proof"]
        urls = [url for url in app["urls"] if url.get("category") in
                {"literal_service_or_web_address", "local_development_address", "runtime_address_template"}]
        pems = {pem_key(item["value"]) for item in app.get("pem_blocks", [])} - {None}
        row = {"app": app["name"], "reference_formats": len(expected), "reference_fixture_tokens": len(fixtures),
               "reference_pem_materials": len(pems), "reference_service_web_and_template_urls": len(urls), "phases": {}}
        for phase in args.phases:
            report_path = args.root / phase / (app["name"] + ".report.json")
            if not report_path.exists():
                continue
            report = json.loads(report_path.read_text(encoding="utf-8"))
            hits = json.loads((args.root / phase / (app["name"] + ".hits.json")).read_text(encoding="utf-8"))
            summary = json.loads((args.root / phase / (app["name"] + ".summary.json")).read_text(encoding="utf-8"))
            inventory = report.get("app", {}).get("apis", {})
            values = {hit["value"] for hit in hits}
            addresses = {url_key(item["url"]) for item in inventory.get("endpoints", [])}
            found_pems = {pem_key(value) for value in values} - {None}
            missing_urls = [item for item in urls if url_key(item["value"]) not in addresses]
            missing_keys = [item for item in expected if item["value"] not in values]
            row["phases"][phase] = {
                "findings": summary["findings"], "files": summary["files"],
                "displayed_keys": len(inventory.get("keys", [])), "displayed_urls": len(addresses),
                "format_matches": len(expected) - len(missing_keys), "format_missing": missing_keys,
                "fixture_token_matches": sum(item["value"] in values for item in fixtures),
                "complete_pem_material_matches": len(pems & found_pems),
                "private_key_findings": sum(f["rule_id"] == "SECRET-KEY-001" for f in report["findings"]),
                "reference_url_matches": len(urls) - len(missing_urls), "reference_url_missing": missing_urls,
                "inventory_limits": inventory.get("truncated", {}), "warnings": report.get("app", {}).get("warnings", []),
                "coverage": report.get("app", {}).get("analysis_coverage", {}),
                "scan_id": summary.get("scan_id"), "engine_notes": summary.get("engine_notes", {}),
            }
        comparison["apps"].append(row)
    (args.root / "comparison.json").write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
    for app in comparison["apps"]:
        print(json.dumps({"app": app["app"], "reference_formats": app["reference_formats"],
                          **{phase: {field: data[field] for field in
                                     ("displayed_keys", "displayed_urls", "format_matches", "complete_pem_material_matches", "reference_url_matches")}
                             for phase, data in app["phases"].items()}}))


if __name__ == "__main__":
    main()
