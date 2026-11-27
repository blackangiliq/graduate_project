"""Independently check retained runtime journals, source coordinates and archive round trips."""
from __future__ import annotations

import argparse
import gc
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))


def verify_locations(capture: dict, decoded_files) -> dict:
    issues, checked = [], 0
    events = capture.get("events", [])
    for observation in capture.get("observations", []):
        identifier = observation.get("id", "unknown")
        references = observation.get("evidence_locations") or [observation.get("evidence", {})]
        for reference in references:
            number = reference.get("line", 0)
            if type(number) is not int or not 1 <= number <= len(events):
                issues.append(f"{identifier}: runtime line is outside retained journal")
            elif events[number - 1].get("id") not in observation.get("event_ids", []):
                issues.append(f"{identifier}: runtime line and event ID disagree")
        for location in observation.get("locations", []):
            if not location.get("verified"):
                continue
            file = decoded_files.get(location.get("file"))
            lines = file.get("lines", []) if isinstance(file, dict) else getattr(file, "lines", [])
            line, start, end = location.get("line", 0), location.get("column", 0), location.get("end_column", 0)
            if (type(line) is not int or type(start) is not int or type(end) is not int
                    or not 1 <= line <= len(lines) or not 1 <= start < end):
                issues.append(f"{identifier}: source coordinates are invalid or missing from archive")
            elif lines[line - 1][start - 1:end - 1] != observation.get("value"):
                issues.append(f"{identifier}: source coordinates do not reproduce the exact full value")
            else:
                checked += 1
    return {"issues": issues, "verified_source_coordinates": checked}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--database", type=Path, default=REPO / "data/sca.db")
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args()
    from sca.dynamic import validate_capture
    from sca.storage import Storage
    store = Storage(str(args.database))
    inventory = json.loads((args.directory / "input_inventory.json").read_text(encoding="utf-8"))
    results = []
    for app in inventory["apps"]:
        if args.only and app["app"] not in args.only:
            continue
        folder = args.directory / app["app"]
        record = {"app": app["app"], "issues": []}
        try:
            summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
            capture = json.loads((folder / "capture.json").read_text(encoding="utf-8"))
            if not summary.get("session_id") or summary["session_id"] != capture.get("session_id"):
                raise ValueError("Latest summary has no matching captured session")
            validate_capture(capture)
            journal = [json.loads(line) for line in Path(capture["artifacts"]["events_file"])
                       .read_text(encoding="utf-8").splitlines()]
            record["journal_equal"] = journal == capture["events"]
            if not record["journal_equal"]:
                record["issues"].append("Retained report differs from the actual JSONL journal")
            scan = store.load_scan(app["static_scan_id"])
            if scan is None:
                raise ValueError("Linked static archive is unavailable")
            locations = verify_locations(capture, scan.decoded_files)
            record["issues"].extend(locations["issues"])
            record["verified_source_coordinates"] = locations["verified_source_coordinates"]
            if summary.get("capture_id"):
                saved = store.load_dynamic_session(summary["capture_id"], scan_id=app["static_scan_id"])
                # Loading adds archive identifiers; payload comparison excludes only those fields.
                payload = {key: value for key, value in (saved or {}).items() if key not in {"capture_id", "scan_id"}}
                record["archive_equal"] = payload == capture
                if not record["archive_equal"]:
                    record["issues"].append("Archived dynamic payload differs from the captured report")
            record.update(status="verified" if not record["issues"] else "failed",
                          capture_status=capture["status"], events=len(capture["events"]),
                          observations=len(capture["observations"]))
            del scan, capture, journal
        except (OSError, ValueError, KeyError, TypeError) as exc:
            record.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        results.append(record)
        print(json.dumps(record, ensure_ascii=True), flush=True)
        gc.collect()
    output = {"method": "Actual JSONL equality, independent event-ID/line and exact source substring checks, archive round trip.",
              "scope": "Evidence integrity only; does not establish exhaustive runtime coverage or exploitability.",
              "apps": results}
    (args.directory / "validation.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    return int(any(item["status"] != "verified" for item in results))


if __name__ == "__main__":
    raise SystemExit(main())
