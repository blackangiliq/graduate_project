"""Publish completed audit phases locally, retaining earlier measurements."""
import hashlib
import json
from pathlib import Path
import shutil


def main():
    repo = Path(__file__).resolve().parents[1]
    root = repo / "data/audits/2026-11-26-phone-apps"
    reference = json.loads((root / "reference.json").read_text(encoding="utf-8"))
    expected = sorted(app["name"] for app in reference["apps"])
    for source, target in (("final_static", "updated"), ("final_deep", "deep")):
        records = [json.loads((root / source / (name + ".summary.json")).read_text(encoding="utf-8"))
                   for name in expected]
        if any(record.get("status") != "ok" for record in records):
            raise RuntimeError("An audit phase is incomplete")
        for name in expected:
            for suffix in (".report.json", ".hits.json", ".sources.json.gz"):
                if not (root / source / (name + suffix)).is_file():
                    raise RuntimeError("A completed app lacks evidence")
        (root / source / "summary.json").write_text(
            json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        archive = root / "intermediate" / ("pre_final_" + target)
        archive.mkdir(parents=True, exist_ok=True)
        (root / target).mkdir(parents=True, exist_ok=True)
        for path in (root / target).glob("*.json"):
            saved = archive / path.name
            if not saved.exists():
                shutil.copy2(path, saved)
        for path in (root / source).iterdir():
            if path.is_file():
                shutil.copy2(path, root / target / path.name)
        print(json.dumps({"phase": target, "apps": len(records),
                          "apks": sum(x["input_apks"] for x in records),
                          "files": sum(x["files"] for x in records),
                          "findings": sum(x["findings"] for x in records),
                          "keys": sum(x["keys"] for x in records),
                          "addresses": sum(x["endpoints"] for x in records),
                          "api_call_sites": sum(x["calls"] for x in records)}))
    paths = [repo / "app.py", repo / "requirements.txt", repo / "learned/edits.yaml"]
    paths += [p for p in (repo / "sca").rglob("*") if p.suffix in (".py", ".yaml")]
    paths += list((repo / "tools").glob("*.py"))
    manifest = {p.relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(set(paths)) if p.is_file()}
    (root / "code_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
