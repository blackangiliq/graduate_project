"""Verify the pinned source references used by the rule review.

python tools/verify_rule_sources.py --download
python tools/verify_rule_sources.py --cache data/upstream-review-2026-11-27

Downloads only the manifest's pinned public source files, never executes them, and
rejects changed bytes. The manifest must be reviewed separately to add a new revision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "evaluation/upstream_sources_2026_11_27.json"


def verify(cache: Path, download: bool = False) -> list[dict]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = []
    cache.mkdir(parents=True, exist_ok=True)
    for source in manifest["sources"]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source["repository"]) \
                or not re.fullmatch(r"[a-f0-9]{40}", source["commit"]) \
                or not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]):
            raise ValueError("invalid pinned source identity")
        relative = source["path"]
        if ".." in Path(relative).parts or relative.startswith(("/", "\\")) or "\\" in relative:
            raise ValueError("invalid source path")
        url = "https://raw.githubusercontent.com/{repository}/{commit}/{path}".format(**source)
        target = cache / (source["sha256"] + ".source")
        if download:
            with urllib.request.urlopen(url, timeout=45) as response:
                payload = response.read(8 * 1024 * 1024 + 1)
            if len(payload) > 8 * 1024 * 1024:
                raise ValueError("source exceeds the download budget: " + relative)
        else:
            payload = target.read_bytes()
        if hashlib.sha256(payload).hexdigest() != source["sha256"]:
            raise ValueError("source content changed: " + source["repository"] + "/" + relative)
        if download:
            target.write_bytes(payload)
        rows.append({"repository": source["repository"], "path": relative,
                     "commit": source["commit"], "sha256": source["sha256"], "verified": True})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "data/upstream-review-2026-11-27")
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    result = verify(args.cache, args.download)
    print(json.dumps({"verified_sources": len(result), "sources": result}, indent=2))


if __name__ == "__main__":
    main()
