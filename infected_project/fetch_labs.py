"""Download the deliberately vulnerable training labs listed in labs.json into this folder.

    python infected_project/fetch_labs.py              # every lab
    python infected_project/fetch_labs.py DVWA DSVW    # only these

Each lab is fetched with git at the commit recorded in labs.json, so that the scan results
in RESULTS.md can be reproduced exactly. Only one commit is fetched (no history), and the
files of folders listed under "exclude" are never downloaded.

The labs are not stored in this repository: they belong to their authors (see the licence
of each one in README.md), together they are large, and several contain fake keys on
purpose that would trip GitHub's secret scanning. They stay on this computer only
(.gitignore). Never deploy them: they are insecure on purpose.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def git(target: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(target), check=True)


def fetch(lab: dict) -> bool:
    target = HERE / lab["name"]
    if (target / ".git").exists():
        print("%-32s already downloaded" % lab["name"])
        return True
    url = "https://github.com/%s.git" % lab["repo"]
    print("%-32s %s @ %s" % (lab["name"], url, lab["commit"][:10]), flush=True)
    target.mkdir(exist_ok=True)
    try:
        git(target, "init", "-q")
        git(target, "remote", "add", "origin", url)
        if lab.get("exclude"):
            git(target, "sparse-checkout", "set", "--no-cone", "/*",
                *["!/%s/" % folder for folder in lab["exclude"]])
        git(target, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", lab["commit"])
        git(target, "checkout", "-q", "FETCH_HEAD")
    except (subprocess.CalledProcessError, OSError) as exc:
        print("  failed: %s" % exc, file=sys.stderr)
        return False
    return True


def main(names: list) -> int:
    labs = json.loads((HERE / "labs.json").read_text(encoding="utf-8"))
    unknown = set(names) - {lab["name"] for lab in labs}
    if unknown:
        print("Unknown lab(s): %s" % ", ".join(sorted(unknown)), file=sys.stderr)
        return 2
    chosen = [lab for lab in labs if not names or lab["name"] in names]
    failed = [lab["name"] for lab in chosen if not fetch(lab)]
    print("\n%d of %d labs ready in %s" % (len(chosen) - len(failed), len(chosen), HERE))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
